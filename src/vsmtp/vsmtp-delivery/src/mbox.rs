/*
 * vSMTP mail transfer agent
 * Copyright (C) 2022 viridIT SAS
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see https://www.gnu.org/licenses/.
 *
*/

use anyhow::Context;
use vsmtp_common::{
    libc_abstraction::chown,
    transfer::{error::LocalDelivery, Status},
    transport::{AbstractTransport, DeliverTo},
    Address, ContextFinished,
};
extern crate alloc;

const CTIME_FORMAT: &[time::format_description::FormatItem<'_>] = time::macros::format_description!(
    "[weekday repr:short] [month repr:short] [day padding:space] [hour]:[minute]:[second] [year]"
);

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    #[serde(with = "r#type")]
    pub(super) r#type: String,
    #[serde(
        serialize_with = "vsmtp_config::parser::syst_group::opt_serialize",
        deserialize_with = "vsmtp_config::parser::syst_group::opt_deserialize"
    )]
    group_local: Option<users::Group>,
}

def_type_serde!("mbox");

impl PartialEq for Payload {
    fn eq(&self, other: &Self) -> bool {
        self.group_local.as_ref().map(users::Group::gid)
            == other.group_local.as_ref().map(users::Group::gid)
    }
}

impl Eq for Payload {}

/// resolver use to write emails on the system following the
/// application/mbox Media Type.
/// (see [rfc4155](https://datatracker.ietf.org/doc/html/rfc4155#appendix-A))
#[derive(Debug, PartialEq, Eq, serde::Deserialize)]
pub struct MBox {
    #[serde(flatten)]
    payload: Payload,
}

impl serde::Serialize for MBox {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_json::to_string(&self.payload)
            .map_err(|e| serde::ser::Error::custom(format!("{e:?}")))
            .and_then(|json| serializer.serialize_str(&json))
    }
}

impl MBox {
    ///
    #[must_use]
    #[inline]
    pub fn new(group_local: Option<users::Group>) -> Self {
        Self {
            payload: Payload {
                group_local,
                r#type: "mbox".to_owned(),
            },
        }
    }
}

impl vsmtp_common::transport::GetID for MBox {}

#[async_trait::async_trait]
impl AbstractTransport for MBox {
    #[inline]
    async fn deliver(
        self: alloc::sync::Arc<Self>,
        ctx: &ContextFinished,
        mut to: DeliverTo,
        content: &[u8],
    ) -> DeliverTo {
        for rcpt in &mut to {
            match users::get_user_by_name(rcpt.0.local_part()).map(|user| {
                // NOTE: only linux system is supported here, is the
                //       path to all mbox always /var/mail ?
                write_content_to_mbox(
                    &rcpt.0,
                    &user,
                    self.payload.group_local.as_ref(),
                    content,
                    &ctx.mail_from.reverse_path,
                    &ctx.connect.connect_timestamp,
                )
            }) {
                Some(Ok(_)) => {
                    tracing::info!("Email delivered.");

                    rcpt.1 = Status::sent();
                }
                Some(Err(error)) => {
                    tracing::error!(%error, "Email delivery failure.");

                    rcpt.1.held_back(LocalDelivery::Other(error.to_string()));
                }
                None => {
                    tracing::error!(
                        error = format!("user not found: {}", rcpt.0.local_part()),
                        "Email delivery failure."
                    );

                    rcpt.1.held_back(LocalDelivery::MailboxDoNotExist {
                        mailbox: rcpt.0.local_part().to_owned(),
                    });
                }
            }
        }
        to
    }
}

fn get_mbox_timestamp_format(timestamp: &time::OffsetDateTime) -> String {
    timestamp
        .format(&CTIME_FORMAT)
        .unwrap_or_else(|_| String::default())
}

fn write_content_to_mbox(
    addr: &Address,
    user: &users::User,
    group_local: Option<&users::Group>,
    content: &[u8],
    from: &Option<Address>,
    connect_timestamp: &time::OffsetDateTime,
) -> anyhow::Result<()> {
    let mbox_dir = std::path::PathBuf::from_iter(["/", "var", "mail"]);
    std::fs::create_dir_all(&mbox_dir)
        .with_context(|| format!("failed to create {}", mbox_dir.display()))?;

    let mbox_filepath = mbox_dir.join(addr.local_part());

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&mbox_filepath)
        .with_context(|| format!("failed to open file at '{}'", mbox_filepath.display()))?;

    chown(
        &mbox_filepath,
        Some(user.uid()),
        group_local.map(users::Group::gid),
    )
    .with_context(|| format!("failed to set user rights to {}", mbox_filepath.display()))?;

    std::io::Write::write_all(&mut file, format!("Delivered-To: {addr}\n").as_bytes())?;
    std::io::Write::write_all(
        &mut file,
        format!(
            "From {} {}\n",
            from.as_ref()
                .map_or_else(|| "null".to_owned(), ToString::to_string),
            get_mbox_timestamp_format(connect_timestamp)
        )
        .as_bytes(),
    )?;
    std::io::Write::write_all(&mut file, content)?;

    Ok(())
}

#[cfg(test)]
mod test {

    use super::*;
    use vsmtp_common::transfer::error::Variant;
    use vsmtp_common::{addr, transport::WrapperSerde};

    #[rstest::rstest]
    #[case::no_group(
        &serde_json::json!({
            "v": r#"{"type":"mbox","group_local":null}"#
        }).to_string(),
        MBox::new(None)
    )]
    #[case::with_group(
        &serde_json::json!({
            "v": r#"{"type":"mbox","group_local":"mail"}"#
        }).to_string(),
        MBox::new(Some(users::get_group_by_name("mail").unwrap()))
    )]
    fn deserialize(#[case] input: &str, #[case] instance: MBox) {
        #[derive(serde::Deserialize, serde::Serialize)]
        struct S {
            v: WrapperSerde,
        }

        let delivery = serde_json::from_str::<S>(input)
            .unwrap()
            .v
            .to_ready(&[MBox::get_symbol()])
            .unwrap();

        assert_eq!(
            delivery,
            WrapperSerde::Ready(alloc::sync::Arc::new(instance))
        );

        assert_eq!(input, serde_json::to_string(&S { v: delivery }).unwrap());
    }

    /*
        #[test]
        fn test_mbox_message_format() {
            let from = addr!("john@doe.com");
            let content = r#"from: john doe <john@doe.com>
    to: green@foo.net
    subject: test email

    This is a raw email."#;

            let timestamp = get_mbox_timestamp_format(&time::OffsetDateTime::UNIX_EPOCH);

            let message = build_mbox_message(&Some(from), &timestamp, content);

            assert_eq!(
                r#"From john@doe.com Thu Jan  1 00:00:00 1970
    from: john doe <john@doe.com>
    to: green@foo.net
    subject: test email

    This is a raw email.
    "#,
                message
            );
        }
        */

    #[rstest::rstest]
    #[case::not_existing("foobar", Err(Variant::LocalDelivery(
        LocalDelivery::MailboxDoNotExist {
            mailbox: "foobar".to_owned()
        }
    )))]
    #[case::no_privilege("root", Err(Variant::LocalDelivery(
        LocalDelivery::Other("failed to open file at '/var/mail/root'".to_owned())
    )))]
    // FIXME: has not the privilege
    // #[case::valid(users::get_current_username().unwrap().to_str().unwrap().to_owned(), Ok(()))]
    fn mbox(#[case] mailbox: String, #[case] expected: Result<(), Variant>) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let context = vsmtp_test::config::local_ctx();
                let fake_message = "Hello World!\r\n";

                let transport = alloc::sync::Arc::new(MBox::new(None));
                let result = alloc::sync::Arc::clone(&transport)
                    .deliver(
                        &context,
                        vec![(addr!(&format!("{mailbox}@domain.com")), Status::default())],
                        fake_message.as_bytes(),
                    )
                    .await;

                #[allow(
                    clippy::indexing_slicing,
                    clippy::unreachable,
                    clippy::wildcard_enum_match_arm
                )]
                match expected {
                    Ok(()) => {
                        assert!(matches!(result[0].1, Status::Sent { .. }));
                        let filepath =
                            std::path::PathBuf::from_iter(["/", "var", "mail", &mailbox]);
                        assert_eq!(
                            std::fs::read_to_string(filepath).unwrap(),
                            format!("Delivered-To: {mailbox}@domain.com\nHello World!\r\n")
                        );
                    }
                    Err(error) => match result[0].1 {
                        Status::HeldBack { ref errors } => {
                            assert_eq!(*errors[0].variant(), error);
                        }
                        _ => unreachable!(),
                    },
                }
            });
    }
}
