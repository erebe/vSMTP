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
    libc_abstraction::{chown, getpwuid},
    transfer::{error::LocalDelivery, Status},
    transport::{AbstractTransport, DeliverTo},
    Address, ContextFinished,
};
extern crate alloc;

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

def_type_serde!("maildir");

impl PartialEq for Payload {
    fn eq(&self, other: &Self) -> bool {
        self.group_local.as_ref().map(users::Group::gid)
            == other.group_local.as_ref().map(users::Group::gid)
    }
}

impl Eq for Payload {}

/// see <https://en.wikipedia.org/wiki/Maildir>
#[derive(Debug, PartialEq, Eq, serde::Deserialize)]
pub struct Maildir {
    #[serde(flatten)]
    payload: Payload,
}

impl serde::Serialize for Maildir {
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

impl vsmtp_common::transport::GetID for Maildir {}

#[async_trait::async_trait]
impl AbstractTransport for Maildir {
    #[tracing::instrument(name = "maildir", skip_all)]
    async fn deliver(
        self: alloc::sync::Arc<Self>,
        ctx: &ContextFinished,
        mut to: DeliverTo,
        content: &[u8],
    ) -> DeliverTo {
        let msg_uuid = &ctx.mail_from.message_uuid;
        for rcpt in &mut to {
            match users::get_user_by_name(rcpt.0.local_part())
                .map(|user| self.write_to_maildir(&rcpt.0, &user, msg_uuid, content))
            {
                Some(Ok(())) => {
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

impl Maildir {
    ///
    #[must_use]
    #[inline]
    pub fn new(group_local: Option<users::Group>) -> Self {
        Self {
            payload: Payload {
                group_local,
                r#type: "maildir".to_owned(),
            },
        }
    }

    // create and set rights for the MailDir & [new,cur,tmp] folder if they don't exists.
    #[allow(clippy::unreachable, clippy::panic_in_result_fn)] // false positive
    #[tracing::instrument(name = "create-maildir", fields(folder = ?path.display()))]
    fn create_and_chown(
        path: &std::path::PathBuf,
        user: &users::User,
        group_local: &Option<users::Group>,
    ) -> anyhow::Result<()> {
        if path.exists() {
            tracing::info!("Folder already exists.");
        } else {
            tracing::debug!("Creating folder.");

            std::fs::create_dir_all(path)
                .with_context(|| format!("failed to create {}", path.display()))?;

            tracing::trace!(
                user = user.uid(),
                group = group_local.as_ref().map_or(u32::MAX, users::Group::gid),
                "Setting permissions.",
            );

            chown(
                path,
                Some(user.uid()),
                group_local.as_ref().map(users::Group::gid),
            )
            .with_context(|| format!("failed to set user rights to {}", path.display()))?;
        }

        Ok(())
    }

    fn write_to_maildir(
        &self,
        addr: &Address,
        user: &users::User,
        msg_uuid: &uuid::Uuid,
        content: &[u8],
    ) -> anyhow::Result<()> {
        let maildir = std::path::PathBuf::from_iter([getpwuid(user.uid())?, "Maildir".into()]);
        Self::create_and_chown(&maildir, user, &self.payload.group_local)?;
        for dir in ["new", "tmp", "cur"] {
            Self::create_and_chown(&maildir.join(dir), user, &self.payload.group_local)?;
        }

        let file_in_maildir_inbox = maildir.join(format!("new/{msg_uuid}.eml"));

        let mut email = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&file_in_maildir_inbox)
            .with_context(|| {
                format!(
                    "failed to open file at '{}'",
                    file_in_maildir_inbox.display()
                )
            })?;

        std::io::Write::write_all(&mut email, format!("Delivered-To: {addr}\n").as_bytes())?;
        std::io::Write::write_all(&mut email, content)?;

        chown(
            &file_in_maildir_inbox,
            Some(user.uid()),
            self.payload.group_local.as_ref().map(users::Group::gid),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use users::os::unix::UserExt;
    use vsmtp_common::transfer::error::Variant;
    use vsmtp_common::{addr, transport::WrapperSerde};
    use vsmtp_test::config::local_ctx;

    #[rstest::rstest]
    #[case::no_group(
        &serde_json::json!({
            "v": r#"{"type":"maildir","group_local":null}"#
        }).to_string(),
        Maildir::new(None)
    )]
    #[case::with_group(
        &serde_json::json!({
            "v": r#"{"type":"maildir","group_local":"mail"}"#
        }).to_string(),
        Maildir::new(Some(users::get_group_by_name("mail").unwrap()))
    )]
    fn deserialize(#[case] input: &str, #[case] instance: Maildir) {
        #[derive(serde::Deserialize, serde::Serialize)]
        struct S {
            v: WrapperSerde,
        }

        let delivery = serde_json::from_str::<S>(input)
            .unwrap()
            .v
            .to_ready(&[Maildir::get_symbol()])
            .unwrap();

        assert_eq!(
            delivery,
            WrapperSerde::Ready(alloc::sync::Arc::new(instance))
        );

        assert_eq!(input, serde_json::to_string(&S { v: delivery }).unwrap());
    }

    #[rstest::rstest]
    #[case::not_existing("foobar", Err(Variant::LocalDelivery(
        LocalDelivery::MailboxDoNotExist {
            mailbox: "foobar".to_owned()
        })
    ))]
    #[case::no_privilege("root", Err(Variant::LocalDelivery(
        LocalDelivery::Other("failed to create /root/Maildir".to_owned())
    )))]
    #[case::valid(users::get_current_username().unwrap().to_str().unwrap().to_owned(), Ok(()))]
    fn maildir(#[case] mailbox: String, #[case] expected: Result<(), Variant>) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let context = local_ctx();
                let fake_message = "Hello World!\r\n";

                let transport = alloc::sync::Arc::new(Maildir::new(None));
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
                        let filepath = std::path::PathBuf::from_iter([
                            users::get_user_by_uid(users::get_current_uid())
                                .unwrap()
                                .home_dir()
                                .as_os_str()
                                .to_str()
                                .unwrap(),
                            "Maildir",
                            "new",
                            &format!("{}.eml", context.mail_from.message_uuid),
                        ]);
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
