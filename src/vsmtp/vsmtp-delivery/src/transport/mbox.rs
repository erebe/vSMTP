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

use super::Transport;
use anyhow::Context;
use vsmtp_common::{
    libc_abstraction::chown,
    mail_context::MessageMetadata,
    rcpt::Rcpt,
    transfer::{EmailTransferStatus, TransferErrors},
};
use vsmtp_config::Config;

const CTIME_FORMAT: &[time::format_description::FormatItem<'_>] = time::macros::format_description!(
    "[weekday repr:short] [month repr:short] [day padding:space] [hour]:[minute]:[second] [year]"
);

/// resolver use to write emails on the system following the
/// application/mbox Media Type.
/// (see [rfc4155](https://datatracker.ietf.org/doc/html/rfc4155#appendix-A))
#[derive(Default)]
pub struct MBox;

// FIXME: use UsersCache.

#[async_trait::async_trait]
impl Transport for MBox {
    async fn deliver(
        self,
        config: &Config,
        metadata: &MessageMetadata,
        from: &vsmtp_common::Address,
        mut to: Vec<Rcpt>,
        content: &str,
    ) -> Vec<Rcpt> {
        let timestamp = get_mbox_timestamp_format(&metadata.timestamp.unwrap());
        let content = build_mbox_message(from, &timestamp, content);

        for rcpt in &mut to {
            match users::get_user_by_name(rcpt.address.local_part()).map(|user| {
                // NOTE: only linux system is supported here, is the
                //       path to all mboxes always /var/mail ?
                write_content_to_mbox(
                    rcpt,
                    &std::path::PathBuf::from_iter(["/", "var", "mail", rcpt.address.local_part()]),
                    &user,
                    config.server.system.group_local.as_ref(),
                    &content,
                )
            }) {
                Some(Ok(_)) => {
                    tracing::info!("Email delivered.");

                    rcpt.email_status = EmailTransferStatus::Sent {
                        timestamp: std::time::SystemTime::now(),
                    }
                }
                Some(Err(error)) => {
                    tracing::error!(%error, "Email delivery failure.");

                    rcpt.email_status.held_back(error);
                }
                None => {
                    tracing::error!(
                        error = format!("user not found: {}", rcpt.address.local_part()),
                        "Email delivery failure."
                    );

                    rcpt.email_status.held_back(TransferErrors::NoSuchMailbox {
                        name: rcpt.address.local_part().to_string(),
                    });
                }
            }
        }
        to
    }
}

fn get_mbox_timestamp_format(timestamp: &std::time::SystemTime) -> String {
    let odt: time::OffsetDateTime = (*timestamp).into();

    odt.format(&CTIME_FORMAT)
        .unwrap_or_else(|_| String::default())
}

fn build_mbox_message(
    from: &vsmtp_common::Address,
    timestamp: &str,
    content: &str,
) -> std::string::String {
    format!("From {} {}\n{}\n", from, timestamp, content)
}

fn write_content_to_mbox(
    rcpt: &Rcpt,
    mbox: &std::path::Path,
    user: &users::User,
    group_local: Option<&users::Group>,
    content: &str,
) -> anyhow::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&mbox)?;

    chown(mbox, Some(user.uid()), group_local.map(users::Group::gid))
        .with_context(|| format!("could not set owner for '{mbox:?}' mbox"))?;

    std::io::Write::write_all(&mut file, format!("Delivered-To: {rcpt}\n").as_bytes())?;
    std::io::Write::write_all(&mut file, content.as_bytes())?;

    Ok(())
}

#[cfg(test)]
mod test {

    use vsmtp_common::addr;

    use super::*;

    #[test]
    fn test_mbox_time_format() {
        // FIXME: I did not find a proper way to compare timestamps because the system time
        //        cannot be zero.
        get_mbox_timestamp_format(&std::time::SystemTime::now());
    }

    #[test]
    fn test_mbox_message_format() {
        let from = addr!("john@doe.com");
        let content = r#"from: john doe <john@doe.com>
to: green@foo.net
subject: test email

This is a raw email."#;

        let timestamp = get_mbox_timestamp_format(&std::time::SystemTime::UNIX_EPOCH);

        let message = build_mbox_message(&from, &timestamp, content);

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

    #[test]
    #[ignore]
    fn test_writing_to_mbox() {
        let user = users::get_user_by_uid(users::get_current_uid())
            .expect("current user has been deleted after running this test");
        let content = "From 0 john@doe.com\nfrom: john doe <john@doe.com>\n";
        let mbox =
            std::path::PathBuf::from_iter(["./tests/generated/", user.name().to_str().unwrap()]);

        std::fs::create_dir_all("./tests/generated/").expect("could not create temporary folders");
        write_content_to_mbox(
            &Rcpt::new(addr!("john.doe@example.com")),
            &mbox,
            &user,
            None,
            content,
        )
        .expect("could not write to mbox");

        assert_eq!(
            content.to_string(),
            std::fs::read_to_string(&mbox).expect("could not read mbox")
        );

        std::fs::remove_file(mbox).unwrap();
    }
}
