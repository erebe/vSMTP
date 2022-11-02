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
    libc_abstraction::{chown, getpwuid},
    mail_context::{Finished, MailContext},
    rcpt::Rcpt,
    transfer::{EmailTransferStatus, TransferErrorsVariant},
};
use vsmtp_config::Config;

/// see <https://en.wikipedia.org/wiki/Maildir>
//
// NOTE: see https://docs.rs/tempfile/3.0.7/tempfile/index.html
#[derive(Default)]
#[non_exhaustive]
pub struct Maildir;

#[async_trait::async_trait]
impl Transport for Maildir {
    #[tracing::instrument(name = "maildir", skip_all)]
    async fn deliver(
        self,
        config: &Config,
        ctx: &MailContext<Finished>,
        _: &vsmtp_common::Address,
        mut to: Vec<Rcpt>,
        content: &str,
    ) -> Vec<Rcpt> {
        let msg_id = ctx.message_id();
        for rcpt in &mut to {
            match users::get_user_by_name(rcpt.address.local_part()).map(|user| {
                Self::write_to_maildir(
                    rcpt,
                    &user,
                    config.server.system.group_local.as_ref(),
                    msg_id,
                    content,
                )
            }) {
                Some(Ok(())) => {
                    tracing::info!("Email delivered.");

                    rcpt.email_status = EmailTransferStatus::sent();
                }
                Some(Err(error)) => {
                    tracing::error!(%error, "Email delivery failure.");

                    rcpt.email_status
                        .held_back(TransferErrorsVariant::LocalDeliveryError {
                            error: error.to_string(),
                        });
                }
                None => {
                    tracing::error!(
                        error = format!("user not found: {}", rcpt.address.local_part()),
                        "Email delivery failure."
                    );

                    rcpt.email_status
                        .held_back(TransferErrorsVariant::NoSuchMailbox {
                            name: rcpt.address.local_part().to_owned(),
                        });
                }
            }
        }
        to
    }
}

impl Maildir {
    // create and set rights for the MailDir & [new,cur,tmp] folder if they don't exists.
    #[allow(clippy::unreachable, clippy::panic_in_result_fn)] // false positive
    #[tracing::instrument(name = "create-maildir", fields(folder = ?path.display()))]
    fn create_and_chown(
        path: &std::path::PathBuf,
        user: &users::User,
        group_local: Option<&users::Group>,
    ) -> anyhow::Result<()> {
        if path.exists() {
            tracing::info!("Folder already exists.");
        } else {
            tracing::debug!("Creating folder.");

            std::fs::create_dir_all(path)
                .with_context(|| format!("failed to create {}", path.display()))?;

            tracing::trace!(
                user = user.uid(),
                group = group_local.map_or(u32::MAX, users::Group::gid),
                "Setting permissions.",
            );

            chown(path, Some(user.uid()), group_local.map(users::Group::gid))
                .with_context(|| format!("failed to set user rights to {}", path.display()))?;
        }

        Ok(())
    }

    fn write_to_maildir(
        rcpt: &Rcpt,
        user: &users::User,
        group_local: Option<&users::Group>,
        msg_id: &str,
        content: &str,
    ) -> anyhow::Result<()> {
        let maildir = std::path::PathBuf::from_iter([getpwuid(user.uid())?, "Maildir".into()]);
        Self::create_and_chown(&maildir, user, group_local)?;
        for dir in ["new", "tmp", "cur"] {
            Self::create_and_chown(&maildir.join(dir), user, group_local)?;
        }

        let file_in_maildir_inbox = maildir.join(format!("new/{msg_id}.eml"));

        let mut email = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&file_in_maildir_inbox)?;

        std::io::Write::write_all(&mut email, format!("Delivered-To: {rcpt}\n").as_bytes())?;
        std::io::Write::write_all(&mut email, content.as_bytes())?;

        chown(
            &file_in_maildir_inbox,
            Some(user.uid()),
            group_local.map(users::Group::gid),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use users::os::unix::UserExt;
    use vsmtp_common::{addr, transfer::Transfer};
    use vsmtp_test::config::{local_ctx, local_test};

    #[allow(clippy::std_instead_of_core)]
    #[rstest::rstest]
    #[case::not_existing("foobar", Err(TransferErrorsVariant::NoSuchMailbox {
        name: "foobar".to_owned()
    }))]
    #[case::no_privilege("root", Err(TransferErrorsVariant::LocalDeliveryError {
        error: "failed to create /root/Maildir".to_owned()
    }))]
    #[case::valid(users::get_current_username().unwrap().to_str().unwrap().to_owned(), Ok(()))]
    async fn maildir(#[case] mailbox: String, #[case] expected: Result<(), TransferErrorsVariant>) {
        let config = local_test();
        let context = local_ctx();
        let fake_message = "Hello World!\r\n";

        let result = Maildir::default()
            .deliver(
                &config,
                &context,
                &addr!("foo@domain.com"),
                vec![Rcpt {
                    address: addr!(&format!("{mailbox}@domain.com")),
                    transfer_method: Transfer::Maildir,
                    email_status: EmailTransferStatus::default(),
                    transaction_type: vsmtp_common::rcpt::TransactionType::Incoming(None),
                }],
                fake_message,
            )
            .await;

        #[allow(
            clippy::indexing_slicing,
            clippy::unreachable,
            clippy::wildcard_enum_match_arm
        )]
        match expected {
            Ok(()) => {
                assert!(matches!(
                    result[0].email_status,
                    EmailTransferStatus::Sent { .. }
                ));
                let filepath = std::path::PathBuf::from_iter([
                    users::get_user_by_uid(users::get_current_uid())
                        .unwrap()
                        .home_dir()
                        .as_os_str()
                        .to_str()
                        .unwrap(),
                    "Maildir",
                    "new",
                    &format!("{}.eml", context.message_id()),
                ]);
                assert_eq!(
                    std::fs::read_to_string(&filepath).unwrap(),
                    format!("Delivered-To: {mailbox}@domain.com\nHello World!\r\n")
                );
            }
            Err(error) => match result[0].email_status {
                EmailTransferStatus::HeldBack { ref errors } => {
                    assert_eq!(errors[0].variant, error);
                }
                _ => unreachable!(),
            },
        }
    }
}
