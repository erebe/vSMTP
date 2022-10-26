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
    #[allow(clippy::unreachable, clippy::panic_in_result_fn)] // false positive
    #[tracing::instrument(name = "create-maildir", level = "warn", fields(folder = ?path))]
    fn create_and_chown(
        path: &std::path::PathBuf,
        user: &users::User,
        group_local: Option<&users::Group>,
    ) -> anyhow::Result<()> {
        tracing::debug!(to = %path.display(), "Creating folder.");

        if path.exists() {
            tracing::warn!("Folder already exists.");
        } else {
            std::fs::create_dir_all(path)
                .with_context(|| format!("failed to create {}", path.display()))?;

            tracing::trace!(
                user = user.uid(),
                group = group_local.map_or(u32::MAX, users::Group::gid),
                "Setting permissions.",
            );

            chown(path, Some(user.uid()), group_local.map(users::Group::gid))
                .with_context(|| format!("failed to set user rights to {:?}", path))?;
        }

        Ok(())
    }

    // NOTE: see https://en.wikipedia.org/wiki/Maildir
    // create and set rights for the MailDir & [new,cur,tmp] folder if they don't exists.
    fn create_maildir(
        user: &users::User,
        group_local: Option<&users::Group>,
        msg_id: &str,
    ) -> anyhow::Result<std::path::PathBuf> {
        let maildir = std::path::PathBuf::from_iter([getpwuid(user.uid())?, "Maildir".into()]);
        Self::create_and_chown(&maildir, user, group_local)?;
        for dir in ["new", "tmp", "cur"] {
            Self::create_and_chown(&maildir.join(dir), user, group_local)?;
        }

        Ok(maildir.join(format!("new/{msg_id}.eml")))
    }

    fn write_to_maildir(
        rcpt: &Rcpt,
        user: &users::User,
        group_local: Option<&users::Group>,
        msg_id: &str,
        content: &str,
    ) -> anyhow::Result<()> {
        let file_in_maildir_inbox = Self::create_maildir(user, group_local, msg_id)?;

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
    use vsmtp_common::addr;

    #[test]
    fn test_maildir_path() {
        let user = users::User::new(10000, "test_user", 10001);
        let current = users::get_user_by_uid(users::get_current_uid()).unwrap();

        // NOTE: if a user with uid 10000 exists, this is not guaranteed to fail.
        // maybe iterate over all users beforehand ?
        getpwuid(user.uid()).unwrap_err();
        assert_eq!(
            getpwuid(current.uid()).unwrap(),
            std::path::Path::new(current.home_dir().as_os_str().to_str().unwrap()),
        );
    }

    #[test]
    #[ignore]
    fn test_writing_to_maildir() {
        let current = users::get_user_by_uid(users::get_current_uid()).unwrap();
        let message_id = "test_message";

        Maildir::write_to_maildir(
            &Rcpt::new(addr!("john.doe@example.com")),
            &current,
            None,
            message_id,
            "email content",
        )
        .unwrap();

        let maildir = std::path::PathBuf::from_iter([
            current.home_dir().as_os_str().to_str().unwrap(),
            "Maildir",
            "new",
            &format!("{}.eml", message_id),
        ]);

        assert_eq!(
            "email content".to_owned(),
            std::fs::read_to_string(&maildir).unwrap()
        );
    }
}
