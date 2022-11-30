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
use crate::{api::DetailedMailContext, GenericQueueManager, QueueID};
use anyhow::Context;
use vsmtp_common::ContextFinished;
use vsmtp_config::Config;
use vsmtp_mail_parser::MessageBody;
extern crate alloc;

/// Extension to the [`GenericQueueManager`] to simplify filesystem implementation.
#[async_trait::async_trait]
pub trait FilesystemQueueManagerExt {
    ///
    #[must_use]
    #[inline]
    fn get_root_folder(config: &Config, queue: &QueueID) -> std::path::PathBuf {
        match *queue {
            QueueID::Dead
            | QueueID::Deferred
            | QueueID::Delegated
            | QueueID::Deliver
            | QueueID::Working => config.server.queues.dirpath.clone(),
            QueueID::Quarantine { .. } => config.app.dirpath.clone(),
        }
    }

    ///
    #[inline]
    fn get_queue_path(&self, queue: &QueueID) -> std::path::PathBuf {
        Self::get_root_folder(self.get_config(), queue).join(queue.to_string())
    }

    ///
    fn init(config: alloc::sync::Arc<Config>) -> anyhow::Result<alloc::sync::Arc<Self>>
    where
        Self: Sized;

    ///
    fn get_config(&self) -> &Config;
}

#[async_trait::async_trait]
impl<T: FilesystemQueueManagerExt + Send + Sync + core::fmt::Debug> GenericQueueManager for T {
    #[inline]
    fn init(config: alloc::sync::Arc<Config>) -> anyhow::Result<alloc::sync::Arc<Self>>
    where
        Self: Sized,
    {
        T::init(config)
    }

    #[inline]
    fn get_config(&self) -> &Config {
        T::get_config(self)
    }

    #[inline]
    async fn write_ctx(&self, queue: &QueueID, ctx: &ContextFinished) -> anyhow::Result<()> {
        let msg_uuid = &ctx.mail_from.message_uuid;
        let queue_path = self.get_queue_path(queue);

        if !queue_path.exists() {
            std::fs::create_dir_all(&queue_path).with_context(|| {
                format!("Cannot create queue folder: `{}`", queue_path.display())
            })?;
        }

        let mut msg_path = queue_path.join(msg_uuid.to_string());
        msg_path.set_extension("json");

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&msg_path)?;

        let serialized = serde_json::to_string_pretty(ctx)?;
        std::io::Write::write_all(&mut file, serialized.as_bytes())?;

        tracing::debug!(to = ?queue_path, "Email context written.");

        Ok(())
    }

    #[inline]
    async fn write_msg(&self, msg_uuid: &uuid::Uuid, msg: &MessageBody) -> anyhow::Result<()> {
        let mails = self.get_config().server.queues.dirpath.join("mails");
        if !mails.exists() {
            std::fs::DirBuilder::new().recursive(true).create(&mails)?;
        }
        {
            let mails_eml = mails.join(format!("{msg_uuid}.eml"));

            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&mails_eml)?;

            std::io::Write::write_all(&mut file, msg.inner().to_string().as_bytes())?;
        }
        if let &Some(ref parsed) = msg.get_parsed() {
            let mails_json = mails.join(format!("{msg_uuid}.json"));
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&mails_json)?;

            std::io::Write::write_all(&mut file, serde_json::to_string(parsed)?.as_bytes())?;
        }

        tracing::debug!(to = ?mails, "Email written.");

        Ok(())
    }

    #[inline]
    async fn remove_ctx(&self, queue: &QueueID, msg_uuid: &uuid::Uuid) -> anyhow::Result<()> {
        let mut ctx_filepath = self.get_queue_path(queue).join(msg_uuid.to_string());

        ctx_filepath.set_extension("json");

        std::fs::remove_file(&ctx_filepath)
            .with_context(|| format!("failed to remove `{}`", ctx_filepath.display()))?;

        tracing::debug!(from = %queue, "Email context removed.");

        Ok(())
    }

    #[inline]
    async fn remove_msg(&self, msg_uuid: &uuid::Uuid) -> anyhow::Result<()> {
        let mails = self.get_config().server.queues.dirpath.join("mails");

        let mails_eml = mails.join(format!("{msg_uuid}.eml"));
        std::fs::remove_file(&mails_eml)
            .with_context(|| format!("failed to remove `{}`", mails_eml.display()))?;

        let mails_json = mails.join(format!("{msg_uuid}.json"));
        if mails_json.exists() {
            std::fs::remove_file(&mails_json)
                .with_context(|| format!("failed to remove `{}`", mails_json.display()))?;
        }

        tracing::debug!(from = ?mails, "Email removed.");

        Ok(())
    }

    #[inline]
    async fn list(&self, queue: &QueueID) -> anyhow::Result<Vec<anyhow::Result<String>>> {
        let queue_path = self.get_queue_path(queue);

        Ok(queue_path
            .read_dir()
            .context(format!("Error from read dir '{}'", queue_path.display()))?
            .map(|i| match i {
                Err(e) => Err(anyhow::Error::new(e)),
                Ok(entry) => match entry.path().file_stem().map(std::ffi::OsStr::to_str) {
                    Some(Some(name)) => Ok(name.to_owned()),
                    _ => Err(anyhow::anyhow!("Invalid file name")),
                },
            })
            .collect::<Vec<Result<_, _>>>())
    }

    #[inline]
    async fn get_ctx(
        &self,
        queue: &QueueID,
        msg_uuid: &uuid::Uuid,
    ) -> anyhow::Result<ContextFinished> {
        let mut ctx_filepath = self.get_queue_path(queue).join(msg_uuid.to_string());

        ctx_filepath.set_extension("json");

        let content = std::fs::read_to_string(&ctx_filepath)
            .with_context(|| format!("Cannot read file '{}'", ctx_filepath.display()))?;

        serde_json::from_str::<ContextFinished>(&content)
            .with_context(|| format!("Cannot deserialize: '{content:?}'"))
    }

    #[inline]
    async fn get_detailed_ctx(
        &self,
        queue: &QueueID,
        msg_uuid: &uuid::Uuid,
    ) -> anyhow::Result<DetailedMailContext> {
        let mut ctx_filepath = self.get_queue_path(queue).join(msg_uuid.to_string());
        ctx_filepath.set_extension("json");

        let file = std::fs::OpenOptions::new().read(true).open(&ctx_filepath)?;

        let modified_at = file.metadata()?.modified()?;

        let content = std::fs::read_to_string(&ctx_filepath)
            .with_context(|| format!("Cannot read file '{}'", ctx_filepath.display()))?;

        Ok(DetailedMailContext {
            ctx: serde_json::from_str::<ContextFinished>(&content)
                .with_context(|| format!("Cannot deserialize: '{content:?}'"))?,
            modified_at,
        })
    }

    #[inline]
    async fn get_msg(&self, msg_uuid: &uuid::Uuid) -> anyhow::Result<MessageBody> {
        let msg_filepath = std::path::PathBuf::from_iter([
            self.get_config().server.queues.dirpath.clone(),
            "mails".into(),
            format!("{msg_uuid}.eml").into(),
        ]);

        let content = std::fs::read_to_string(&msg_filepath)
            .with_context(|| format!("Cannot read file '{}'", msg_filepath.display()))?;

        // TODO: get parsed if exist

        MessageBody::try_from(content.as_str())
    }
}
