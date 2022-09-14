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
use vsmtp_common::mail_context::MailContext;
use vsmtp_config::Config;
use vsmtp_mail_parser::MessageBody;

///
// TODO: handle canonicalization of path (& chown)
pub struct QueueManager {
    config: std::sync::Arc<Config>,
}

impl std::fmt::Debug for QueueManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueueManager").finish_non_exhaustive()
    }
}

impl QueueManager {
    fn get_root_folder(config: &Config, queue: &QueueID) -> std::path::PathBuf {
        match queue {
            QueueID::Dead
            | QueueID::Deferred
            | QueueID::Delegated
            | QueueID::Deliver
            | QueueID::Working => config.server.queues.dirpath.clone(),
            QueueID::Quarantine { .. } => config.app.dirpath.clone(),
        }
    }
}

#[async_trait::async_trait]
impl GenericQueueManager for QueueManager {
    fn init(config: std::sync::Arc<Config>) -> anyhow::Result<std::sync::Arc<Self>> {
        <QueueID as strum::IntoEnumIterator>::iter()
            .map(|q| {
                let dir = Self::get_root_folder(&config, &q).join(q.to_string());
                std::fs::create_dir_all(&dir).with_context(|| {
                    format!("could not create `{q}` directory at `{}`", dir.display())
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok(std::sync::Arc::new(Self { config }))
    }

    async fn get_config(&self) -> &Config {
        &self.config
    }

    async fn write_ctx(&self, queue: &QueueID, ctx: &MailContext) -> anyhow::Result<()> {
        let message_id = &ctx
            .metadata
            .message_id
            .as_ref()
            .expect("not ill-formed mail context");

        let queue_path = Self::get_root_folder(&self.config, queue).join(queue.to_string());

        if !queue_path.exists() {
            std::fs::create_dir_all(&queue_path).with_context(|| {
                format!("Cannot create queue folder: `{}`", queue_path.display())
            })?;
        }

        let mut msg_path = queue_path.join(message_id);
        msg_path.set_extension("json");

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&msg_path)?;

        std::io::Write::write_all(&mut file, serde_json::to_string(ctx)?.as_bytes())?;

        tracing::debug!(to = ?queue_path, "Email context written.");

        Ok(())
    }

    fn write_msg(&self, message_id: &str, msg: &MessageBody) -> anyhow::Result<()> {
        let mails = self.config.server.queues.dirpath.join("mails");
        if !mails.exists() {
            std::fs::DirBuilder::new().recursive(true).create(&mails)?;
        }
        {
            let mails_eml = mails.join(format!("{message_id}.eml"));
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&mails_eml)?;

            std::io::Write::write_all(&mut file, msg.inner().to_string().as_bytes())?;
        }
        if let Some(parsed) = &msg.get_parsed() {
            let mails_json = mails.join(format!("{message_id}.json"));
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

    async fn remove_ctx(&self, queue: &QueueID, msg_id: &str) -> anyhow::Result<()> {
        let mut ctx_filepath = Self::get_root_folder(&self.config, queue)
            .join(queue.to_string())
            .join(&msg_id);

        ctx_filepath.set_extension("json");

        std::fs::remove_file(&ctx_filepath)
            .with_context(|| format!("failed to remove `{}`", ctx_filepath.display()))?;

        tracing::debug!(from = %queue, "Email context removed.");

        Ok(())
    }

    async fn remove_msg(&self, msg_id: &str) -> anyhow::Result<()> {
        let mails = self.config.server.queues.dirpath.join("mails");

        let mails_eml = mails.join(format!("{msg_id}.eml"));
        std::fs::remove_file(&mails_eml)
            .with_context(|| format!("failed to remove `{}`", mails_eml.display()))?;

        let mails_json = mails.join(format!("{msg_id}.json"));
        if mails_json.exists() {
            std::fs::remove_file(&mails_json)
                .with_context(|| format!("failed to remove `{}`", mails_json.display()))?;
        }

        tracing::debug!(from = ?mails, "Email removed.");

        Ok(())
    }

    fn list(&self, queue: &QueueID) -> anyhow::Result<Vec<anyhow::Result<String>>> {
        let queue_path = Self::get_root_folder(&self.config, queue).join(queue.to_string());

        Ok(queue_path
            .read_dir()
            .context(format!("Error from read dir '{}'", queue_path.display()))?
            .map(|i| match i {
                Err(e) => Err(anyhow::Error::new(e)),
                Ok(entry) => match entry.path().file_name().map(std::ffi::OsStr::to_str) {
                    Some(Some(name)) => Ok(name.to_string()),
                    _ => Err(anyhow::anyhow!("Invalid file name")),
                },
            })
            .collect::<Vec<Result<_, _>>>())
    }

    fn get_ctx(&self, queue: &QueueID, msg_id: &str) -> anyhow::Result<MailContext> {
        let mut ctx_filepath = Self::get_root_folder(&self.config, queue)
            .join(queue.to_string())
            .join(&msg_id);

        ctx_filepath.set_extension("json");

        let content = std::fs::read_to_string(&ctx_filepath)
            .with_context(|| format!("Cannot read file '{}'", ctx_filepath.display()))?;

        serde_json::from_str::<MailContext>(&content)
            .with_context(|| format!("Cannot deserialize: '{content:?}'"))
    }

    fn get_detailed_ctx(
        &self,
        queue: &QueueID,
        msg_id: &str,
    ) -> anyhow::Result<DetailedMailContext> {
        let mut ctx_filepath = Self::get_root_folder(&self.config, queue)
            .join(queue.to_string())
            .join(&msg_id);
        ctx_filepath.set_extension("json");

        let file = std::fs::OpenOptions::new().read(true).open(&ctx_filepath)?;

        let modified_at = file.metadata()?.modified()?;

        let content = std::fs::read_to_string(&ctx_filepath)
            .with_context(|| format!("Cannot read file '{}'", ctx_filepath.display()))?;

        Ok(DetailedMailContext {
            ctx: serde_json::from_str::<MailContext>(&content)
                .with_context(|| format!("Cannot deserialize: '{content:?}'"))?,
            modified_at,
        })
    }

    fn get_msg(&self, msg_id: &str) -> anyhow::Result<MessageBody> {
        let msg_filepath = std::path::PathBuf::from_iter([
            self.config.server.queues.dirpath.clone(),
            "mails".into(),
            format!("{msg_id}.eml").into(),
        ]);

        let content = std::fs::read_to_string(&msg_filepath)
            .with_context(|| format!("Cannot read file '{}'", msg_filepath.display()))?;

        // TODO: get parsed if exist

        MessageBody::try_from(content.as_str())
    }
}
