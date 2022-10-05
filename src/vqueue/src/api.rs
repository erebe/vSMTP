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
use vsmtp_common::mail_context::MailContext;
use vsmtp_config::Config;
use vsmtp_mail_parser::MessageBody;

/// identifiers for all mail queues.
#[derive(Debug, PartialEq, Eq, Clone, strum::Display, strum::EnumString, strum::EnumIter)]
#[strum(serialize_all = "lowercase")]
pub enum QueueID {
    /// Postq.
    Working,
    /// 1st attempt to deliver.
    Deliver,
    /// the message has been delegated.
    Delegated,
    /// 1st delivery attempt failed.
    Deferred,
    /// Too many attempts failed.
    Dead,
    ///
    Quarantine {
        /// User defined name of the quarantine, can be a reason (ex: "spam")
        /// or a time (ex: "2020-01-01"), or a domain ...
        name: String,
    },
}

///
#[derive(Debug, Clone)]
pub struct DetailedMailContext {
    pub(crate) ctx: MailContext,
    pub(crate) modified_at: std::time::SystemTime,
}

/// CRUB operation for mail in queues.
#[async_trait::async_trait]
pub trait GenericQueueManager
where
    Self: std::fmt::Debug + Sync + Send,
{
    ///
    fn init(config: std::sync::Arc<Config>) -> anyhow::Result<std::sync::Arc<Self>>
    where
        Self: Sized;

    ///
    fn get_config(&self) -> &Config;

    ///
    async fn write_ctx(&self, queue: &QueueID, ctx: &MailContext) -> anyhow::Result<()>;

    ///
    async fn write_msg(&self, message_id: &str, msg: &MessageBody) -> anyhow::Result<()>;

    ///
    async fn write_both(
        &self,
        queue: &QueueID,
        ctx: &MailContext,
        msg: &MessageBody,
    ) -> anyhow::Result<()>
    where
        Self: Sized,
    {
        let msg_id = ctx
            .metadata
            .message_id
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("`message_id` is missing"))?;

        self.write_ctx(queue, ctx).await?;
        self.write_msg(msg_id, msg).await?;
        Ok(())
    }

    ///
    async fn remove_ctx(&self, queue: &QueueID, msg_id: &str) -> anyhow::Result<()>;

    ///
    async fn remove_msg(&self, msg_id: &str) -> anyhow::Result<()>;

    ///
    async fn remove_both(&self, queue: &QueueID, msg_id: &str) -> anyhow::Result<()>
    where
        Self: Sized,
    {
        self.remove_ctx(queue, msg_id).await?;
        self.remove_msg(msg_id).await?;
        Ok(())
    }

    /// Get the list of message IDs in the queue.
    async fn list(&self, queue: &QueueID) -> anyhow::Result<Vec<anyhow::Result<String>>>;

    ///
    async fn get_ctx(&self, queue: &QueueID, msg_id: &str) -> anyhow::Result<MailContext>;

    ///
    async fn get_detailed_ctx(
        &self,
        queue: &QueueID,
        msg_id: &str,
    ) -> anyhow::Result<DetailedMailContext>;

    ///
    async fn get_msg(&self, msg_id: &str) -> anyhow::Result<MessageBody>;

    ///
    async fn get_both(
        &self,
        queue: &QueueID,
        msg_id: &str,
    ) -> anyhow::Result<(MailContext, MessageBody)>
    where
        Self: Sized,
    {
        Ok((
            self.get_ctx(queue, msg_id).await?,
            self.get_msg(msg_id).await?,
        ))
    }

    ///
    async fn move_to_from_id(
        &self,
        before: &QueueID,
        after: &QueueID,
        msg_id: &str,
    ) -> anyhow::Result<()>
    where
        Self: Sized,
    {
        anyhow::ensure!(before != after, "Queues are the same: `{before}`");

        let ctx = self.get_ctx(before, msg_id).await?;
        self.move_to(before, after, &ctx).await?;

        Ok(())
    }

    ///
    async fn move_to(
        &self,
        before: &QueueID,
        after: &QueueID,
        ctx: &MailContext,
    ) -> anyhow::Result<()>
    where
        Self: Sized,
    {
        anyhow::ensure!(before != after, "Queues are the same: `{before}`");

        tracing::debug!(from = %before, to = %after, "Moving email.");

        self.write_ctx(after, ctx).await?;
        self.remove_ctx(
            before,
            ctx.metadata
                .message_id
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("`message_id` is missing"))?,
        )
        .await?;

        Ok(())
    }
}
