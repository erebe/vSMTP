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
use vsmtp_common::{transport::DeserializerFn, ContextFinished};
use vsmtp_config::Config;
use vsmtp_mail_parser::MessageBody;
extern crate alloc;

/// identifiers for all mail queues.
#[allow(clippy::exhaustive_enums)]
#[derive(Debug, PartialEq, Eq, Clone, strum::IntoStaticStr, strum::EnumString, strum::EnumIter)]
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

impl core::fmt::Display for QueueID {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Quarantine { name } => write!(f, "quarantine/{name}"),
            &Self::Working | &Self::Deliver | &Self::Delegated | &Self::Deferred | &Self::Dead => {
                write!(f, "{}", Into::<&'static str>::into(self))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_id_to_string() {
        for (q, str) in [
            QueueID::Working,
            QueueID::Deliver,
            QueueID::Delegated,
            QueueID::Deferred,
            QueueID::Dead,
            QueueID::Quarantine {
                name: "foobar".to_owned(),
            },
        ]
        .into_iter()
        .zip([
            "working",
            "deliver",
            "delegated",
            "deferred",
            "dead",
            "quarantine/foobar",
        ]) {
            assert_eq!(q.to_string(), str);
        }
    }
}

///
#[derive(Clone)]
pub struct DetailedMailContext {
    pub(crate) ctx: ContextFinished,
    pub(crate) modified_at: std::time::SystemTime,
}

/// CRUD operation for mail in queues.
#[async_trait::async_trait]
pub trait GenericQueueManager
where
    Self: core::fmt::Debug + Sync + Send,
{
    /// This method is called to initialize the queue manager.
    ///
    /// All the method of [`GenericQueueManager`] take `&self` meaning that you should
    /// wrap the mutable inner state in a `Mutex` or `RwLock`.
    ///
    /// The configuration must be stored and accessible using [`GenericQueueManager::get_config()`].
    fn init(
        config: alloc::sync::Arc<Config>,
        transport_deserializer: Vec<DeserializerFn>,
    ) -> anyhow::Result<alloc::sync::Arc<Self>>
    where
        Self: Sized;

    ///
    fn get_config(&self) -> &Config;

    ///
    fn get_transport_deserializer(&self) -> &[DeserializerFn];

    ///
    async fn write_ctx(&self, queue: &QueueID, ctx: &ContextFinished) -> anyhow::Result<()>;

    ///
    async fn write_msg(&self, msg_uuid: &uuid::Uuid, msg: &MessageBody) -> anyhow::Result<()>;

    ///
    #[inline]
    async fn write_both(
        &self,
        queue: &QueueID,
        ctx: &ContextFinished,
        msg: &MessageBody,
    ) -> anyhow::Result<()>
    where
        Self: Sized,
    {
        self.write_ctx(queue, ctx).await?;
        self.write_msg(&ctx.mail_from.message_uuid, msg).await?;
        Ok(())
    }

    ///
    async fn remove_ctx(&self, queue: &QueueID, msg_uuid: &uuid::Uuid) -> anyhow::Result<()>;

    ///
    async fn remove_msg(&self, msg_uuid: &uuid::Uuid) -> anyhow::Result<()>;

    ///
    #[inline]
    async fn remove_both(&self, queue: &QueueID, msg_uuid: &uuid::Uuid) -> anyhow::Result<()>
    where
        Self: Sized,
    {
        self.remove_ctx(queue, msg_uuid).await?;
        self.remove_msg(msg_uuid).await?;
        Ok(())
    }

    /// Get the list of message IDs in the queue.
    async fn list(&self, queue: &QueueID) -> anyhow::Result<Vec<anyhow::Result<String>>>;

    ///
    async fn get_ctx(
        &self,
        queue: &QueueID,
        msg_uuid: &uuid::Uuid,
    ) -> anyhow::Result<ContextFinished>;

    ///
    async fn get_detailed_ctx(
        &self,
        queue: &QueueID,
        msg_uuid: &uuid::Uuid,
    ) -> anyhow::Result<DetailedMailContext>;

    ///
    async fn get_msg(&self, msg_uuid: &uuid::Uuid) -> anyhow::Result<MessageBody>;

    ///
    #[inline]
    async fn get_both(
        &self,
        queue: &QueueID,
        msg_uuid: &uuid::Uuid,
    ) -> anyhow::Result<(ContextFinished, MessageBody)>
    where
        Self: Sized,
    {
        Ok((
            self.get_ctx(queue, msg_uuid).await?,
            self.get_msg(msg_uuid).await?,
        ))
    }

    ///
    #[inline]
    async fn move_to_from_id(
        &self,
        before: &QueueID,
        after: &QueueID,
        msg_uuid: &uuid::Uuid,
    ) -> anyhow::Result<()>
    where
        Self: Sized,
    {
        anyhow::ensure!(before != after, "Queues are the same: `{before}`");

        let ctx = self.get_ctx(before, msg_uuid).await?;
        self.move_to(before, after, &ctx).await?;

        Ok(())
    }

    ///
    #[inline]
    async fn move_to(
        &self,
        before: &QueueID,
        after: &QueueID,
        ctx: &ContextFinished,
    ) -> anyhow::Result<()>
    where
        Self: Sized,
    {
        anyhow::ensure!(before != after, "Queues are the same: `{before}`");

        tracing::debug!(from = %before, to = %after, "Moving email.");

        self.write_ctx(after, ctx).await?;
        self.remove_ctx(before, &ctx.mail_from.message_uuid).await?;

        Ok(())
    }
}
