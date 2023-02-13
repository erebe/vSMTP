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
use crate::ProcessMessage;
use anyhow::Context;
use time::ext::NumericalDuration;
use vqueue::{GenericQueueManager, QueueID};
use vsmtp_common::transfer::Status;
use vsmtp_config::Config;
use vsmtp_delivery::{split_and_sort_and_send, SenderOutcome};

pub async fn flush_deferred_queue<Q: GenericQueueManager + Sized + 'static>(
    config: std::sync::Arc<Config>,
    queue_manager: std::sync::Arc<Q>,
    flushing_at: time::OffsetDateTime,
) {
    let queued = match queue_manager.list(&QueueID::Deferred).await {
        Ok(queued) => queued,
        Err(error) => {
            tracing::error!(%error, "Listing deferred queue failure.");
            return;
        }
    };

    for i in queued {
        let message_uuid = match i.map(|i| uuid::Uuid::parse_str(&i)) {
            Ok(Ok(message_uuid)) => message_uuid,
            Ok(Err(error)) => {
                tracing::error!(%error, "Invalid message id in deferred queue.");
                continue;
            }
            Err(error) => {
                tracing::error!(%error, "Deferred message id missing.");
                continue;
            }
        };

        if let Err(error) = handle_one_in_deferred_queue(
            config.clone(),
            queue_manager.clone(),
            ProcessMessage {
                message_uuid,
                delegated: false,
            },
            flushing_at,
        )
        .await
        {
            tracing::error!(%error, "Flushing deferred queue failure.");
        }
    }
}

#[tracing::instrument(name = "deferred", skip_all, err, fields(uuid = %process_message.message_uuid))]
async fn handle_one_in_deferred_queue<Q: GenericQueueManager + Sized + 'static>(
    config: std::sync::Arc<Config>,
    queue_manager: std::sync::Arc<Q>,
    process_message: ProcessMessage,
    flushing_at: time::OffsetDateTime,
) -> anyhow::Result<()> {
    tracing::debug!("Processing email.");

    let mut ctx = queue_manager
        .get_ctx(&QueueID::Deferred, &process_message.message_uuid)
        .await?;

    let last_error = ctx
        .rcpt_to
        .delivery
        .values()
        .flatten()
        .filter_map(|i| match &i.1 {
            Status::HeldBack { errors } => errors.last().map(|e| e.timestamp),
            _ => None,
        })
        .min();

    let held_back_count = ctx
        .rcpt_to
        .delivery
        .values()
        .flatten()
        .filter(|i| matches!(i.1, Status::HeldBack { .. }))
        .count() as i64;

    match last_error {
        Some(last_error)
            // last error + (error_count * 5min)
            if last_error
                .checked_add(held_back_count.seconds() * 60 * 5)
                .unwrap()
                > flushing_at =>
        {
            tracing::debug!("Email is not ready to be flushed.");
            return Ok(());
        }
        _ => {}
    }

    let msg = queue_manager.get_msg(&process_message.message_uuid).await?;

    match split_and_sort_and_send(config, &mut ctx, &msg).await {
        SenderOutcome::MoveToDead => queue_manager
            .move_to(&QueueID::Deferred, &QueueID::Dead, &ctx)
            .await
            .with_context(|| {
                format!(
                    "cannot move file from `{}` to `{}`",
                    QueueID::Deferred,
                    QueueID::Dead
                )
            }),
        SenderOutcome::MoveToDeferred => queue_manager
            .write_ctx(&QueueID::Deferred, &ctx)
            .await
            .with_context(|| format!("failed to update context in `{}`", QueueID::Deferred)),
        SenderOutcome::RemoveFromDisk => {
            queue_manager
                .remove_both(&QueueID::Deferred, &process_message.message_uuid)
                .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vsmtp_common::transport::{AbstractTransport, WrapperSerde};
    use vsmtp_config::DnsResolvers;
    use vsmtp_delivery::{Deliver, Forward, MBox, Maildir};
    use vsmtp_test::config::{local_ctx, local_msg, local_test};

    #[tokio::test]
    async fn move_to_deferred() {
        let config = std::sync::Arc::new(local_test());
        let queue_manager = <vqueue::temp::QueueManager as vqueue::GenericQueueManager>::init(
            config.clone(),
            vec![
                Deliver::get_symbol(),
                Forward::get_symbol(),
                Maildir::get_symbol(),
                MBox::get_symbol(),
            ],
        )
        .unwrap();
        let resolvers = std::sync::Arc::new(DnsResolvers::from_config(&config).unwrap());

        let mut ctx = local_ctx();
        let message_uuid = uuid::Uuid::new_v4();
        ctx.mail_from.message_uuid = message_uuid;
        ctx.rcpt_to
            .delivery
            .entry(WrapperSerde::Ready(std::sync::Arc::new(Deliver::new(
                resolvers.get_resolver_root(),
                config.clone(),
            ))))
            .and_modify(|rcpt| {
                rcpt.push(("test@localhost".parse().unwrap(), Status::default()));
            })
            .or_insert_with(|| vec![("test@localhost".parse().unwrap(), Status::default())]);

        queue_manager
            .write_both(&QueueID::Deferred, &ctx, &local_msg())
            .await
            .unwrap();

        handle_one_in_deferred_queue(
            config.clone(),
            queue_manager.clone(),
            ProcessMessage {
                message_uuid,
                delegated: false,
            },
            time::OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .unwrap();

        queue_manager
            .get_ctx(&QueueID::Deliver, &message_uuid)
            .await
            .unwrap_err();
        queue_manager
            .get_ctx(&QueueID::Dead, &message_uuid)
            .await
            .unwrap_err();

        queue_manager
            .get_ctx(&QueueID::Deferred, &message_uuid)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn move_to_dead() {
        let config = std::sync::Arc::new(local_test());
        let queue_manager = <vqueue::temp::QueueManager as vqueue::GenericQueueManager>::init(
            config.clone(),
            vec![],
        )
        .unwrap();

        let mut ctx = local_ctx();
        let message_uuid = uuid::Uuid::new_v4();
        ctx.mail_from.message_uuid = message_uuid;

        queue_manager
            .write_both(&QueueID::Deferred, &ctx, &local_msg())
            .await
            .unwrap();

        handle_one_in_deferred_queue(
            config.clone(),
            queue_manager.clone(),
            ProcessMessage {
                message_uuid,
                delegated: false,
            },
            time::OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .unwrap();

        queue_manager
            .get_ctx(&QueueID::Deferred, &message_uuid)
            .await
            .unwrap_err();

        queue_manager
            .get_ctx(&QueueID::Dead, &message_uuid)
            .await
            .unwrap();
    }
}
