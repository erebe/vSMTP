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
use crate::{
    delivery::{send_mail, SenderOutcome},
    ProcessMessage,
};
use anyhow::Context;
use vqueue::{GenericQueueManager, QueueID};
use vsmtp_config::{Config, DnsResolvers};

// TODO: what should be the procedure on failure here ?
pub async fn flush_deferred_queue<Q: GenericQueueManager + Sized + 'static>(
    config: std::sync::Arc<Config>,
    resolvers: std::sync::Arc<DnsResolvers>,
    queue_manager: std::sync::Arc<Q>,
) {
    let queued = match queue_manager.list(&QueueID::Deferred).await {
        Ok(queued) => queued,
        Err(error) => {
            tracing::error!(%error, "Listing deferred queue failure.");
            return;
        }
    };

    for i in queued {
        let msg_id = match i {
            Ok(msg_id) => msg_id,
            Err(error) => {
                tracing::error!(%error, "Deferred message id missing.");
                continue;
            }
        };

        if let Err(error) = handle_one_in_deferred_queue(
            config.clone(),
            resolvers.clone(),
            queue_manager.clone(),
            ProcessMessage {
                message_id: msg_id,
                delegated: false,
            },
        )
        .await
        {
            tracing::error!(%error, "Flushing deferred queue failure.");
        }
    }
}

#[tracing::instrument(name = "deferred", skip_all, fields(message_id = %process_message.message_id))]
async fn handle_one_in_deferred_queue<Q: GenericQueueManager + Sized + 'static>(
    config: std::sync::Arc<Config>,
    resolvers: std::sync::Arc<DnsResolvers>,
    queue_manager: std::sync::Arc<Q>,
    process_message: ProcessMessage,
) -> anyhow::Result<()> {
    tracing::debug!("Processing email.");

    let (mut mail_context, mail_message) = queue_manager
        .get_both(&QueueID::Deferred, &process_message.message_id)
        .await?;

    match send_mail(&config, &mut mail_context, &mail_message, resolvers).await {
        SenderOutcome::MoveToDead => queue_manager
            .move_to(&QueueID::Deferred, &QueueID::Dead, &mail_context)
            .await
            .with_context(|| {
                format!(
                    "cannot move file from `{}` to `{}`",
                    QueueID::Deferred,
                    QueueID::Dead
                )
            }),
        SenderOutcome::MoveToDeferred => queue_manager
            .write_ctx(&QueueID::Deferred, &mail_context)
            .await
            .with_context(|| format!("failed to update context in `{}`", QueueID::Deferred)),
        SenderOutcome::RemoveFromDisk => {
            // TODO: remove both ?
            queue_manager
                .remove_ctx(&QueueID::Deferred, &process_message.message_id)
                .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vsmtp_common::{rcpt::Rcpt, Address};
    use vsmtp_test::config::{local_ctx, local_msg, local_test};

    #[tokio::test]
    #[function_name::named]
    async fn move_to_deferred() {
        let config = std::sync::Arc::new(local_test());
        let queue_manager =
            <vqueue::temp::QueueManager as vqueue::GenericQueueManager>::init(config.clone())
                .unwrap();

        let mut ctx = local_ctx();
        ctx.set_message_id(function_name!().to_string());
        ctx.forward_paths_mut().push(Rcpt::new(
            <Address as std::str::FromStr>::from_str("test@localhost").unwrap(),
        ));

        queue_manager
            .write_both(&QueueID::Deferred, &ctx, &local_msg())
            .await
            .unwrap();

        let resolvers = std::sync::Arc::new(DnsResolvers::from_config(&config).unwrap());

        handle_one_in_deferred_queue(
            config.clone(),
            resolvers,
            queue_manager.clone(),
            ProcessMessage {
                message_id: function_name!().to_string(),
                delegated: false,
            },
        )
        .await
        .unwrap();

        queue_manager
            .get_ctx(&QueueID::Deliver, function_name!())
            .await
            .unwrap_err();
        queue_manager
            .get_ctx(&QueueID::Dead, function_name!())
            .await
            .unwrap_err();

        queue_manager
            .get_ctx(&QueueID::Deferred, function_name!())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[function_name::named]
    async fn move_to_dead() {
        let config = std::sync::Arc::new(local_test());
        let queue_manager =
            <vqueue::temp::QueueManager as vqueue::GenericQueueManager>::init(config.clone())
                .unwrap();

        let mut ctx = local_ctx();
        ctx.set_message_id(function_name!().to_string());

        queue_manager
            .write_both(&QueueID::Deferred, &ctx, &local_msg())
            .await
            .unwrap();
        let resolvers = std::sync::Arc::new(DnsResolvers::from_config(&config).unwrap());

        handle_one_in_deferred_queue(
            config.clone(),
            resolvers,
            queue_manager.clone(),
            ProcessMessage {
                message_id: function_name!().to_string(),
                delegated: false,
            },
        )
        .await
        .unwrap();

        queue_manager
            .get_ctx(&QueueID::Deferred, function_name!())
            .await
            .unwrap_err();

        queue_manager
            .get_ctx(&QueueID::Dead, function_name!())
            .await
            .unwrap();
    }
}
