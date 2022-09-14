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
use vsmtp_config::{Config, Resolvers};

// TODO: what should be the procedure on failure here ?
pub async fn flush_deferred_queue<Q: GenericQueueManager + Sized + 'static>(
    config: std::sync::Arc<Config>,
    resolvers: std::sync::Arc<Resolvers>,
    queue_manager: std::sync::Arc<Q>,
) {
    let queued = match queue_manager.list(&QueueID::Deferred) {
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
    resolvers: std::sync::Arc<Resolvers>,
    queue_manager: std::sync::Arc<Q>,
    process_message: ProcessMessage,
) -> anyhow::Result<()> {
    tracing::debug!("Processing email.");

    let (mut mail_context, mail_message) =
        queue_manager.get_both(&QueueID::Deferred, &process_message.message_id)?;

    match send_mail(&config, &mut mail_context, &mail_message, &resolvers).await {
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
    async fn move_to_deferred() {
        let mut config = local_test();
        config.server.queues.dirpath = "./tmp/spool_deferred1".into();
        let _rm = std::fs::remove_dir_all(&config.server.queues.dirpath);

        let config = std::sync::Arc::new(config);
        let queue_manager =
            <vqueue::fs::QueueManager as vqueue::GenericQueueManager>::init(config.clone())
                .unwrap();

        let msg_id = "move_to_deferred";

        let mut ctx = local_ctx();
        ctx.metadata.message_id = Some(msg_id.to_string());
        ctx.envelop.rcpt.push(Rcpt::new(
            <Address as std::str::FromStr>::from_str("test@localhost").unwrap(),
        ));

        queue_manager
            .write_both(&QueueID::Deferred, &ctx, &local_msg())
            .await
            .unwrap();

        let resolvers = std::sync::Arc::new(
            vsmtp_config::build_resolvers(&config).expect("could not initialize dns"),
        );

        handle_one_in_deferred_queue(
            config.clone(),
            resolvers,
            queue_manager,
            ProcessMessage {
                message_id: msg_id.to_string(),
                delegated: false,
            },
        )
        .await
        .unwrap();

        assert!(config
            .server
            .queues
            .dirpath
            .join(format!("{}/{}.json", QueueID::Deferred, msg_id))
            .exists());
    }

    #[tokio::test]
    async fn move_to_dead() {
        let mut config = local_test();
        config.server.queues.dirpath = "./tmp/spool_deferred2".into();
        let _rm = std::fs::remove_dir_all(&config.server.queues.dirpath);

        let config = std::sync::Arc::new(config);
        let queue_manager =
            <vqueue::fs::QueueManager as vqueue::GenericQueueManager>::init(config.clone())
                .unwrap();

        let msg_id = "move_to_dead";

        let mut ctx = local_ctx();
        ctx.metadata.message_id = Some(msg_id.to_string());

        queue_manager
            .write_both(&QueueID::Deferred, &ctx, &local_msg())
            .await
            .unwrap();

        let resolvers = std::sync::Arc::new(
            vsmtp_config::build_resolvers(&config).expect("could not initialize dns"),
        );

        handle_one_in_deferred_queue(
            config.clone(),
            resolvers,
            queue_manager,
            ProcessMessage {
                message_id: msg_id.to_string(),
                delegated: false,
            },
        )
        .await
        .unwrap();

        assert!(!config
            .server
            .queues
            .dirpath
            .join(format!("{}/{}.json", QueueID::Deferred, msg_id))
            .exists());

        assert!(config
            .server
            .queues
            .dirpath
            .join(format!("{}/{}.json", QueueID::Dead, msg_id))
            .exists());
    }
}
