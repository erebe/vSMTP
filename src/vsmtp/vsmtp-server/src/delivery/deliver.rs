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
    delegate,
    delivery::{add_trace_information, send_mail, SenderOutcome},
    ProcessMessage,
};
use vqueue::{GenericQueueManager, QueueID};
use vsmtp_common::{state::State, status::Status, transfer::EmailTransferStatus};
use vsmtp_config::{Config, Resolvers};
use vsmtp_rule_engine::RuleEngine;

pub async fn flush_deliver_queue<Q: GenericQueueManager + Sized + 'static>(
    config: std::sync::Arc<Config>,
    resolvers: std::sync::Arc<Resolvers>,
    queue_manager: std::sync::Arc<Q>,
    rule_engine: std::sync::Arc<RuleEngine>,
) {
    // FIXME: add span on the function.
    tracing::info!("Flushing deliver queue.");

    let queued = match queue_manager.list(&QueueID::Deliver) {
        Ok(queued) => queued,
        Err(error) => {
            tracing::error!(%error, "Flushing failed");
            todo!("what should we do on flushing error ? stop the server, simply log the error ?")
        }
    };

    for i in queued {
        let msg_id = match i {
            Ok(msg_id) => msg_id,
            Err(_) => todo!(),
        };

        let _err = handle_one_in_delivery_queue(
            config.clone(),
            resolvers.clone(),
            queue_manager.clone(),
            ProcessMessage {
                message_id: msg_id,
                delegated: false,
            },
            rule_engine.clone(),
        )
        .await;
    }
}

/// handle and send one email pulled from the delivery queue.
///
/// # Errors
///
/// * failed to open the email.
/// * failed to parse the email.
/// * failed to send an email.
/// * rule engine mutex is poisoned.
/// * failed to add trace data to the email.
/// * failed to copy the email to other queues or remove it from the delivery queue.
#[tracing::instrument(name = "delivery", skip_all)]
#[allow(clippy::too_many_lines)]
pub async fn handle_one_in_delivery_queue<Q: GenericQueueManager + Sized + 'static>(
    config: std::sync::Arc<Config>,
    resolvers: std::sync::Arc<Resolvers>,
    queue_manager: std::sync::Arc<Q>,
    process_message: ProcessMessage,
    rule_engine: std::sync::Arc<RuleEngine>,
) -> anyhow::Result<()> {
    let queue = if process_message.delegated {
        QueueID::Delegated
    } else {
        QueueID::Deliver
    };

    let (mail_context, mail_message) =
        queue_manager.get_both(&queue, &process_message.message_id)?;

    let (mut mail_context, mut mail_message, result, skipped) = rule_engine.just_run_when(
        State::Delivery,
        config.clone(),
        resolvers.clone(),
        queue_manager.clone(),
        mail_context,
        mail_message,
    );

    match &skipped {
        Some(status @ Status::Quarantine(path)) => {
            queue_manager
                .move_to(
                    &queue,
                    &QueueID::Quarantine { name: path.into() },
                    &mail_context,
                )
                .await?;

            queue_manager.write_msg(&process_message.message_id, &mail_message)?;

            tracing::warn!(status = status.as_ref(), "Rules skipped.");

            return Ok(());
        }
        Some(status @ Status::Delegated(delegator)) => {
            mail_context.metadata.skipped = Some(Status::DelegationResult);

            queue_manager
                .move_to(&queue, &QueueID::Delegated, &mail_context)
                .await?;

            queue_manager.write_msg(&process_message.message_id, &mail_message)?;

            // NOTE: needs to be executed after writing, because the other
            //       thread could pickup the email faster than this function.
            delegate(delegator, &mail_context, &mail_message)?;

            tracing::warn!(status = status.as_ref(), "Rules skipped.");

            return Ok(());
        }
        Some(Status::DelegationResult) => {
            anyhow::bail!(
                "delivery is the last stage, delegation results cannot travel down any further."
            )
        }
        Some(Status::Deny(code)) => {
            for rcpt in &mut mail_context.envelop.rcpt {
                rcpt.email_status = EmailTransferStatus::Failed {
                    timestamp: std::time::SystemTime::now(),
                    reason: format!("rule engine denied the message in delivery: {code:?}."),
                };
            }

            queue_manager
                .move_to(&queue, &QueueID::Dead, &mail_context)
                .await?;

            queue_manager.write_msg(&process_message.message_id, &mail_message)?;

            return Ok(());
        }
        Some(reason) => {
            tracing::warn!(status = ?reason, "Rules skipped.");
        }
        None => {}
    };

    add_trace_information(&config, &mail_context, &mut mail_message, &result)?;

    match send_mail(&config, &mut mail_context, &mail_message, &resolvers).await {
        SenderOutcome::MoveToDead => {
            queue_manager
                .move_to(&queue, &QueueID::Dead, &mail_context)
                .await?;

            queue_manager.write_msg(&process_message.message_id, &mail_message)
        }
        SenderOutcome::MoveToDeferred => {
            queue_manager
                .move_to(&queue, &QueueID::Deferred, &mail_context)
                .await?;

            queue_manager.write_msg(&process_message.message_id, &mail_message)
        }
        SenderOutcome::RemoveFromDisk => {
            queue_manager
                .remove_both(&queue, &process_message.message_id)
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
        config.server.queues.dirpath = "./tmp/spool_deliver1".into();
        let _rm = std::fs::remove_dir_all(&config.server.queues.dirpath);

        let config = std::sync::Arc::new(config);
        let queue_manager =
            <vqueue::fs::QueueManager as vqueue::GenericQueueManager>::init(config.clone())
                .unwrap();

        let msg_id = "move_to_deferred";

        let mut ctx = local_ctx();
        ctx.metadata.message_id = Some(msg_id.to_string());
        ctx.metadata.timestamp = Some(std::time::SystemTime::now());
        ctx.envelop.rcpt.push(Rcpt::new(
            <Address as std::str::FromStr>::from_str("test@foobar.com").unwrap(),
        ));

        queue_manager
            .write_both(&QueueID::Deliver, &ctx, &local_msg())
            .await
            .unwrap();

        let resolvers = std::sync::Arc::new(
            vsmtp_config::build_resolvers(&config).expect("could not initialize dns"),
        );

        handle_one_in_delivery_queue(
            config.clone(),
            resolvers,
            queue_manager,
            ProcessMessage {
                message_id: msg_id.to_string(),
                delegated: false,
            },
            std::sync::Arc::new(RuleEngine::from_script(config.clone(), "#{}").unwrap()),
        )
        .await
        .unwrap();

        assert!(!config
            .server
            .queues
            .dirpath
            .join(format!("{}/{}.json", QueueID::Deliver, msg_id))
            .exists());
        assert!(config
            .server
            .queues
            .dirpath
            .join(format!("{}/{}.json", QueueID::Deferred, msg_id))
            .exists());
    }

    #[tokio::test]
    async fn denied() {
        let mut config = local_test();
        config.server.queues.dirpath = "./tmp/spool_deliver_denied".into();
        let _rm = std::fs::remove_dir_all(&config.server.queues.dirpath);

        let config = std::sync::Arc::new(config);
        let queue_manager =
            <vqueue::fs::QueueManager as vqueue::GenericQueueManager>::init(config.clone())
                .unwrap();

        let msg_id = "message_uid";

        let mut ctx = local_ctx();
        ctx.metadata.message_id = Some(msg_id.to_string());
        ctx.metadata.timestamp = Some(std::time::SystemTime::now());

        queue_manager
            .write_both(&QueueID::Deliver, &ctx, &local_msg())
            .await
            .unwrap();

        let resolvers = std::sync::Arc::new(
            vsmtp_config::build_resolvers(&config).expect("could not initialize dns"),
        );

        handle_one_in_delivery_queue(
            config.clone(),
            resolvers,
            queue_manager,
            ProcessMessage {
                message_id: msg_id.to_string(),
                delegated: false,
            },
            std::sync::Arc::new(
                RuleEngine::from_script(
                    config.clone(),
                    &format!("#{{ {}: [ rule \"\" || sys::deny() ] }}", State::Delivery),
                )
                .unwrap(),
            ),
        )
        .await
        .unwrap();

        assert!(!config
            .server
            .queues
            .dirpath
            .join(format!("{}/{}.json", QueueID::Deliver, msg_id))
            .exists());

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
