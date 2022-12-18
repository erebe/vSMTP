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
use crate::{delegate, delivery::add_trace_information, ProcessMessage};
use anyhow::Context;
use vqueue::{GenericQueueManager, QueueID};
use vsmtp_common::{
    status::Status,
    transfer::{EmailTransferStatus, RuleEngineVariants, TransferErrorsVariant},
};
use vsmtp_config::{Config, DnsResolvers};
use vsmtp_delivery::{split_and_sort_and_send, Sender, SenderOutcome};
use vsmtp_rule_engine::{ExecutionStage, RuleEngine};

pub async fn flush_deliver_queue<Q: GenericQueueManager + Sized + 'static>(
    config: std::sync::Arc<Config>,
    resolvers: std::sync::Arc<DnsResolvers>,
    queue_manager: std::sync::Arc<Q>,
    rule_engine: std::sync::Arc<RuleEngine>,
    sender: std::sync::Arc<Sender>,
) {
    // FIXME: add span on the function.
    tracing::info!("Flushing deliver queue.");

    let queued = match queue_manager.list(&QueueID::Deliver).await {
        Ok(queued) => queued,
        Err(error) => {
            tracing::error!(%error, "Flushing failed");
            return;
        }
    };

    for i in queued {
        let message_uuid = match i
            .as_ref()
            .map(|i| <uuid::Uuid as std::str::FromStr>::from_str(i))
        {
            Ok(Ok(message_uuid)) => message_uuid,
            Ok(Err(error)) => {
                tracing::error!(%error, "Invalid message id in deliver queue.");
                continue;
            }
            Err(error) => {
                tracing::error!(%error, "Deliver message id missing.");
                continue;
            }
        };

        let _err = handle_one_in_delivery_queue(
            config.clone(),
            resolvers.clone(),
            queue_manager.clone(),
            ProcessMessage {
                message_uuid,
                delegated: false,
            },
            rule_engine.clone(),
            sender.clone(),
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
#[allow(clippy::too_many_lines)]
#[tracing::instrument(name = "delivery", skip_all, err, fields(uuid = %process_message.message_uuid))]
pub async fn handle_one_in_delivery_queue<Q: GenericQueueManager + Sized + 'static>(
    config: std::sync::Arc<Config>,
    resolvers: std::sync::Arc<DnsResolvers>,
    queue_manager: std::sync::Arc<Q>,
    process_message: ProcessMessage,
    rule_engine: std::sync::Arc<RuleEngine>,
    sender: std::sync::Arc<Sender>,
) -> anyhow::Result<()> {
    let queue = if process_message.delegated {
        QueueID::Delegated
    } else {
        QueueID::Deliver
    };

    let (ctx, mail_message) = queue_manager
        .get_both(&queue, &process_message.message_uuid)
        .await?;

    let mut skipped = ctx.connect.skipped.clone();
    let (ctx, mut mail_message, result) = rule_engine.just_run_when(
        &mut skipped,
        ExecutionStage::Delivery,
        vsmtp_common::Context::Finished(ctx),
        mail_message,
    );

    let mut ctx = ctx.unwrap_finished().context("context is not finished")?;

    match &skipped {
        Some(status @ Status::Quarantine(path)) => {
            queue_manager
                .move_to(&queue, &QueueID::Quarantine { name: path.into() }, &ctx)
                .await?;

            queue_manager
                .write_msg(&process_message.message_uuid, &mail_message)
                .await?;

            tracing::warn!(status = status.as_ref(), "Rules skipped.");

            return Ok(());
        }
        Some(status @ Status::Delegated(delegator)) => {
            ctx.connect.skipped = Some(Status::DelegationResult);

            queue_manager
                .move_to(&queue, &QueueID::Delegated, &ctx)
                .await?;

            queue_manager
                .write_msg(&process_message.message_uuid, &mail_message)
                .await?;

            // NOTE: needs to be executed after writing, because the other
            //       thread could pickup the email faster than this function.
            delegate(delegator, &ctx, &mail_message)?;

            tracing::warn!(status = status.as_ref(), "Rules skipped.");

            return Ok(());
        }
        Some(Status::DelegationResult) => {
            anyhow::bail!(
                "delivery is the last stage, delegation results cannot travel down any further."
            )
        }
        Some(Status::Deny(code)) => {
            for rcpt in &mut ctx.rcpt_to.forward_paths {
                rcpt.email_status = EmailTransferStatus::failed(TransferErrorsVariant::RuleEngine(
                    RuleEngineVariants::Denied(code.clone()),
                ));
            }

            queue_manager.move_to(&queue, &QueueID::Dead, &ctx).await?;

            queue_manager
                .write_msg(&process_message.message_uuid, &mail_message)
                .await?;

            return Ok(());
        }
        Some(reason) => {
            tracing::warn!(status = ?reason, "Rules skipped.");
        }
        None => {}
    };

    add_trace_information(&ctx, &mut mail_message, &result)?;

    match split_and_sort_and_send(&config, &mut ctx, &mail_message, resolvers, sender).await {
        SenderOutcome::MoveToDead => {
            queue_manager.move_to(&queue, &QueueID::Dead, &ctx).await?;

            queue_manager
                .write_msg(&process_message.message_uuid, &mail_message)
                .await
        }
        SenderOutcome::MoveToDeferred => {
            queue_manager
                .move_to(&queue, &QueueID::Deferred, &ctx)
                .await?;

            queue_manager
                .write_msg(&process_message.message_uuid, &mail_message)
                .await
        }
        SenderOutcome::RemoveFromDisk => {
            queue_manager
                .remove_both(&queue, &process_message.message_uuid)
                .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vsmtp_common::{rcpt::Rcpt, Address};
    use vsmtp_test::config::{local_ctx, local_msg, local_test};

    #[tokio::test(flavor = "multi_thread")]
    async fn move_to_deferred() {
        let config = std::sync::Arc::new(local_test());
        let queue_manager =
            <vqueue::temp::QueueManager as vqueue::GenericQueueManager>::init(config.clone())
                .unwrap();

        let mut ctx = local_ctx();
        let message_uuid = uuid::Uuid::new_v4();
        ctx.mail_from.message_uuid = message_uuid;
        ctx.rcpt_to.forward_paths.push(Rcpt::new(
            <Address as std::str::FromStr>::from_str("test@foobar.com").unwrap(),
        ));

        queue_manager
            .write_both(&QueueID::Deliver, &ctx, &local_msg())
            .await
            .unwrap();
        let resolvers = std::sync::Arc::new(DnsResolvers::from_config(&config).unwrap());
        let sender = std::sync::Arc::new(Sender::default());

        handle_one_in_delivery_queue(
            config.clone(),
            resolvers.clone(),
            queue_manager.clone(),
            ProcessMessage {
                message_uuid,
                delegated: false,
            },
            std::sync::Arc::new(
                RuleEngine::with_hierarchy(
                    config.clone(),
                    |builder| Ok(builder.add_root_filter_rules("#{}")?.build()),
                    resolvers,
                    queue_manager.clone(),
                )
                .unwrap(),
            ),
            sender,
        )
        .await
        .unwrap();

        queue_manager
            .get_ctx(&QueueID::Deliver, &message_uuid)
            .await
            .unwrap_err();

        queue_manager
            .get_ctx(&QueueID::Deferred, &message_uuid)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn denied() {
        let config = std::sync::Arc::new(local_test());
        let queue_manager =
            <vqueue::temp::QueueManager as vqueue::GenericQueueManager>::init(config.clone())
                .unwrap();

        let mut ctx = local_ctx();
        let message_uuid = uuid::Uuid::new_v4();
        ctx.mail_from.message_uuid = message_uuid;

        queue_manager
            .write_both(&QueueID::Deliver, &ctx, &local_msg())
            .await
            .unwrap();
        let resolvers = std::sync::Arc::new(DnsResolvers::from_config(&config).unwrap());
        let sender = std::sync::Arc::new(Sender::default());

        handle_one_in_delivery_queue(
            config.clone(),
            resolvers.clone(),
            queue_manager.clone(),
            ProcessMessage {
                message_uuid,
                delegated: false,
            },
            std::sync::Arc::new(
                RuleEngine::with_hierarchy(
                    config.clone(),
                    |builder| {
                        Ok(builder
                            .add_root_filter_rules(&format!(
                                "#{{ {}: [ rule \"\" || sys::deny() ] }}",
                                ExecutionStage::Delivery
                            ))?
                            .build())
                    },
                    resolvers,
                    queue_manager.clone(),
                )
                .unwrap(),
            ),
            sender,
        )
        .await
        .unwrap();

        queue_manager
            .get_ctx(&QueueID::Deliver, &message_uuid)
            .await
            .unwrap_err();

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
