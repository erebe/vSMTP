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
use crate::{delegate, ProcessMessage};
use vqueue::{GenericQueueManager, QueueID};
use vsmtp_common::{
    mail_context::{Finished, MailContext},
    state::State,
    status::Status,
    transfer::EmailTransferStatus,
};
use vsmtp_rule_engine::RuleEngine;

pub async fn start<Q: GenericQueueManager + Sized + 'static>(
    rule_engine: std::sync::Arc<RuleEngine>,
    queue_manager: std::sync::Arc<Q>,
    mut working_receiver: tokio::sync::mpsc::Receiver<ProcessMessage>,
    delivery_sender: tokio::sync::mpsc::Sender<ProcessMessage>,
) {
    loop {
        if let Some(pm) = working_receiver.recv().await {
            let rule_engine = rule_engine.clone();
            let queue_manager = queue_manager.clone();
            let delivery_sender = delivery_sender.clone();

            tokio::spawn(async move {
                let _err =
                    handle_one_in_working_queue(rule_engine, queue_manager, pm, delivery_sender)
                        .await;
            });
        }
    }
}

#[allow(clippy::too_many_lines)]
#[tracing::instrument(name = "working", skip_all)]
async fn handle_one_in_working_queue<Q: GenericQueueManager + Sized + 'static>(
    rule_engine: std::sync::Arc<RuleEngine>,
    queue_manager: std::sync::Arc<Q>,
    process_message: ProcessMessage,
    delivery_sender: tokio::sync::mpsc::Sender<ProcessMessage>,
) -> anyhow::Result<()> {
    let queue = if process_message.delegated {
        QueueID::Delegated
    } else {
        QueueID::Working
    };

    let (ctx, mail_message) = queue_manager
        .get_both(&queue, &process_message.message_id)
        .await?;

    let (ctx, mail_message, _, skipped) =
        rule_engine.just_run_when(State::PostQ, ctx, mail_message);

    let mut ctx: MailContext<Finished> = ctx
        .try_into()
        .expect("the inner state of mail_context must not change");

    let mut move_to_queue = Option::<QueueID>::None;
    let mut send_to_delivery = false;
    let mut write_email = true;
    let mut delegated = false;

    match &skipped {
        Some(Status::Quarantine(path)) => {
            queue_manager
                .move_to(&queue, &QueueID::Quarantine { name: path.into() }, &ctx)
                .await?;

            tracing::warn!(stage = %State::PostQ, status = "quarantine", "Rules skipped.");
        }
        Some(status @ Status::Delegated(delegator)) => {
            ctx.set_skipped(Some(Status::DelegationResult));

            // NOTE:  moving here because the delegation process could try to
            //        pickup the email before it's written on disk.
            queue_manager
                .clone()
                .move_to(&queue, &QueueID::Delegated, &ctx)
                .await?;

            queue_manager
                .write_msg(&process_message.message_id, &mail_message)
                .await?;

            // NOTE: needs to be executed after writing, because the other
            //       thread could pickup the email faster than this function.
            delegate(delegator, &ctx, &mail_message)?;

            write_email = false;
            delegated = true;

            tracing::warn!(stage = %State::PostQ, status = status.as_ref(), "Rules skipped.");
        }
        Some(Status::DelegationResult) => {
            send_to_delivery = true;
            delegated = true;
        }
        Some(Status::Deny(code)) => {
            for rcpt in ctx.forward_paths_mut() {
                rcpt.email_status = EmailTransferStatus::Failed {
                    timestamp: std::time::SystemTime::now(),
                    reason: format!("rule engine denied the message in postq: {code:?}."),
                };
            }

            move_to_queue = Some(QueueID::Dead);
        }
        Some(reason) => {
            tracing::warn!(status = ?reason, "Rules skipped.");

            move_to_queue = Some(QueueID::Deliver);
            send_to_delivery = true;
        }
        None => {
            move_to_queue = Some(QueueID::Deliver);
            send_to_delivery = true;
        }
    };

    if write_email {
        queue_manager
            .write_msg(&process_message.message_id, &mail_message)
            .await?;
    }

    if let Some(next_queue) = move_to_queue {
        queue_manager.move_to(&queue, &next_queue, &ctx).await?;
    }

    if send_to_delivery {
        delivery_sender
            .send(ProcessMessage {
                message_id: process_message.message_id.clone(),
                delegated,
            })
            .await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vsmtp_config::DnsResolvers;
    use vsmtp_test::config::{local_ctx, local_msg, local_test};

    #[tokio::test]
    async fn cannot_deserialize() {
        let config = local_test();

        let (delivery_sender, _delivery_receiver) =
            tokio::sync::mpsc::channel::<ProcessMessage>(10);

        let config = std::sync::Arc::new(config);

        let resolvers = std::sync::Arc::new(DnsResolvers::from_config(&config).unwrap());
        let queue_manager =
            <vqueue::temp::QueueManager as vqueue::GenericQueueManager>::init(config.clone())
                .unwrap();

        assert!(handle_one_in_working_queue(
            std::sync::Arc::new(
                RuleEngine::from_script(config, "#{}", resolvers.clone(), queue_manager.clone())
                    .unwrap()
            ),
            queue_manager,
            ProcessMessage {
                message_id: "not_such_message_named_like_this".to_string(),
                delegated: false,
            },
            delivery_sender,
        )
        .await
        .is_err());
    }

    #[tokio::test]
    #[function_name::named]
    async fn basic() {
        let config = std::sync::Arc::new(local_test());
        let queue_manager =
            <vqueue::temp::QueueManager as vqueue::GenericQueueManager>::init(config.clone())
                .unwrap();

        let mut ctx = local_ctx();
        ctx.set_message_id(function_name!().to_string());
        queue_manager
            .write_both(&QueueID::Working, &ctx, &local_msg())
            .await
            .unwrap();

        let (delivery_sender, mut delivery_receiver) =
            tokio::sync::mpsc::channel::<ProcessMessage>(10);
        let resolvers = std::sync::Arc::new(DnsResolvers::from_config(&config).unwrap());

        handle_one_in_working_queue(
            std::sync::Arc::new(
                RuleEngine::from_script(
                    config.clone(),
                    "#{}",
                    resolvers.clone(),
                    queue_manager.clone(),
                )
                .unwrap(),
            ),
            queue_manager.clone(),
            ProcessMessage {
                message_id: function_name!().to_string(),
                delegated: false,
            },
            delivery_sender,
        )
        .await
        .unwrap();

        assert_eq!(
            delivery_receiver.recv().await.unwrap().message_id,
            function_name!()
        );
        queue_manager
            .get_ctx(&QueueID::Working, function_name!())
            .await
            .unwrap_err();
        queue_manager
            .get_ctx(&QueueID::Deliver, function_name!())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[function_name::named]
    async fn denied() {
        let config = std::sync::Arc::new(local_test());
        let queue_manager =
            <vqueue::temp::QueueManager as vqueue::GenericQueueManager>::init(config.clone())
                .unwrap();

        let mut ctx = local_ctx();
        ctx.set_message_id(function_name!().to_string());
        queue_manager
            .write_both(&QueueID::Working, &ctx, &local_msg())
            .await
            .unwrap();

        let (delivery_sender, _delivery_receiver) =
            tokio::sync::mpsc::channel::<ProcessMessage>(10);
        let resolvers = std::sync::Arc::new(DnsResolvers::from_config(&config).unwrap());

        handle_one_in_working_queue(
            std::sync::Arc::new(
                RuleEngine::from_script(
                    config.clone(),
                    &format!("#{{ {}: [ rule \"\" || sys::deny() ] }}", State::PostQ),
                    resolvers.clone(),
                    queue_manager.clone(),
                )
                .unwrap(),
            ),
            queue_manager.clone(),
            ProcessMessage {
                message_id: function_name!().to_string(),
                delegated: false,
            },
            delivery_sender,
        )
        .await
        .unwrap();

        queue_manager
            .get_ctx(&QueueID::Working, function_name!())
            .await
            .unwrap_err();
        queue_manager
            .get_ctx(&QueueID::Dead, function_name!())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[function_name::named]
    async fn quarantine() {
        let config = std::sync::Arc::new(local_test());
        let queue_manager =
            <vqueue::temp::QueueManager as vqueue::GenericQueueManager>::init(config.clone())
                .unwrap();

        let mut ctx = local_ctx();
        ctx.set_message_id(function_name!().to_string());
        queue_manager
            .write_both(&QueueID::Working, &ctx, &local_msg())
            .await
            .unwrap();

        let (delivery_sender, _delivery_receiver) =
            tokio::sync::mpsc::channel::<ProcessMessage>(10);
        let resolvers = std::sync::Arc::new(DnsResolvers::from_config(&config).unwrap());

        handle_one_in_working_queue(
            std::sync::Arc::new(
                RuleEngine::from_script(
                    config.clone(),
                    &format!(
                        "#{{ {}: [ rule \"quarantine\" || quarantine(\"unit-test\") ] }}",
                        State::PostQ
                    ),
                    resolvers.clone(),
                    queue_manager.clone(),
                )
                .unwrap(),
            ),
            queue_manager.clone(),
            ProcessMessage {
                message_id: function_name!().to_string(),
                delegated: false,
            },
            delivery_sender,
        )
        .await
        .unwrap();

        queue_manager
            .get_ctx(
                &QueueID::Quarantine {
                    name: "unit-test".to_string(),
                },
                function_name!(),
            )
            .await
            .unwrap();

        queue_manager
            .get_ctx(&QueueID::Working, function_name!())
            .await
            .unwrap_err();
        queue_manager
            .get_ctx(&QueueID::Dead, function_name!())
            .await
            .unwrap_err();
    }
}
