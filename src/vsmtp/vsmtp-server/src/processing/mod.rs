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
use vsmtp_common::{state::State, status::Status, transfer::EmailTransferStatus};
use vsmtp_config::{Config, Resolvers};
use vsmtp_rule_engine::RuleEngine;

pub async fn start<Q: GenericQueueManager + Sized + 'static>(
    config: std::sync::Arc<Config>,
    rule_engine: std::sync::Arc<RuleEngine>,
    resolvers: std::sync::Arc<Resolvers>,
    queue_manager: std::sync::Arc<Q>,
    mut working_receiver: tokio::sync::mpsc::Receiver<ProcessMessage>,
    delivery_sender: tokio::sync::mpsc::Sender<ProcessMessage>,
) {
    loop {
        if let Some(pm) = working_receiver.recv().await {
            let config = config.clone();
            let rule_engine = rule_engine.clone();
            let resolvers = resolvers.clone();
            let queue_manager = queue_manager.clone();
            let delivery_sender = delivery_sender.clone();

            tokio::spawn(async move {
                let _err = handle_one_in_working_queue(
                    config,
                    rule_engine,
                    resolvers,
                    queue_manager,
                    pm,
                    delivery_sender,
                )
                .await;
            });
        }
    }
}

#[allow(clippy::too_many_lines)]
#[tracing::instrument(name = "working", skip_all)]
async fn handle_one_in_working_queue<Q: GenericQueueManager + Sized + 'static>(
    config: std::sync::Arc<Config>,
    rule_engine: std::sync::Arc<RuleEngine>,
    resolvers: std::sync::Arc<Resolvers>,
    queue_manager: std::sync::Arc<Q>,
    process_message: ProcessMessage,
    delivery_sender: tokio::sync::mpsc::Sender<ProcessMessage>,
) -> anyhow::Result<()> {
    let queue = if process_message.delegated {
        QueueID::Delegated
    } else {
        QueueID::Working
    };

    let (ctx, mail_message) = queue_manager.get_both(&queue, &process_message.message_id)?;

    let (mut ctx, mail_message, _, skipped) = rule_engine.just_run_when(
        State::PostQ,
        config.clone(),
        resolvers,
        queue_manager.clone(),
        ctx,
        mail_message,
    );

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
            ctx.metadata.skipped = Some(Status::DelegationResult);

            // NOTE:  moving here because the delegation process could try to
            //        pickup the email before it's written on disk.
            queue_manager
                .clone()
                .move_to(&queue, &QueueID::Delegated, &ctx)
                .await?;

            queue_manager.write_msg(&process_message.message_id, &mail_message)?;

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
            for rcpt in &mut ctx.envelop.rcpt {
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
        queue_manager.write_msg(&process_message.message_id, &mail_message)?;
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
    use vsmtp_test::config::{local_ctx, local_msg, local_test};

    #[tokio::test]
    async fn cannot_deserialize() {
        let config = local_test();

        let (delivery_sender, _delivery_receiver) =
            tokio::sync::mpsc::channel::<ProcessMessage>(10);

        let config = std::sync::Arc::new(config);

        let resolvers = std::sync::Arc::new(vsmtp_config::build_resolvers(&config).unwrap());
        let queue_manager =
            <vqueue::fs::QueueManager as vqueue::GenericQueueManager>::init(config.clone())
                .unwrap();

        assert!(handle_one_in_working_queue(
            config.clone(),
            std::sync::Arc::new(RuleEngine::from_script(config, "#{}").unwrap()),
            resolvers,
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
    async fn basic() {
        let mut config = local_test();
        config.server.queues.dirpath = "./tmp/spool_basic".into();
        let _rm = std::fs::remove_dir_all(&config.server.queues.dirpath);

        let config = std::sync::Arc::new(config);
        let queue_manager =
            <vqueue::fs::QueueManager as vqueue::GenericQueueManager>::init(config.clone())
                .unwrap();

        let msg_id = "message_uid";

        let mut ctx = local_ctx();
        ctx.metadata.message_id = Some(msg_id.to_string());
        queue_manager
            .write_both(&QueueID::Working, &ctx, &local_msg())
            .await
            .unwrap();

        let (delivery_sender, mut delivery_receiver) =
            tokio::sync::mpsc::channel::<ProcessMessage>(10);

        let resolvers = std::sync::Arc::new(
            vsmtp_config::build_resolvers(&config).expect("could not initialize dns"),
        );

        handle_one_in_working_queue(
            config.clone(),
            std::sync::Arc::new(RuleEngine::from_script(config.clone(), "#{}").unwrap()),
            resolvers,
            queue_manager,
            ProcessMessage {
                message_id: msg_id.to_string(),
                delegated: false,
            },
            delivery_sender,
        )
        .await
        .unwrap();

        assert_eq!(
            delivery_receiver.recv().await.unwrap().message_id,
            "message_uid"
        );
        assert!(!config
            .server
            .queues
            .dirpath
            .join("working/message_uid.json")
            .exists());
        assert!(config
            .server
            .queues
            .dirpath
            .join("deliver/message_uid.json")
            .exists());
    }

    #[tokio::test]
    async fn denied() {
        let mut config = local_test();
        config.server.queues.dirpath = "./tmp/spool_denied".into();
        let _rm = std::fs::remove_dir_all(&config.server.queues.dirpath);

        let config = std::sync::Arc::new(config);
        let queue_manager =
            <vqueue::fs::QueueManager as vqueue::GenericQueueManager>::init(config.clone())
                .unwrap();

        let msg_id = "message_uid";

        let mut ctx = local_ctx();
        ctx.metadata.message_id = Some(msg_id.to_string());
        queue_manager
            .write_both(&QueueID::Working, &ctx, &local_msg())
            .await
            .unwrap();

        let (delivery_sender, _delivery_receiver) =
            tokio::sync::mpsc::channel::<ProcessMessage>(10);

        let resolvers = std::sync::Arc::new(
            vsmtp_config::build_resolvers(&config).expect("could not initialize dns"),
        );

        handle_one_in_working_queue(
            config.clone(),
            std::sync::Arc::new(
                RuleEngine::from_script(
                    config.clone(),
                    &format!("#{{ {}: [ rule \"\" || sys::deny() ] }}", State::PostQ),
                )
                .unwrap(),
            ),
            resolvers,
            queue_manager,
            ProcessMessage {
                message_id: msg_id.to_string(),
                delegated: false,
            },
            delivery_sender,
        )
        .await
        .unwrap();

        assert!(!config
            .server
            .queues
            .dirpath
            .join("working/message_uid.json")
            .exists());
        assert!(config
            .server
            .queues
            .dirpath
            .join("dead/message_uid.json")
            .exists());
    }
}
