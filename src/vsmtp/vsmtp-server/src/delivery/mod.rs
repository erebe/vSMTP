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
    channel_message::ProcessMessage,
    delivery::{
        deferred::flush_deferred_queue,
        deliver::{flush_deliver_queue, handle_one_in_delivery_queue},
    },
};
use anyhow::Context;
use time::format_description::well_known::Rfc2822;
use vqueue::GenericQueueManager;
use vsmtp_common::mail_context::Finished;
use vsmtp_common::{mail_context::MailContext, status::Status};
use vsmtp_config::{Config, DnsResolvers};
use vsmtp_delivery::Sender;
use vsmtp_mail_parser::MessageBody;
use vsmtp_rule_engine::RuleEngine;

mod deferred;
mod deliver;

pub async fn start<Q: GenericQueueManager + Sized + 'static>(
    config: std::sync::Arc<Config>,
    rule_engine: std::sync::Arc<RuleEngine>,
    resolvers: std::sync::Arc<DnsResolvers>,
    queue_manager: std::sync::Arc<Q>,
    mut delivery_receiver: tokio::sync::mpsc::Receiver<ProcessMessage>,
    sender: std::sync::Arc<Sender>,
) {
    flush_deliver_queue(
        config.clone(),
        resolvers.clone(),
        queue_manager.clone(),
        rule_engine.clone(),
        sender.clone(),
    )
    .await;

    // NOTE: emails stored in the deferred queue are likely to slow down the process.
    //       the pickup process of this queue should be slower than pulling from the delivery queue.
    //       https://www.postfix.org/QSHAPE_README.html#queues
    let mut flush_deferred_interval =
        tokio::time::interval(config.server.queues.delivery.deferred_retry_period);

    loop {
        tokio::select! {
            Some(pm) = delivery_receiver.recv() => {
                tokio::spawn(
                    handle_one_in_delivery_queue(
                        config.clone(),
                        resolvers.clone(),
                        queue_manager.clone(),
                        pm,
                        rule_engine.clone(),
                        sender.clone(),
                    )
                );
            }
            _ = flush_deferred_interval.tick() => {
                tracing::info!("cronjob delay elapsed `{}s`, flushing queue.",
                    config.server.queues.delivery.deferred_retry_period.as_secs());
                tokio::spawn(
                    flush_deferred_queue(
                        config.clone(),
                        resolvers.clone(),
                        queue_manager.clone(),
                        sender.clone(),
                    )
                );
            }
        };
    }
}

// <https://datatracker.ietf.org/doc/html/rfc5321#section-4.4>
fn add_trace_information(
    ctx: &MailContext<Finished>,
    message: &mut MessageBody,
    rule_engine_result: &Status,
) -> anyhow::Result<()> {
    message.prepend_header(
        "X-VSMTP",
        &create_vsmtp_status_stamp(
            ctx.message_id(),
            env!("CARGO_PKG_VERSION"),
            rule_engine_result,
        ),
    );

    message.prepend_header(
        "Received",
        &create_received_stamp(
            ctx.client_name(),
            ctx.server_name(),
            ctx.message_id(),
            ctx.mail_timestamp(),
        )
        .context("failed to create Receive header timestamp")?,
    );

    Ok(())
}

fn create_received_stamp(
    client_helo: &str,
    server_domain: &str,
    message_id: &str,
    received_timestamp: &time::OffsetDateTime,
) -> anyhow::Result<String> {
    let date = received_timestamp.format(&Rfc2822)?;
    Ok(format!(
        "from {client_helo} by {server_domain} with SMTP id {message_id}; {date}"
    ))
}

fn create_vsmtp_status_stamp(message_id: &str, version: &str, status: &Status) -> String {
    format!(
        "id=\"{message_id}\"; version=\"{version}\"; status=\"{}\"",
        status.as_ref()
    )
}

#[cfg(test)]
mod test {
    use super::add_trace_information;
    use time::format_description::well_known::Rfc2822;
    use vsmtp_common::status::Status;
    use vsmtp_mail_parser::{MessageBody, RawBody};
    use vsmtp_test::config::local_ctx;

    /*
    /// This test produce side-effect and may make other test fails
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn start() {
        let mut config = config::local_test();
        config.server.queues.dirpath = "./tmp".into();

        let rule_engine = std::sync::Arc::new(std::sync::RwLock::new(
            RuleEngine::from_script("#{}").unwrap(),
        ));

        let (delivery_sender, delivery_receiver) = tokio::sync::mpsc::channel::<ProcessMessage>(10);

        let task = tokio::spawn(super::start(
            std::sync::Arc::new(config),
            rule_engine,
            delivery_receiver,
        ));

        delivery_sender
            .send(ProcessMessage {
                message_id: "test".to_string(),
            })
            .await
            .unwrap();

        task.await.unwrap().unwrap();
    }
    */

    #[test]
    fn test_add_trace_information() {
        let mut ctx = local_ctx();

        let mut message = MessageBody::default();
        ctx.set_message_id("test_message_id".to_string());
        add_trace_information(&ctx, &mut message, &Status::Next).unwrap();

        pretty_assertions::assert_eq!(
            *message.inner(),
            RawBody::new_empty(vec![
                [
                    "Received: from client.testserver.com".to_string(),
                    " by testserver.com".to_string(),
                    " with SMTP".to_string(),
                    " id test_message_id; ".to_string(),
                    { ctx.mail_timestamp().format(&Rfc2822).unwrap() }
                ]
                .concat(),
                format!(
                    "X-VSMTP: id=\"test_message_id\"; version=\"{ver}\"; status=\"next\"",
                    ver = env!("CARGO_PKG_VERSION"),
                ),
            ])
        );
    }
}
