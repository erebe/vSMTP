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
use vsmtp_common::status::Status;
use vsmtp_common::ContextFinished;
use vsmtp_config::Config;
use vsmtp_mail_parser::MessageBody;
use vsmtp_rule_engine::RuleEngine;

mod deferred;
mod deliver;

pub async fn start<Q: GenericQueueManager + Sized + 'static>(
    config: std::sync::Arc<Config>,
    rule_engine: std::sync::Arc<RuleEngine>,
    queue_manager: std::sync::Arc<Q>,
    mut delivery_receiver: tokio::sync::mpsc::Receiver<ProcessMessage>,
) {
    flush_deliver_queue(config.clone(), queue_manager.clone(), rule_engine.clone()).await;

    let mut flush_deferred_interval =
        tokio::time::interval(config.server.queues.delivery.deferred_retry_period);

    loop {
        tokio::select! {
            Some(pm) = delivery_receiver.recv() => {
                tokio::spawn(
                    handle_one_in_delivery_queue(
                        config.clone(),
                        queue_manager.clone(),
                        pm,
                        rule_engine.clone(),
                    )
                );
            }
            _ = flush_deferred_interval.tick() => {
                tracing::info!("cronjob delay elapsed `{}s`, flushing queue.",
                    config.server.queues.delivery.deferred_retry_period.as_secs());
                tokio::spawn(
                    flush_deferred_queue(
                        config.clone(),
                        queue_manager.clone(),
                        time::OffsetDateTime::now_utc(),
                    )
                );
            }
        };
    }
}

// <https://datatracker.ietf.org/doc/html/rfc5321#section-4.4>
fn add_trace_information(
    ctx: &ContextFinished,
    message: &mut MessageBody,
    status: &Status,
) -> anyhow::Result<()> {
    message.prepend_header(
        "X-VSMTP",
        &format!(
            "id=\"{message_uuid}\"; version=\"{version}\"; status=\"{status}\"",
            message_uuid = ctx.mail_from.message_uuid,
            version = env!("CARGO_PKG_VERSION"),
            status = status.as_ref()
        ),
    );

    message.prepend_header(
        "Received",
        &format!(
            "from {client_helo} by {server_domain} with SMTP id {message_uuid}; {date}",
            client_helo = ctx.helo.client_name,
            server_domain = ctx.connect.server_name,
            message_uuid = ctx.mail_from.message_uuid,
            date = ctx
                .mail_from
                .mail_timestamp
                .format(&Rfc2822)
                .context("failed to create Receive header timestamp")?
        ),
    );

    Ok(())
}

#[cfg(test)]
mod test {
    use super::add_trace_information;
    use time::format_description::well_known::Rfc2822;
    use vsmtp_common::status::Status;
    use vsmtp_mail_parser::{MessageBody, RawBody};
    use vsmtp_test::config::local_ctx;

    #[test]
    fn test_add_trace_information() {
        let mut ctx = local_ctx();

        let mut message = MessageBody::default();
        let msg_uuid = uuid::Uuid::nil();
        ctx.mail_from.message_uuid = msg_uuid;
        add_trace_information(&ctx, &mut message, &Status::Next).unwrap();

        pretty_assertions::assert_eq!(
            *message.inner(),
            RawBody::new_empty(vec![
                [
                    "Received: from client.testserver.com".to_string(),
                    " by testserver.com".to_string(),
                    " with SMTP".to_string(),
                    " id 00000000-0000-0000-0000-000000000000; ".to_string(),
                    ctx.mail_from.mail_timestamp.format(&Rfc2822).unwrap(),
                    "\r\n".to_string()
                ]
                .concat(),
                format!(
                    "X-VSMTP: id=\"00000000-0000-0000-0000-000000000000\"; version=\"{ver}\"; status=\"next\"\r\n",
                    ver = env!("CARGO_PKG_VERSION"),
                ),
            ])
        );
    }
}
