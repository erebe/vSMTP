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
use crate::transport::{Deliver, Forward, MBox, Maildir, Transport};
use crate::Sender;
use vsmtp_common::{
    rcpt::Rcpt,
    transfer::{EmailTransferStatus, ForwardTarget, Transfer, TransferErrorsVariant},
    ContextFinished,
};
use vsmtp_config::{Config, DnsResolvers};
use vsmtp_mail_parser::MessageBody;
extern crate alloc;

///
#[must_use]
#[allow(clippy::exhaustive_enums)]
#[derive(Debug)]
pub enum SenderOutcome {
    ///
    MoveToDead,
    ///
    MoveToDeferred,
    ///
    RemoveFromDisk,
}

///
#[allow(clippy::unreachable)] // false positive
#[tracing::instrument(name = "send", skip_all)]
pub async fn split_and_sort_and_send(
    config: &Config,
    message_ctx: &mut ContextFinished,
    message_body: &MessageBody,
    resolvers: alloc::sync::Arc<DnsResolvers>,
    sender: alloc::sync::Arc<Sender>,
) -> SenderOutcome {
    let mut acc: std::collections::HashMap<Transfer, Vec<Rcpt>> = std::collections::HashMap::new();
    for i in message_ctx
        .rcpt_to
        .forward_paths
        .iter()
        .filter(|r| r.email_status.is_sendable())
    {
        acc.entry(i.transfer_method.clone())
            .and_modify(|domain| domain.push(i.clone()))
            .or_insert_with(|| vec![i.clone()]);
    }

    if acc.is_empty() {
        tracing::warn!("No recipients to send to.");
        return SenderOutcome::MoveToDead;
    }

    let message_content = message_body.inner().to_string();

    let from = &message_ctx.mail_from.reverse_path;

    let futures = acc.into_iter().map(|(key, to)| match key {
        Transfer::Forward(forward_target) => {
            let resolver = match forward_target.clone() {
                ForwardTarget::Domain(domain) => resolvers.get_resolver_or_root(&domain),
                ForwardTarget::Ip(_) | ForwardTarget::Socket(_) => resolvers.get_resolver_root(),
            };

            Forward::new(forward_target, resolver, alloc::sync::Arc::clone(&sender)).deliver(
                config,
                message_ctx,
                from,
                to,
                &message_content,
            )
        }
        Transfer::Deliver => Deliver::new(
            resolvers.get_resolver_or_root(
                #[allow(clippy::expect_used)]
                to.get(0)
                    .expect("at least one element in the group")
                    .address
                    .domain(),
            ),
            alloc::sync::Arc::clone(&sender),
        )
        .deliver(config, message_ctx, from, to, &message_content),
        Transfer::Mbox => MBox.deliver(config, message_ctx, from, to, &message_content),
        Transfer::Maildir => Maildir.deliver(config, message_ctx, from, to, &message_content),
    });

    message_ctx.rcpt_to.forward_paths = futures_util::future::join_all(futures)
        .await
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    tracing::debug!(rcpt = ?message_ctx.rcpt_to.forward_paths
        .iter().map(ToString::to_string).collect::<Vec<_>>(), "Sending.");
    tracing::trace!(rcpt = ?message_ctx.rcpt_to.forward_paths);

    if message_ctx.rcpt_to.forward_paths.is_empty() {
        tracing::warn!("No recipients to send to, or all transfer method are set to none.");
        return SenderOutcome::MoveToDead;
    }

    if message_ctx
        .rcpt_to
        .forward_paths
        .iter()
        .all(|rcpt| matches!(rcpt.email_status, EmailTransferStatus::Sent { .. }))
    {
        tracing::info!("Send operation successful.");
        return SenderOutcome::RemoveFromDisk;
    }

    if message_ctx
        .rcpt_to
        .forward_paths
        .iter()
        .all(|rcpt| !rcpt.email_status.is_sendable())
    {
        tracing::warn!("No more sendable recipients.");
        return SenderOutcome::MoveToDead;
    }

    for rcpt in &mut message_ctx.rcpt_to.forward_paths {
        if matches!(&rcpt.email_status, &EmailTransferStatus::Waiting { .. }) {
            rcpt.email_status
                .held_back(TransferErrorsVariant::StillWaiting);
        }
    }

    let mut out = None;
    for rcpt in &mut message_ctx.rcpt_to.forward_paths {
        if matches!(&rcpt.email_status, EmailTransferStatus::HeldBack{ errors }
            if errors.len() >= config.server.queues.delivery.deferred_retry_max)
        {
            rcpt.email_status =
                EmailTransferStatus::failed(TransferErrorsVariant::MaxDeferredAttemptReached);
            tracing::warn!("Delivery error count maximum reached, moving to dead.");
            out = Some(SenderOutcome::MoveToDead);
        }
    }

    let out = out.unwrap_or(SenderOutcome::MoveToDeferred);
    tracing::warn!("Some send operations failed, email {:?}.", out);
    tracing::debug!(failed = ?message_ctx
        .rcpt_to
        .forward_paths
        .iter()
        .filter(|r| !matches!(r.email_status, EmailTransferStatus::Sent { .. }))
        .map(|r| (r.address.to_string(), r.email_status.clone()))
        .collect::<Vec<_>>()
    );

    out
}
