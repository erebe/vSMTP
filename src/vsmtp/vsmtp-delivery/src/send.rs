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
use futures_util::FutureExt;
use vsmtp_common::{
    transfer::{Status, TransferErrorsVariant},
    transport::WrapperSerde,
    ContextFinished, Domain,
};
use vsmtp_config::Config;
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
    config: alloc::sync::Arc<Config>,
    message_ctx: &mut ContextFinished,
    message_body: &MessageBody,
) -> SenderOutcome {
    let transports = message_ctx
        .rcpt_to
        .delivery
        .iter()
        .filter_map(|(k, rcpt)| {
            let rcpt = rcpt
                .iter()
                .filter_map(|(r, status)| status.is_sendable().then(|| (r.clone(), status.clone())))
                .collect::<Vec<_>>();

            if rcpt.is_empty() {
                None
            } else {
                Some((k.clone().unwrap_ready(), rcpt))
            }
        })
        .collect::<std::collections::HashMap<_, _>>();

    if transports.is_empty() {
        tracing::warn!("No recipients to send to.");
        return SenderOutcome::MoveToDead;
    }

    let message_content = message_body.inner().to_string();
    let message_bytes = message_content.as_bytes();

    let futures = transports.into_iter().map(|(transport, to)| {
        alloc::sync::Arc::clone(&transport)
            .deliver(message_ctx, to, message_bytes)
            .map(|r| (WrapperSerde::Ready(transport), r))
    });

    message_ctx.rcpt_to.delivery = futures_util::future::join_all(futures)
        .await
        .into_iter()
        .collect::<std::collections::HashMap<_, _>>();

    tracing::debug!(rcpt = ?message_ctx.rcpt_to.delivery
        .values().collect::<Vec<_>>(), "Sending.");
    tracing::trace!(rcpt = ?message_ctx.rcpt_to.delivery);

    if message_ctx.rcpt_to.delivery.is_empty() {
        tracing::warn!("No recipients to send to, or all transfer method are set to none.");
        return SenderOutcome::MoveToDead;
    }

    if message_ctx
        .rcpt_to
        .delivery
        .values()
        .flatten()
        .all(|(_, status)| matches!(status, Status::Sent { .. }))
    {
        tracing::info!("Send operation successful.");
        return SenderOutcome::RemoveFromDisk;
    }

    if message_ctx
        .rcpt_to
        .delivery
        .values()
        .flatten()
        .all(|(_, status)| !status.is_sendable())
    {
        tracing::warn!("No more sendable recipients.");
        return SenderOutcome::MoveToDead;
    }

    for rcpt in &mut message_ctx.rcpt_to.delivery.values_mut().flatten() {
        if matches!(&rcpt.1, &Status::Waiting { .. }) {
            rcpt.1.held_back(TransferErrorsVariant::StillWaiting);
        }
    }

    let mut out = None;
    for rcpt in &mut message_ctx.rcpt_to.delivery.values_mut().flatten() {
        if matches!(&rcpt.1, Status::HeldBack{ errors }
            if errors.len() >= config.server.queues.delivery.deferred_retry_max)
        {
            rcpt.1 = Status::failed(TransferErrorsVariant::MaxDeferredAttemptReached);
            tracing::warn!("Delivery error count maximum reached, moving to dead.");
            out = Some(SenderOutcome::MoveToDead);
        }
    }

    let out = out.unwrap_or(SenderOutcome::MoveToDeferred);
    tracing::warn!("Some send operations failed, email {:?}.", out);
    tracing::debug!(failed = ?message_ctx
        .rcpt_to
        .delivery
        .values()
        .flatten()
        .filter(|r| !matches!(r.1, Status::Sent { .. }))
        .map(|r| (r.0.to_string(), r.1.clone()))
        .collect::<Vec<_>>()
    );

    out
}

pub struct SenderParameters {
    pub relay_target: Domain,
    pub server_name: Domain,
    pub hello_name: Domain,
    pub port: u16,
    pub certificate: Vec<rustls::Certificate>,
}

#[allow(clippy::module_name_repetitions)]
pub async fn smtp_send(
    params: SenderParameters,
    envelop: &lettre::address::Envelope,
    message: &[u8],
) -> Result<lettre::transport::smtp::response::Response, lettre::transport::smtp::Error> {
    let builder = lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous(
        params.relay_target.to_string(),
    )
    .port(params.port)
    .hello_name(lettre::transport::smtp::extension::ClientId::Domain(
        params.hello_name.to_string(),
    ));

    // NOTE: there is no way to build `lettre::transport::smtp::client::Certificate` from `Vec<rustls::Certificate>`.
    // rustls::Certificate => PEM => lettre::transport::smtp::client::Certificate => rustls::Certificate
    let certs = params
        .certificate
        .iter()
        .map(|c| {
            pem::encode(&pem::Pem {
                tag: "CERTIFICATE".to_owned(),
                contents: c.0.clone(),
            })
        })
        .flat_map(|c| c.as_bytes().to_vec())
        .collect::<Vec<_>>();

    let builder = builder.tls(lettre::transport::smtp::client::Tls::Required(
        lettre::transport::smtp::client::TlsParameters::builder(params.server_name.to_string())
            .add_root_certificate(lettre::transport::smtp::client::Certificate::from_pem(
                &certs,
            )?)
            .build()?,
    ));

    let transport = builder.build();

    lettre::AsyncTransport::send_raw(&transport, envelop, message).await
}
