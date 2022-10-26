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
use super::Transport;
use crate::{to_lettre_envelope, Sender, SenderParameters};
use trust_dns_resolver::TokioAsyncResolver;
use vsmtp_common::{
    mail_context::{Finished, MailContext},
    rcpt::Rcpt,
    transfer::{EmailTransferStatus, ForwardTarget, TransferErrorsVariant},
    Address, SMTP_PORT,
};
use vsmtp_config::Config;
extern crate alloc;

/// the email will be directly delivered to the server, **without** mx lookup.
pub struct Forward<'resolver> {
    to: ForwardTarget,
    resolver: &'resolver TokioAsyncResolver,
    senders: alloc::sync::Arc<Sender>,
}

impl<'resolver> Forward<'resolver> {
    /// create a new deliver with a resolver to get data from the distant dns server.
    #[must_use]
    #[inline]
    pub const fn new(
        to: ForwardTarget,
        resolver: &'resolver TokioAsyncResolver,
        senders: alloc::sync::Arc<Sender>,
    ) -> Self {
        Self {
            to,
            resolver,
            senders,
        }
    }
}

impl Forward<'_> {
    async fn reverse_lookup(
        &self,
        query: &std::net::IpAddr,
    ) -> Result<Option<String>, trust_dns_resolver::error::ResolveError> {
        Ok(self
            .resolver
            .reverse_lookup(*query)
            .await?
            .into_iter()
            .next()
            .map(|s| s.to_string()))

        //            .ok_or_else(|| anyhow::anyhow!("no domain found for {query}"))
        //
    }

    async fn deliver_inner(
        &mut self,
        ctx: &MailContext<Finished>,
        from: &Address,
        to: &[Rcpt],
        message: &str,
    ) -> Result<lettre::transport::smtp::response::Response, TransferErrorsVariant> {
        let envelop = to_lettre_envelope(from, to).map_err(|e| {
            tracing::error!("{}", e.to_string());
            TransferErrorsVariant::EnvelopIllFormed {
                reverse_path: from.clone(),
                forward_paths: to.to_vec(),
            }
        })?;

        tracing::debug!(?self.to, "Forwarding email.");

        // if the domain is unknown, we ask the dns to get it (tls parameters required the domain).
        let (server, port) = match self.to {
            ForwardTarget::Domain(ref domain) => (domain.clone(), None),
            ForwardTarget::Ip(ref ip) => (
                self.reverse_lookup(ip)
                    .await
                    .map_err(|e| TransferErrorsVariant::DnsRecord {
                        error: e.to_string(),
                    })?
                    .ok_or_else(|| TransferErrorsVariant::DnsRecord {
                        error: format!("no domain found for {ip}"),
                    })?,
                None,
            ),
            ForwardTarget::Socket(ref socket) => (
                self.reverse_lookup(&socket.ip())
                    .await
                    .map_err(|e| TransferErrorsVariant::DnsRecord {
                        error: e.to_string(),
                    })?
                    .ok_or_else(|| TransferErrorsVariant::DnsRecord {
                        error: format!("no domain found for {ip}", ip = socket.ip()),
                    })?,
                Some(socket.port()),
            ),
        };

        self.senders
            .send(
                &SenderParameters {
                    server,
                    hello_name: ctx.server_name().to_owned(),
                    pool_idle_timeout: core::time::Duration::from_secs(60),
                    pool_max_size: 3,
                    pool_min_idle: 1,
                    port: port.unwrap_or(SMTP_PORT),
                },
                &envelop,
                message.as_bytes(),
            )
            .await
            .map_err(|e| TransferErrorsVariant::Smtp {
                error: e.to_string(),
            })
    }
}

#[async_trait::async_trait]
impl Transport for Forward<'_> {
    #[tracing::instrument(name = "forward", skip_all)]
    async fn deliver(
        mut self,
        _: &Config,
        ctx: &MailContext<Finished>,
        from: &Address,
        mut to: Vec<Rcpt>,
        message: &str,
    ) -> Vec<Rcpt> {
        match self.deliver_inner(ctx, from, &to, message).await {
            Ok(code) => {
                tracing::info!("Email delivered.");
                tracing::debug!(?code);

                for i in &mut to {
                    i.email_status = EmailTransferStatus::sent();
                }
            }
            Err(error) => {
                tracing::error!(%error, "Email delivery failure.");

                let is_permanent = error.is_permanent();

                for i in &mut to {
                    if is_permanent {
                        i.email_status = EmailTransferStatus::failed(error.clone());
                    } else {
                        i.email_status.held_back(error.clone());
                    }
                }
            }
        }
        to
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{transport::Transport, Sender};
    use trust_dns_resolver::TokioAsyncResolver;
    use vsmtp_common::{
        rcpt::Rcpt,
        transfer::{EmailTransferStatus, ForwardTarget, Transfer, TransferErrorsVariant},
    };
    use vsmtp_test::config::{local_ctx, local_msg, local_test};

    #[test_log::test(tokio::test)]
    async fn forward() {
        let config = local_test();
        let ctx = local_ctx();
        let msg = local_msg();

        let target = ForwardTarget::Socket("127.0.0.1:9999".parse().unwrap());

        let updated_rcpt = Forward::new(
            target.clone(),
            &TokioAsyncResolver::tokio_from_system_conf().unwrap(),
            alloc::sync::Arc::new(Sender::default()),
        )
        .deliver(
            &config,
            &ctx,
            &"root@localhost".parse().unwrap(),
            vec![Rcpt {
                address: "root@localhost".parse().unwrap(),
                transfer_method: Transfer::Forward(target),
                email_status: EmailTransferStatus::default(),
            }],
            &msg.inner().to_string(),
        )
        .await;

        #[allow(clippy::wildcard_enum_match_arm)]
        match &updated_rcpt.first().unwrap().email_status {
            &EmailTransferStatus::HeldBack { ref errors } => assert_eq!(
                errors.first().unwrap().variant,
                TransferErrorsVariant::Smtp {
                    error: "fail to send email".to_owned()
                }
            ),
            _ => panic!(),
        }
    }
}
