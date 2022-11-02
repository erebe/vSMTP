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
    transfer::{EmailTransferStatus, TransferErrorsVariant},
    Address, SMTP_PORT,
};
use vsmtp_config::Config;
extern crate alloc;

/// the email will be sent to another mail exchanger via mx record resolution & smtp.
pub struct Deliver<'resolver> {
    resolver: &'resolver TokioAsyncResolver,
    senders: alloc::sync::Arc<Sender>,
}

impl<'resolver> Deliver<'resolver> {
    /// create a new deliver with a resolver to get data from the distant dns server.
    #[must_use]
    #[inline]
    pub const fn new(
        resolver: &'resolver TokioAsyncResolver,
        senders: alloc::sync::Arc<Sender>,
    ) -> Self {
        Self { resolver, senders }
    }
}

impl Deliver<'_> {
    /// fetch mx records for a specific domain and order them by priority.
    async fn get_mx_records(
        &self,
        query: &str,
    ) -> Result<
        Vec<trust_dns_resolver::proto::rr::rdata::MX>,
        trust_dns_resolver::error::ResolveError,
    > {
        let mut records_by_priority = self
            .resolver
            .mx_lookup(query)
            .await?
            .into_iter()
            .collect::<Vec<_>>();
        records_by_priority.sort_by_key(trust_dns_resolver::proto::rr::rdata::MX::preference);
        Ok(records_by_priority)
    }

    async fn deliver_one_domain(
        &self,
        ctx: &MailContext<Finished>,
        message: &str,
        from: &Address,
        domain: String,
        mut rcpt: Vec<Rcpt>,
    ) -> Vec<Rcpt> {
        match self
            .deliver_one_domain_inner(ctx, message, from, &domain, &rcpt)
            .await
        {
            Ok(()) => {
                for i in &mut rcpt {
                    i.email_status = EmailTransferStatus::sent();
                }
                rcpt
            }
            Err(error) => {
                tracing::warn!(?error);

                tracing::trace!(rcpt = ?rcpt.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(), sender = %from.full(), %domain);

                let is_permanent = error.is_permanent();

                for i in &mut rcpt {
                    if is_permanent {
                        i.email_status = EmailTransferStatus::failed(error.clone());
                    } else {
                        i.email_status.held_back(error.clone());
                    }
                }

                rcpt
            }
        }
    }

    async fn deliver_one_domain_inner(
        &self,
        ctx: &MailContext<Finished>,
        message: &str,
        from: &Address,
        domain: &str,
        rcpt: &[Rcpt],
    ) -> Result<(), TransferErrorsVariant> {
        let envelop = to_lettre_envelope(from, rcpt).map_err(|e| {
            tracing::error!("{}", e.to_string());
            TransferErrorsVariant::EnvelopIllFormed {
                reverse_path: from.clone(),
                forward_paths: rcpt.to_vec(),
            }
        })?;
        tracing::trace!(?envelop);

        let records =
            self.get_mx_records(domain)
                .await
                .map_err(|e| TransferErrorsVariant::DnsRecord {
                    error: e.to_string(),
                })?;
        tracing::trace!(?records);

        if records.is_empty() {
            // using directly the AAAA record instead of an mx record.
            // see https://www.rfc-editor.org/rfc/rfc5321#section-5.1
            tracing::warn!("empty set of MX records found for '{domain}'");

            self.senders
                .send(
                    &SenderParameters {
                        server: domain.to_owned(),
                        hello_name: ctx.server_name().to_owned(),
                        pool_idle_timeout: core::time::Duration::from_secs(60),
                        pool_max_size: 3,
                        pool_min_idle: 1,
                        port: SMTP_PORT,
                    },
                    &envelop,
                    message.as_bytes(),
                )
                .await
                .map_err(|e| TransferErrorsVariant::Smtp {
                    error: e.to_string(),
                })?;
            return Ok(());
        }

        let hosts = records
            .into_iter()
            .map(|r| r.exchange().to_string())
            .collect::<Vec<_>>();

        for host in &hosts {
            tracing::debug!("Trying to send an email.");
            tracing::trace!(%host);

            // checking for a null mx record.
            // see https://datatracker.ietf.org/doc/html/rfc7505
            if host == "." {
                tracing::error!(
                    "Trying to deliver to '{domain}', but a null mx record was found. '{domain}' does not want to receive messages."
                );

                return Err(TransferErrorsVariant::HasNullMX {
                    domain: domain.to_owned(),
                });
            }

            match self
                .senders
                .send(
                    &SenderParameters {
                        server: host.to_string(),
                        hello_name: ctx.server_name().to_owned(),
                        pool_idle_timeout: core::time::Duration::from_secs(60),
                        pool_max_size: 3,
                        pool_min_idle: 1,
                        port: SMTP_PORT,
                    },
                    &envelop,
                    message.as_bytes(),
                )
                .await
            {
                Ok(response) => {
                    tracing::info!("Email sent successfully");
                    tracing::trace!(%host, sender = %from, ?envelop, ?response);

                    return Ok(());
                }
                Err(err) => {
                    tracing::error!("failed to send message from '{from}' to '{host}': {err}");
                }
            }
        }

        Err(TransferErrorsVariant::DeliveryError { targets: hosts })
    }
}

#[async_trait::async_trait]
impl Transport for Deliver<'_> {
    #[inline]
    async fn deliver(
        self,
        _: &Config,
        ctx: &MailContext<Finished>,
        from: &vsmtp_common::Address,
        to: Vec<Rcpt>,
        message: &str,
    ) -> Vec<Rcpt> {
        let mut rcpt_by_domain = std::collections::HashMap::<String, Vec<Rcpt>>::new();
        for rcpt in to {
            rcpt_by_domain
                .entry(rcpt.address.domain().to_owned())
                .and_modify(|domain| domain.push(rcpt.clone()))
                .or_insert_with(|| vec![rcpt.clone()]);
        }

        let futures = rcpt_by_domain
            .into_iter()
            .map(|(domain, rcpt)| self.deliver_one_domain(ctx, message, from, domain, rcpt));

        futures_util::future::join_all(futures)
            .await
            .into_iter()
            .flatten()
            .collect()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        transport::{deliver::Deliver, Transport},
        Sender,
    };
    use trust_dns_resolver::{
        config::{ResolverConfig, ResolverOpts},
        TokioAsyncResolver,
    };
    use vsmtp_common::{
        rcpt::{Rcpt, TransactionType},
        transfer::{EmailTransferStatus, Transfer, TransferErrorsVariant},
    };
    use vsmtp_test::config::{local_ctx, local_msg, local_test};

    /*
    #[tokio::test]
    async fn test_get_mx_records() {
        // FIXME: find a way to guarantee that the mx records exists.
        let mut config = Config::default();
        config.server.dns = FieldServerDNS::System;
        let resolvers = vsmtp_config::build_resolvers(&config).unwrap();
        let deliver = Deliver::new(resolvers.get(&config.server.domain).unwrap());

        deliver
            .get_mx_records("google.com")
            .await
            .expect("couldn't find any mx records for google.com");

        assert!(deliver.get_mx_records("invalid_query").await.is_err());
    }
    */

    #[test_log::test(tokio::test)]
    async fn test_delivery() {
        let config = local_test();
        let ctx = local_ctx();
        let msg = local_msg();

        let updated_rcpt = Deliver::new(
            &TokioAsyncResolver::tokio(ResolverConfig::google(), ResolverOpts::default()).unwrap(),
            alloc::sync::Arc::new(Sender::default()),
        )
        .deliver(
            &config,
            &ctx,
            &"root@foo.bar".parse().unwrap(),
            vec![Rcpt {
                address: "root@foo.bar".parse().unwrap(),
                transfer_method: Transfer::Deliver,
                email_status: EmailTransferStatus::default(),
                transaction_type: TransactionType::default(),
            }],
            &msg.inner().to_string(),
        )
        .await;

        #[allow(clippy::wildcard_enum_match_arm)]
        match &updated_rcpt.first().unwrap().email_status {
            &EmailTransferStatus::HeldBack { ref errors } => assert_eq!(
                errors.first().unwrap().variant,
                TransferErrorsVariant::DnsRecord {
                    error: "no record found for Query { name: Name(\"foo.bar.\"), query_type: MX, query_class: IN }".to_owned(),
                }
            ),
            _ => panic!(),
        }
    }
}
