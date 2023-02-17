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
use crate::{send::SenderParameters, to_lettre_envelope};
use trust_dns_resolver::TokioAsyncResolver;
use vsmtp_common::{
    transfer::{Status, TransferErrorsVariant},
    transport::{AbstractTransport, DeliverTo},
    Address, ContextFinished, Domain, Target,
};
use vsmtp_config::Config;
extern crate alloc;

#[allow(clippy::std_instead_of_core)]
#[allow(clippy::empty_structs_with_brackets)]
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    #[serde(with = "r#type")]
    pub(super) r#type: String,
}

def_type_serde!("deliver");

/// the email will be sent to another mail exchanger via mx record resolution & smtp.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deliver {
    #[serde(skip, default = "crate::dns::default")]
    resolver: alloc::sync::Arc<TokioAsyncResolver>,
    #[serde(skip)]
    #[allow(dead_code)]
    config: alloc::sync::Arc<Config>,
    #[serde(flatten)]
    payload: Payload,
}

impl core::fmt::Debug for Deliver {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Deliver")
            .field("resolver", &self.resolver)
            .field("payload", &self.payload)
            .finish()
    }
}

impl serde::Serialize for Deliver {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_json::to_string(&self.payload)
            .map_err(|e| serde::ser::Error::custom(format!("{e:?}")))
            .and_then(|json| serializer.serialize_str(&json))
    }
}

impl Deliver {
    /// create a new deliver with a resolver to get data from the distant dns server.
    #[must_use]
    #[inline]
    pub fn new(
        resolver: alloc::sync::Arc<TokioAsyncResolver>,
        config: alloc::sync::Arc<Config>,
    ) -> Self {
        Self {
            resolver,
            config,
            payload: Payload {
                r#type: "deliver".to_owned(),
            },
        }
    }

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
        ctx: &ContextFinished,
        message: &[u8],
        from: &Option<Address>,
        domain: Domain,
        mut rcpt: DeliverTo,
    ) -> DeliverTo {
        match self
            .deliver_one_domain_inner(ctx, message, from, &domain, &rcpt)
            .await
        {
            Ok(()) => {
                for i in &mut rcpt {
                    i.1 = Status::sent();
                }
                rcpt
            }
            Err(error) => {
                tracing::warn!(?error);

                tracing::trace!(
                    rcpt = ?rcpt.iter()
                        .map(|r| r.0.clone())
                        .collect::<Vec<_>>(),
                    sender = ?from,
                    %domain
                );

                let is_permanent = error.is_permanent();

                for i in &mut rcpt {
                    if is_permanent {
                        i.1 = Status::failed(error.clone());
                    } else {
                        i.1.held_back(error.clone());
                    }
                }

                rcpt
            }
        }
    }

    async fn deliver_one_domain_inner(
        &self,
        ctx: &ContextFinished,
        message: &[u8],
        from: &Option<Address>,
        domain: &Domain,
        rcpt: &DeliverTo,
    ) -> Result<(), TransferErrorsVariant> {
        let envelop = to_lettre_envelope(from, rcpt.iter().map(|(r, _)| r));
        tracing::trace!(?envelop);

        let records = self
            .get_mx_records(&domain.to_string())
            .await
            .map_err(|e| TransferErrorsVariant::DnsRecord {
                error: e.to_string(),
            })?;
        tracing::trace!(?records);

        if records.is_empty() {
            // using directly the AAAA record instead of an mx record.
            // see https://www.rfc-editor.org/rfc/rfc5321#section-5.1
            tracing::warn!("empty set of MX records found for '{domain}'");

            // get_cert_for_server(&ctx.connect.server_name, &self.config)
            // .ok_or(TransferErrorsVariant::TlsNoCertificate {})?,

            SenderParameters::from(Target::Domain(domain.clone()))
                .smtp_send(&ctx.connect.server_name, &envelop, message, None)
                .await
                .map_err(|e| TransferErrorsVariant::Smtp {
                    error: e.to_string(),
                })?;
            return Ok(());
        }

        let mxs = records
            .iter()
            .map(trust_dns_resolver::proto::rr::rdata::MX::exchange)
            .collect::<Vec<_>>();

        for mx in &mxs {
            tracing::debug!(%mx, "Trying to send an email.");

            // checking for a null mx record.
            // see https://datatracker.ietf.org/doc/html/rfc7505
            if mx.is_root() {
                tracing::error!(
                    "Trying to deliver to '{domain}', but a null mx record was found. '{domain}' does not want to receive messages."
                );

                return Err(TransferErrorsVariant::HasNullMX {
                    domain: domain.clone(),
                });
            }

            // get_cert_for_server(&ctx.connect.server_name, &self.config)
            // .ok_or(TransferErrorsVariant::TlsNoCertificate {})?,

            match SenderParameters::from(Target::Domain((*mx).clone()))
                .smtp_send(&ctx.connect.server_name, &envelop, message, None)
                .await
            {
                Ok(response) => {
                    tracing::info!("Email sent successfully");
                    tracing::trace!(%mx, sender = ?from, ?envelop, ?response);

                    return Ok(());
                }
                Err(err) => {
                    tracing::error!(
                        ?from,
                        ?mx,
                        %err,
                        "failed to send message"
                    );
                }
            }
        }

        Err(TransferErrorsVariant::DeliveryError {
            targets: mxs.into_iter().cloned().collect(),
        })
    }
}

impl vsmtp_common::transport::GetID for Deliver {}

#[async_trait::async_trait]
impl AbstractTransport for Deliver {
    #[inline]
    async fn deliver(
        self: alloc::sync::Arc<Self>,
        context: &ContextFinished,
        rcpt_to: DeliverTo,
        message: &[u8],
    ) -> DeliverTo {
        let mut rcpt_by_domain = std::collections::HashMap::<Domain, DeliverTo>::new();
        for i in rcpt_to {
            rcpt_by_domain
                .entry(i.0.domain())
                .and_modify(|domain| domain.push(i.clone()))
                .or_insert_with(|| vec![i]);
        }

        let futures = rcpt_by_domain.into_iter().map(|(domain, rcpt)| {
            self.deliver_one_domain(
                context,
                message,
                &context.mail_from.reverse_path,
                domain,
                rcpt,
            )
        });

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
    use crate::deliver::Deliver;
    use trust_dns_resolver::{
        config::{ResolverConfig, ResolverOpts},
        TokioAsyncResolver,
    };
    use vsmtp_common::{
        transfer::{Status, TransferErrorsVariant},
        transport::{AbstractTransport, WrapperSerde},
    };
    use vsmtp_test::config::{local_ctx, local_msg, local_test};

    #[test_log::test(tokio::test)]
    async fn test_delivery() {
        let config = local_test();
        let ctx = local_ctx();
        let msg = local_msg();

        let transport = alloc::sync::Arc::new(Deliver::new(
            alloc::sync::Arc::new(
                TokioAsyncResolver::tokio(ResolverConfig::google(), ResolverOpts::default())
                    .unwrap(),
            ),
            alloc::sync::Arc::new(config),
        ));
        let updated_rcpt = alloc::sync::Arc::clone(&transport)
            .deliver(
                &ctx,
                vec![(vsmtp_common::addr!("root@foo.bar"), Status::default())],
                msg.inner().to_string().as_bytes(),
            )
            .await;

        #[allow(clippy::wildcard_enum_match_arm)]
        match &updated_rcpt.first().unwrap().1 {
            Status::HeldBack { errors } => assert_eq!(
                errors.first().unwrap().variant,
                TransferErrorsVariant::DnsRecord {
                    error: "no record found for Query { name: Name(\"foo.bar.\"), query_type: MX, query_class: IN }".to_owned(),
                }
            ),
            _ => panic!(),
        }
    }

    #[rstest::rstest]
    #[case(
        &serde_json::json!({
            "v": r#"{"type":"deliver"}"#,
        }).to_string(),
        Deliver::new(
            alloc::sync::Arc::new(TokioAsyncResolver::tokio_from_system_conf().unwrap()),
            alloc::sync::Arc::new(local_test())
        )
    )]
    fn deserialize(#[case] input: &str, #[case] instance: Deliver) {
        #[derive(serde::Deserialize, serde::Serialize)]
        struct S {
            v: WrapperSerde,
        }

        let delivery = serde_json::from_str::<S>(input)
            .unwrap()
            .v
            .to_ready(&[Deliver::get_symbol()])
            .unwrap();

        assert_eq!(
            delivery,
            WrapperSerde::Ready(alloc::sync::Arc::new(instance))
        );

        assert_eq!(input, serde_json::to_string(&S { v: delivery }).unwrap());
    }
}
