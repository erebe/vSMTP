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
    get_cert_for_server,
    send::{smtp_send, SenderParameters},
    to_lettre_envelope,
};
use trust_dns_resolver::TokioAsyncResolver;
use vsmtp_common::{
    transfer::{Status, TransferErrorsVariant},
    transport::{AbstractTransport, DeliverTo},
    Address, ContextFinished, Domain, Target, SMTP_PORT,
};
use vsmtp_config::Config;
extern crate alloc;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    #[serde(with = "r#type")]
    pub(super) r#type: String,
    to: Target,
}

def_type_serde!("forward");

/// the email will be directly delivered to the server, **without** mx lookup.
#[derive(Debug, serde::Deserialize)]
pub struct Forward {
    #[serde(skip, default = "crate::dns::default")]
    resolver: alloc::sync::Arc<TokioAsyncResolver>,
    #[serde(skip)]
    config: alloc::sync::Arc<Config>,
    #[serde(flatten)]
    payload: Payload,
}

impl serde::Serialize for Forward {
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

impl Forward {
    /// create a new deliver with a resolver to get data from the distant dns server.
    #[must_use]
    #[inline]
    pub fn new(
        to: Target,
        resolver: alloc::sync::Arc<TokioAsyncResolver>,
        config: alloc::sync::Arc<Config>,
    ) -> Self {
        Self {
            resolver,
            config,
            payload: Payload {
                to,
                r#type: "forward".to_owned(),
            },
        }
    }

    async fn reverse_lookup(
        &self,
        query: &std::net::IpAddr,
    ) -> Result<Option<Domain>, trust_dns_resolver::error::ResolveError> {
        Ok(self
            .resolver
            .reverse_lookup(*query)
            .await?
            .into_iter()
            .next())
    }

    async fn deliver_inner(
        &self,
        ctx: &ContextFinished,
        from: &Option<Address>,
        to: &DeliverTo,
        message: &[u8],
    ) -> Result<lettre::transport::smtp::response::Response, TransferErrorsVariant> {
        let envelop = to_lettre_envelope(from, to.iter().map(|(rcpt, _)| rcpt));

        tracing::debug!(?self.payload.to, "Forwarding email.");

        // if the domain is unknown, we ask the dns to get it (tls parameters required the domain).
        let (server, port) = match self.payload.to {
            Target::Domain(ref domain) => (domain.clone(), None),
            Target::Ip(ref ip) => (
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
            Target::Socket(ref socket) => (
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

        smtp_send(
            SenderParameters {
                relay_target: server.clone(),
                server_name: server,
                hello_name: ctx.connect.server_name.clone(),
                port: port.unwrap_or(SMTP_PORT),
                certificate: get_cert_for_server(&ctx.connect.server_name, &self.config)
                    .ok_or(TransferErrorsVariant::TlsNoCertificate {})?,
            },
            &envelop,
            message,
        )
        .await
        .map_err(|e| TransferErrorsVariant::Smtp {
            error: e.to_string(),
        })
    }
}

impl vsmtp_common::transport::GetID for Forward {}

#[async_trait::async_trait]
impl AbstractTransport for Forward {
    #[tracing::instrument(name = "forward", skip_all)]
    async fn deliver(
        self: alloc::sync::Arc<Self>,
        ctx: &ContextFinished,
        mut to: DeliverTo,
        message: &[u8],
    ) -> DeliverTo {
        match self
            .deliver_inner(ctx, &ctx.mail_from.reverse_path, &to, message)
            .await
        {
            Ok(code) => {
                tracing::info!("Email delivered.");
                tracing::debug!(?code);

                for i in &mut to {
                    i.1 = Status::sent();
                }
            }
            Err(error) => {
                tracing::error!(%error, "Email delivery failure.");

                let is_permanent = error.is_permanent();

                for i in &mut to {
                    if is_permanent {
                        i.1 = Status::failed(error.clone());
                    } else {
                        i.1.held_back(error.clone());
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
    use trust_dns_resolver::TokioAsyncResolver;
    use vsmtp_common::{
        transfer::{Status, TransferErrorsVariant},
        transport::{AbstractTransport, WrapperSerde},
        Target,
    };
    use vsmtp_test::config::{local_ctx, local_msg, local_test, with_tls};

    #[test_log::test(tokio::test)]
    async fn forward() {
        let config = with_tls();
        let ctx = local_ctx();
        let msg = local_msg();

        let target = Target::Socket("127.0.0.1:9999".parse().unwrap());

        let transport = alloc::sync::Arc::new(Forward::new(
            target.clone(),
            alloc::sync::Arc::new(TokioAsyncResolver::tokio_from_system_conf().unwrap()),
            alloc::sync::Arc::new(config),
        ));
        let updated_rcpt = alloc::sync::Arc::clone(&transport)
            .deliver(
                &ctx,
                vec![("root@localhost".parse().unwrap(), Status::default())],
                msg.inner().to_string().as_bytes(),
            )
            .await;

        #[allow(clippy::wildcard_enum_match_arm)]
        match &updated_rcpt.first().unwrap().1 {
            Status::HeldBack { errors } => assert_eq!(
                errors.first().unwrap().variant,
                TransferErrorsVariant::TlsNoCertificate {}
            ),
            _ => panic!(),
        }
    }

    #[rstest::rstest]
    #[case(
        &serde_json::json!({
            "v": r#"{"type":"forward","to":{"Domain":"localhost"}}"#,
        }).to_string(),
        Forward::new(
            Target::Domain("localhost".parse().expect("")),
            alloc::sync::Arc::new(TokioAsyncResolver::tokio_from_system_conf().unwrap()),
            alloc::sync::Arc::new(local_test())
        )
    )]
    fn deserialize(#[case] input: &str, #[case] instance: Forward) {
        #[derive(serde::Deserialize, serde::Serialize)]
        struct S {
            v: WrapperSerde,
        }

        let delivery = serde_json::from_str::<S>(input)
            .unwrap()
            .v
            .to_ready(&[Forward::get_symbol()])
            .unwrap();

        assert_eq!(
            delivery,
            WrapperSerde::Ready(alloc::sync::Arc::new(instance))
        );

        assert_eq!(input, serde_json::to_string(&S { v: delivery }).unwrap());
    }
}
