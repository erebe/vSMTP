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
    ContextFinished, Domain, Target, SMTP_PORT, SUBMISSIONS_PORT, SUBMISSION_PORT,
};
use vsmtp_config::Config;
use vsmtp_mail_parser::MessageBody;
use vsmtp_protocol::ConnectionKind;
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

///
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    strum::AsRefStr,
    strum::Display,
    strum::EnumString,
    serde_with::DeserializeFromStr,
    serde_with::SerializeDisplay,
)]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum TlsPolicy {
    /// Do not use TLS.
    None,
    /// If the server supports STARTTLS, use it.
    #[default]
    #[strum(serialize = "opportunistic")]
    StarttlsOpportunistic,
    /// If the server no not support STARTTLS, abort.
    #[strum(serialize = "required")]
    StarttlsRequired,
    /// Use TLS right after connection.
    Tunnel,
}

const SUPPORTED_TLS_POLICY: &[TlsPolicy; 4] = &[
    TlsPolicy::None,
    TlsPolicy::StarttlsOpportunistic,
    TlsPolicy::StarttlsRequired,
    TlsPolicy::Tunnel,
];

/// Parameters to send a message.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::exhaustive_structs)]
pub struct SenderParameters {
    ///
    #[serde(default)]
    pub kind: ConnectionKind,
    ///
    #[serde(default, alias = "domain")]
    pub host: Target,
    ///
    #[serde(default)]
    pub hello_name: Option<Domain>,
    ///
    pub port: u16,
    ///
    #[serde(default)]
    pub credentials: Option<(String, String)>,
    ///
    #[serde(default)]
    pub tls: TlsPolicy,
}

#[derive(Debug, thiserror::Error)]
pub enum SenderParametersParseError {
    #[error("missing host")]
    MissingHost,

    #[error("credentials are missing with this scheme")]
    MissingCredentials,

    #[error("scheme {scheme} is not supported")]
    UnsupportedScheme { scheme: String },

    #[error("invalid value '{got}' for parameter '{parameter}'; expected: '{valid}'",
        valid = valid.join(",")
    )]
    InvalidParameters {
        got: String,
        parameter: String,
        valid: Vec<String>,
    },

    #[error("parameter '{key}'/'{value}' is not supported")]
    UnknownParameters { key: String, value: String },

    #[error("cannot specify both 'smtps://' and '?tls='")]
    TunnelOverride,

    #[error("url parse error: {0}")]
    Url(#[from] url::ParseError),
}

impl TryFrom<url::Url> for SenderParameters {
    type Error = SenderParametersParseError;

    #[allow(clippy::unwrap_in_result)]
    #[inline]
    fn try_from(value: url::Url) -> Result<Self, Self::Error> {
        // TODO: ipv6 scope is parsed ?
        #[allow(clippy::expect_used)]
        let host = match value.host() {
            Some(url::Host::Domain(domain)) => domain.to_owned().parse().expect("url ensure valid"),
            Some(url::Host::Ipv4(ip)) => ip.to_string().parse().expect("url ensure valid"),
            Some(url::Host::Ipv6(ip)) => ip.to_string().parse().expect("url ensure valid"),
            None => return Err(SenderParametersParseError::MissingHost),
        };

        let scheme = value.scheme();
        let (credentials, port, kind) = if scheme == "smtps" {
            match value.password() {
                Some(password) => (
                    Some((value.username(), password)),
                    value.port().unwrap_or(SUBMISSIONS_PORT),
                    ConnectionKind::Tunneled,
                ),
                None => return Err(SenderParametersParseError::MissingCredentials),
            }
        } else if scheme == "smtp" {
            value.password().map_or_else(
                || {
                    (
                        None,
                        value.port().unwrap_or(SMTP_PORT),
                        ConnectionKind::Relay,
                    )
                },
                |password| {
                    (
                        Some((value.username(), password)),
                        value.port().unwrap_or(SUBMISSION_PORT),
                        ConnectionKind::Submission,
                    )
                },
            )
        } else {
            return Err(SenderParametersParseError::UnsupportedScheme {
                scheme: scheme.to_owned(),
            });
        };

        let mut tls_policy = if kind == ConnectionKind::Tunneled {
            TlsPolicy::Tunnel
        } else {
            TlsPolicy::default()
        };

        for (k, v) in value.query_pairs() {
            match k {
                alloc::borrow::Cow::Borrowed("tls") => {
                    tls_policy = v.parse().map_err(|_err| {
                        SenderParametersParseError::InvalidParameters {
                            got: v.into_owned(),
                            parameter: k.into_owned(),
                            valid: SUPPORTED_TLS_POLICY
                                .iter()
                                .map(AsRef::as_ref)
                                .map(str::to_string)
                                .collect(),
                        }
                    })?;
                }
                _ => {
                    return Err(SenderParametersParseError::UnknownParameters {
                        key: k.into_owned(),
                        value: v.into_owned(),
                    })
                }
            }
        }

        if kind == ConnectionKind::Tunneled && tls_policy != TlsPolicy::Tunnel {
            return Err(SenderParametersParseError::TunnelOverride);
        }

        Ok(Self {
            host,
            hello_name: None,
            port,
            credentials: credentials.map(|(user, pass)| (user.to_owned(), pass.to_owned())),
            kind,
            tls: tls_policy,
        })
    }
}

impl core::str::FromStr for SenderParameters {
    type Err = <Self as TryFrom<url::Url>>::Error;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        <Target as core::str::FromStr>::from_str(s).map_or_else(
            |_| {
                url::Url::parse(s)
                    .map_err(Into::into)
                    .and_then(Self::try_from)
            },
            |target| Ok(Self::from(target)),
        )
    }
}

impl From<Target> for SenderParameters {
    #[inline]
    fn from(value: Target) -> Self {
        match value {
            Target::Domain(domain) => Self {
                kind: ConnectionKind::Relay,
                host: Target::Domain(domain),
                hello_name: None,
                port: SMTP_PORT,
                credentials: None,
                tls: TlsPolicy::default(),
            },
            Target::Ip(ip) => Self {
                kind: ConnectionKind::Relay,
                host: Target::Ip(ip),
                hello_name: None,
                port: SMTP_PORT,
                credentials: None,
                tls: TlsPolicy::default(),
            },
            Target::Socket(socket) => Self {
                kind: ConnectionKind::Relay,
                host: Target::Ip(socket.ip()),
                hello_name: None,
                port: socket.port(),
                credentials: None,
                tls: TlsPolicy::default(),
            },
        }
    }
}

impl SenderParameters {
    #[allow(clippy::module_name_repetitions)]
    pub(crate) async fn smtp_send(
        &self,
        hello_name: &Domain,
        envelop: &lettre::address::Envelope,
        message: &[u8],
        certificate: Option<Vec<rustls::Certificate>>,
    ) -> Result<lettre::transport::smtp::response::Response, lettre::transport::smtp::Error> {
        use lettre::transport::smtp::{
            client::{Certificate, Tls, TlsParameters},
            extension::ClientId,
        };

        let mut builder = lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous(
            self.host.to_string(),
        )
        .port(self.port)
        .hello_name(ClientId::Domain(
            self.hello_name.as_ref().unwrap_or(hello_name).to_string(),
        ));

        if matches!(
            &self.tls,
            TlsPolicy::StarttlsOpportunistic | TlsPolicy::StarttlsRequired | TlsPolicy::Tunnel
        ) {
            let mut tls_builder = TlsParameters::builder(self.host.to_string());

            // for self signed message
            if let Some(cert) = &certificate {
                // NOTE: there is no way to build `lettre::transport::smtp::client::Certificate` from `Vec<rustls::Certificate>`.
                // rustls::Certificate => PEM => lettre::transport::smtp::client::Certificate => rustls::Certificate
                let certs = cert
                    .iter()
                    .map(|c| {
                        pem::encode(&pem::Pem {
                            tag: "CERTIFICATE".to_owned(),
                            contents: c.0.clone(),
                        })
                    })
                    .flat_map(|c| c.as_bytes().to_vec())
                    .collect::<Vec<_>>();

                tls_builder = tls_builder.add_root_certificate(Certificate::from_pem(&certs)?);
            }

            let params = tls_builder.build()?;

            builder = builder.tls(match self.tls {
                TlsPolicy::StarttlsOpportunistic => Tls::Opportunistic(params),
                TlsPolicy::StarttlsRequired => Tls::Required(params),
                TlsPolicy::Tunnel => Tls::Wrapper(params),
                #[allow(clippy::unreachable)]
                TlsPolicy::None => unreachable!(),
            });
        }

        if let Some(credentials) = &self.credentials {
            builder = builder.credentials(credentials.clone().into());
        };

        let transport = builder.build();

        lettre::AsyncTransport::send_raw(&transport, envelop, message).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[rstest::rstest]
    fn parse(
        #[values("smtp", "smtps")] scheme: &str,
        #[values("localhost", "127.0.0.1")] host: &str,
        #[values(None, Some(SMTP_PORT), Some(10025))] port: Option<u16>,
        #[values(None, Some(("foo", "bar")))] credentials: Option<(&str, &str)>,
        #[values(None, Some("none"))] tls_opt: Option<&str>,
    ) {
        let mut url = match (credentials, port) {
            (Some((user, pass)), Some(port)) => {
                format!("{scheme}://{user}:{pass}@{host}:{port}")
            }
            (Some((user, pass)), None) => {
                format!("{scheme}://{user}:{pass}@{host}")
            }
            (None, Some(port)) => {
                format!("{scheme}://{host}:{port}")
            }
            (None, None) => {
                format!("{scheme}://{host}")
            }
        };

        if let Some(tls_opt) = tls_opt {
            url = format!("{url}?tls={tls_opt}");
        }

        match url.parse::<SenderParameters>() {
            Ok(params) => {
                assert_eq!(params.host, host.parse().unwrap());
                assert_eq!(
                    params.port,
                    port.unwrap_or(if scheme == "smtps" {
                        SUBMISSIONS_PORT
                    } else if credentials.is_some() {
                        SUBMISSION_PORT
                    } else {
                        SMTP_PORT
                    })
                );
                assert_eq!(
                    params.credentials,
                    credentials.map(|(user, pass)| (user.to_owned(), pass.to_owned()))
                );
            }
            Err(SenderParametersParseError::TunnelOverride)
                if scheme == "smtps" && tls_opt.is_some() => {}
            Err(SenderParametersParseError::MissingCredentials)
                if credentials.is_none() && scheme == "smtps" => {}
            Err(e) => {
                panic!("{e}");
            }
        }
    }
}
