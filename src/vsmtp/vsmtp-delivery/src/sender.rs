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

use anyhow::Context;
extern crate alloc;

///
#[allow(clippy::module_name_repetitions)]
#[non_exhaustive]
#[derive(Debug, Eq, Clone, Hash, PartialEq)]
pub struct SenderParameters {
    ///
    pub server: String,
    ///
    pub hello_name: String,
    ///
    pub pool_idle_timeout: core::time::Duration,
    ///
    pub pool_max_size: u32,
    ///
    pub pool_min_idle: u32,
    ///
    pub port: u16,
    // use_dane: bool,
    // certificate: ...
}

type SenderInner = alloc::sync::Arc<lettre::AsyncSmtpTransport<lettre::Tokio1Executor>>;

///
#[derive(Default)]
pub struct Sender {
    senders: std::sync::RwLock<std::collections::HashMap<SenderParameters, SenderInner>>,
}

impl Sender {
    /// Send a mail to the transport using the given parameters.
    /// Create a new transport if none existing.
    ///
    /// # Errors
    ///
    /// * The inner `RwLock` is poisoned.
    /// * [`lettre::AsyncTransport::send_raw()`] fails.
    #[inline]
    pub async fn send(
        &self,
        params: &SenderParameters,
        envelop: &lettre::address::Envelope,
        message: &[u8],
    ) -> anyhow::Result<lettre::transport::smtp::response::Response> {
        use lettre::AsyncTransport;

        let sender = {
            if !self
                .senders
                .read()
                .map_err(|e| anyhow::anyhow!(e.to_string()))?
                .contains_key(params)
            {
                tracing::trace!(?params, "Key no found for transport with parameters");

                let new_sender = Self::build_sender(params);
                let mut writer = self
                    .senders
                    .write()
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                writer.insert(params.clone(), new_sender);
            }

            alloc::sync::Arc::clone(
                #[allow(clippy::expect_used)]
                self.senders
                    .read()
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?
                    .get(params)
                    .expect("key added right before"),
            )
        };

        sender
            .send_raw(envelop, message)
            .await
            .context("fail to send email")
    }

    fn build_sender(params: &SenderParameters) -> SenderInner {
        tracing::trace!(?params, "Creating a transport");

        let builder = lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous(
            params.server.clone(),
        )
        .port(params.port)
        .hello_name(lettre::transport::smtp::extension::ClientId::Domain(
            params.hello_name.clone(),
        ))
        .pool_config(
            lettre::transport::smtp::PoolConfig::new()
                .idle_timeout(params.pool_idle_timeout)
                .max_size(params.pool_max_size)
                .min_idle(params.pool_min_idle),
        );

        // let builder = builder.tls(tls);

        // builder.timeout(timeout)

        alloc::sync::Arc::new(builder.build())
    }
}

/*
    fn build_transport(
        config: &Config,
        // will be used for tlsa record resolving.
        _: &TokioAsyncResolver,
        from: &vsmtp_common::Address,
        target: &str,
        port: Option<u16>,
    ) -> anyhow::Result<lettre::AsyncSmtpTransport<lettre::Tokio1Executor>> {
        let tls_builder =
            lettre::transport::smtp::client::TlsParameters::builder(target.to_string());

        // from's domain could match the root domain of the server.
        let tls_parameters =
            if config.server.name == from.domain() && config.server.tls.is_some() {
                tls_builder.add_root_certificate(
                    lettre::transport::smtp::client::Certificate::from_der(
                        config
                            .server
                            .tls
                            .as_ref()
                            .unwrap()
                            .certificate
                            .inner
                            .0
                            .clone(),
                    )
                    .context("failed to parse certificate as der")?,
                )
            }
            // or a domain from one of the virtual domains.
            else if let Some(tls_config) = config
                .server
                .r#virtual
                .get(from.domain())
                .and_then(|domain| domain.tls.as_ref())
            {
                tls_builder.add_root_certificate(
                    lettre::transport::smtp::client::Certificate::from_der(
                        tls_config.certificate.inner.0.clone(),
                    )
                    .context("failed to parse certificate as der")?,
                )
            // if not, no certificate are used.
            } else {
                tls_builder
            }
            .build()
            .context("failed to build tls parameters")?;

        Ok(
            lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous(target)
                .hello_name(lettre::transport::smtp::extension::ClientId::Domain(
                    // FIXME: should be the domain of the server.
                    from.domain().to_string(),
                ))
                .port(port.unwrap_or(lettre::transport::smtp::SMTP_PORT))
                .tls(lettre::transport::smtp::client::Tls::Opportunistic(
                    tls_parameters,
                ))
                .build(),
        )
    }

*/
