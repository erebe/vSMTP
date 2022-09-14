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

use super::Connection;
use super::{rsasl_callback::ValidationVSL, Callback};
use vqueue::GenericQueueManager;
use vsmtp_common::{auth::Mechanism, mail_context::ConnectionContext, CodeID};
use vsmtp_config::{field::FieldServerSMTPAuth, Resolvers};
use vsmtp_rule_engine::RuleEngine;

#[allow(clippy::module_name_repetitions)]
#[must_use]
#[derive(thiserror::Error, Debug)]
enum Error {
    #[error("authentication failed: {0}")]
    Failed(rsasl::prelude::SessionError),
    #[error("authentication cancelled")]
    Canceled,
    #[error("authentication timeout")]
    Timeout(std::io::Error),
    #[error("base64 decoding error")]
    InvalidBase64(base64::DecodeError),
    #[error("error while sending a response: `{0}`")]
    SendingResponse(anyhow::Error),
    #[error("error while reading message: `{0}`")]
    ReadingMessage(std::io::Error),
    #[error("SASL error: `{0}`")]
    BackendError(rsasl::prelude::SASLError),
    #[error("mechanism `{0}` must be used in encrypted connection")]
    AuthMechanismMustBeEncrypted(Mechanism),
    #[error("client started the authentication but server did not send any challenge: `{0}`")]
    AuthClientMustNotStart(Mechanism),
}

const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

struct Writer<'a, S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
{
    conn: &'a mut Connection<S>,
}

macro_rules! await_ {
    ($future:expr) => {
        tokio::task::block_in_place(move || tokio::runtime::Handle::current().block_on($future))
    };
}

impl<'a, S> std::io::Write for Writer<'a, S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        use tokio::io::AsyncWriteExt;
        await_! { async move {
            self.conn.inner.inner.write_all(b"334 ").await?;
            self.conn
                .inner
                .inner
                .write_all(base64::encode(buf).as_bytes())
                .await?;
            self.conn.inner.inner.write_all(b"\r\n").await?;
            std::io::Result::Ok(())
        }}
        .map(|_| buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        await_! {
            tokio::io::AsyncWriteExt::flush(&mut self.conn.inner.inner)
        }
    }
}

impl<S> Connection<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn handle_auth(
        &mut self,
        _auth_config: FieldServerSMTPAuth,
        rule_engine: std::sync::Arc<RuleEngine>,
        resolvers: std::sync::Arc<Resolvers>,
        queue_manager: std::sync::Arc<dyn GenericQueueManager>,
        helo_domain: &mut Option<String>,
        args: (Mechanism, Option<Vec<u8>>),
        helo_pre_auth: String,
    ) -> anyhow::Result<()> {
        let rsasl_config = rsasl::config::SASLConfig::builder()
            .with_default_mechanisms()
            .with_defaults()
            .with_callback(Callback {
                rule_engine,
                resolvers,
                config: self.config.clone(),
                conn_ctx: self.context.clone(),
                queue_manager,
            })
            .map_err(|e| anyhow::anyhow!("Failed to initialize SASL config: {e}"))?;

        if let Err(error) = self.on_authentication(rsasl_config, args).await {
            tracing::warn!(%error, "SASL exchange failure.");

            match error {
                Error::Failed(e) => {
                    self.send_code(CodeID::AuthInvalidCredentials).await?;
                    anyhow::bail!("{e} - {}", CodeID::AuthInvalidCredentials)
                }
                Error::Canceled => {
                    self.context.authentication_attempt += 1;
                    *helo_domain = Some(helo_pre_auth);

                    let retries_max = self
                        .config
                        .server
                        .smtp
                        .auth
                        .as_ref()
                        .unwrap()
                        .attempt_count_max;
                    if retries_max != -1 && self.context.authentication_attempt > retries_max {
                        self.send_code(CodeID::AuthRequired).await?;
                        anyhow::bail!("Auth: Attempt max {retries_max} reached");
                    }
                    self.send_code(CodeID::AuthClientCanceled).await?;
                    Ok(())
                }
                Error::Timeout(_) => {
                    self.send_code(CodeID::Timeout).await?;
                    anyhow::bail!("{}", CodeID::Timeout)
                }
                Error::InvalidBase64(_) => {
                    self.send_code(CodeID::AuthErrorDecode64).await?;
                    Ok(())
                }
                otherwise => anyhow::bail!("{otherwise}"),
            }
        } else {
            // TODO: When a security layer takes effect
            // helo_domain = None;

            *helo_domain = Some(helo_pre_auth);
            Ok(())
        }
    }

    async fn on_authentication(
        &mut self,
        rsasl_config: std::sync::Arc<rsasl::config::SASLConfig>,
        args: (Mechanism, Option<Vec<u8>>),
    ) -> Result<(), Error> {
        // TODO: if initial data == "=" ; it mean empty ""

        let (mechanism, initial_response) = args;

        if mechanism.must_be_under_tls() && !self.context.is_secured {
            if self
                .config
                .server
                .smtp
                .auth
                .as_ref()
                .map_or(false, |auth| auth.enable_dangerous_mechanism_in_clair)
            {
                tracing::warn!(
                    %mechanism,
                    "Unsecured AUTH mechanism used on a non-encrypted connection."
                );
            } else {
                self.send_code(CodeID::AuthMechanismMustBeEncrypted)
                    .await
                    .map_err(Error::SendingResponse)?;

                return Err(Error::AuthMechanismMustBeEncrypted(mechanism));
            }
        }

        let sasl_server = rsasl::prelude::SASLServer::<ValidationVSL>::new(rsasl_config);

        let temp = mechanism.to_string();
        let selected = rsasl::prelude::Mechname::parse(temp.as_bytes()).unwrap();
        let mut session = sasl_server
            .start_suggested(selected)
            .map_err(Error::BackendError)?;

        let mut writer = Writer { conn: self };

        let data = match initial_response {
            Some(_) if !mechanism.client_first() => {
                self.send_code(CodeID::AuthClientMustNotStart)
                    .await
                    .map_err(Error::SendingResponse)?;

                return Err(Error::AuthClientMustNotStart(mechanism));
            }
            Some(buffer) => Some(buffer),
            None => None,
        };

        let mut data = if session.are_we_first() {
            None
        } else {
            match data {
                Some(data) => Some(base64::decode(data).map_err(Error::InvalidBase64)?),
                None => {
                    writer.conn.send("334 \r\n").await.unwrap();

                    match writer.conn.read(READ_TIMEOUT).await {
                        Ok(Some(buffer)) if buffer == "*" => return Err(Error::Canceled),
                        Ok(Some(buffer)) => {
                            Some(base64::decode(buffer).map_err(Error::InvalidBase64)?)
                        }
                        Err(timeout) if timeout.kind() == std::io::ErrorKind::TimedOut => {
                            return Err(Error::Timeout(timeout));
                        }
                        Ok(None) => {
                            return Err(Error::ReadingMessage(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "connection closed",
                            )))
                        }
                        Err(e) => return Err(Error::ReadingMessage(e)),
                    }
                }
            }
        };

        while {
            let (state, _) = session
                .step(data.as_deref(), &mut writer)
                .map_err(Error::Failed)?;
            state.is_running()
        } {
            data = match writer.conn.read(READ_TIMEOUT).await {
                Ok(Some(buffer)) if buffer == "*" => return Err(Error::Canceled),
                Ok(Some(buffer)) => Some(base64::decode(buffer).map_err(Error::InvalidBase64)?),
                Ok(None) | Err(_) => todo!(),
            };
        }

        match session.validation() {
            Some((conn_ctx, _skipped)) => {
                self.context = ConnectionContext {
                    is_authenticated: true,
                    ..conn_ctx
                };

                self.send_code(CodeID::AuthSucceeded)
                    .await
                    .map_err(Error::SendingResponse)?;

                Ok(())
            }
            None => todo!(),
        }
    }
}
