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

use crate::{Receiver, ReceiverHandler};
use tokio::io::AsyncWriteExt;
use tokio_stream::StreamExt;
use vsmtp_common::auth::Mechanism;

///
#[repr(transparent)]
#[allow(clippy::exhaustive_structs)]
pub struct CallbackWrap(pub Box<dyn rsasl::callback::SessionCallback + Send + Sync>);

// #[allow(clippy::missing_trait_methods)] // rustc 1.66
impl rsasl::callback::SessionCallback for CallbackWrap {
    #[inline]
    fn callback(
        &self,
        session_data: &rsasl::callback::SessionData,
        context: &rsasl::callback::Context<'_>,
        request: &mut rsasl::callback::Request<'_>,
    ) -> Result<(), rsasl::prelude::SessionError> {
        self.0.callback(session_data, context, request)
    }

    #[inline]
    fn validate(
        &self,
        session_data: &rsasl::callback::SessionData,
        context: &rsasl::callback::Context<'_>,
        validate: &mut rsasl::validate::Validate<'_>,
    ) -> Result<(), rsasl::validate::ValidationError> {
        self.0.validate(session_data, context, validate)
    }
}

/// The possible outcomes of a SMTP-SASL handshake.
#[derive(Debug, thiserror::Error)]
#[allow(clippy::exhaustive_enums)]
pub enum AuthError {
    /// [`Verb::Auth`](crate::Verb::Auth) contains an initial buffer where the mechanism is not supposed to.
    #[error("client must not start with this mechanism")]
    ClientMustNotStart,
    /// The authentication has failed.
    #[error("validation failed: {0}")]
    ValidationError(Box<dyn std::error::Error + Send + Sync>),
    /// The client send `*\r\n` during the SASL handshake.
    #[error("sasl challenge cancelled by the client")]
    Canceled,
    /// The buffer sent/received during the SMTP+SASL handshake must be [`base64`] encoded.
    #[error("base64 decoding fail: {source}")]
    Base64 {
        /// Inner error.
        #[from]
        #[source]
        source: base64::DecodeError,
    },
    /// Error while reading/writing to the underlying stream.
    #[error("io error: {0}")]
    IO(#[from] std::io::Error),
    /// Other error produced by the SASL backend.
    #[error("error produced by the backend: {0}")]
    SessionError(rsasl::prelude::SessionError),
    /// Error while initializing the SASL backend.
    #[error("error while initializing the SASL backend: {0}")]
    ConfigError(#[from] rsasl::prelude::SASLError),
}

impl<
        T: ReceiverHandler + Send,
        V: rsasl::validate::Validation + Send,
        W: tokio::io::AsyncWrite + Unpin + Send,
        R: tokio::io::AsyncRead + Unpin + Send,
    > Receiver<T, V, W, R>
where
    V::Value: Send + Sync,
{
    pub(crate) async fn authenticate(
        &mut self,
        mechanism: Mechanism,
        initial_response: Option<Vec<u8>>,
    ) -> Result<(), AuthError> {
        // FIXME: rsasl+async
        macro_rules! block_on {
            ($future:expr) => {
                tokio::task::block_in_place(move || {
                    tokio::runtime::Handle::current().block_on($future)
                })
            };
        }

        struct AdapterSMTPandSASL<'writer, W: tokio::io::AsyncWrite + Unpin + Send>(&'writer mut W);

        // #[allow(clippy::missing_trait_methods)] // rustc 1.66
        impl<'writer, W: tokio::io::AsyncWrite + Unpin + Send> std::io::Write
            for AdapterSMTPandSASL<'writer, W>
        {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                block_on! { async move {
                    self.0.write_all(b"334 ").await?;
                    self.0.write_all(base64::encode(buf).as_bytes()).await?;
                    self.0.write_all(b"\r\n").await?;
                    std::io::Result::Ok(())
                }}
                .map(|_| buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                block_on! { tokio::io::AsyncWriteExt::flush(&mut self.0) }
            }
        }
        let callback = self.handler.generate_sasl_callback();

        let rsasl_config = rsasl::config::SASLConfig::builder()
            .with_default_mechanisms()
            .with_callback(callback)?;

        let sasl_server = rsasl::prelude::SASLServer::<V>::new(rsasl_config);

        let temp = mechanism.to_string();
        #[allow(clippy::expect_used)]
        let selected =
            rsasl::prelude::Mechname::parse(temp.as_bytes()).expect("mechanism is valid");
        let mut session = sasl_server.start_suggested(selected)?;

        let mut adapter = AdapterSMTPandSASL(&mut self.sink.inner);
        let challenge_stream = self.stream.as_line_stream().map(|line| {
            let l = line.map(|buffer| {
                buffer
                    .strip_suffix(b"\r\n")
                    .map(<[u8]>::to_vec)
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Line does not end with \r\n",
                        )
                    })
            });
            match l {
                Ok(Ok(l)) => Ok(l),
                Ok(Err(e)) | Err(e) => Err(e),
            }
        });
        tokio::pin!(challenge_stream);

        macro_rules! next_challenge_line {
            ($challenge_stream:expr) => {
                match challenge_stream.next().await {
                    Some(Ok(buffer)) if buffer == b"*" => return Err(AuthError::Canceled),
                    Some(Ok(buffer)) => Some(
                        base64::decode(buffer).map_err(|source| AuthError::Base64 { source })?,
                    ),
                    Some(Err(e)) => todo!("{}", e),
                    None => todo!("what happen when the client close the connection?"),
                }
            };
        }

        let mut data = match (initial_response, session.are_we_first()) {
            (None, true) => None,
            (None, false) => {
                std::io::Write::write(&mut adapter, &[])?;
                next_challenge_line!(challenge_stream)
            }
            (Some(_), true) => return Err(AuthError::ClientMustNotStart),
            (Some(data), false) => Some(base64::decode(data)?),
        };

        #[allow(clippy::wildcard_enum_match_arm)]
        while session
            .step(data.as_deref(), &mut adapter)
            .map_err(|e| match e {
                rsasl::prelude::SessionError::ValidationError(
                    rsasl::validate::ValidationError::Boxed(e),
                ) => AuthError::ValidationError(e),
                otherwise => AuthError::SessionError(otherwise),
            })?
            .is_running()
        {
            data = next_challenge_line!(challenge_stream);
        }

        #[allow(clippy::todo)]
        session.validation().map_or_else(
            || todo!("what happen when the validator return nothing ?"),
            |_v| Ok(()),
        )
    }
}
