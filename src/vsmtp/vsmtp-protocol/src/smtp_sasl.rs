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

use tokio::io::AsyncWriteExt;
use tokio_stream::StreamExt;
use vsmtp_common::auth::Mechanism;

use crate::{Receiver, ReceiverHandler};

/// The possible outcomes of a SMTP-SASL handshake.
#[derive(Debug, thiserror::Error)]
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
        #[source]
        source: base64::DecodeError,
    },
    /// Other error produced by the SASL backend.
    #[error("error produced by the backend: {0}")]
    SessionError(rsasl::prelude::SessionError),
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

        struct AdapterSMTPandSASL<'a, W: tokio::io::AsyncWrite + Unpin + Send>(&'a mut W);

        impl<'a, W: tokio::io::AsyncWrite + Unpin + Send> std::io::Write for AdapterSMTPandSASL<'a, W> {
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
            .with_defaults()
            .with_callback(callback)
            .unwrap();

        let sasl_server = rsasl::prelude::SASLServer::<V>::new(rsasl_config);

        let temp = mechanism.to_string();
        let selected = rsasl::prelude::Mechname::parse(temp.as_bytes()).unwrap();
        let mut session = sasl_server.start_suggested(selected).unwrap();

        let mut adapter = AdapterSMTPandSASL(&mut self.sink.inner);
        let challenge_stream = self.stream.as_line_stream().map(|l| {
            let l = l.map(|l| {
                #[allow(clippy::redundant_closure_for_method_calls)]
                l.strip_suffix(b"\r\n").map(|l| l.to_vec()).ok_or_else(|| {
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
                std::io::Write::write(&mut adapter, &[]).unwrap();
                next_challenge_line!(challenge_stream)
            }
            (Some(_), true) => return Err(AuthError::ClientMustNotStart),
            (Some(data), false) => {
                Some(base64::decode(data).map_err(|source| AuthError::Base64 { source })?)
            }
        };

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

        session.validation().map_or_else(
            || todo!("what happen when the validator return nothing ?"),
            |_v| Ok(()),
        )
    }
}
