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
    sink::Sink,
    stream::{Error, Stream},
    AcceptArgs, AuthArgs, ConnectionKind, EhloArgs, HeloArgs, MailFromArgs, ParseArgsError,
    RcptToArgs, ReceiverHandler, Verb,
};
use tokio_rustls::rustls;
use tokio_stream::StreamExt;
use vsmtp_common::{auth::Mechanism, Stage};
extern crate alloc;

enum HandshakeOutcome {
    Message,
    UpgradeTLS {
        config: alloc::sync::Arc<rustls::ServerConfig>,
        handshake_timeout: std::time::Duration,
    },
    Authenticate {
        mechanism: Mechanism,
        initial_response: Option<Vec<u8>>,
    },
    Quit,
}

pub struct ErrorCounter {
    pub error_count: i64,
    pub threshold_soft_error: i64,
    pub threshold_hard_error: i64,
}

/// An handle to send event from the [`ReceiverHandler`] to the [`Receiver`].
#[allow(clippy::module_name_repetitions)]
#[derive(Default)]
pub struct ReceiverContext {
    outcome: Option<HandshakeOutcome>,
}

impl ReceiverContext {
    /// Make the [`Receiver`] quit the connection early, and close cleanly.
    #[inline]
    pub fn deny(&mut self) {
        self.outcome = Some(HandshakeOutcome::Quit);
    }

    /// Make the [`Receiver`] initialize a TLS handshake.
    #[inline]
    pub fn upgrade_tls(
        &mut self,
        config: alloc::sync::Arc<rustls::ServerConfig>,
        handshake_timeout: std::time::Duration,
    ) {
        self.outcome = Some(HandshakeOutcome::UpgradeTLS {
            config,
            handshake_timeout,
        });
    }

    /// Make the [`Receiver`] initialize a SASL handshake.
    #[inline]
    pub fn authenticate(&mut self, mechanism: Mechanism, initial_response: Option<Vec<u8>>) {
        self.outcome = Some(HandshakeOutcome::Authenticate {
            mechanism,
            initial_response,
        });
    }
}

/// A SMTP receiver.
pub struct Receiver<
    T: ReceiverHandler + Send,
    V: rsasl::validate::Validation + Send,
    W: tokio::io::AsyncWrite + Unpin + Send,
    R: tokio::io::AsyncRead + Unpin + Send,
> where
    V::Value: Send + Sync,
{
    pub(crate) handler: T,
    pub(crate) sink: Sink<W>,
    pub(crate) stream: Stream<R>,
    error_counter: ErrorCounter,
    context: ReceiverContext,
    kind: ConnectionKind,
    message_size_max: usize,
    v: std::marker::PhantomData<V>,
}

impl<T: ReceiverHandler + Send, V: rsasl::validate::Validation + Send>
    Receiver<T, V, tokio::net::tcp::OwnedWriteHalf, tokio::net::tcp::OwnedReadHalf>
where
    V::Value: Send + Sync,
{
    fn upgrade_tls(
        self,
        config: alloc::sync::Arc<rustls::ServerConfig>,
        handshake_timeout: std::time::Duration,
    ) -> impl tokio_stream::Stream<Item = std::io::Result<()>> {
        async_stream::try_stream! {
            let tcp_stream = self
                .sink
                .inner
                .reunite(self.stream.inner)
                .expect("valid stream/sink pair");

            let acceptor = tokio_rustls::TlsAcceptor::from(config);

            let tls_tcp_stream = tokio::time::timeout(
                handshake_timeout,
                acceptor.accept(tcp_stream),
            )
            .await??;

            let tls_config = tls_tcp_stream.get_ref().1.clone();
            let sni = tls_config.sni_hostname().map(str::to_string);

            let protocol_version = tls_config.protocol_version()
                .expect("tls handshake completed").clone();
            let negotiated_cipher_suite = tls_config.negotiated_cipher_suite()
                .expect("tls handshake completed").clone();
            let peer_certificates = tls_config. peer_certificates()
                .map(<[rustls::Certificate]>::to_vec);
            let alpn_protocol = tls_config.alpn_protocol()
                .map(<[u8]>::to_vec)
                .clone();

            // FIXME: see https://github.com/tokio-rs/tls/issues/40
            let (read, write) = tokio::io::split(tls_tcp_stream);

            let (stream, sink) = (Stream::new(read), Sink::new(write));

            let secured_receiver = Receiver {
                sink,
                stream,
                context: ReceiverContext { outcome: None },
                handler: self.handler,
                error_counter: self.error_counter,
                kind: self.kind,
                message_size_max: self.message_size_max,
                v: self.v,
            }.into_secured_stream(
                sni,
                protocol_version,
                negotiated_cipher_suite,
                peer_certificates,
                alpn_protocol
            );

            for await i in secured_receiver {
                yield i?;
            }
        }
    }

    /// Create a new [`Receiver`] from a TCP/IP stream.
    #[inline]
    pub fn new(
        tcp_stream: tokio::net::TcpStream,
        kind: ConnectionKind,
        handler: T,
        threshold_soft_error: i64,
        threshold_hard_error: i64,
        message_size_max: usize,
    ) -> Self {
        let (read, write) = tcp_stream.into_split();
        let (stream, sink) = (Stream::new(read), Sink::new(write));
        Self {
            handler,
            sink,
            stream,
            error_counter: ErrorCounter {
                error_count: 0,
                threshold_soft_error,
                threshold_hard_error,
            },
            context: ReceiverContext { outcome: None },
            kind,
            message_size_max,
            v: std::marker::PhantomData,
        }
    }

    /// Handle the inner stream to produce a [`tokio_stream::Stream`], each item
    /// being a successful SMTP transaction.
    #[inline]
    pub fn into_stream(
        mut self,
        client_addr: std::net::SocketAddr,
        server_addr: std::net::SocketAddr,
        timestamp: time::OffsetDateTime,
        uuid: uuid::Uuid,
    ) -> impl tokio_stream::Stream<Item = std::io::Result<()>> {
        async_stream::try_stream! {
            let reply_accept = self.handler.on_accept(
                &mut self.context,
                AcceptArgs {
                    client_addr,
                    server_addr,
                    kind: self.kind,
                    timestamp,
                    uuid,
                }
            ).await;

            let produced_context_accept = std::mem::take(&mut self.context);
            if let Some(outcome) = produced_context_accept.outcome {
                match outcome {
                    HandshakeOutcome::Message | HandshakeOutcome::Authenticate { .. } => todo!(),
                    HandshakeOutcome::UpgradeTLS { config, handshake_timeout } => {
                        for await i in self.upgrade_tls(config, handshake_timeout) {
                            yield i?;
                        }
                        return;
                    }
                    HandshakeOutcome::Quit => return,
                }
            }

            self.sink
                .send_reply(&mut self.context, &mut self.error_counter, &mut self.handler, reply_accept)
                .await?;

            loop {
                match self.smtp_handshake().await? {
                    HandshakeOutcome::Message => {
                        let message_stream = self.stream.as_message_stream(self.message_size_max).fuse();
                        tokio::pin!(message_stream);

                        let reply = self.handler.on_message(&mut self.context, message_stream).await;
                        self.sink
                            .send_reply(&mut self.context, &mut self.error_counter, &mut self.handler, reply)
                            .await?;

                        yield ();
                    },
                    HandshakeOutcome::UpgradeTLS { config, handshake_timeout } => {
                        for await i in self.upgrade_tls(config, handshake_timeout) {
                            yield i?;
                        }
                        return;
                    },
                    HandshakeOutcome::Authenticate { mechanism, initial_response } => {
                        let auth_result = self.authenticate(mechanism, initial_response).await;
                        // if security layer ...

                        let reply = self.handler.on_post_auth(&mut self.context, auth_result).await;
                        self.sink
                            .send_reply(&mut self.context, &mut self.error_counter, &mut self.handler, reply)
                            .await?;

                        let produced_context = std::mem::take(&mut self.context);
                        if matches!(produced_context.outcome, Some(HandshakeOutcome::Quit)) {
                            return;
                        }

                    },
                    HandshakeOutcome::Quit => break,
                }
            }
        }
    }
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
    fn into_secured_stream(
        mut self,
        sni: Option<String>,
        protocol_version: rustls::ProtocolVersion,
        negotiated_cipher_suite: rustls::SupportedCipherSuite,
        peer_certificates: Option<Vec<rustls::Certificate>>,
        alpn_protocol: Option<Vec<u8>>,
    ) -> impl tokio_stream::Stream<Item = std::io::Result<()>> {
        async_stream::try_stream! {
            let reply_post_tls_handshake = self.handler.on_post_tls_handshake(
                sni,
                protocol_version,
                negotiated_cipher_suite.suite(),
                peer_certificates,
                alpn_protocol
            ).await;

            if self.kind == ConnectionKind::Tunneled {
                self.sink.send_reply(
                    &mut self.context,
                    &mut self.error_counter,
                    &mut self.handler,
                    reply_post_tls_handshake
                ).await?;
            }

            loop {
                match self.smtp_handshake().await? {
                    HandshakeOutcome::Message => {
                        let message_stream = self.stream.as_message_stream(self.message_size_max).fuse();
                        tokio::pin!(message_stream);

                        let reply = self.handler.on_message(&mut self.context, message_stream).await;
                        self.sink
                            .send_reply(&mut self.context, &mut self.error_counter, &mut self.handler, reply)
                            .await?;

                        yield ();
                    },
                    HandshakeOutcome::UpgradeTLS { .. } => todo!(),
                    HandshakeOutcome::Authenticate { mechanism, initial_response } => {
                        let auth_result = self.authenticate(mechanism, initial_response).await;
                        // if security layer ...

                        let reply = self.handler.on_post_auth(&mut self.context, auth_result).await;
                        self.sink
                            .send_reply(&mut self.context, &mut self.error_counter, &mut self.handler, reply)
                            .await?;

                        let produced_context = std::mem::take(&mut self.context);
                        if matches!(produced_context.outcome, Some(HandshakeOutcome::Quit)) {
                            return;
                        }

                    },
                    HandshakeOutcome::Quit => break,
                }
            }
        }
    }

    /// SMTP handshake (generate the envelope and metadata).
    ///
    /// # Returns
    ///
    /// * the `Vec<u8>` is the bytes read with the SMTP verb "DATA\r\n"
    #[allow(clippy::too_many_lines)]
    async fn smtp_handshake(&mut self) -> std::io::Result<HandshakeOutcome> {
        macro_rules! handle_args {
            ($args_output:ty, $args:expr, $on_event:tt) => {
                match <$args_output>::try_from($args) {
                    Ok(args) => self.handler.$on_event(&mut self.context, args).await,
                    Err(e) => self.handler.on_args_error(e).await,
                }
            };
            ($args_output:ty, $args:expr, Option: $on_event:tt) => {
                match <$args_output>::try_from($args) {
                    Ok(args) => self.handler.$on_event(&mut self.context, args).await,
                    Err(e) => Some(self.handler.on_args_error(e).await),
                }
            };
        }

        let command_stream = self
            .stream
            .as_command_stream()
            .timeout(std::time::Duration::from_secs(30));
        tokio::pin!(command_stream);

        loop {
            let command = match command_stream.try_next().await {
                Ok(Some(command)) => command,
                Ok(None) => return Ok(HandshakeOutcome::Quit),
                Err(e) => {
                    tracing::warn!("Closing after {} without receiving a command", e);
                    #[allow(clippy::expect_used)]
                    self.sink
                        .send_reply(
                            &mut self.context,
                            &mut self.error_counter,
                            &mut self.handler,
                            "451 Timeout - closing connection\r\n"
                                .parse()
                                .expect("valid syntax"),
                        )
                        .await?;

                    return Ok(HandshakeOutcome::Quit);
                }
            };

            let (verb, args) = match command {
                Ok(command) => command,
                Err(e) => match e {
                    Error::BufferTooLong { expected, got } => {
                        let reply = self
                            .handler
                            .on_args_error(ParseArgsError::BufferTooLong { expected, got })
                            .await;
                        self.sink
                            .send_reply(
                                &mut self.context,
                                &mut self.error_counter,
                                &mut self.handler,
                                reply,
                            )
                            .await?;
                        continue;
                    }
                    Error::Io(io) => return Err(io),
                },
            };
            tracing::trace!("<< {:?} ; {:?}", verb, std::str::from_utf8(&args.0));

            let stage = self.handler.get_stage();
            let reply = match (verb, stage) {
                (Verb::Helo, _) => Some(handle_args!(HeloArgs, args, on_helo)),
                (Verb::Ehlo, _) => Some(handle_args!(EhloArgs, args, on_ehlo)),
                (Verb::Noop, _) => Some(self.handler.on_noop().await),
                (Verb::Rset, _) => Some(self.handler.on_rset().await),
                (Verb::StartTls, Stage::Connect | Stage::Helo) => {
                    Some(self.handler.on_starttls(&mut self.context).await)
                }
                (Verb::Auth, Stage::Connect | Stage::Helo) => {
                    handle_args!(AuthArgs, args, Option: on_auth)
                }
                (Verb::MailFrom, Stage::Helo | Stage::MailFrom) => {
                    Some(handle_args!(MailFromArgs, args, on_mail_from))
                }
                (Verb::RcptTo, Stage::MailFrom | Stage::RcptTo) => {
                    Some(handle_args!(RcptToArgs, args, on_rcpt_to))
                }
                (Verb::Data, Stage::RcptTo) => {
                    self.context.outcome = Some(HandshakeOutcome::Message);
                    Some(self.handler.on_data().await)
                }
                (Verb::Quit, _) => {
                    self.context.outcome = Some(HandshakeOutcome::Quit);
                    Some(self.handler.on_quit().await)
                }
                (Verb::Help, _) => Some(self.handler.on_help(args).await),
                (Verb::Unknown, _) => Some(self.handler.on_unknown(args.0).await),
                otherwise => Some(self.handler.on_bad_sequence(otherwise).await),
            };

            if let Some(reply) = reply {
                self.sink
                    .send_reply(
                        &mut self.context,
                        &mut self.error_counter,
                        &mut self.handler,
                        reply,
                    )
                    .await?;
            }

            let produced_context = std::mem::take(&mut self.context);
            if let Some(done) = produced_context.outcome {
                return Ok(done);
            }
        }
    }
}
