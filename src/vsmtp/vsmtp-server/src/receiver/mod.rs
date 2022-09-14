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
use self::transaction::{Transaction, TransactionResult};
use tokio_rustls::rustls;
use vqueue::GenericQueueManager;
use vsmtp_common::{
    mail_context::{ConnectionContext, MAIL_CAPACITY},
    state::State,
    status::Status,
    CodeID, ConnectionKind,
};
use vsmtp_config::Resolvers;
use vsmtp_mail_parser::{MailParserOnFly, MessageBody, ParserOutcome, RawBody};
use vsmtp_rule_engine::RuleEngine;

mod connection;
mod io;
mod on_mail;
mod rsasl_callback;
mod rsasl_exchange;

pub use io::AbstractIO;
pub mod transaction;
pub use connection::Connection;
pub use on_mail::{MailHandler, OnMail};
pub use rsasl_callback::Callback;

#[derive(Default)]
struct NoParsing;

#[async_trait::async_trait]
impl MailParserOnFly for NoParsing {
    async fn parse<'a>(
        &'a mut self,
        mut stream: impl tokio_stream::Stream<Item = String> + Unpin + Send + 'a,
    ) -> ParserOutcome {
        let mut headers = Vec::with_capacity(20);
        let mut body = String::with_capacity(MAIL_CAPACITY);

        while let Some(line) = tokio_stream::StreamExt::next(&mut stream).await {
            if line.is_empty() {
                break;
            }
            headers.push(line);
        }

        while let Some(line) = tokio_stream::StreamExt::next(&mut stream).await {
            body.push_str(&line);
            body.push_str("\r\n");
        }

        Ok(either::Left(RawBody::new(headers, body)))
    }
}

impl<S> Connection<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + Sync + std::fmt::Debug,
{
    /// Receives the incomings mail of a connection
    ///
    /// # Errors
    ///
    /// * server failed to send a message
    /// * a transaction failed
    /// * the pre-queue processing of the mail failed
    #[tracing::instrument(name = "transaction", skip_all)]
    pub async fn receive<M>(
        &mut self,
        tls_config: Option<std::sync::Arc<rustls::ServerConfig>>,
        rule_engine: std::sync::Arc<RuleEngine>,
        resolvers: std::sync::Arc<Resolvers>,
        queue_manager: std::sync::Arc<dyn GenericQueueManager>,
        mail_handler: &mut M,
    ) -> anyhow::Result<()>
    where
        M: OnMail + Send,
    {
        if self.kind == ConnectionKind::Tunneled {
            if let Some(tls_config) = tls_config {
                return self
                    .upgrade_to_secured(
                        tls_config,
                        rule_engine,
                        resolvers,
                        queue_manager,
                        mail_handler,
                    )
                    .await;
            }
            anyhow::bail!("config ill-formed, handling a secured connection without valid config")
        }

        let mut helo_domain = None;

        self.send_code(CodeID::Greetings).await?;

        loop {
            let mut transaction = Transaction::new(
                self,
                &helo_domain,
                rule_engine.clone(),
                resolvers.clone(),
                queue_manager.clone(),
            );

            match transaction.receive(self, &helo_domain).await? {
                TransactionResult::HandshakeSMTP => {
                    tracing::info!("SMTP handshake initiated.");

                    self.send_code(CodeID::DataStart).await?;

                    if !self
                        .handle_stream(
                            mail_handler,
                            transaction,
                            &mut helo_domain,
                            queue_manager.clone(),
                        )
                        .await?
                    {
                        return Ok(());
                    }
                }
                TransactionResult::HandshakeTLS => {
                    tracing::debug!("TLS handshake initiated");

                    if let Some(tls_config) = tls_config {
                        return self
                            .upgrade_to_secured(
                                tls_config,
                                rule_engine,
                                resolvers,
                                queue_manager,
                                mail_handler,
                            )
                            .await;
                    }
                    self.send_code(CodeID::TlsNotAvailable).await?;
                    anyhow::bail!("{:?}", CodeID::TlsNotAvailable)
                }
                TransactionResult::HandshakeSASL(helo_pre_auth, mechanism, initial_response) => {
                    tracing::debug!("SASL handshake initiated");

                    if let Some(auth_config) = &self.config.server.smtp.auth {
                        self.handle_auth(
                            auth_config.clone(),
                            rule_engine.clone(),
                            resolvers.clone(),
                            queue_manager.clone(),
                            &mut helo_domain,
                            (mechanism, initial_response),
                            helo_pre_auth,
                        )
                        .await?;
                    } else {
                        self.send_code(CodeID::Unimplemented).await?;
                    }
                }
                TransactionResult::SessionEnded(code) => {
                    tracing::info!("The session just ended. (due to QUIT command or EOF)");

                    self.send_reply_or_code(code).await?;
                    return Ok(());
                }
            }
        }
    }

    // NOTE: the implementation of `receive` and `receive_secured` are very similar,
    // but need to be distinct (and thus not called in a recursion fashion) because of
    // `rustc --explain E0275`
    #[tracing::instrument(parent = None, name = "receive secured transaction", skip_all)]
    async fn receive_secured<M>(
        &mut self,
        rule_engine: std::sync::Arc<RuleEngine>,
        resolvers: std::sync::Arc<Resolvers>,
        queue_manager: std::sync::Arc<dyn GenericQueueManager>,
        mail_handler: &mut M,
    ) -> anyhow::Result<()>
    where
        M: OnMail + Send,
    {
        if self.kind == ConnectionKind::Tunneled {
            self.send_code(CodeID::Greetings).await?;
        }

        let mut helo_domain = None;

        loop {
            let mut transaction = Transaction::new(
                self,
                &helo_domain,
                rule_engine.clone(),
                resolvers.clone(),
                queue_manager.clone(),
            );

            match transaction.receive(self, &helo_domain).await? {
                TransactionResult::HandshakeSMTP => {
                    self.send_code(CodeID::DataStart).await?;

                    if !self
                        .handle_stream(
                            mail_handler,
                            transaction,
                            &mut helo_domain,
                            queue_manager.clone(),
                        )
                        .await?
                    {
                        return Ok(());
                    }
                }
                TransactionResult::HandshakeTLS => {
                    self.send_code(CodeID::AlreadyUnderTLS).await?;
                }
                TransactionResult::HandshakeSASL(helo_pre_auth, mechanism, initial_response) => {
                    if let Some(auth_config) = &self.config.server.smtp.auth {
                        self.handle_auth(
                            auth_config.clone(),
                            rule_engine.clone(),
                            resolvers.clone(),
                            queue_manager.clone(),
                            &mut helo_domain,
                            (mechanism, initial_response),
                            helo_pre_auth,
                        )
                        .await?;
                    } else {
                        self.send_code(CodeID::Unimplemented).await?;
                    }
                }
                TransactionResult::SessionEnded(code) => {
                    self.send_reply_or_code(code).await?;
                    return Ok(());
                }
            }
        }
    }

    async fn upgrade_to_secured<M>(
        &mut self,
        tls_config: std::sync::Arc<rustls::ServerConfig>,
        rule_engine: std::sync::Arc<RuleEngine>,
        resolvers: std::sync::Arc<Resolvers>,
        queue_manager: std::sync::Arc<dyn GenericQueueManager>,
        mail_handler: &mut M,
    ) -> anyhow::Result<()>
    where
        M: OnMail + Send,
    {
        let mut secured_conn = {
            if self.kind != ConnectionKind::Tunneled {
                self.send_code(CodeID::TlsGoAhead).await?;
            }

            let smtps_config = self.config.server.tls.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "server accepted tls encrypted transaction, but not tls config provided"
                )
            })?;
            let acceptor = tokio_rustls::TlsAcceptor::from(tls_config.clone());

            let stream = tokio::time::timeout(
                smtps_config.handshake_timeout,
                acceptor.accept(&mut self.inner.inner),
            )
            .await??;

            Connection {
                kind: self.kind,
                context: ConnectionContext {
                    server_name: stream
                        .get_ref()
                        .1
                        .sni_hostname()
                        .unwrap_or(&self.context.server_name)
                        .to_string(),
                    is_secured: true,
                    ..self.context.clone()
                },
                config: self.config.clone(),
                inner: AbstractIO::new(stream),
            }
        };

        secured_conn
            .receive_secured(rule_engine, resolvers, queue_manager, mail_handler)
            .await
    }

    async fn handle_stream<M>(
        &mut self,
        mail_handler: &mut M,
        mut transaction: Transaction,
        helo_domain: &mut Option<String>,
        queue_manager: std::sync::Arc<dyn GenericQueueManager>,
    ) -> anyhow::Result<bool>
    where
        M: OnMail + Send,
    {
        // fetching the email using the transaction's stream.
        {
            tracing::info!("SMTP handshake completed, fetching email.");
            let mut body = {
                let stream = Transaction::stream(self);
                tokio::pin!(stream);
                NoParsing::default().parse(stream).await?
            };

            let handle = transaction.rule_state.message();
            let mut message = handle.write().unwrap();

            // Headers could have been added to the email before preq,
            // so we start by prepending them to the headers received.
            let preq_headers = message.inner().headers_lines();

            match &mut body {
                either::Left(raw) => raw.prepend_header(preq_headers.map(str::to_string)),
                either::Right(parsed) => {
                    parsed.prepend_headers(preq_headers.filter_map(|s| {
                        s.split_once(':')
                            .map(|(key, value)| (key.to_string(), value.to_string()))
                    }));
                }
            };

            *message = MessageBody::from(body);
        }

        let status = transaction
            .rule_engine
            .run_when(&mut transaction.rule_state, State::PreQ);

        match status {
            Status::Info(packet) => {
                self.send_reply_or_code(packet).await?;
                return Ok(true);
            }
            Status::Deny(packet) => {
                self.send_reply_or_code(packet).await?;
                return Ok(false);
            }
            _ => (),
        }

        {
            let mail_context = transaction.rule_state.context();
            let mut state_writer = mail_context.write().unwrap();
            state_writer.metadata.skipped = transaction.rule_state.skipped().cloned();
        }

        let (mail_context, message, _) = transaction.rule_state.take().unwrap();

        let helo = mail_context.envelop.helo.clone();
        let code = mail_handler
            .on_mail(self, Box::new(mail_context), message, queue_manager)
            .await;
        *helo_domain = Some(helo);
        self.send_code(code).await?;

        Ok(true)
    }
}
