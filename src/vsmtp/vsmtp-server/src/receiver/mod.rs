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
    mail_context::{Connect, Finished, Helo, MailContext, TlsProperties},
    state::State,
    status::Status,
    CodeID, ConnectionKind,
};
use vsmtp_config::DnsResolvers;
use vsmtp_mail_parser::{BasicParser, Mail, MailParser, MessageBody, RawBody};
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
        resolvers: std::sync::Arc<DnsResolvers>,
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
            let mut transaction = Transaction::new(self, &helo_domain, rule_engine.clone());

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
        resolvers: std::sync::Arc<DnsResolvers>,
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
            let mut transaction = Transaction::new(self, &helo_domain, rule_engine.clone());

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
        resolvers: std::sync::Arc<DnsResolvers>,
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
                context: Connect {
                    server_name: stream
                        .get_ref()
                        .1
                        .sni_hostname()
                        .unwrap_or(&self.context.server_name)
                        .to_string(),
                    tls: Some(TlsProperties {}),
                    ..self.context.clone()
                },
                inner: AbstractIO::new(stream),
                config: self.config.clone(),
                error_count: self.error_count,
                authentication_attempt: self.authentication_attempt,
            }
        };

        secured_conn
            .receive_secured(rule_engine, resolvers, queue_manager, mail_handler)
            .await
    }

    #[allow(clippy::too_many_lines)]
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
            fn set_body(message: &mut MessageBody, mut body: either::Either<RawBody, Mail>) {
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

            tracing::info!("SMTP handshake completed, fetching email.");
            let body = {
                let stream = Transaction::stream(self);
                tokio::pin!(stream);
                MailParser::parse(&mut BasicParser::default(), stream).await?
            };

            let handle = transaction.rule_state.message();
            let mut message = handle.write().unwrap();

            if let Some(rule_state_internal) = &mut transaction.rule_state_internal {
                let handle_internal = rule_state_internal.message();
                let mut message_internal = handle_internal.write().unwrap();
                set_body(&mut message_internal, body.clone());
                set_body(&mut message, body);
            } else {
                set_body(&mut message, body);
            }
        }

        transaction
            .rule_state
            .context()
            .write()
            .unwrap()
            .set_state_finished()
            .unwrap();

        if let Some(state) = transaction.rule_state_internal.as_mut() {
            state
                .context()
                .write()
                .unwrap()
                .set_state_finished()
                .unwrap();
        }

        // FIXME: do not run the outgoing rule state if there are no outgoing recipients.
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
            state_writer.set_skipped(transaction.rule_state.skipped().cloned());
        }

        let code_internal = if let Some(mut state) = transaction.rule_state_internal {
            let status_internal = transaction.rule_engine.run_when(&mut state, State::PreQ);

            // NOTE: The status returned by the rule engine in an internal state
            //       takes priority over the outgoing state.
            match status_internal {
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
                let mail_context = state.context();
                let mut state_writer = mail_context.write().unwrap();
                state_writer.set_skipped(state.skipped().cloned());
            }

            let (mail_context, message, _) = state.take().unwrap();

            if std::convert::TryInto::<&MailContext<Connect>>::try_into(&mail_context).is_ok() {
                // when received "DATA\r\n.\r\n"
                return Ok(false);
            }
            if std::convert::TryInto::<&MailContext<Helo>>::try_into(&mail_context).is_ok() {
                // when received "DATA\r\nHELO xxx\r\n.\r\n"
                return Ok(false);
            }

            let mail_context: MailContext<Finished> = match mail_context.try_into() {
                Ok(finished) => finished,
                Err(e) => todo!("{}", e),
            };

            Some(
                mail_handler
                    .on_mail(self, Box::new(mail_context), message, queue_manager.clone())
                    .await,
            )
        } else {
            None
        };

        let (mail_context, message, _) = transaction.rule_state.take().unwrap();

        if std::convert::TryInto::<&MailContext<Connect>>::try_into(&mail_context).is_ok() {
            // when received "DATA\r\n.\r\n"
            return Ok(false);
        }
        if std::convert::TryInto::<&MailContext<Helo>>::try_into(&mail_context).is_ok() {
            // when received "DATA\r\nHELO xxx\r\n.\r\n"
            return Ok(false);
        }

        let mail_context: MailContext<Finished> = match mail_context.try_into() {
            Ok(finished) => finished,
            Err(e) => todo!("{}", e),
        };

        let helo = mail_context.client_name().to_string();

        let code = mail_handler
            .on_mail(self, Box::new(mail_context), message, queue_manager)
            .await;

        // NOTE: which code should take priority ?
        let code = code_internal.map_or(code, |code_internal| code_internal);

        *helo_domain = Some(helo);
        self.send_code(code).await?;

        Ok(true)
    }
}
