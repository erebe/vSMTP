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
use super::connection::Connection;
use vqueue::GenericQueueManager;
use vsmtp_common::{
    addr, auth::Mechanism, event::Event, mail_context::MessageMetadata, rcpt::Rcpt, state::State,
    status::Status, Address, CodeID, Envelop, ReplyOrCodeID,
};
use vsmtp_config::{field::TlsSecurityLevel, Config, Resolvers};
use vsmtp_mail_parser::MessageBody;
use vsmtp_rule_engine::{RuleEngine, RuleState};

type ProcessedEvent = (ReplyOrCodeID, Option<State>);

pub struct Transaction {
    state: State,
    pub rule_state: RuleState,
    pub rule_engine: std::sync::Arc<RuleEngine>,
}

impl std::fmt::Debug for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transaction")
            .field("state", &self.state)
            .field("rule_state", &self.rule_state)
            .finish()
    }
}

#[allow(clippy::module_name_repetitions)]
pub enum TransactionResult {
    /// The SMTP handshake has been completed, `DATA` has been receive we are now
    /// handling the message body.
    HandshakeSMTP,
    /// A TLS handshake has been requested
    HandshakeTLS,
    /// A SASL (AUTH) handshake has been requested
    HandshakeSASL(String, Mechanism, Option<Vec<u8>>),
    /// The client sended a `QUIT` command or the client stream reached EOF,
    /// the connection will be closed.
    SessionEnded(ReplyOrCodeID),
}

impl Transaction {
    fn parse_and_apply_and_get_reply<
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
    >(
        &mut self,
        client_message: &str,
        connection: &Connection<S>,
    ) -> either::Either<ProcessedEvent, TransactionResult> {
        let command_or_code = Event::parse_cmd(client_message);

        tracing::trace!(message = %client_message, parsed = ?command_or_code);

        command_or_code.map_or_else(
            |c| either::Left((ReplyOrCodeID::Left(c), None)),
            |command| self.process_event(command, connection),
        )
    }

    #[allow(clippy::too_many_lines)]
    fn process_event<
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
    >(
        &mut self,
        event: Event,
        connection: &Connection<S>,
    ) -> either::Either<ProcessedEvent, TransactionResult> {
        match (&self.state, event) {
            (_, Event::NoopCmd) => either::Left((ReplyOrCodeID::Left(CodeID::Ok), None)),

            (_, Event::HelpCmd(_)) => either::Left((ReplyOrCodeID::Left(CodeID::Help), None)),

            (_, Event::RsetCmd) => {
                {
                    let state = self.rule_state.context();
                    let mut ctx = state.write().unwrap();
                    ctx.metadata = MessageMetadata {
                        timestamp: None,
                        message_id: None,
                        skipped: None,
                        spf: None,
                        dkim: None,
                    };
                    ctx.envelop.rcpt.clear();
                    ctx.envelop.mail_from = addr!("default@domain.com");
                }
                self.reset_message();
                either::Left((ReplyOrCodeID::Left(CodeID::Ok), Some(State::Helo)))
            }

            (_, Event::ExpnCmd(_) | Event::VrfyCmd(_) /*| Event::PrivCmd*/) => {
                either::Left((ReplyOrCodeID::Left(CodeID::Unimplemented), None))
            }

            (_, Event::QuitCmd) => either::Right(TransactionResult::SessionEnded(
                ReplyOrCodeID::Left(CodeID::Closing),
            )),

            (state, Event::HeloCmd(helo)) => {
                if !matches!(state, State::Connect) {
                    self.reset_message();
                }

                self.set_helo(helo);

                match self.rule_engine.run_when(&mut self.rule_state, State::Helo) {
                    Status::Info(packet) => either::Left((packet, None)),
                    Status::Deny(packet) => either::Right(TransactionResult::SessionEnded(packet)),
                    _ => either::Left((ReplyOrCodeID::Left(CodeID::Helo), Some(State::Helo))),
                }
            }

            (_, Event::EhloCmd(_)) if connection.config.server.smtp.disable_ehlo => {
                either::Left((ReplyOrCodeID::Left(CodeID::Unimplemented), None))
            }

            (state, Event::EhloCmd(helo)) => {
                if !matches!(state, State::Connect) {
                    self.reset_message();
                }

                self.set_helo(helo);

                match self.rule_engine.run_when(&mut self.rule_state, State::Helo) {
                    Status::Info(packet) => either::Left((packet, None)),
                    Status::Deny(packet) => either::Right(TransactionResult::SessionEnded(packet)),
                    _ => either::Left((
                        ReplyOrCodeID::Left(if connection.context.is_secured {
                            CodeID::EhloSecured
                        } else {
                            CodeID::EhloPain
                        }),
                        Some(State::Helo),
                    )),
                }
            }

            (State::Helo | State::Connect, Event::StartTls)
                if connection.config.server.tls.is_none() =>
            {
                either::Left((ReplyOrCodeID::Left(CodeID::TlsNotAvailable), None))
            }

            (State::Helo | State::Connect, Event::StartTls)
                if connection.config.server.tls.is_some() =>
            {
                either::Right(TransactionResult::HandshakeTLS)
            }

            (State::Helo, Event::Auth(mechanism, initial_response))
                if !connection.context.is_authenticated =>
            {
                either::Right(TransactionResult::HandshakeSASL(
                    self.rule_state
                        .context()
                        .read()
                        .expect("`rule_state` mutex is not poisoned")
                        .envelop
                        .helo
                        .clone(),
                    mechanism,
                    initial_response,
                ))
            }

            (State::Helo, Event::MailCmd(..))
                if !connection.context.is_secured
                    && connection
                        .config
                        .server
                        .tls
                        .as_ref()
                        .map(|smtps| smtps.security_level)
                        == Some(TlsSecurityLevel::Encrypt) =>
            {
                either::Left((ReplyOrCodeID::Left(CodeID::TlsRequired), None))
            }

            (State::Helo, Event::MailCmd(..))
                if !connection.context.is_authenticated
                    && connection
                        .config
                        .server
                        .smtp
                        .auth
                        .as_ref()
                        .map_or(false, |auth| auth.must_be_authenticated) =>
            {
                either::Left((ReplyOrCodeID::Left(CodeID::AuthRequired), None))
            }

            (State::Helo, Event::MailCmd(mail_from, _body_bit_mime, _auth_mailbox)) => {
                // TODO: store in envelop _body_bit_mime & _auth_mailbox
                // TODO: handle : mail_from can be "<>"
                self.set_mail_from(mail_from.unwrap(), connection);

                match self
                    .rule_engine
                    .run_when(&mut self.rule_state, State::MailFrom)
                {
                    Status::Info(packet) => either::Left((packet, None)),
                    Status::Deny(packet) => either::Right(TransactionResult::SessionEnded(packet)),
                    Status::Accept(packet) | Status::Faccept(packet) => {
                        either::Left((packet, Some(State::MailFrom)))
                    }
                    Status::Delegated(_)
                    | Status::DelegationResult
                    | Status::Next
                    | Status::Quarantine(_)
                    | Status::Packet(_) => {
                        either::Left((ReplyOrCodeID::Left(CodeID::Ok), Some(State::MailFrom)))
                    }
                }
            }

            (State::MailFrom | State::RcptTo, Event::RcptCmd(rcpt_to)) => {
                self.set_rcpt_to(rcpt_to);

                match self
                    .rule_engine
                    .run_when(&mut self.rule_state, State::RcptTo)
                {
                    Status::Info(packet) => either::Left((packet, None)),
                    Status::Deny(packet) => either::Right(TransactionResult::SessionEnded(packet)),
                    _ if self.rule_state.context().read().unwrap().envelop.rcpt.len()
                        >= connection.config.server.smtp.rcpt_count_max =>
                    {
                        either::Left((ReplyOrCodeID::Left(CodeID::TooManyRecipients), None))
                    }
                    Status::Accept(packet) | Status::Faccept(packet) => {
                        either::Left((packet, Some(State::RcptTo)))
                    }
                    Status::Delegated(_)
                    | Status::DelegationResult
                    | Status::Next
                    | Status::Quarantine(_)
                    | Status::Packet(_) => {
                        either::Left((ReplyOrCodeID::Left(CodeID::Ok), Some(State::RcptTo)))
                    }
                }
            }

            (State::RcptTo, Event::DataCmd) => either::Right(TransactionResult::HandshakeSMTP),

            _ => either::Left((ReplyOrCodeID::Left(CodeID::BadSequence), None)),
        }
    }

    fn set_connect<
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
    >(
        &mut self,
        connection: &Connection<S>,
    ) {
        let state = self.rule_state.context();
        let ctx = &mut state.write().unwrap();

        ctx.connection.client_addr = connection.context.client_addr;
        ctx.connection.timestamp = connection.context.timestamp;
    }

    fn set_helo(&mut self, helo: String) {
        {
            let state = self.rule_state.context();
            let mut ctx = state.write().unwrap();

            ctx.metadata = MessageMetadata {
                timestamp: None,
                message_id: None,
                skipped: None,
                spf: None,
                dkim: None,
            };
            ctx.envelop = Envelop {
                helo,
                mail_from: addr!("no@address.net"),
                rcpt: vec![],
            };
        }
    }

    fn set_mail_from<
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
    >(
        &mut self,
        mail_from: Address,
        connection: &Connection<S>,
    ) {
        let now = std::time::SystemTime::now();

        {
            let state = self.rule_state.context();
            let mut ctx = state.write().unwrap();
            ctx.envelop.rcpt.clear();
            ctx.envelop.mail_from = mail_from;
            ctx.metadata = MessageMetadata {
                timestamp: Some(now),
                message_id: Some(format!(
                    "{}{}{}{}",
                    now.duration_since(std::time::SystemTime::UNIX_EPOCH)
                        .expect("did went back in time")
                        .as_micros(),
                    connection
                        .context
                        .timestamp
                        .duration_since(std::time::SystemTime::UNIX_EPOCH)
                        .expect("did went back in time")
                        .as_millis(),
                    std::iter::repeat_with(fastrand::alphanumeric)
                        .take(36)
                        .collect::<String>(),
                    std::process::id()
                )),
                skipped: self.rule_state.skipped().cloned(),
                spf: None,
                dkim: None,
            };
        }
    }

    fn set_rcpt_to(&mut self, rcpt_to: Address) {
        self.rule_state
            .context()
            .write()
            .unwrap()
            .envelop
            .rcpt
            .push(Rcpt::new(rcpt_to));
    }

    /// reset the message but keeps headers.
    fn reset_message(&mut self) {
        let state = self.rule_state.message();
        *state.write().unwrap() = MessageBody::default();
    }

    pub fn new<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug>(
        conn: &mut Connection<S>,
        helo_domain: &Option<String>,
        rule_engine: std::sync::Arc<RuleEngine>,
        resolvers: std::sync::Arc<Resolvers>,
        queue_manager: std::sync::Arc<dyn GenericQueueManager>,
    ) -> Transaction {
        let rule_state = RuleState::with_connection(
            conn.config.clone(),
            resolvers,
            queue_manager,
            &rule_engine,
            conn.context.clone(),
        );

        Self {
            state: if helo_domain.is_none() {
                State::Connect
            } else {
                State::Helo
            },
            rule_state,
            rule_engine,
        }
    }

    pub fn stream<
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
    >(
        connection: &mut Connection<S>,
    ) -> impl tokio_stream::Stream<Item = String> + '_ {
        let read_timeout = connection.config.server.smtp.timeout_client.data;
        async_stream::stream! {
            let mut message_size = 0;
            loop {
                match connection.read(read_timeout).await {
                    Ok(Some(client_message)) => {

                        message_size += client_message.len();

                        if message_size >= connection.config.server.message_size_limit {
                            return match connection.send_code(CodeID::MessageSizeExceeded).await {
                                Ok(_) => (),
                                Err(_) => () // TODO:
                            }
                        }

                        let command_or_code = Event::parse_data(client_message);

                        match command_or_code {
                            Ok(Some(line)) => yield line,
                            Ok(None) => break,
                            Err(code) => {
                                match connection.send_code(code).await {
                                    Ok(_) => (),
                                    Err(e) => todo!("{e:?}")
                                }
                            },
                        }
                    }
                    e => todo!("{e:?}"),
                }
            }
        }
    }

    #[tracing::instrument(name = "smtp", skip_all)]
    pub async fn receive<
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Sync + Send + Unpin + std::fmt::Debug,
    >(
        &mut self,
        connection: &mut Connection<S>,
        helo_domain: &Option<String>,
    ) -> anyhow::Result<TransactionResult> {
        if let Some(helo) = helo_domain.as_ref().cloned() {
            self.set_helo(helo);
        } else {
            self.set_connect(connection);

            let status = self
                .rule_engine
                .run_when(&mut self.rule_state, State::Connect);

            match status {
                Status::Info(packet) => connection.send_reply_or_code(packet).await?,
                Status::Deny(packet) => {
                    connection.send_reply_or_code(packet).await?;

                    anyhow::bail!(
                        "connection at '{}' has been denied when connecting.",
                        connection.context.client_addr
                    )
                }
                _ => {}
            }
        }

        let mut read_timeout = get_timeout_for_state(&connection.config, self.state);

        loop {
            match connection.read(read_timeout).await {
                Ok(Some(client_message)) => {
                    let parsed_message =
                        self.parse_and_apply_and_get_reply(&client_message, connection);

                    match parsed_message {
                        either::Left((reply_to_send, new_state)) => {
                            if let Some(new_state) = new_state {
                                tracing::debug!(
                                    old = %self.state,
                                    new = %new_state,
                                    "State changed."
                                );

                                self.state = new_state;
                                read_timeout =
                                    get_timeout_for_state(&connection.config, self.state);
                            }
                            connection.send_reply_or_code(reply_to_send).await?;
                        }
                        either::Right(transaction_result) => {
                            return Ok(transaction_result);
                        }
                    }
                }
                Ok(None) => {
                    anyhow::bail!("end-of-file is considered as an error, closing")
                }
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    connection.send_code(CodeID::Timeout).await?;
                    anyhow::bail!(e)
                }
                Err(e) => {
                    anyhow::bail!(e)
                }
            }
        }
    }
}

const TIMEOUT_DEFAULT: u64 = 5 * 60 * 1000; // 5min

fn get_timeout_for_state(config: &std::sync::Arc<Config>, state: State) -> std::time::Duration {
    match state {
        State::Connect => config.server.smtp.timeout_client.connect,
        State::Helo => config.server.smtp.timeout_client.helo,
        State::MailFrom => config.server.smtp.timeout_client.mail_from,
        State::RcptTo => config.server.smtp.timeout_client.rcpt_to,
        State::Authenticate | State::PreQ | State::PostQ | State::Delivery => {
            std::time::Duration::from_millis(TIMEOUT_DEFAULT)
        }
    }
}
