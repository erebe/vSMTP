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
use vsmtp_common::{
    addr,
    auth::Mechanism,
    event::Event,
    mail_context::MessageMetadata,
    rcpt::Rcpt,
    re::{anyhow, either, log, tokio},
    state::StateSMTP,
    status::Status,
    Address, CodeID, Envelop, ReplyOrCodeID,
};
use vsmtp_config::{field::TlsSecurityLevel, Config, Resolvers};
use vsmtp_mail_parser::MessageBody;
use vsmtp_rule_engine::{RuleEngine, RuleState};

enum ProcessedEvent {
    Reply(ReplyOrCodeID),
    ReplyChangeState(StateSMTP, ReplyOrCodeID),
}

pub struct Transaction {
    state: StateSMTP,
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
    #[tracing::instrument(skip(connection, client_message))]
    fn parse_and_apply_and_get_reply<
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
    >(
        &mut self,
        client_message: &str,
        connection: &Connection<S>,
    ) -> either::Either<ProcessedEvent, TransactionResult> {
        let command_or_code = Event::parse_cmd(client_message);

        log::trace!("received={client_message:?}; parsed=`{command_or_code:?}`");

        command_or_code.map_or_else(
            |c| either::Left(ProcessedEvent::Reply(ReplyOrCodeID::Left(c))),
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
            (_, Event::NoopCmd) => {
                either::Left(ProcessedEvent::Reply(ReplyOrCodeID::Left(CodeID::Ok)))
            }

            (_, Event::HelpCmd(_)) => {
                either::Left(ProcessedEvent::Reply(ReplyOrCodeID::Left(CodeID::Help)))
            }

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
                either::Left(ProcessedEvent::ReplyChangeState(
                    StateSMTP::Helo,
                    ReplyOrCodeID::Left(CodeID::Ok),
                ))
            }

            (_, Event::ExpnCmd(_) | Event::VrfyCmd(_) /*| Event::PrivCmd*/) => either::Left(
                ProcessedEvent::Reply(ReplyOrCodeID::Left(CodeID::Unimplemented)),
            ),

            (_, Event::QuitCmd) => either::Right(TransactionResult::SessionEnded(
                ReplyOrCodeID::Left(CodeID::Closing),
            )),

            (state, Event::HeloCmd(helo)) => {
                if !matches!(state, StateSMTP::Connect) {
                    self.reset_message();
                }

                self.set_helo(helo);

                match self
                    .rule_engine
                    .run_when(&mut self.rule_state, &StateSMTP::Helo)
                {
                    Status::Info(packet) => either::Left(ProcessedEvent::Reply(packet)),
                    Status::Deny(packet) => either::Right(TransactionResult::SessionEnded(packet)),
                    _ => either::Left(ProcessedEvent::ReplyChangeState(
                        StateSMTP::Helo,
                        ReplyOrCodeID::Left(CodeID::Helo),
                    )),
                }
            }

            (_, Event::EhloCmd(_)) if connection.config.server.smtp.disable_ehlo => either::Left(
                ProcessedEvent::Reply(ReplyOrCodeID::Left(CodeID::Unimplemented)),
            ),

            (state, Event::EhloCmd(helo)) => {
                if !matches!(state, StateSMTP::Connect) {
                    self.reset_message();
                }

                self.set_helo(helo);

                match self
                    .rule_engine
                    .run_when(&mut self.rule_state, &StateSMTP::Helo)
                {
                    Status::Info(packet) => either::Left(ProcessedEvent::Reply(packet)),
                    Status::Deny(packet) => either::Right(TransactionResult::SessionEnded(packet)),
                    _ => either::Left(ProcessedEvent::ReplyChangeState(
                        StateSMTP::Helo,
                        ReplyOrCodeID::Left(if connection.context.is_secured {
                            CodeID::EhloSecured
                        } else {
                            CodeID::EhloPain
                        }),
                    )),
                }
            }

            (StateSMTP::Helo | StateSMTP::Connect, Event::StartTls)
                if connection.config.server.tls.is_none() =>
            {
                either::Left(ProcessedEvent::Reply(ReplyOrCodeID::Left(
                    CodeID::TlsNotAvailable,
                )))
            }

            (StateSMTP::Helo | StateSMTP::Connect, Event::StartTls)
                if connection.config.server.tls.is_some() =>
            {
                either::Right(TransactionResult::HandshakeTLS)
            }

            (StateSMTP::Helo, Event::Auth(mechanism, initial_response))
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

            (StateSMTP::Helo, Event::MailCmd(..))
                if !connection.context.is_secured
                    && connection
                        .config
                        .server
                        .tls
                        .as_ref()
                        .map(|smtps| smtps.security_level)
                        == Some(TlsSecurityLevel::Encrypt) =>
            {
                either::Left(ProcessedEvent::Reply(ReplyOrCodeID::Left(
                    CodeID::TlsRequired,
                )))
            }

            (StateSMTP::Helo, Event::MailCmd(..))
                if !connection.context.is_authenticated
                    && connection
                        .config
                        .server
                        .smtp
                        .auth
                        .as_ref()
                        .map_or(false, |auth| auth.must_be_authenticated) =>
            {
                either::Left(ProcessedEvent::Reply(ReplyOrCodeID::Left(
                    CodeID::AuthRequired,
                )))
            }

            (StateSMTP::Helo, Event::MailCmd(mail_from, _body_bit_mime, _auth_mailbox)) => {
                // TODO: store in envelop _body_bit_mime & _auth_mailbox
                // TODO: handle : mail_from can be "<>"
                self.set_mail_from(mail_from.unwrap(), connection);

                match self
                    .rule_engine
                    .run_when(&mut self.rule_state, &StateSMTP::MailFrom)
                {
                    Status::Info(packet) => either::Left(ProcessedEvent::Reply(packet)),
                    Status::Deny(packet) => either::Right(TransactionResult::SessionEnded(packet)),
                    Status::Accept(packet) | Status::Faccept(packet) => either::Left(
                        ProcessedEvent::ReplyChangeState(StateSMTP::MailFrom, packet),
                    ),
                    Status::Delegated(_)
                    | Status::DelegationResult
                    | Status::Next
                    | Status::Quarantine(_)
                    | Status::Packet(_) => either::Left(ProcessedEvent::ReplyChangeState(
                        StateSMTP::MailFrom,
                        ReplyOrCodeID::Left(CodeID::Ok),
                    )),
                }
            }

            (StateSMTP::MailFrom | StateSMTP::RcptTo, Event::RcptCmd(rcpt_to)) => {
                self.set_rcpt_to(rcpt_to);

                match self
                    .rule_engine
                    .run_when(&mut self.rule_state, &StateSMTP::RcptTo)
                {
                    Status::Info(packet) => either::Left(ProcessedEvent::Reply(packet)),
                    Status::Deny(packet) => either::Right(TransactionResult::SessionEnded(packet)),
                    _ if self.rule_state.context().read().unwrap().envelop.rcpt.len()
                        >= connection.config.server.smtp.rcpt_count_max =>
                    {
                        either::Left(ProcessedEvent::Reply(ReplyOrCodeID::Left(
                            CodeID::TooManyRecipients,
                        )))
                    }
                    Status::Accept(packet) | Status::Faccept(packet) => {
                        either::Left(ProcessedEvent::ReplyChangeState(StateSMTP::RcptTo, packet))
                    }
                    Status::Delegated(_)
                    | Status::DelegationResult
                    | Status::Next
                    | Status::Quarantine(_)
                    | Status::Packet(_) => either::Left(ProcessedEvent::ReplyChangeState(
                        StateSMTP::RcptTo,
                        ReplyOrCodeID::Left(CodeID::Ok),
                    )),
                }
            }

            (StateSMTP::RcptTo, Event::DataCmd) => either::Right(TransactionResult::HandshakeSMTP),

            _ => either::Left(ProcessedEvent::Reply(ReplyOrCodeID::Left(
                CodeID::BadSequence,
            ))),
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
    ) -> Transaction {
        let rule_state = RuleState::with_connection(
            conn.config.as_ref(),
            resolvers,
            &rule_engine,
            conn.context.clone(),
        );

        Self {
            state: if helo_domain.is_none() {
                StateSMTP::Connect
            } else {
                StateSMTP::Helo
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
            loop {
                match connection.read(read_timeout).await {
                    Ok(Some(client_message)) => {
                        let command_or_code = Event::parse_data(client_message);
                        log::trace!("parsed=`{command_or_code:?}`");

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
                .run_when(&mut self.rule_state, &StateSMTP::Connect);

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

        let mut read_timeout = get_timeout_for_state(&connection.config, &self.state);

        loop {
            match connection.read(read_timeout).await {
                Ok(Some(client_message)) => {
                    let parsed_message =
                        self.parse_and_apply_and_get_reply(&client_message, connection);

                    match parsed_message {
                        either::Left(x) => match x {
                            ProcessedEvent::Reply(reply_to_send) => {
                                connection.send_reply_or_code(reply_to_send).await?;
                            }
                            ProcessedEvent::ReplyChangeState(new_state, reply_to_send) => {
                                log::info!(
                                    "STATE: {old_state:?} => {new_state:?}",
                                    old_state = self.state,
                                );
                                self.state = new_state;
                                read_timeout =
                                    get_timeout_for_state(&connection.config, &self.state);
                                connection.send_reply_or_code(reply_to_send).await?;
                            }
                        },
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

fn get_timeout_for_state(
    config: &std::sync::Arc<Config>,
    state: &StateSMTP,
) -> std::time::Duration {
    match state {
        StateSMTP::Connect => config.server.smtp.timeout_client.connect,
        StateSMTP::Helo => config.server.smtp.timeout_client.helo,
        StateSMTP::MailFrom => config.server.smtp.timeout_client.mail_from,
        StateSMTP::RcptTo => config.server.smtp.timeout_client.rcpt_to,
        StateSMTP::Authenticate | StateSMTP::PreQ | StateSMTP::PostQ | StateSMTP::Delivery => {
            std::time::Duration::from_millis(TIMEOUT_DEFAULT)
        }
    }
}
