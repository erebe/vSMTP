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

use crate::{Handler, OnMail};
use tokio_stream::StreamExt;
use vsmtp_common::{status::Status, CodeID, Reply};
use vsmtp_mail_parser::{BasicParser, Mail, MailParser, MessageBody, ParserError, RawBody};
use vsmtp_protocol::{Error, ReceiverContext};
use vsmtp_rule_engine::{ExecutionStage, RuleEngine, RuleState};

impl<M: OnMail + Send> Handler<M> {
    pub(super) fn handle_preq_header(
        rule_engine: &RuleEngine,
        state: &RuleState,
        mut skipped: Option<Status>,
        mut mail: either::Either<RawBody, Mail>,
    ) -> Status {
        // NOTE: some header might has been added by the user
        // before the reception of the message
        {
            let message = state.message();
            let mut guard = message.write().expect("message poisoned");

            let iter = guard.inner().headers_lines();
            match &mut mail {
                either::Left(raw) => raw.prepend_header(iter.map(str::to_owned)),
                either::Right(parsed) => {
                    parsed.prepend_headers(iter.filter_map(|s| {
                        s.split_once(':')
                            .map(|(key, value)| (key.to_string(), value.to_string()))
                    }));
                }
            };
            *guard = MessageBody::from(mail);
        }

        state
            .context()
            .write()
            .expect("state poisoned")
            .to_finished()
            .expect("bad state");

        let status = rule_engine.run_when(state, &mut skipped, ExecutionStage::PreQ);

        if let Some(skipped) = skipped {
            state
                .context()
                .write()
                .expect("state poisoned")
                .set_skipped(skipped);
        }
        status
    }

    #[allow(clippy::too_many_lines)]
    pub(super) async fn on_message_inner(
        &mut self,
        ctx: &mut ReceiverContext,
        stream: impl tokio_stream::Stream<Item = Result<Vec<u8>, Error>> + Send + Unpin,
    ) -> Reply {
        tracing::info!("SMTP handshake completed, fetching email...");
        let stream = stream.map(|l| match l {
            Ok(l) => Ok(l),
            Err(Error::Io(io)) => Err(ParserError::Io(io)),
            Err(Error::BufferTooLong { expected, got }) => {
                Err(ParserError::BufferTooLong { expected, got })
            }
            Err(Error::Utf8(_)) => todo!(),
        });

        let mail = match BasicParser::default().parse(stream).await {
            Ok(mail) => mail,
            Err(ParserError::BufferTooLong { .. }) => {
                return self.reply_in_config(CodeID::MessageSizeExceeded);
            }
            Err(otherwise) => todo!("handle error cleanly {:?}", otherwise),
        };
        tracing::info!("Message body fully received, processing...");

        let internal_reply = if let Some(state_internal) = &self.state_internal {
            let status = Self::handle_preq_header(
                &self.rule_engine,
                state_internal,
                self.skipped.clone(),
                mail.clone(),
            );

            let (mail_ctx, message) = std::mem::replace(&mut self.state_internal, None)
                .unwrap()
                .take();
            let mut mail_ctx = mail_ctx
                .unwrap_finished()
                .expect("has been set to finished");

            let reply = match status {
                Status::Deny(code_or_reply) => {
                    ctx.deny();
                    self.reply_or_code_in_config(code_or_reply)
                }
                Status::Delegated(_) => unreachable!(),
                status => {
                    mail_ctx.connect.skipped = Some(status);
                    let code = self
                        .on_mail
                        .on_mail(Box::new(mail_ctx), message, self.queue_manager.clone())
                        .await;

                    self.reply_in_config(code)
                }
            };
            Some(reply)
        } else {
            None
        };
        let reply = {
            let status = Self::handle_preq_header(
                &self.rule_engine,
                &self.state,
                self.skipped.clone(),
                mail,
            );
            let (mail_ctx, message) =
                std::mem::replace(&mut self.state, self.rule_engine.spawn()).take();
            let mut mail_ctx = mail_ctx
                .unwrap_finished()
                .expect("has been set to finished");

            self.state
                .context()
                .write()
                .expect("state poisoned")
                .to_connect(
                    mail_ctx.connect.client_addr,
                    mail_ctx.connect.server_addr,
                    mail_ctx.connect.server_name.clone(),
                    mail_ctx.connect.connect_timestamp,
                    mail_ctx.connect.connect_uuid,
                )
                .expect("bad state")
                .to_helo(
                    mail_ctx.helo.client_name.clone(),
                    mail_ctx.helo.using_deprecated,
                )
                .expect("bad state");

            if mail_ctx.rcpt_to.delivery.is_empty() {
                None
            } else {
                let reply = match status {
                    Status::Deny(code_or_reply) => {
                        ctx.deny();
                        self.reply_or_code_in_config(code_or_reply)
                    }
                    Status::Delegated(_) => unreachable!(),
                    status => {
                        mail_ctx.connect.skipped = Some(status);
                        let code = self
                            .on_mail
                            .on_mail(Box::new(mail_ctx), message, self.queue_manager.clone())
                            .await;

                        self.reply_in_config(code)
                    }
                };

                Some(reply)
            }
        };

        match (internal_reply, reply) {
            (Some(internal_reply), Some(reply)) => internal_reply.extended(&reply),
            (Some(internal_reply), None) => internal_reply,
            (None, Some(reply)) => reply,
            // both mail are empty: should be unreachable
            (None, None) => todo!(),
        }
    }
}
