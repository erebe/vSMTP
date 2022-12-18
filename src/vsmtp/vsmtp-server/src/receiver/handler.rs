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
use crate::on_mail::OnMail;
use tokio_rustls::rustls;
use vqueue::GenericQueueManager;
use vsmtp_common::{status::Status, CodeID, Reply, Stage, TransactionType};
use vsmtp_config::Config;
use vsmtp_protocol::{
    AcceptArgs, AuthArgs, AuthError, CallbackWrap, EhloArgs, Error, HeloArgs, MailFromArgs,
    RcptToArgs, ReceiverContext,
};
use vsmtp_rule_engine::{ExecutionStage, RuleEngine, RuleState};

///
pub struct Handler<M: OnMail> {
    // TODO: remove on_mail
    pub(super) on_mail: Box<M>,

    pub(super) state: std::sync::Arc<RuleState>,
    // NOTE:
    // In case the transaction context is outgoing, we create two states
    // to run two batches of rules at the same time, one for internal transaction
    // with recipients that have the same domain as the sender, and another
    // for any other recipient domain.
    // FIXME: find another way to do this
    pub(super) state_internal: Option<std::sync::Arc<RuleState>>,
    pub(super) skipped: Option<Status>,
    //
    pub(super) config: std::sync::Arc<Config>,
    pub(super) rustls_config: Option<std::sync::Arc<rustls::ServerConfig>>,
    pub(super) rule_engine: std::sync::Arc<RuleEngine>,
    pub(super) queue_manager: std::sync::Arc<dyn GenericQueueManager>,
}

impl<M: OnMail> Handler<M> {
    ///
    #[must_use]
    pub fn new(
        on_mail: Box<M>,
        config: std::sync::Arc<Config>,
        rustls_config: Option<std::sync::Arc<rustls::ServerConfig>>,
        rule_engine: std::sync::Arc<RuleEngine>,
        queue_manager: std::sync::Arc<dyn GenericQueueManager>,
    ) -> Self {
        Self {
            on_mail,
            state: rule_engine.spawn(),
            state_internal: None,
            skipped: None,
            config,
            rustls_config,
            rule_engine,
            queue_manager,
        }
    }
}

impl<M: OnMail + Send> Handler<M> {
    pub(super) fn reply_in_config(&self, code: CodeID) -> Reply {
        self.config
            .server
            .smtp
            .codes
            .get(&code)
            .expect("config ill formed")
            .clone()
    }

    pub(super) fn reply_or_code_in_config(
        &self,
        code_or_reply: either::Either<CodeID, Reply>,
    ) -> Reply {
        match code_or_reply {
            either::Left(code) => self.reply_in_config(code),
            either::Right(reply) => reply,
        }
    }
}

#[async_trait::async_trait]
impl<M: OnMail + Send + Sync> vsmtp_protocol::ReceiverHandler for Handler<M> {
    fn generate_sasl_callback(&self) -> CallbackWrap {
        self.generate_sasl_callback_inner()
    }

    async fn on_accept(&mut self, ctx: &mut ReceiverContext, args: AcceptArgs) -> Reply {
        self.on_accept_inner(ctx, &args)
    }

    async fn on_post_tls_handshake(
        &mut self,
        sni: Option<String>,
        protocol_version: rustls::ProtocolVersion,
        cipher_suite: rustls::CipherSuite,
        peer_certificates: Option<Vec<rustls::Certificate>>,
        alpn_protocol: Option<Vec<u8>>,
    ) -> Reply {
        self.on_post_tls_handshake_inner(
            sni,
            protocol_version,
            cipher_suite,
            peer_certificates,
            alpn_protocol,
        )
    }

    async fn on_starttls(&mut self, ctx: &mut ReceiverContext) -> Reply {
        self.on_starttls_inner(ctx)
    }

    async fn on_auth(&mut self, ctx: &mut ReceiverContext, args: AuthArgs) -> Option<Reply> {
        self.on_auth_inner(ctx, args)
    }

    async fn on_post_auth(
        &mut self,
        ctx: &mut ReceiverContext,
        result: Result<(), AuthError>,
    ) -> Reply {
        self.on_post_auth_inner(ctx, result)
    }

    async fn on_helo(&mut self, ctx: &mut ReceiverContext, args: HeloArgs) -> Reply {
        self.on_helo_inner(ctx, args)
    }

    async fn on_ehlo(&mut self, ctx: &mut ReceiverContext, args: EhloArgs) -> Reply {
        self.on_ehlo_inner(ctx, args)
    }

    async fn on_mail_from(&mut self, ctx: &mut ReceiverContext, args: MailFromArgs) -> Reply {
        let reverse_path = args
            .reverse_path
            .expect("TODO: handle null reverse path")
            .parse()
            .expect("handle invalid mailbox");

        let is_outgoing = self.rule_engine.is_handled_domain(&reverse_path);

        self.state
            .context()
            .write()
            .expect("state poisoned")
            .to_mail_from(reverse_path, is_outgoing)
            .unwrap();

        let e = match self.rule_engine.run_when(
            &self.state,
            &mut self.skipped,
            ExecutionStage::MailFrom,
        ) {
            Status::Info(e) | Status::Faccept(e) | Status::Accept(e) => e,
            Status::Quarantine(_) | Status::Next | Status::DelegationResult => {
                either::Left(CodeID::Ok)
            }
            Status::Deny(code) => {
                ctx.deny();
                code
            }
            Status::Delegated(_) => unreachable!(),
        };

        self.reply_or_code_in_config(e)
    }

    #[allow(clippy::too_many_lines)]
    async fn on_rcpt_to(&mut self, ctx: &mut ReceiverContext, args: RcptToArgs) -> Reply {
        // FIXME: handle internal state too ??
        if self
            .state
            .context()
            .read()
            .expect("state poisoned")
            .forward_paths()
            .map_or(0, Vec::len)
            >= self.config.server.smtp.rcpt_count_max
        {
            return self.reply_in_config(CodeID::TooManyRecipients);
        }

        let forward_path = args.forward_path.parse().unwrap();

        let is_internal = {
            let ctx = self.state.context();
            let mut ctx = ctx.write().unwrap();

            let (is_outgoing, is_handled) = (
                ctx.is_outgoing().expect("bad state"),
                self.rule_engine.is_handled_domain(&forward_path),
            );

            let reverse_path = ctx.reverse_path().unwrap().clone();

            match (is_outgoing, is_handled) {
                (true, true) if forward_path.domain() == reverse_path.domain() => {
                    tracing::debug!(
                        "INTERNAL: forward and reverse path domain are both: {}",
                        forward_path.domain()
                    );

                    if self.state_internal.is_none() {
                        tracing::debug!("No previous `internal_state`. Copying...");
                        let mut ctx_internal = ctx.clone();

                        ctx_internal.generate_message_id().expect("bad state");
                        if let Ok(rcpt) = ctx_internal.forward_paths_mut() {
                            rcpt.clear();
                        }

                        self.state_internal = Some(
                            self.rule_engine.spawn_with(
                                ctx_internal,
                                self.state
                                    .message()
                                    .read()
                                    .expect("message poisoned")
                                    .clone(),
                            ),
                        );
                    }

                    let internal_ctx = self.state_internal.as_ref().unwrap().context();
                    let mut internal_guard = internal_ctx.write().expect("state poisoned");
                    internal_guard.add_forward_path(forward_path).unwrap();
                    internal_guard
                        .set_transaction_type(TransactionType::Internal)
                        .expect("bad state");

                    ctx.set_transaction_type(TransactionType::Outgoing {
                        domain: reverse_path.domain().to_string(),
                    })
                    .expect("bad state");

                    true
                }
                (true, _) => {
                    tracing::debug!(
                        "OUTGOING: reverse:${} => forward:${}",
                        reverse_path.domain(),
                        forward_path.domain()
                    );

                    ctx.add_forward_path(forward_path).unwrap();
                    ctx.set_transaction_type(TransactionType::Outgoing {
                        domain: reverse_path.domain().to_owned(),
                    })
                    .expect("bad state");

                    false
                }
                (false, forward_path_is_handled) => {
                    tracing::debug!(
                        "INCOMING: reverse:${} => forward:${}",
                        reverse_path.domain(),
                        forward_path.domain()
                    );

                    ctx.set_transaction_type(TransactionType::Incoming(
                        if forward_path_is_handled {
                            Some(forward_path.domain().to_owned())
                        } else {
                            None
                        },
                    ))
                    .expect("bad state");
                    ctx.add_forward_path(forward_path).unwrap();

                    false
                }
            }
        };

        let state = match self.state_internal.as_mut() {
            Some(state_internal) if is_internal => state_internal,
            _ => &mut self.state,
        };

        let e = match self
            .rule_engine
            .run_when(state, &mut self.skipped, ExecutionStage::RcptTo)
        {
            Status::Info(e) | Status::Faccept(e) | Status::Accept(e) => e,
            Status::Quarantine(_) | Status::Next | Status::DelegationResult => {
                either::Left(CodeID::Ok)
            }
            Status::Deny(code) => {
                ctx.deny();
                code
            }
            Status::Delegated(_) => unreachable!(),
        };

        self.reply_or_code_in_config(e)
    }

    async fn on_rset(&mut self) -> Reply {
        self.state
            .context()
            .write()
            .expect("state poisoned")
            .reset();

        self.state_internal = None;

        // TODO: reset message?

        self.reply_in_config(CodeID::Ok)
    }

    async fn on_message(
        &mut self,
        ctx: &mut ReceiverContext,
        stream: impl tokio_stream::Stream<Item = Result<Vec<u8>, Error>> + Send + Unpin,
    ) -> Reply {
        self.on_message_inner(ctx, stream).await
    }

    async fn on_hard_error(&mut self, ctx: &mut ReceiverContext, reply: Reply) -> Reply {
        ctx.deny();
        Reply::combine(&reply, &self.reply_in_config(CodeID::TooManyError))
    }

    async fn on_soft_error(&mut self, _: &mut ReceiverContext, reply: Reply) -> Reply {
        tokio::time::sleep(self.config.server.smtp.error.delay).await;
        reply
    }

    fn get_stage(&self) -> Stage {
        self.state
            .context()
            .write()
            .expect("state poisoned")
            .stage()
    }
}
