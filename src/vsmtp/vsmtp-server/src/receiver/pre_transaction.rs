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
use tokio_rustls::rustls;
use vsmtp_common::{auth::Credentials, status::Status, ClientName, CodeID, Reply};
use vsmtp_protocol::{
    AcceptArgs, AuthArgs, AuthError, CallbackWrap, ConnectionKind, EhloArgs, HeloArgs,
    ReceiverContext,
};
use vsmtp_rule_engine::{ExecutionStage, RuleEngine, RuleState};

impl<M: OnMail + Send> Handler<M> {
    pub(super) fn generic_helo(
        &mut self,
        ctx: &mut ReceiverContext,
        client_name: ClientName,
        using_deprecated: bool,
        default: CodeID,
    ) -> Reply {
        self.state
            .context()
            .write()
            .expect("state poisoned")
            .to_helo(client_name, using_deprecated)
            .expect("bad state");

        let e =
            match self
                .rule_engine
                .run_when(&self.state, &mut self.skipped, ExecutionStage::Helo)
            {
                Status::Info(e) | Status::Faccept(e) | Status::Accept(e) => e,
                Status::Quarantine(_) | Status::Next | Status::DelegationResult => {
                    either::Left(default)
                }
                Status::Deny(code) => {
                    ctx.deny();
                    code
                }
                // FIXME: user ran a delegate method before postq/delivery
                Status::Delegated(_) => unreachable!(),
            };

        self.reply_or_code_in_config(e)
    }

    pub(super) fn on_accept_inner(
        &mut self,
        ctx: &mut ReceiverContext,
        args: &AcceptArgs,
    ) -> Reply {
        self.state
            .context()
            .write()
            .expect("state poisoned")
            .to_connect(
                args.client_addr,
                args.server_addr,
                self.config.server.name.clone(),
                args.timestamp,
                args.uuid,
            )
            .expect("bad state");

        if self
            .rule_engine
            .get_delegation_directive_bound_to_address(args.server_addr)
            .is_some()
        {
            self.state
                .context()
                .write()
                .expect("bad state")
                .set_skipped(Status::DelegationResult);
            self.skipped = Some(Status::DelegationResult);
        }

        let e =
            match self
                .rule_engine
                .run_when(&self.state, &mut self.skipped, ExecutionStage::Connect)
            {
                // FIXME: do we really want to let the end-user override the EHLO/HELO reply?
                Status::Info(e) | Status::Faccept(e) | Status::Accept(e) => e,
                Status::Quarantine(_) | Status::Next | Status::DelegationResult => {
                    either::Left(CodeID::Greetings)
                }
                Status::Deny(code) => {
                    ctx.deny();
                    return self.reply_or_code_in_config(code);
                }
                // FIXME: user ran a delegate method before postq/delivery
                Status::Delegated(_) => unreachable!(),
            };

        // NOTE: in that case, the return value is ignored and
        // we have to manually trigger the TLS handshake,
        if args.kind == ConnectionKind::Tunneled
            && !self
                .state
                .context()
                .read()
                .expect("state poisoned")
                .is_secured()
        {
            match &self.rustls_config {
                Some(config) => ctx.upgrade_tls(config.clone(), std::time::Duration::from_secs(2)),
                None => ctx.deny(),
            }
            return "000 ignored value".parse().unwrap();
        }

        self.reply_or_code_in_config(e)
    }

    pub(super) fn generate_sasl_callback_inner(&self) -> CallbackWrap {
        CallbackWrap(Box::new(RsaslSessionCallback {
            rule_engine: self.rule_engine.clone(),
            state: self.state.clone(),
        }))
    }

    pub(super) fn on_post_tls_handshake_inner(
        &mut self,
        sni: Option<String>,
        protocol_version: rustls::ProtocolVersion,
        cipher_suite: rustls::CipherSuite,
        peer_certificates: Option<Vec<rustls::Certificate>>,
        alpn_protocol: Option<Vec<u8>>,
    ) -> Reply {
        self.state
            .context()
            .write()
            .expect("state poisoned")
            .to_secured(
                sni,
                protocol_version,
                cipher_suite,
                peer_certificates,
                alpn_protocol,
            )
            .expect("bad state");

        self.reply_in_config(CodeID::Greetings)
    }

    pub(super) fn on_starttls_inner(&mut self, ctx: &mut ReceiverContext) -> Reply {
        let code = if self
            .state
            .context()
            .read()
            .expect("state poisoned")
            .is_secured()
        {
            CodeID::AlreadyUnderTLS
        } else {
            self.rustls_config
                .as_ref()
                .map_or(CodeID::TlsNotAvailable, |config| {
                    ctx.upgrade_tls(config.clone(), std::time::Duration::from_secs(2));
                    CodeID::TlsGoAhead
                })
        };

        self.reply_in_config(code)
    }

    pub(super) fn on_auth_inner(
        &mut self,
        ctx: &mut ReceiverContext,
        args: AuthArgs,
    ) -> Option<Reply> {
        if let Some(auth) = &self.config.server.smtp.auth {
            if !self
                .state
                .context()
                .read()
                .expect("state poisoned")
                .is_secured()
                && args.mechanism.must_be_under_tls()
                && !auth.enable_dangerous_mechanism_in_clair
            {
                return Some(self.reply_in_config(CodeID::AuthMechanismMustBeEncrypted));
            }

            ctx.authenticate(args.mechanism, args.initial_response);

            None
        } else {
            Some(self.reply_in_config(CodeID::Unimplemented))
        }
    }

    pub(super) fn on_post_auth_inner(
        &mut self,
        ctx: &mut ReceiverContext,
        result: Result<(), AuthError>,
    ) -> Reply {
        let code = match result {
            Ok(()) => {
                self.state
                    .context()
                    .write()
                    .expect("state poisoned")
                    .auth_mut()
                    .expect("bad state")
                    .authenticated = true;

                CodeID::AuthSucceeded
            }
            Err(AuthError::ClientMustNotStart) => CodeID::AuthClientMustNotStart,
            Err(AuthError::ValidationError(..)) => {
                ctx.deny();
                CodeID::AuthInvalidCredentials
            }
            Err(AuthError::Canceled) => {
                let state = self.state.context();
                let mut guard = state.write().expect("state poisoned");
                let auth_properties = guard.to_auth().expect("bad state");

                auth_properties.cancel_count += 1;
                let attempt_count_max = self
                    .config
                    .server
                    .smtp
                    .auth
                    .as_ref()
                    .map_or(-1, |auth| auth.attempt_count_max);

                if attempt_count_max != -1
                    && auth_properties.cancel_count >= attempt_count_max.try_into().unwrap()
                {
                    ctx.deny();
                }

                CodeID::AuthClientCanceled
            }
            Err(AuthError::Base64 { .. }) => CodeID::AuthErrorDecode64,
            Err(AuthError::SessionError(e)) => {
                tracing::warn!(%e, "auth error");
                ctx.deny();
                CodeID::AuthTempError
            }
            Err(AuthError::IO(e)) => todo!("{}", e),
            Err(AuthError::ConfigError(e)) => todo!("{}", e),
        };
        self.reply_in_config(code)
    }

    pub(super) fn on_helo_inner(&mut self, ctx: &mut ReceiverContext, args: HeloArgs) -> Reply {
        self.generic_helo(
            ctx,
            ClientName::Domain(args.client_name),
            true,
            CodeID::Helo,
        )
    }

    pub(super) fn on_ehlo_inner(&mut self, ctx: &mut ReceiverContext, args: EhloArgs) -> Reply {
        self.generic_helo(
            ctx,
            args.client_name,
            false,
            if self
                .state
                .context()
                .read()
                .expect("state poisoned")
                .is_secured()
            {
                CodeID::EhloSecured
            } else {
                CodeID::EhloPain
            },
        )
    }
}

///
pub struct ValidationVSL;

impl rsasl::validate::Validation for ValidationVSL {
    type Value = ();
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error(
        "the rules at stage '{}' returned non '{}' status",
        ExecutionStage::Authenticate,
        Status::Accept(either::Left(CodeID::Ok)).as_ref()
    )]
    NonAcceptCode,
}

struct RsaslSessionCallback {
    rule_engine: std::sync::Arc<RuleEngine>,
    state: std::sync::Arc<RuleState>,
}

impl RsaslSessionCallback {
    #[allow(clippy::unnecessary_wraps)]
    fn inner_validate(
        &self,
        credentials: Credentials,
    ) -> Result<<ValidationVSL as rsasl::validate::Validation>::Value, ValidationError> {
        self.state
            .context()
            .write()
            .expect("state poisoned")
            .with_credentials(credentials)
            .expect("bad state");

        let mut skipped = None;
        let result =
            self.rule_engine
                .run_when(&self.state, &mut skipped, ExecutionStage::Authenticate);

        if !matches!(result, Status::Accept(..)) {
            return Err(ValidationError::NonAcceptCode);
        }

        Ok(())
    }
}

impl rsasl::callback::SessionCallback for RsaslSessionCallback {
    fn callback(
        &self,
        session_data: &rsasl::callback::SessionData,
        context: &rsasl::callback::Context<'_>,
        request: &mut rsasl::callback::Request<'_>,
    ) -> Result<(), rsasl::prelude::SessionError> {
        let _ = (session_data, context, request);
        Ok(())
    }

    fn validate(
        &self,
        session_data: &rsasl::callback::SessionData,
        context: &rsasl::callback::Context<'_>,
        validate: &mut rsasl::validate::Validate<'_>,
    ) -> Result<(), rsasl::validate::ValidationError> {
        let credentials = Credentials::try_from((session_data, context)).map_err(|e| match e {
            vsmtp_common::auth::Error::MissingField => {
                rsasl::validate::ValidationError::MissingRequiredProperty
            }
            otherwise => rsasl::validate::ValidationError::Boxed(Box::new(otherwise)),
        })?;

        validate.with::<ValidationVSL, _>(|| {
            self.inner_validate(credentials)
                .map_err(|e| rsasl::validate::ValidationError::Boxed(Box::new(e)))
        })?;

        Ok(())
    }
}
