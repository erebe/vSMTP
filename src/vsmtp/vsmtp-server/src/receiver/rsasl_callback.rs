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

use vqueue::GenericQueueManager;
use vsmtp_common::{
    auth::{Credentials, Mechanism},
    mail_context::ConnectionContext,
    state::State,
    status::Status,
};
use vsmtp_config::{Config, Resolvers};
use vsmtp_rule_engine::{RuleEngine, RuleState};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("mechanism unsupported: `{0}`")]
    UnsupportedMechanism(String),
    #[error("mechanism unsupported: `{0}`")]
    Utf8(std::str::Utf8Error),
    #[error("the rule engine returned an error: `{0:?}`")]
    RuleEngineResult(Status),
}

///
pub struct ValidationVSL;

impl rsasl::validate::Validation for ValidationVSL {
    type Value = (ConnectionContext, Option<Status>);
}

///
pub struct Callback {
    ///
    pub rule_engine: std::sync::Arc<RuleEngine>,
    ///
    pub resolvers: std::sync::Arc<Resolvers>,
    ///
    pub queue_manager: std::sync::Arc<dyn GenericQueueManager>,
    ///
    pub config: std::sync::Arc<Config>,
    ///
    pub conn_ctx: ConnectionContext,
}

impl Callback {
    fn inner_validate(
        &self,
        credentials: &Credentials,
    ) -> Result<<ValidationVSL as rsasl::validate::Validation>::Value, Error> {
        let mut rule_state = RuleState::with_connection(
            self.config.clone(),
            self.resolvers.clone(),
            self.queue_manager.clone(),
            &self.rule_engine,
            ConnectionContext {
                credentials: Some(credentials.clone()),
                ..self.conn_ctx.clone()
            },
        );

        // NOTE: could use `just_run_here` ?

        let result = self
            .rule_engine
            .run_when(&mut rule_state, State::Authenticate);

        if !matches!(result, Status::Accept(..)) {
            return Err(Error::RuleEngineResult(result));
        }

        let (ctx, _, skipped) = rule_state.take().expect("no strong reference here");

        Ok((ctx.connection, skipped))
    }
}

impl rsasl::callback::SessionCallback for Callback {
    fn callback(
        &self,
        session_data: &rsasl::callback::SessionData,
        context: &rsasl::callback::Context<'_>,
        request: &mut rsasl::callback::Request<'_>,
    ) -> Result<(), rsasl::prelude::SessionError> {
        let _ = (session_data, context, request);
        todo!()
    }

    fn validate(
        &self,
        session_data: &rsasl::callback::SessionData,
        context: &rsasl::callback::Context<'_>,
        validate: &mut rsasl::validate::Validate<'_>,
    ) -> Result<(), rsasl::validate::ValidationError> {
        let credentials = match session_data.mechanism().mechanism {
            mech if mech == Mechanism::Plain.as_ref() || mech == Mechanism::Login.as_ref() => {
                Credentials::Verify {
                    authid: context
                        .get_ref::<rsasl::property::AuthId>()
                        .ok_or(rsasl::validate::ValidationError::MissingRequiredProperty)?
                        .to_string(),
                    authpass: std::str::from_utf8(
                        context
                            .get_ref::<rsasl::property::Password>()
                            .ok_or(rsasl::validate::ValidationError::MissingRequiredProperty)?,
                    )
                    .map_err(|e| rsasl::validate::ValidationError::Boxed(Box::new(Error::Utf8(e))))?
                    .to_string(),
                }
            }
            mech if mech == Mechanism::Anonymous.as_ref() => Credentials::AnonymousToken {
                token: context
                    .get_ref::<rsasl::mechanisms::anonymous::AnonymousToken>()
                    .ok_or(rsasl::validate::ValidationError::MissingRequiredProperty)?
                    .to_string(),
            },
            mech if mech == Mechanism::CramMd5.as_ref() => todo!(),
            otherwise => {
                return Err(rsasl::validate::ValidationError::Boxed(Box::new(
                    Error::UnsupportedMechanism(otherwise.to_string()),
                )));
            }
        };

        validate.with::<ValidationVSL, _>(|| {
            self.inner_validate(&credentials)
                .map_err(|e| rsasl::validate::ValidationError::Boxed(Box::new(e)))
        })?;

        Ok(())
    }
}
