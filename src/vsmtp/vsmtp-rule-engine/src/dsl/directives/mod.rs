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

use crate::{rule_state::RuleState, vsl_guard_ok, ExecutionStage};
use vsmtp_common::status::Status;

pub mod action;
#[cfg(feature = "delegation")]
pub mod delegation;
pub mod rule;

pub type Directives = std::collections::BTreeMap<ExecutionStage, Vec<Directive>>;

///
#[derive(strum::AsRefStr)]
#[strum(serialize_all = "lowercase")]
pub enum Directive {
    /// execute code that return a status.
    Rule {
        ///
        name: String,
        ///
        pointer: rhai::FnPtr,
    },
    /// execute code that does not need a return value.
    Action {
        ///
        name: String,
        ///
        pointer: rhai::FnPtr,
    },
    /// delegate a message to a service, and execute the
    /// inner rhai function when the message is forwarded
    /// to the service receive endpoint.
    #[cfg(feature = "delegation")]
    Delegation {
        ///
        name: String,
        ///
        pointer: rhai::FnPtr,
        ///
        service: std::sync::Arc<crate::dsl::smtp::service::Smtp>,
    },
}

impl std::fmt::Debug for Directive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct(self.as_ref())
            .field("name", &self.name())
            .finish_non_exhaustive()
    }
}

#[must_use]
#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    #[error("vsl execution produced an error: {0}")]
    RuntimeError(#[from] Box<rhai::EvalAltResult>),
    // NOTE: non exhaustive for delegation error ?
}

impl Directive {
    pub(crate) fn parse_directive(
        symbols: &[rhai::ImmutableString],
        look_ahead: &str,
        state: &mut rhai::Dynamic,
    ) -> Result<Option<rhai::ImmutableString>, rhai::ParseError> {
        if symbols.len() == 1 {
            *state = rhai::Dynamic::from(symbols[0].clone());
        }

        let directive_type = state.to_string();

        match symbols.len() {
            // In case of a delegation, we need to associate a smtp service.
            // 'delegate' -> service.
            #[cfg(feature = "delegation")]
            1 if directive_type.as_str() == "delegate" => Ok(Some("$expr$".into())),
            // service    -> directive name
            #[cfg(feature = "delegation")]
            2 if directive_type.as_str() == "delegate" => Ok(Some("$string$".into())),
            // dn         -> directive body
            #[cfg(feature = "delegation")]
            3 if directive_type.as_str() == "delegate" => Ok(Some("$expr$".into())),
            #[cfg(feature = "delegation")]
            4 if directive_type.as_str() == "delegate" => Ok(None),

            // For any other directive ...
            // directive keyword -> directive name
            1 => Ok(Some("$string$".into())),
            // directive name    -> directive body
            2 => Ok(Some("$expr$".into())),
            3 => Ok(None),

            _ => Err(rhai::ParseError(
                Box::new(rhai::ParseErrorType::BadInput(
                    rhai::LexError::UnexpectedInput(format!(
                        "Improper {directive_type} declaration: the '{look_ahead}' keyword is unknown.",
                    )),
                )),
                rhai::Position::NONE,
            )),
        }
    }

    pub(crate) fn name(&self) -> &str {
        match self {
            #[cfg(feature = "delegation")]
            Self::Delegation { name, .. } => name,
            Self::Rule { name, .. } | Self::Action { name, .. } => name,
        }
    }

    #[tracing::instrument(skip(rule_state, ast, stage), ret, err)]
    pub(crate) fn execute(
        &self,
        rule_state: &RuleState,
        ast: &rhai::AST,
        stage: ExecutionStage,
    ) -> Result<Status, ExecutionError> {
        match self {
            Self::Rule { pointer, .. } => rule_state
                .engine()
                .call_fn(&mut rhai::Scope::new(), ast, pointer.fn_name(), ())
                .map_err(Into::into),
            Self::Action { pointer, .. } => {
                rule_state
                    .engine()
                    .call_fn(&mut rhai::Scope::new(), ast, pointer.fn_name(), ())?;

                Ok(Status::Next)
            }
            #[cfg(feature = "delegation")]
            Self::Delegation {
                pointer,
                service,
                name,
            } => {
                let args = vsl_guard_ok!(rule_state.message().read())
                    .get_header("X-VSMTP-DELEGATION")
                    .and_then(|header| {
                        vsmtp_mail_parser::get_mime_header("X-VSMTP-DELEGATION", &header)
                            .args
                            .get("directive")
                            .cloned()
                    });

                // FIXME: This check is made twice (once in RuleEngine::run_when).
                //
                // If the 'directive' field set in the header matches the name
                // of the current directive, we pull old context from the working
                // queue and run the block of code.
                // Otherwise, we add the X-VSMTP-DELEGATION to the message.
                match args {
                    Some(header_directive) if header_directive == *name => rule_state
                        .engine()
                        .call_fn(&mut rhai::Scope::new(), ast, pointer.fn_name(), ())
                        .map_err(Into::into),
                    _ => {
                        vsl_guard_ok!(rule_state.message().write()).prepend_header(
                            "X-VSMTP-DELEGATION",
                            &format!(
                                "sent; stage={stage}; directive=\"{name}\"; id=\"{}\"",
                                vsl_guard_ok!(rule_state.context().read())
                                    .message_uuid()
                                    .unwrap()
                            ),
                        );

                        Ok(Status::Delegated(service.delegator.clone()))
                    }
                }
            }
        }
    }
}
