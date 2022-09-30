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

use super::service::Service;
use crate::{api::EngineResult, rule_state::RuleState, vsl_guard_ok};
use vsmtp_common::{state::State, status::Status};

/// a set of directives, filtered by smtp stage.
pub type Directives = std::collections::BTreeMap<State, Vec<Directive>>;

/// a type of rule that can be executed from a function pointer.
#[derive(strum::AsRefStr)]
#[strum(serialize_all = "lowercase")]
pub enum Directive {
    /// execute code that return a status.
    Rule { name: String, pointer: rhai::FnPtr },
    /// execute code that does not need a return value.
    Action { name: String, pointer: rhai::FnPtr },
    /// delegate a message to a service, and execute the
    /// inner rhai function when the message is forwarded
    /// to the service receive endpoint.
    Delegation {
        name: String,
        pointer: rhai::FnPtr,
        service: std::sync::Arc<Service>,
    },
}

impl std::fmt::Debug for Directive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Directive")
            .field("type", &self.as_ref())
            .field("name", &self.name())
            .finish_non_exhaustive()
    }
}

impl Directive {
    /// Get the name of the directive.
    pub fn name(&self) -> &str {
        match self {
            Self::Delegation { name, .. } | Self::Rule { name, .. } | Self::Action { name, .. } => {
                name
            }
        }
    }

    /// Execute the content of the directive.
    pub fn execute(
        &self,
        rule_state: &mut RuleState,
        ast: &rhai::AST,
        stage: State,
    ) -> EngineResult<Status> {
        match self {
            Directive::Rule { pointer, .. } => {
                rule_state
                    .engine()
                    .call_fn(&mut rhai::Scope::new(), ast, pointer.fn_name(), ())
            }
            Directive::Action { pointer, .. } => {
                rule_state
                    .engine()
                    .call_fn(&mut rhai::Scope::new(), ast, pointer.fn_name(), ())?;

                Ok(Status::Next)
            }
            Directive::Delegation {
                pointer,
                service,
                name,
            } => {
                if let Service::Smtp { delegator, .. } = &**service {
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
                    return match args {
                        Some(header_directive) if header_directive == *name => rule_state
                            .engine()
                            .call_fn(&mut rhai::Scope::new(), ast, pointer.fn_name(), ()),
                        _ => {
                            // FIXME: fold this header.
                            vsl_guard_ok!(rule_state.message().write()).prepend_header(
                                "X-VSMTP-DELEGATION",
                                &format!(
                                    "sent; stage={stage}; directive=\"{name}\"; id=\"{}\"",
                                    vsl_guard_ok!(rule_state.context().read())
                                        .metadata
                                        .message_id
                                        .as_ref()
                                        .unwrap()
                                ),
                            );

                            Ok(Status::Delegated(delegator.clone()))
                        }
                    };
                }

                Err(format!(
                    "cannot delegate security using a '{service}' service in {stage}: '{name}'.",
                )
                .into())
            }
        }
    }
}
