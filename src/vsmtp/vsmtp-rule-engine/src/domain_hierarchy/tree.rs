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

use crate::{
    api::state::deny, dsl::directives::Directives, Directive, ExecutionStage, RuleEngine, RuleState,
};
use vsmtp_common::status::Status;
use vsmtp_common::{domain_iter, Domain};
use vsmtp_config::field::{FieldAppVSL, FieldServerVirtual};

/// Rules that automatically deny the transaction once run.
const DEFAULT_ROOT_FILTERING_RULES: &str = include_str!("../../default/root_filter_rules.rhai");
const DEFAULT_FALLBACK_RULES: &str = include_str!("../../default/fallback_rules.rhai");

const DEFAULT_INCOMING_RULES: &str = include_str!("../../default/incoming_rules.rhai");
const DEFAULT_OUTGOING_RULES: &str = include_str!("../../default/outgoing_rules.rhai");
const DEFAULT_INTERNAL_RULES: &str = include_str!("../../default/internal_rules.rhai");

const PANIC_MSG_INVALID_DEFAULT: &str = "default value are valid";
const PANIC_MSG_MISSING_DEFAULT: &str = "default value has been set";

/// Encapsulate all ASTs of rules split by domain and transaction type.
#[derive(Debug)]
pub struct SubDomainHierarchy {
    pub(super) root_filter: Script,
    pub(super) fallback: Script,
    pub(super) default_values: DomainDirectives,
    pub(super) domains: std::collections::BTreeMap<Domain, DomainDirectives>,
}

// NOTE: using a macro to avoid code duplication and fatal typo.
macro_rules! fn_get_script {
    ($which:tt) => {
        pub(crate) fn $which<'t, 'd: 't>(&'t self, domain: &'d DomainDirectives) -> &Script {
            domain.$which.as_ref().unwrap_or_else(|| {
                self.default_values
                    .$which
                    .as_ref()
                    .expect(PANIC_MSG_MISSING_DEFAULT)
            })
        }
    };
}

impl SubDomainHierarchy {
    /// Generic rules called for pre-mail stages to every transactions.
    pub(crate) const fn root_filter(&self) -> &Script {
        &self.root_filter
    }

    /// Used if an error occurred in the hierarchy's logic.
    pub(crate) const fn fallback(&self) -> &Script {
        &self.fallback
    }

    pub(crate) fn get_all(&self) -> impl Iterator<Item = &DomainDirectives> {
        self.domains.values()
    }

    fn_get_script!(incoming);
    fn_get_script!(outgoing);
    fn_get_script!(internal);

    /// Return the directives for the given domain **or any parent domain**.
    pub(crate) fn get_any(&self, domain: &Domain) -> Option<&DomainDirectives> {
        let domain_str = domain.to_string();
        domain_iter(&domain_str).find_map(|parent| {
            self.domains
                .get(&<Domain as std::str::FromStr>::from_str(parent).expect("domain is valid"))
        })
    }
}

#[derive(Debug)]
pub struct DomainDirectives {
    pub(super) incoming: Option<Script>,
    pub(super) outgoing: Option<Script>,
    pub(super) internal: Option<Script>,
}

impl DomainDirectives {
    #[tracing::instrument(skip(engine, domain_dir), err)]
    fn new(engine: &rhai::Engine, domain_dir: &std::path::Path) -> anyhow::Result<Self> {
        Ok(Self {
            incoming: Script::compile_file(engine, &domain_dir.join("incoming.vsl"))?,
            outgoing: Script::compile_file(engine, &domain_dir.join("outgoing.vsl"))?,
            internal: Script::compile_file(engine, &domain_dir.join("internal.vsl"))?,
        })
    }

    fn default_value(engine: &rhai::Engine) -> Self {
        Self {
            incoming: Some(
                Script::compile_source(engine, DEFAULT_INCOMING_RULES)
                    .expect(PANIC_MSG_INVALID_DEFAULT),
            ),
            internal: Some(
                Script::compile_source(engine, DEFAULT_INTERNAL_RULES)
                    .expect(PANIC_MSG_INVALID_DEFAULT),
            ),
            outgoing: Some(
                Script::compile_source(engine, DEFAULT_OUTGOING_RULES)
                    .expect(PANIC_MSG_INVALID_DEFAULT),
            ),
        }
    }
}

#[derive(Debug)]
pub struct Script {
    directives: Directives,
    ast: rhai::AST,
}

impl Script {
    pub(crate) const fn ast(&self) -> &rhai::AST {
        &self.ast
    }

    pub(crate) fn directives_at(&self, stage: ExecutionStage) -> Option<&Vec<Directive>> {
        self.directives.get(&stage)
    }

    pub(crate) fn directives(&self) -> impl Iterator<Item = &Directive> {
        self.directives.values().flatten()
    }

    pub(crate) fn execute(
        rule_state: &RuleState,
        ast: &rhai::AST,
        directives: &[Directive],
        smtp_state: ExecutionStage,
    ) -> Status {
        let mut status = Status::Next;

        for directive in directives {
            status = directive
                .execute(rule_state, ast, smtp_state)
                .unwrap_or_else(|e| {
                    let error_status = deny();
                    tracing::warn!(%e, "error while executing directive returning: {:?}", error_status);
                    error_status
                });

            if status != Status::Next {
                break;
            }
        }

        status
    }

    #[tracing::instrument(skip(engine), err)]
    fn compile_file(engine: &rhai::Engine, path: &std::path::Path) -> anyhow::Result<Option<Self>> {
        match std::fs::read_to_string(path) {
            Ok(source) => Some(Self::compile_source(engine, &source)).transpose(),
            // NOTE: file not found (os error 2) is acceptable as scripts are optional.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                tracing::warn!("script not found, using default rules instead");
                Ok(None)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub(super) fn compile_source(engine: &rhai::Engine, source: &str) -> anyhow::Result<Self> {
        tracing::trace!(%source, "compiling script...");

        let ast = engine
            .compile_into_self_contained(&rhai::Scope::new(), source)
            .map_err(|err| anyhow::anyhow!("failed to compile vsl scripts: {err}"))?;

        Ok(Self {
            directives: RuleEngine::extract_directives(engine, &ast)?,
            ast,
        })
    }
}

impl SubDomainHierarchy {
    /// Create a new hierarchy of rules using the rhai engine.
    ///
    /// # Errors
    ///
    /// * Failed to compile scripts.
    #[tracing::instrument(skip(engine, config, domains), err)]
    pub fn new(
        engine: &rhai::Engine,
        config: &FieldAppVSL,
        domains: &std::collections::BTreeMap<Domain, FieldServerVirtual>,
    ) -> anyhow::Result<Self> {
        match &config {
            FieldAppVSL {
                filter_path: Some(filter_path),
                domain_dir,
            } => {
                tracing::info!("Analyzing vSL rules at {}", filter_path.display());

                Ok(Self {
                    root_filter: Script::compile_file(engine, filter_path)?.unwrap_or_else(|| {
                        Script::compile_source(engine, DEFAULT_ROOT_FILTERING_RULES)
                            .expect(PANIC_MSG_INVALID_DEFAULT)
                    }),
                    fallback: Script::compile_source(engine, DEFAULT_FALLBACK_RULES)
                        .expect(PANIC_MSG_INVALID_DEFAULT),
                    default_values: DomainDirectives::default_value(engine),
                    domains: if let Some(domain_dir) = domain_dir {
                        tracing::info!(
                            "Expecting '{}/**/{{incoming,outgoing,internal}}.vsl'",
                            domain_dir.display()
                        );

                        Some(
                            domains
                                .keys()
                                .map(|domain| {
                                    tracing::info!(?domain, "loading domain rules...");
                                    DomainDirectives::new(
                                        engine,
                                        &domain_dir.join(domain.to_string()),
                                    )
                                    .map(|d| (domain.clone(), d))
                                })
                                .collect::<Result<std::collections::BTreeMap<_, _>, _>>()?,
                        )
                    } else {
                        None
                    }
                    .unwrap_or_default(),
                })
            }
            FieldAppVSL {
                filter_path: None, ..
            } => {
                tracing::warn!(
                    "No 'filter.vsl' provided in the config, the server will deny any incoming transaction by default."
                );
                Ok(Self::new_empty(engine))
            }
        }
    }

    pub(super) fn new_empty(engine: &rhai::Engine) -> Self {
        Self {
            root_filter: Script::compile_source(engine, DEFAULT_ROOT_FILTERING_RULES)
                .expect(PANIC_MSG_INVALID_DEFAULT),
            fallback: Script::compile_source(engine, DEFAULT_FALLBACK_RULES)
                .expect(PANIC_MSG_INVALID_DEFAULT),
            default_values: DomainDirectives::default_value(engine),
            domains: std::collections::BTreeMap::new(),
        }
    }
}
