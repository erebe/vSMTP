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
use anyhow::Context;
use vsmtp_common::status::Status;

/// Rules that automatically deny the transaction once run.
const DEFAULT_ROOT_FILTERING_RULES: &str = include_str!("../default/root_filter_rules.rhai");
const DEFAULT_FALLBACK_RULES: &str = include_str!("../default/fallback_rules.rhai");
const DEFAULT_INCOMING_RULES: &str = include_str!("../default/incoming_rules.rhai");
const DEFAULT_OUTGOING_RULES: &str = include_str!("../default/outgoing_rules.rhai");
const DEFAULT_INTERNAL_RULES: &str = include_str!("../default/internal_rules.rhai");

const PANIC_MSG_INVALID_DEFAULT: &str = "default value are valid";
const PANIC_MSG_MISSING_DEFAULT: &str = "default value has been set";

/// Encapsulate all ASTs of rules split by domain and transaction type.
#[derive(Debug)]
pub struct SubDomainHierarchy {
    root_filter: Script,
    fallback: Script,
    default_values: DomainDirectives,
    domains: std::collections::BTreeMap<String, DomainDirectives>,
}

// NOTE: using a macro to avoid code duplication and fatal typo.
macro_rules! fn_get_script {
    ($which:tt) => {
        pub(super) fn $which<'t, 'd: 't>(&'t self, domain: &'d DomainDirectives) -> &Script {
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
    pub(super) const fn root_filter(&self) -> &Script {
        &self.root_filter
    }

    /// Used if an error occurred in the hierarchy's logic.
    pub(super) const fn fallback(&self) -> &Script {
        &self.fallback
    }

    pub(super) fn get(&self, domain: &str) -> Option<&DomainDirectives> {
        self.domains.get(domain)
    }

    pub(super) fn get_all(&self) -> impl Iterator<Item = &DomainDirectives> {
        self.domains.values()
    }

    pub(super) fn contains(&self, domain: &str) -> bool {
        self.domains.contains_key(domain)
    }

    fn_get_script!(incoming);
    fn_get_script!(outgoing);
    fn_get_script!(internal);
}

#[derive(Debug)]
pub(super) struct DomainDirectives {
    incoming: Option<Script>,
    outgoing: Option<Script>,
    internal: Option<Script>,
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
pub(super) struct Script {
    directives: Directives,
    ast: rhai::AST,
}

impl Script {
    pub(super) const fn ast(&self) -> &rhai::AST {
        &self.ast
    }

    pub(super) fn directives_at(&self, stage: ExecutionStage) -> Option<&Vec<Directive>> {
        self.directives.get(&stage)
    }

    pub(super) fn directives(&self) -> impl Iterator<Item = &Directive> {
        self.directives.values().flatten()
    }

    pub(super) fn execute(
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

    fn compile_source(engine: &rhai::Engine, source: &str) -> anyhow::Result<Self> {
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
    /// Create a new hierarchy of rules using the rhai engine and a path to the configuration of the server.
    ///
    /// # Errors
    /// * Failed to compile scripts.
    #[tracing::instrument(skip(engine, filter_path, domain_dir), err)]
    pub fn new(
        engine: &rhai::Engine,
        filter_path: &std::path::Path,
        domain_dir: Option<&std::path::Path>,
    ) -> anyhow::Result<Self> {
        let mut hierarchy = std::collections::BTreeMap::new();

        if let Some(domain_dir) = domain_dir {
            tracing::info!(
                "Expecting '{}/**/{{incoming,outgoing,internal}}.vsl'",
                domain_dir.display()
            );

            for entry in std::fs::read_dir(domain_dir).with_context(|| {
                format!("Cannot read domain directory in '{}'", domain_dir.display())
            })? {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    continue;
                }

                let domain_dir = entry.path();
                let domain = domain_dir
                    .file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .ok_or_else(|| anyhow::anyhow!("failed to get file name"))?;

                tracing::info!(domain, "loading domain rules...");

                hierarchy.insert(
                    domain.to_owned(),
                    DomainDirectives::new(engine, &domain_dir)?,
                );
            }
        }

        Ok(Self {
            root_filter: Script::compile_file(engine, filter_path)?.unwrap_or_else(|| {
                Script::compile_source(engine, DEFAULT_ROOT_FILTERING_RULES)
                    .expect(PANIC_MSG_INVALID_DEFAULT)
            }),
            fallback: Script::compile_source(engine, DEFAULT_FALLBACK_RULES)
                .expect(PANIC_MSG_INVALID_DEFAULT),
            default_values: DomainDirectives::default_value(engine),
            domains: hierarchy,
        })
    }

    /// Create a hierarchy with no domains configured and default behavior.
    ///
    /// # Errors
    /// * Fail to compile default scripts.
    pub fn new_empty(engine: &rhai::Engine) -> anyhow::Result<Self> {
        Ok(Self {
            root_filter: Script::compile_source(engine, DEFAULT_ROOT_FILTERING_RULES)
                .expect(PANIC_MSG_INVALID_DEFAULT),
            fallback: Script::compile_source(engine, DEFAULT_FALLBACK_RULES)
                .expect(PANIC_MSG_INVALID_DEFAULT),
            default_values: DomainDirectives::default_value(engine),
            domains: std::collections::BTreeMap::new(),
        })
    }
}

// NOTE: Could be marked as debug, since creating a hierarchy from code is
//       only used in tests.
/// Build a sub-hierarchy from code.
#[derive(Debug)]
pub struct Builder<'a> {
    engine: &'a rhai::Engine,
    inner: SubDomainHierarchy,
}

impl<'a> Builder<'a> {
    /// Create a new builder. The sub-hierarchy will load default deny rules.
    ///
    /// # Errors
    /// * Failed to compile default scripts.
    pub fn new(engine: &'a rhai::Engine) -> anyhow::Result<Self> {
        Ok(Self {
            engine,
            inner: SubDomainHierarchy::new_empty(engine)?,
        })
    }

    /// compile a main script and add it to the hierarchy.
    ///
    /// # Errors
    /// * Failed to compile the script.
    pub fn add_root_filter_rules(mut self, script: &str) -> anyhow::Result<Self> {
        self.inner.root_filter = Script::compile_source(self.engine, script)?;
        Ok(self)
    }

    /// compile incoming, outgoing & internal scripts and add them to a domain of the hierarchy.
    ///     ///
    /// # Errors
    /// * Failed to compile any domain script.
    pub fn add_domain_rules(
        self,
        domain: impl Into<String>,
    ) -> DomainDirectivesBuilder<'a, WantsIncoming> {
        DomainDirectivesBuilder {
            inner: self,
            domain: domain.into(),
            state: WantsIncoming {},
        }
    }

    /// build the sub domain hierarchy.
    #[allow(clippy::missing_const_for_fn)] // false positive.
    #[must_use]
    pub fn build(self) -> SubDomainHierarchy {
        self.inner
    }
}

/// Build domain directives using scripts as input.
#[derive(Debug)]
pub struct DomainDirectivesBuilder<'a, State: std::fmt::Debug> {
    inner: Builder<'a>,
    domain: String,
    state: State,
}

///
#[derive(Debug)]
pub struct WantsIncoming;

impl<'a> DomainDirectivesBuilder<'a, WantsIncoming> {
    /// Add incoming rules for this domain.
    ///
    /// # Errors
    /// * Failed to compile the script.
    pub fn with_incoming(
        self,
        incoming: &str,
    ) -> anyhow::Result<DomainDirectivesBuilder<'a, WantsOutgoing>> {
        Ok(DomainDirectivesBuilder::<'a, WantsOutgoing> {
            state: WantsOutgoing {
                incoming: Script::compile_source(self.inner.engine, incoming)?,
            },
            inner: self.inner,
            domain: self.domain,
        })
    }

    /// Add default incoming rules.
    ///
    /// # Errors
    /// * Failed to compile the script.
    pub fn with_default(self) -> anyhow::Result<DomainDirectivesBuilder<'a, WantsOutgoing>> {
        self.with_incoming(DEFAULT_INCOMING_RULES)
    }
}

///
#[derive(Debug)]
pub struct WantsOutgoing {
    incoming: Script,
}

impl<'a> DomainDirectivesBuilder<'a, WantsOutgoing> {
    /// Add outgoing rules for this domain.
    ///
    /// # Errors
    /// * Failed to compile the script.

    pub fn with_outgoing(
        self,
        outgoing: &str,
    ) -> anyhow::Result<DomainDirectivesBuilder<'a, WantsInternal>> {
        Ok(DomainDirectivesBuilder::<'a, WantsInternal> {
            state: WantsInternal {
                parent: self.state,
                outgoing: Script::compile_source(self.inner.engine, outgoing)?,
            },
            inner: self.inner,
            domain: self.domain,
        })
    }

    /// Add default outgoing rules for this domain.
    ///
    /// # Errors
    /// * Failed to compile the script.
    pub fn with_default(self) -> anyhow::Result<DomainDirectivesBuilder<'a, WantsInternal>> {
        self.with_outgoing(DEFAULT_OUTGOING_RULES)
    }
}

///
#[derive(Debug)]
pub struct WantsInternal {
    parent: WantsOutgoing,
    outgoing: Script,
}

impl<'a> DomainDirectivesBuilder<'a, WantsInternal> {
    /// Add internal rules for this domain.
    ///
    /// # Errors
    /// * Failed to compile the script.
    pub fn with_internal(
        self,
        internal: &str,
    ) -> anyhow::Result<DomainDirectivesBuilder<'a, WantsBuild>> {
        Ok(DomainDirectivesBuilder::<'a, WantsBuild> {
            state: WantsBuild {
                parent: self.state,
                internal: Script::compile_source(self.inner.engine, internal)?,
            },
            inner: self.inner,
            domain: self.domain,
        })
    }

    /// Add default internal rules for this domain.
    ///
    /// # Errors
    /// * Failed to compile the script.
    pub fn with_default(self) -> anyhow::Result<DomainDirectivesBuilder<'a, WantsBuild>> {
        self.with_internal(DEFAULT_INTERNAL_RULES)
    }
}

///
#[derive(Debug)]
pub struct WantsBuild {
    parent: WantsInternal,
    internal: Script,
}

impl<'a> DomainDirectivesBuilder<'a, WantsBuild> {
    /// Build the directive set for the given domain.
    #[allow(clippy::missing_const_for_fn)] // false positive.
    #[must_use]
    pub fn build(mut self) -> Builder<'a> {
        self.inner.inner.domains.insert(
            self.domain,
            DomainDirectives {
                incoming: Some(self.state.parent.parent.incoming),
                outgoing: Some(self.state.parent.outgoing),
                internal: Some(self.state.internal),
            },
        );

        self.inner
    }
}
