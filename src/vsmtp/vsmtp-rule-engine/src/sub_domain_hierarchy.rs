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

use anyhow::Context;
use vsmtp_plugins::rhai;

use crate::{dsl::directives::Directives, RuleEngine};

/// Rules that automatically deny the transaction once run.
const DEFAULT_MAIN_RULES: &str = include_str!("../api/default_main_rules.rhai");
const DEFAULT_FALLBACK_RULES: &str = include_str!("../api/default_fallback_rules.rhai");

const DEFAULT_INCOMING_RULES: &str = include_str!("../api/default_incoming_rules.rhai");
const DEFAULT_OUTGOING_RULES: &str = include_str!("../api/default_outgoing_rules.rhai");
const DEFAULT_INTERNAL_RULES: &str = include_str!("../api/default_internal_rules.rhai");

/// Encapsulate all ASTs of rules split by domain and transaction type.
#[derive(Debug)]
pub struct SubDomainHierarchy {
    /// basic rules called for pre-mail stages.
    pub main: Script,
    /// Post-mail rules executed if the sender's domain isn't found in [`Self::domains`].
    pub fallback: Script,
    /// Domain specific rules, executed following the transaction context.
    pub domains: std::collections::BTreeMap<String, DomainDirectives>,
}

/// Encapsulate all ASTs of rules split transaction type.
#[derive(Debug)]
pub struct DomainDirectives {
    ///
    pub incoming: Script,
    ///
    pub outgoing: Script,
    ///
    pub internal: Script,
}

/// A set of directives and it's underlying Rhai AST.
#[derive(Debug)]
pub struct Script {
    ///
    pub ast: rhai::AST,
    ///
    pub directives: Directives,
}

impl SubDomainHierarchy {
    /// Create a new hierarchy of rules using the rhai engine and a path to the configuration of the server.
    ///
    /// # Errors
    /// * Failed to compile scripts.
    #[tracing::instrument(skip(engine), err)]
    pub fn new(engine: &rhai::Engine, path: &std::path::Path) -> anyhow::Result<Self> {
        let mut hierarchy = std::collections::BTreeMap::new();

        tracing::debug!(
            "Expecting '{}/**/{{incoming,outgoing,internal}}.vsl'",
            path.display()
        );

        // Searching for domain folders.
        for entry in std::fs::read_dir(path).with_context(|| {
            format!(
                "Cannot read subdomain in the directory '{}'",
                path.display()
            )
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

            hierarchy.insert(
                domain.to_owned(),
                DomainDirectives {
                    incoming: Self::rules_from_path_or_default(
                        engine,
                        &domain_dir.join("incoming.vsl"),
                        DEFAULT_INCOMING_RULES,
                    )
                    .with_context(|| {
                        format!(
                            "failed to compile the 'incoming.vsl' script for the '{domain}' domain"
                        )
                    })?,
                    outgoing: Self::rules_from_path_or_default(
                        engine,
                        &domain_dir.join("outgoing.vsl"),
                        DEFAULT_OUTGOING_RULES,
                    )
                    .with_context(|| {
                        format!(
                            "failed to compile the 'outgoing.vsl' script for the '{domain}' domain"
                        )
                    })?,
                    internal: Self::rules_from_path_or_default(
                        engine,
                        &domain_dir.join("internal.vsl"),
                        DEFAULT_INTERNAL_RULES,
                    )
                    .with_context(|| {
                        format!(
                            "failed to compile the 'internal.vsl' script for the '{domain}' domain"
                        )
                    })?,
                },
            );
        }

        Ok(Self {
            main: Self::rules_from_path_or_default(
                engine,
                &path.join("main.vsl"),
                DEFAULT_MAIN_RULES,
            )
            .context("failed to load your rule entrypoint file (main.vsl)")?,
            fallback: Self::rules_from_path_or_default(
                engine,
                &path.join("fallback.vsl"),
                DEFAULT_FALLBACK_RULES,
            )
            .context("failed to load your rule fallback file (fallback.vsl)")?,
            domains: hierarchy,
        })
    }

    /// Create a hierarchy with no domains configured and default behavior.
    ///
    /// # Errors
    /// * Fail to compile default scripts.
    pub fn new_empty(engine: &rhai::Engine) -> anyhow::Result<Self> {
        Ok(Self {
            main: Self::rules_from_script(engine, DEFAULT_MAIN_RULES)?,
            fallback: Self::rules_from_script(engine, DEFAULT_FALLBACK_RULES)?,
            domains: std::collections::BTreeMap::new(),
        })
    }

    /// Create rules from a path, use a default script if the default path could not be loaded
    fn rules_from_path_or_default(
        engine: &rhai::Engine,
        path: &std::path::Path,
        default: &str,
    ) -> anyhow::Result<Script> {
        std::fs::read_to_string(path).map_or_else(
            |error| {
                tracing::warn!(
                    %error, "script at {path:?} could not be loaded, using default rules instead"
                );

                Self::rules_from_script(engine, default)
            },
            |script| Self::rules_from_script(engine, &script),
        )
    }

    /// Create rules by compiling the given script and return it's AST and extracted directives.
    fn rules_from_script(engine: &rhai::Engine, script: &str) -> anyhow::Result<Script> {
        let ast = engine
            .compile_into_self_contained(&rhai::Scope::new(), script)
            .map_err(|err| anyhow::anyhow!("failed to compile vsl scripts: {err}"))?;

        let directives = RuleEngine::extract_directives(engine, &ast)?;

        Ok(Script { ast, directives })
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
    pub fn add_main_rules(mut self, script: &str) -> anyhow::Result<Self> {
        self.inner.main = SubDomainHierarchy::rules_from_script(self.engine, script)?;
        Ok(self)
    }

    /// compile a fallback script and add it to the hierarchy.
    ///     ///
    /// # Errors
    /// * Failed to compile the script.

    pub fn add_fallback_rules(mut self, script: &str) -> anyhow::Result<Self> {
        self.inner.fallback = SubDomainHierarchy::rules_from_script(self.engine, script)?;
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
                incoming: SubDomainHierarchy::rules_from_script(self.inner.engine, incoming)?,
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
                outgoing: SubDomainHierarchy::rules_from_script(self.inner.engine, outgoing)?,
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
                internal: SubDomainHierarchy::rules_from_script(self.inner.engine, internal)?,
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
                incoming: self.state.parent.parent.incoming,
                outgoing: self.state.parent.outgoing,
                internal: self.state.internal,
            },
        );

        self.inner
    }
}
