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
use super::tree::{DomainDirectives, Script};
use crate::SubDomainHierarchy;
use vsmtp_common::Domain;

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
    pub fn new(engine: &'a rhai::Engine) -> Self {
        Self {
            engine,
            inner: SubDomainHierarchy::new_empty(engine),
        }
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
    ///
    /// # Errors
    /// * Failed to compile any domain script.
    #[must_use]
    pub const fn add_domain_rules(
        self,
        domain: Domain,
    ) -> DomainDirectivesBuilder<'a, WantsIncoming> {
        DomainDirectivesBuilder {
            inner: self,
            domain,
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
#[allow(clippy::module_name_repetitions)]
pub struct DomainDirectivesBuilder<'a, State: std::fmt::Debug> {
    inner: Builder<'a>,
    domain: Domain,
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
                incoming: Some(Script::compile_source(self.inner.engine, incoming)?),
            },
            inner: self.inner,
            domain: self.domain,
        })
    }

    /// Add default incoming rules.
    ///
    /// # Errors
    /// * Failed to compile the script.
    #[allow(clippy::missing_const_for_fn)] // false positive.
    pub fn with_default(self) -> DomainDirectivesBuilder<'a, WantsOutgoing> {
        DomainDirectivesBuilder::<'a, WantsOutgoing> {
            state: WantsOutgoing { incoming: None },
            inner: self.inner,
            domain: self.domain,
        }
    }
}

///
#[derive(Debug)]
pub struct WantsOutgoing {
    incoming: Option<Script>,
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
                outgoing: Some(Script::compile_source(self.inner.engine, outgoing)?),
            },
            inner: self.inner,
            domain: self.domain,
        })
    }

    /// Add default outgoing rules for this domain.
    ///
    /// # Errors
    #[allow(clippy::missing_const_for_fn)] // false positive.
    pub fn with_default(self) -> DomainDirectivesBuilder<'a, WantsInternal> {
        DomainDirectivesBuilder::<'a, WantsInternal> {
            state: WantsInternal {
                parent: self.state,
                outgoing: None,
            },
            inner: self.inner,
            domain: self.domain,
        }
    }
}

///
#[derive(Debug)]
pub struct WantsInternal {
    parent: WantsOutgoing,
    outgoing: Option<Script>,
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
                internal: Some(Script::compile_source(self.inner.engine, internal)?),
            },
            inner: self.inner,
            domain: self.domain,
        })
    }

    /// Add default internal rules for this domain.
    ///
    /// # Errors
    #[allow(clippy::missing_const_for_fn)] // false positive.
    pub fn with_default(self) -> DomainDirectivesBuilder<'a, WantsBuild> {
        DomainDirectivesBuilder::<'a, WantsBuild> {
            state: WantsBuild {
                parent: self.state,
                internal: None,
            },
            inner: self.inner,
            domain: self.domain,
        }
    }
}

///
#[derive(Debug)]
pub struct WantsBuild {
    parent: WantsInternal,
    internal: Option<Script>,
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
