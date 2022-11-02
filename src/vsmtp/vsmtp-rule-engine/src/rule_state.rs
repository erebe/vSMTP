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
use crate::api::{Context, Message, Server};
use crate::rule_engine::RuleEngine;
use vsmtp_common::mail_context::{Connect, MailContextAPI};
use vsmtp_common::status::Status;
use vsmtp_mail_parser::MessageBody;
use vsmtp_plugins::rhai;

/// a state container that bridges rhai's & rust contexts.
pub struct RuleState {
    /// A lightweight engine for evaluation.
    pub(super) engine: rhai::Engine,
    /// A pointer to the server api.
    pub(super) server: Server,
    /// A pointer to the mail context for the current connection.
    pub(super) mail_context: Context,
    /// A pointer to the mail body for the current connection.
    pub(super) message: Message,
    // NOTE: we could replace this property by a `skip` function on
    //       the `Status` enum.
    /// A state to check if the next rules need to be executed or skipped.
    pub(super) skip: Option<Status>,
}

impl RuleState {
    /// create a new rule state with connection data.
    #[must_use]
    pub fn with_connection(rule_engine: &RuleEngine, conn: Connect) -> Self {
        let state = rule_engine.spawn();

        // TODO: update skip state for delegation.
        // // all rule are skipped until the designated rule
        // // in case of a delegation result.
        // #[cfg(feature = "delegation")]
        // if rule_engine
        //     .rules
        //     .iter()
        //     .flat_map(|(_, d)| d)
        //     .any(|d| match d {
        //         Directive::Delegation { service, .. } => service.receiver == conn.server_addr,
        //         _ => false,
        //     })
        // {
        //     state.skip = Some(Status::DelegationResult);
        // }

        state
            .mail_context
            .write()
            .expect("`mail_context` mutex cannot be poisoned here")
            .set_state_connect(conn);

        state
    }

    /// create a `RuleState` from an existing mail context (f.e. when deserializing a context)
    #[must_use]
    pub fn with_context(
        rule_engine: &RuleEngine,
        mail_context: MailContextAPI,
        message: MessageBody,
    ) -> Self {
        // all rule are skipped until the designated rule
        // in case of a delegation result.
        let skip = mail_context.skipped().cloned();

        let mut this = rule_engine.spawn_with(mail_context, message);
        this.skip = skip;
        this
    }

    /// fetch the email context (possibly) mutated by the user's rules.
    #[must_use]
    pub fn context(&self) -> Context {
        self.mail_context.clone()
    }

    /// fetch the message body (possibly) mutated by the user's rules.
    #[must_use]
    pub fn message(&self) -> Message {
        self.message.clone()
    }

    /// Consume the instance and return the inner [`MailContextAPI`] and [`MessageBody`]
    ///
    /// # Errors
    ///
    /// * at least one strong reference of the [`std::sync::Arc`] is living
    /// * the [`std::sync::RwLock`] is poisoned
    pub fn take(self) -> anyhow::Result<(MailContextAPI, MessageBody, Option<Status>)> {
        // early drop of engine because a strong reference is living inside
        let skipped = self.skipped().cloned();
        drop(self.engine);
        Ok((
            std::sync::Arc::try_unwrap(self.mail_context)
                .map_err(|_| {
                    anyhow::anyhow!("strong reference of the field `mail_context` exists")
                })?
                .into_inner()?,
            std::sync::Arc::try_unwrap(self.message)
                .map_err(|_| anyhow::anyhow!("strong reference of the field `message` exists"))?
                .into_inner()?,
            skipped,
        ))
    }

    /// get the engine used to evaluate rules for this state.
    #[must_use]
    pub const fn engine(&self) -> &rhai::Engine {
        &self.engine
    }

    /// have all rules been skipped ?
    #[must_use]
    pub const fn skipped(&self) -> Option<&Status> {
        self.skip.as_ref()
    }

    /// future rule execution need to be skipped for this state.
    pub fn skipping(&mut self, status: Status) {
        self.skip = Some(status);
    }

    /// future rules can be resumed.
    pub fn resume(&mut self) {
        self.skip = None;
    }
}
