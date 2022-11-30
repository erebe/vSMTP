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
use vsmtp_mail_parser::MessageBody;

/// a state container that bridges rhai's & rust contexts.
#[derive(Debug)]
pub struct RuleState {
    pub(super) engine: rhai::Engine,
    pub(super) server: Server,
    pub(super) mail_context: Context,
    pub(super) message: Message,
}

impl RuleState {
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

    /// get the engine used to evaluate rules for this state.
    #[must_use]
    pub const fn engine(&self) -> &rhai::Engine {
        &self.engine
    }

    /// Consume the instance and return the inner [`Context`] and [`MessageBody`]
    #[must_use]
    pub fn take(self: std::sync::Arc<Self>) -> (vsmtp_common::Context, MessageBody) {
        let this = std::sync::Arc::try_unwrap(self).expect("Arc: strong reference alive");

        // early drop of engine because a strong reference is living inside
        drop(this.engine);
        (
            std::sync::Arc::try_unwrap(this.mail_context)
                .expect("Arc: strong reference alive")
                .into_inner()
                .expect("RwLock: is poisoned"),
            std::sync::Arc::try_unwrap(this.message)
                .expect("Arc: strong reference alive")
                .into_inner()
                .expect("RwLock: is poisoned"),
        )
    }
}
