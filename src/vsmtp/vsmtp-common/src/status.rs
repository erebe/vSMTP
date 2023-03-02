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

use crate::ReplyOrCodeID;

// NOTE: only in this crate and not the rule-engine one because of the [`Context::skipped`] field.
/// Status of the mail context treated by the rule engine.
#[derive(Debug, Clone, PartialEq, Eq, strum::AsRefStr, serde::Deserialize, serde::Serialize)]
#[strum(serialize_all = "snake_case")]
pub enum Status {
    /// accepts the current stage value, skips all rules in the stage.
    Accept(ReplyOrCodeID),

    /// continue to the next rule / stage.
    Next,

    /// immediately stops the transaction and send an error code.
    Deny(ReplyOrCodeID),

    /// ignore all future rules for the transaction.
    Faccept(ReplyOrCodeID),

    /// ignore all future rules for the transaction.
    /// the String parameter is the path to the quarantine folder.
    /// this status disable delivery to all recipients.
    Quarantine(String),

    /// the email as been delegated to another service.
    // #[cfg(feature = "delegation")]
    #[serde(skip)]
    Delegated(SmtpConnection),

    /// the rule engine must skip all rules until a given
    /// rule received in the email's header.
    // #[cfg(feature = "delegation")]
    DelegationResult,
}

impl Status {
    /// Should the evaluation of the rules finish ?
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        matches!(
            self,
            Self::Faccept(_) | Self::Deny(_) | Self::Quarantine(_) | Self::Delegated(_)
        )
    }
}

/// a transport using the smtp protocol.
/// (mostly a new type over `lettre::SmtpTransport` to implement debug
/// and make switching transport easy if needed)
#[derive(Clone)]
pub struct SmtpConnection(pub std::sync::Arc<std::sync::Mutex<lettre::SmtpTransport>>);

impl Eq for SmtpConnection {}
impl PartialEq for SmtpConnection {
    fn eq(&self, _: &Self) -> bool {
        false
    }
}

impl std::fmt::Debug for SmtpConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SmtpTransport").finish()
    }
}
