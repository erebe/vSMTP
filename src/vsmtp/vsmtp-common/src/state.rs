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

/// State of the pipeline SMTP
#[derive(
    Debug,
    Eq,
    PartialEq,
    Hash,
    Copy,
    Clone,
    Ord,
    PartialOrd,
    serde_with::DeserializeFromStr,
    serde_with::SerializeDisplay,
    strum::EnumString,
    strum::Display,
)]
#[strum(serialize_all = "lowercase")]
pub enum State {
    /// After TCP/IP socket has been accepted
    Connect,
    /// After receiving HELO/EHLO command
    Helo,
    /// After receiving AUTH command
    Authenticate,
    /// After receiving MAIL FROM command
    #[strum(serialize = "mail")]
    MailFrom,
    /// After receiving RCPT TO command
    #[strum(serialize = "rcpt")]
    RcptTo,
    /// Before write on disk
    PreQ,
    /// After write on disk & connection closed
    PostQ,
    /// Right before sending to recipient
    Delivery,
}

impl State {
    /// As the email been received at the current stage ?
    #[must_use]
    pub const fn is_email_received(&self) -> bool {
        matches!(self, Self::PostQ | Self::Delivery)
    }
}
