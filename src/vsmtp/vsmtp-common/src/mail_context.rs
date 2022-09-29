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
use crate::{auth::Credentials, envelop::Envelop, status::Status};
use vsmtp_auth::{dkim, spf};

/// average size of a mail
pub const MAIL_CAPACITY: usize = 10_000_000; // 10MB

/// metadata
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct MessageMetadata {
    /// instant when the last "MAIL FROM" has been received.
    pub timestamp: Option<std::time::SystemTime>,
    /// unique id generated when the "MAIL FROM" has been received.
    /// format: {mail timestamp}{connection timestamp}{process id}
    // TODO: use uuid format
    pub message_id: Option<String>,
    /// whether further rule analysis has been skipped.
    pub skipped: Option<Status>,
    /// result of the spf evaluation.
    pub spf: Option<spf::Result>,
    /// result of the dkim verification
    pub dkim: Option<dkim::VerificationResult>,
}

/// Representation of one connection
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ConnectionContext {
    /// time of connection by the client.
    pub timestamp: std::time::SystemTime,
    /// emitter of the mail
    pub client_addr: std::net::SocketAddr,
    /// credentials of the client.
    pub credentials: Option<Credentials>,
    /// server's domain of the connection. (from config.server.domain or sni)
    pub server_name: String,
    /// server socket used for this connection.
    pub server_addr: std::net::SocketAddr,
    /// is the client authenticated by the sasl protocol ?
    pub is_authenticated: bool,
    /// is the connection under tls ?
    pub is_secured: bool,
    /// number of error the client made so far
    pub error_count: i64,
    /// number of time the AUTH command has been received (and failed)
    pub authentication_attempt: i64,
}

/// Representation of one mail obtained by a transaction SMTP
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct MailContext {
    /// information of the connection producing this message
    pub connection: ConnectionContext,
    /// envelop of the message
    pub envelop: Envelop,
    /// metadata
    pub metadata: MessageMetadata,
}
