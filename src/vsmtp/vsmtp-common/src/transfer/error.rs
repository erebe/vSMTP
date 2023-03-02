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

use crate::{CodeID, Domain, Reply, ReplyCode, Target};

/// The envelop to use for the SMTP exchange is invalid
#[derive(Debug, Clone, thiserror::Error, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "testing", derive(PartialEq, Eq))]
pub enum Envelop {
    /// No rcpt provided, therefor no `RCPT TO` can be sent to the remote server
    #[error("the envelop does not contain any recipient")]
    NoRecipient,
    // TODO: add too many rcpt
}

/// Error produced by local delivery method (Maildir / Mbox)
#[derive(Debug, Clone, thiserror::Error, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "testing", derive(PartialEq, Eq))]
pub enum LocalDelivery {
    /// The requested mailbox does not exist on the system
    #[error("mailbox `{mailbox}` does not exist")]
    MailboxDoNotExist {
        /// Mailbox name
        // FIXME: should be a type `Mailbox` ?
        mailbox: String,
    },
    ///
    // FIXME: should be std::io::Error ?
    #[error("todo")]
    Other(String),
}

/// Error produced by the ip/mx lookup of a target
#[derive(Debug, Clone, thiserror::Error, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "testing", derive(PartialEq, Eq))]
pub enum Lookup {
    /// No records found for the given query
    #[error("record not found")]
    NoRecords {},

    /// The lookup returned a record with a null MX
    #[error("null MX record found for '{domain}'")]
    ContainsNullMX {
        /// Domain of the DNS zone
        domain: Domain,
    },

    /// The lookup timed out
    #[error("timed out")]
    TimedOut,

    ///
    #[error("no connections available")]
    NoConnections,

    ///
    // FIXME: should handle all the IO case ..?
    #[error("io error: {0}")]
    IO(String),

    ///
    // FIXME: should handle all the proto case ..?
    #[error("dns-proto error: {0}")]
    Proto(String),

    ///
    #[error("message: {0}")]
    Message(String),

    ///
    #[error("not implemented")]
    NotImplemented,
}

/// Error produced by the queue manager
#[derive(Debug, Clone, thiserror::Error, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "testing", derive(PartialEq, Eq))]
pub enum Queuer {
    /// The recipient is still in status [`crate::transfer::Status::Waiting`] after a delivery attempt
    #[error("recipient is still in status waiting")]
    StillWaiting,

    /// Failed too many time to deliver the email
    #[error("max deferred attempt reached")]
    MaxDeferredAttemptReached,
}

/// Errors produced by a SMTP exchange
#[derive(Debug, Clone, thiserror::Error, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "testing", derive(PartialEq, Eq))]
pub enum Delivery {
    /// Failed to parse the reply of the server
    #[error("failed to parse the reply of the server: source={}",
        with_source
            .as_ref()
            .map_or("null", String::as_str)
    )]
    ReplyParsing {
        /// The source of the error
        with_source: Option<String>,
    },

    /// The server replied with a permanent error 5xx
    #[error("permanent error: {reply}: {}",
        with_source
            .as_ref()
            .map_or("null", String::as_str)
    )]
    Permanent {
        /// The reply code
        reply: ReplyCode,
        /// The source of the error
        with_source: Option<String>,
    },

    /// The server replied with a transient error 4xx
    #[error("transient error: {reply}: {}",
        with_source
            .as_ref()
            .map_or("null", String::as_str)
    )]
    Transient {
        /// The reply code
        reply: ReplyCode,
        /// The source of the error
        with_source: Option<String>,
    },

    /// Error caused by the TLS
    #[error("tls: {}",
        with_source
            .as_ref()
            .map_or("null", String::as_str)
    )]
    Tls {
        /// The source of the error
        with_source: Option<String>,
    },

    /// Internal error of the client
    #[error("client: {}",
        with_source
            .as_ref()
            .map_or("null", String::as_str)
    )]
    Client {
        /// The source of the error
        with_source: Option<String>,
    },

    /// Error due to the underlying connection
    #[error("connection: {}",
        with_source
            .as_ref()
            .map_or("null", String::as_str)
    )]
    Connection {
        /// The source of the error
        with_source: Option<String>,
    },
}

impl From<std::io::Error> for Delivery {
    fn from(err: std::io::Error) -> Self {
        Self::Connection {
            with_source: Some(err.to_string()),
        }
    }
}

/// Errors produced by the rule engine
#[derive(Debug, Clone, thiserror::Error, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "testing", derive(PartialEq, Eq))]
pub enum Rule {
    /// The rule engine has denied the transaction
    #[error("denied: {0}")]
    Denied(either::Either<CodeID, Reply>),
}

///
#[derive(Debug, Clone, thiserror::Error, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "testing", derive(PartialEq, Eq))]
pub enum Variant {
    /// The local delivery failed
    #[error("<local delivery>: {0}")]
    LocalDelivery(#[from] LocalDelivery),

    /// The envelop to use for the SMTP exchange is invalid
    #[error("<envelop>: {0}")]
    Envelop(#[from] Envelop),

    /// The lookup of the target failed
    #[error("<dns>: {0}")]
    Lookup(#[from] Lookup),

    /// The queue manager failed
    #[error("<queuer>: {0}")]
    Queuer(#[from] Queuer),

    /// The delivery failed
    #[error("<delivery>: {}",
        .0.iter()
        .map(|(domain, e)| format!("{domain}:{e}"))
        .collect::<Vec<_>>()
        .join(", ")
    )]
    Delivery(Vec<(Target, Delivery)>),

    /// An error produced by the rules engine
    #[error("<rules>: {0}")]
    Rules(#[from] Rule),
}

impl From<trust_dns_resolver::error::ResolveError> for Lookup {
    fn from(error: trust_dns_resolver::error::ResolveError) -> Self {
        match error.kind() {
            trust_dns_resolver::error::ResolveErrorKind::Message(e) => {
                Self::Message((*e).to_string())
            }
            trust_dns_resolver::error::ResolveErrorKind::Msg(e) => Self::Message(e.to_string()),
            trust_dns_resolver::error::ResolveErrorKind::NoConnections => Self::NoConnections,
            trust_dns_resolver::error::ResolveErrorKind::NoRecordsFound {
                query: _,
                soa: _,
                negative_ttl: _,
                response_code: _,
                trusted: _,
            } => Self::NoRecords {},
            trust_dns_resolver::error::ResolveErrorKind::Io(io) => Self::IO(io.to_string()),
            trust_dns_resolver::error::ResolveErrorKind::Proto(proto) => {
                Self::Proto(proto.to_string())
            }
            trust_dns_resolver::error::ResolveErrorKind::Timeout => Self::TimedOut,
            // NOTE: non_exhaustive
            _ => Self::NotImplemented,
        }
    }
}

impl From<lettre::transport::smtp::Error> for Delivery {
    fn from(value: lettre::transport::smtp::Error) -> Self {
        let with_source = std::error::Error::source(&value).map(ToString::to_string);

        if value.is_client() {
            Self::Client { with_source }
        } else if value.is_permanent() {
            Self::Permanent {
                with_source,
                reply: value
                    .status()
                    .expect("error is permanent and has code")
                    .into(),
            }
        } else if value.is_transient() {
            Self::Transient {
                with_source,
                reply: value
                    .status()
                    .expect("error is transient and has code")
                    .into(),
            }
        } else if value.is_response() {
            Self::ReplyParsing { with_source }
        } else if value.is_tls() {
            Self::Tls { with_source }
        } else {
            // connection or network
            Self::Connection { with_source }
        }
    }
}

impl Delivery {
    fn is_permanent(&self) -> bool {
        match self {
            Self::Permanent { .. } => true,

            Self::ReplyParsing { .. }
            | Self::Transient { .. }
            | Self::Tls { .. }
            | Self::Client { .. }
            | Self::Connection { .. } => false,
        }
    }
}

impl Variant {
    /// Is the error considered permanent, and retrying would produce the same result
    #[must_use]
    pub fn is_permanent(&self) -> bool {
        match self {
            Self::LocalDelivery(
                LocalDelivery::MailboxDoNotExist { .. } | LocalDelivery::Other(_),
            )
            | Self::Envelop(Envelop::NoRecipient)
            | Self::Queuer(Queuer::StillWaiting | Queuer::MaxDeferredAttemptReached) => true,

            Self::Lookup(
                Lookup::NoRecords {}
                | Lookup::TimedOut
                | Lookup::NoConnections
                | Lookup::IO(_)
                | Lookup::Proto(_)
                | Lookup::Message(_)
                | Lookup::ContainsNullMX { .. },
            )
            | Self::Rules(Rule::Denied(_)) => false,

            Self::Delivery(attempts) => attempts.iter().all(|(_, e)| e.is_permanent()),

            Self::Lookup(Lookup::NotImplemented) => unreachable!(),
        }
    }
}
