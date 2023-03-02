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

//! vSMTP common definition

#![doc(html_no_source)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
//
#![warn(rust_2018_idioms)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(clippy::cargo)]
#![warn(clippy::undocumented_unsafe_blocks)]
//
#![allow(clippy::missing_const_for_fn)] // see https://github.com/rust-lang/rust-clippy/issues/9271

/// Default smtp port
pub const SMTP_PORT: u16 = 25;

/// Default submission port
pub const SUBMISSION_PORT: u16 = 587;

/// Default submission over TLS port
///
/// Defined in [RFC8314](https://tools.ietf.org/html/rfc8314)
pub const SUBMISSIONS_PORT: u16 = 465;

#[macro_use]
mod types {
    #[macro_use]
    pub mod address;
    pub mod client_name;
    pub mod code_id;
    pub mod domain;
    pub mod reply;
    pub mod reply_code;
    pub mod target;
    pub mod tls_cipher_suite;
    pub mod tls_protocol_version;
}

pub use types::{
    address::Address,
    client_name::ClientName,
    code_id::CodeID,
    domain::{domain_iter, Domain},
    reply::Reply,
    reply_code::*,
    target::Target,
    tls_cipher_suite::CipherSuite,
    tls_protocol_version::ProtocolVersion,
};

///
pub mod transport;

///
pub type ReplyOrCodeID = either::Either<CodeID, Reply>;

mod context;
pub use context::{
    AuthProperties, ConnectProperties, Context, ContextConnect, ContextFinished, ContextHelo,
    ContextMailFrom, ContextRcptTo, Error, FinishedProperties, HeloProperties, MailFromProperties,
    RcptToProperties, Stage, TlsProperties, TransactionType,
};

/// abstraction of the libc
pub mod libc_abstraction;

/// status of the mail context
pub mod status;

/// transfer related types
pub mod transfer {
    /// underlying transfer errors
    pub mod error;
    mod status;

    pub use status::{Error, Status};
}

/// parsing utils.
pub mod utils;

/// Data related to ESMTP Authentication
pub mod auth {
    mod credentials;
    mod mechanism;

    pub use credentials::{Credentials, Error};
    pub use mechanism::Mechanism;
}

#[cfg(test)]
mod tests {
    mod libc_abstraction;
}

#[doc(hidden)]
#[macro_export]
macro_rules! collection {
    // map-like
    ($($k:expr => $v:expr),* $(,)?) => {{
        use std::iter::{Iterator, IntoIterator};
        Iterator::collect(IntoIterator::into_iter([$(($k, $v),)*]))
    }};
    // set-like
    ($($v:expr),* $(,)?) => {{
        use std::iter::{Iterator, IntoIterator};
        Iterator::collect(IntoIterator::into_iter([$($v,)*]))
    }};
}
