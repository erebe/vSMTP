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

//! vSMTP protocol implementation
//!
//! Currently only implement a ESMTPSA server.

#![doc(html_no_source)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
//
#![warn(rust_2018_idioms)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(clippy::cargo)]
//
#![allow(clippy::use_self)]
//
mod command;
mod connection_kind;
mod receiver;
mod receiver_handler;
mod sink;
mod smtp_sasl;
mod stream;

pub use command::{
    AcceptArgs, AuthArgs, EhloArgs, HeloArgs, MailFromArgs, ParseArgsError, RcptToArgs,
    UnparsedArgs, Verb,
};
pub use connection_kind::ConnectionKind;
pub use receiver::{Receiver, ReceiverContext};
pub use receiver_handler::ReceiverHandler;
pub use smtp_sasl::AuthError;
pub use stream::Error;
