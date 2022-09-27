//! vSMTP mail parser

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
#![allow(clippy::use_self)] // false positive with enums

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
pub(crate) mod helpers;

mod implementation {
    pub mod basic_parser;
    pub mod mail_mime_parser;
}

pub use implementation::{
    basic_parser::BasicParser, mail_mime_parser::get_mime_header, mail_mime_parser::MailMimeParser,
};

mod message {
    pub mod mail;
    #[allow(clippy::module_name_repetitions)]
    pub mod message_body;
    pub mod mime_type;
    pub mod raw_body;
}

pub use message::mail::*;
pub use message::message_body::*;
pub use message::mime_type::*;
pub use message::raw_body::*;

mod traits {
    pub mod error;
    pub mod mail_parser;
}

pub use traits::{
    error::{ParserError, ParserResult},
    mail_parser::MailParser,
};

#[cfg(test)]
pub mod tests;

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
