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

//! vQueue: the vSMTP's queue manager

#![doc(html_no_source)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
//
#![warn(rust_2018_idioms)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(clippy::cargo)]
#![warn(clippy::restriction)]
//
#![allow(clippy::multiple_crate_versions)]
#![allow(clippy::integer_arithmetic, clippy::arithmetic_side_effects)] // issue with strum
// restriction we ignore
#![allow(
    clippy::missing_docs_in_private_items,
    clippy::pattern_type_mismatch,
    clippy::blanket_clippy_restriction_lints,
    clippy::pub_use,
    clippy::implicit_return,
    clippy::unseparated_literal_suffix,
    clippy::shadow_reuse,
    clippy::mod_module_files
)]
//
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::std_instead_of_core))]
#![cfg_attr(docsrs, feature(doc_cfg))]

/// Module containing the Command Line Interpreter
pub mod cli {
    ///
    pub mod args;
    ///
    pub mod execute;
    ///
    pub mod debugger {
        ///
        pub mod message_move;
        ///
        pub mod message_remove;
        ///
        pub mod message_show;
        ///
        pub mod show;
    }
}

mod api;
mod extension;
pub use api::{GenericQueueManager, QueueID};
pub use extension::FilesystemQueueManagerExt;

mod implementation {
    /// The filesystem implementation of the queue manager,
    /// writing mails ([`MailContext`](vsmtp_common::Context) and [`MessageBody`](vsmtp_mail_parser::MessageBody))
    /// to the `/var/spool/vsmtp` directory (path configurable).
    ///
    /// The structure of the spool is the following:
    ///
    /// ```shell
    /// $> tree -L 2 /var/spool/vsmtp
    /// /var/spool/vsmtp
    /// ├── dead                   # fatal error happened
    /// ├── delegated              # [`delegation flow`] (smtp ping/pong with another service)
    /// ├── deliver                # to deliver (first attempt)
    /// ├── deferred               # to deliver (1..N) times (at least one error occurred before)
    /// ├── mails                  # the message body (received between DATA and "<CRLF>.<CRLF>"
    /// │   ├── <msg-id>.eml       # * stored as received (not modified)
    /// │   └── <msg-id-2>.json    # * parsed and stored in .json (possibly modified)
    /// └── working                # mail to be processed (after taking its responsibility bu issuing a "250 Ok")
    /// ```
    pub mod fs;

    /// Similar to the filesystem implementation, but using a temporary directory.
    ///
    /// Only used for testing.
    #[cfg(feature = "testing")]
    #[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
    pub mod temp;
}

pub use implementation::fs;

#[cfg(feature = "testing")]
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
pub use implementation::temp;
