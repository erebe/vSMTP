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

//! vSMTP delivery system

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
// restriction we ignore
#![allow(clippy::blanket_clippy_restriction_lints)]
#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::pub_use)]
#![allow(clippy::implicit_return)]
#![allow(clippy::mod_module_files)]
#![allow(clippy::shadow_reuse)]
//
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::panic))]

mod send;
mod sender;

use anyhow::Context;
pub use send::{split_and_sort_and_send, SenderOutcome};
pub use sender::{Sender, SenderParameters};
use vsmtp_common::{rcpt::Rcpt, Address};
use vsmtp_config::Config;

// at this point there should be no error
fn to_lettre_envelope(from: &Address, rcpt: &[Rcpt]) -> anyhow::Result<lettre::address::Envelope> {
    lettre::address::Envelope::new(
        Some(
            from.full()
                .parse()
                .with_context(|| format!("failed to parse from address: {}", from.full()))?,
        ),
        rcpt.iter()
            .map(|r| {
                r.address
                    .full()
                    .parse()
                    .with_context(|| format!("failed to parse from address: {}", from.full()))
            })
            .collect::<anyhow::Result<Vec<_>>>()?,
    )
    .with_context(|| "failed to construct `lettre` envelope")
}

fn get_cert_for_server(server_name: &str, config: &Config) -> Option<rustls::Certificate> {
    config.server.r#virtual.get(server_name).map_or_else(
        || {
            config
                .server
                .tls
                .as_ref()
                .map(|tls| tls.certificate.inner.clone())
        },
        |v| v.tls.as_ref().map(|tls| tls.certificate.inner.clone()),
    )
}

/// a few helpers to create systems that will deliver emails.
pub mod transport {
    use vsmtp_common::{rcpt::Rcpt, Address, ContextFinished};
    use vsmtp_config::Config;

    ///
    #[async_trait::async_trait]
    pub trait Transport {
        /// Take the data required to deliver the email and return the updated version of the recipient.
        async fn deliver(
            self,
            config: &Config,
            context: &ContextFinished,
            from: &Address,
            to: Vec<Rcpt>,
            content: &str,
        ) -> Vec<Rcpt>;
    }

    mod deliver;
    mod forward;
    mod maildir;
    mod mbox;

    pub use deliver::Deliver;
    pub use forward::Forward;
    pub use maildir::Maildir;
    pub use mbox::MBox;
}
