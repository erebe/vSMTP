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
#![deny(unsafe_code)]
//
#![warn(rust_2018_idioms)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(clippy::cargo)]
#![warn(clippy::restriction)]
// restriction we ignore
#![allow(
    clippy::blanket_clippy_restriction_lints,
    clippy::missing_docs_in_private_items,
    clippy::pub_use,
    clippy::implicit_return,
    clippy::mod_module_files,
    clippy::shadow_reuse,
    clippy::pattern_type_mismatch,
    clippy::missing_trait_methods
)]
//
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::std_instead_of_core,
        clippy::missing_trait_methods,
        clippy::as_conversions,
        clippy::undocumented_unsafe_blocks
    )
)]

mod send;

pub use send::{split_and_sort_and_send, SenderOutcome};
use vsmtp_common::{Address, Domain};
use vsmtp_config::Config;
extern crate alloc;

mod dns {
    #[allow(clippy::expect_used)]
    pub fn default() -> alloc::sync::Arc<trust_dns_resolver::TokioAsyncResolver> {
        alloc::sync::Arc::new(
            trust_dns_resolver::TokioAsyncResolver::tokio(
                trust_dns_resolver::config::ResolverConfig::google(),
                trust_dns_resolver::config::ResolverOpts::default(),
            )
            .expect("default resolver is valid"),
        )
    }
}

/// A macro to define serde/deser method for a field `type`
#[macro_export]
macro_rules! def_type_serde {
    ($v:expr) => {
        mod r#type {
            pub fn deserialize<'de, D>(deserialize: D) -> Result<String, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = <String as serde::Deserialize>::deserialize(deserialize)?;
                if value == $v {
                    Ok(value)
                } else {
                    Err(serde::de::Error::custom(format!("Expected `type={}`", $v)))
                }
            }

            pub fn serialize<S>(_: &String, serialize: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serialize.serialize_str($v)
            }
        }
    };
}

// at this point there should be no error
#[allow(clippy::expect_used)]
fn to_lettre_envelope<'item>(
    from: &Option<Address>,
    rcpt: impl Iterator<Item = &'item Address>,
) -> lettre::address::Envelope {
    lettre::address::Envelope::new(
        from.as_ref().map(Address::to_lettre),
        rcpt.map(Address::to_lettre).collect::<Vec<_>>(),
    )
    .expect("at least one rcpt")
}

fn get_cert_for_server(server_name: &Domain, config: &Config) -> Option<Vec<rustls::Certificate>> {
    config
        .server
        .r#virtual
        .get(server_name)
        .and_then(|v| v.tls.as_ref().map(|tls| tls.certificate.inner.clone()))
}

mod deliver;
mod forward;
mod maildir;
mod mbox;

pub use deliver::Deliver;
pub use forward::Forward;
pub use maildir::Maildir;
pub use mbox::MBox;
