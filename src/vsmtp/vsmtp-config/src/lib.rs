//! vSMTP configuration
//!
//! This module contains the configuration for the vSMTP server.
//!
//! The behavior of your server can be configured using a configuration file,
//! and using the `-c, --config` flag of the `vsmtp`.
//!
//! All the parameters are optional and have default values.
//! If `-c, --config` is not provided, the default values of the configuration will be used.
//!
//! The configuration file will be read and parsed right after starting the program,
//! producing an error if there is an invalid syntax, a filepath failed to be opened,
//! or any kind of errors.
//!
//! If you have a non-explicit error when you start your server, you can create an issue
//! on the [github repo](https://github.com/viridIT/vSMTP), or ask for help in our discord server.
//!
//! # Configuration
//!
//! The type [`Config`] expose two methods :
//! * [`Config::builder`] to create a new configuration builder.
//! * [`Config::from_toml`] to read a configuration from a TOML file.
//!
//! # Example
//!
//! You can find examples of TOML file at <https://github.com/viridIT/vSMTP/tree/develop/examples/config>

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
#![allow(clippy::use_self)] // false positive

#[cfg(test)]
mod tests;

mod parser {
    pub mod socket_addr;
    pub mod syst_group;
    pub mod syst_user;
    pub mod tls_certificate;
    pub mod tls_cipher_suite;
    pub mod tls_private_key;
    pub mod tls_protocol_version;
    pub mod tracing_directive;
}

/// The configuration builder for programmatically instantiating
pub mod builder {
    mod wants;
    mod with;

    pub(crate) mod validate;
    pub use wants::*;
    pub use with::*;
}

mod config;
mod default;
mod ensure;
mod rustls_helper;
mod virtual_tls;

mod dns_resolver;

pub use dns_resolver::DnsResolvers;

pub use config::{field, Config};
pub use rustls_helper::get_rustls_config;

use builder::{Builder, WantsVersion};

impl Config {
    /// Create an instance of [`Builder`].
    #[must_use]
    pub const fn builder() -> Builder<WantsVersion> {
        Builder {
            state: WantsVersion(()),
        }
    }

    /// Parse a [`Config`] with [TOML] format
    ///
    /// # Errors
    ///
    /// * data is not a valid [TOML]
    /// * one field is unknown
    /// * the version requirement are not fulfilled
    /// * a mandatory field is not provided (no default value)
    ///
    /// # Panics
    ///
    /// * if the field `user` or `group` are missing, the default value `vsmtp`
    ///   will be used, if no such user/group exist, builder will panic
    ///
    /// [TOML]: https://github.com/toml-lang/toml
    pub fn from_toml(input: &str) -> anyhow::Result<Self> {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct VersionRequirement {
            version_requirement: semver::VersionReq,
        }

        let version_requirement = toml::from_str::<VersionRequirement>(input)?.version_requirement;
        let pkg_version = semver::Version::parse(env!("CARGO_PKG_VERSION"))?;

        if !version_requirement.matches(&pkg_version) {
            anyhow::bail!(
                "Version requirement not fulfilled: expected '{version_requirement}' but got '{pkg_version}'"
            );
        }

        toml::from_str::<Self>(input)
            .map(Self::ensure)
            .map_err(anyhow::Error::new)?
    }
}
