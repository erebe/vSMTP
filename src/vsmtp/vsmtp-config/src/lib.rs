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
//! * [`Config::from_vsl_file`] to read a configuration from a vSL file.
//!
//! # Example
//!
//! You can find examples of vSL config files at <https://github.com/viridIT/vSMTP/tree/develop/examples/config>

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
#![allow(clippy::missing_const_for_fn)] // see https://github.com/rust-lang/rust-clippy/issues/9271

#[cfg(test)]
mod tests;

///
pub mod parser {
    pub(crate) mod socket_addr;
    ///
    pub mod syst_group;
    pub(crate) mod syst_user;
    pub(crate) mod tls_certificate;
    pub(crate) mod tls_private_key;
    pub(crate) mod tracing_directive;
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

use anyhow::Context;
use config::field::FieldServerVirtual;
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

    /// Create a [`Config`] from a vsl [JSON] file.
    ///
    /// # Errors
    ///
    /// * Data is not valid vsl.
    /// * Found an unknown field.
    /// * Version requirements are not fulfilled.
    /// * A mandatory field is missing. (when no default value is provided)
    /// * File could not be opened or read.
    ///
    /// [JSON]: https://fr.wikipedia.org/wiki/JavaScript_Object_Notation
    pub fn from_vsl_file(path: impl AsRef<std::path::Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();

        let vsmtp_config_dir = std::path::PathBuf::from(path.parent().ok_or_else(|| {
            anyhow::anyhow!(
                "File '{}' does not have a valid parent directory for configuration files",
                path.display()
            )
        })?);

        let script =
            std::fs::read_to_string(path).context(format!("Cannot read file at {path:?}"))?;

        let mut config = Self::from_vsl_script(script, Some(&vsmtp_config_dir))?;

        config.path = Some(path.to_path_buf());

        Ok(config)
    }

    /// Create a [`Config`] from vsl data.
    ///
    /// # Errors
    ///
    /// * Data is not valid vsl.
    /// * Found an unknown field.
    /// * Version requirements are not fulfilled.
    /// * A mandatory field is missing. (when no default value is provided)
    pub fn from_vsl_script(
        script: impl AsRef<str>,
        resolve_path: Option<&std::path::PathBuf>,
    ) -> anyhow::Result<Self> {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct VersionRequirement {
            version_requirement: semver::VersionReq,
        }

        let script = script.as_ref();
        let mut engine = rhai::Engine::new();

        if let Some(resolve_path) = resolve_path.as_ref() {
            engine.set_module_resolver(
                rhai::module_resolvers::FileModuleResolver::new_with_path_and_extension(
                    resolve_path,
                    "vsl",
                ),
            );
        }

        engine.register_global_module(vsmtp_plugin_vsl::unix_module().into());

        let ast = engine
            .compile(script)
            .context("Failed to compile root configuration (config.vsl)")?;

        let user_config: rhai::Map = engine
            .call_fn(
                &mut rhai::Scope::new(),
                &ast,
                "on_config",
                (Self::default_json()?,),
            )
            .context("Could not get main configuration.")?;

        let raw_config =
            serde_json::to_string(&user_config).context("The main configuration is malformed")?;

        let config = &mut serde_json::Deserializer::from_str(&raw_config);

        let config = match serde_path_to_error::deserialize(config) {
            Ok(config) => config,
            Err(error) => anyhow::bail!(Self::format_error(&error)?),
        };

        let mut config = Self::ensure(config)?;

        let pkg_version = semver::Version::parse(env!("CARGO_PKG_VERSION"))?;
        if !config.version_requirement.matches(&pkg_version) {
            anyhow::bail!(
                "Version requirement not fulfilled: expected '{}' but got '{}'",
                config.version_requirement,
                pkg_version
            );
        }

        config.get_domain_config(&engine)?;

        Ok(config)
    }

    fn default_json() -> anyhow::Result<rhai::Map> {
        let mut config = Self::default_with_current_user_and_group();

        config
            .server
            .smtp
            .codes
            .remove(&vsmtp_common::CodeID::EhloPain);
        config
            .server
            .smtp
            .codes
            .remove(&vsmtp_common::CodeID::EhloSecured);

        let mut config_json =
            rhai::Engine::new().parse_json(serde_json::to_string(&config)?, true)?;

        // We remove the created default `vsmtp` user & group so the server can use the right defaults if the
        // user does not specify any user / group in it's configuration.
        //
        // See `default_with_current_user_and_group` for context.
        {
            let server = &mut *config_json
                .get_mut("server")
                .expect("server key should be present")
                .write_lock::<rhai::Map>()
                .expect("failed to lock server config option");

            let system = &mut *server
                .get_mut("system")
                .expect("system key should be present")
                .write_lock::<rhai::Map>()
                .expect("failed to lock system config option");

            system.remove("user");
            system.remove("group");
        }

        Ok(config_json)
    }

    fn get_domain_config(&mut self, engine: &rhai::Engine) -> anyhow::Result<()> {
        if let Some(domains_path) = &self.app.vsl.domain_dir {
            for entry in std::fs::read_dir(domains_path).with_context(|| {
                format!(
                    "Cannot read domain directory in '{}'",
                    domains_path.display()
                )
            })? {
                let entry = entry?;
                let file_type = entry.file_type()?;
                if file_type.is_file() {
                    continue;
                }

                let pre_symlink_domain = entry.file_name().to_string_lossy().to_string();

                let symlink_domain = if file_type.is_symlink() {
                    Some(
                        std::fs::read_link(entry.path())?
                            .file_name()
                            .ok_or_else(|| anyhow::anyhow!("error symlink to root is invalid"))?
                            .to_string_lossy()
                            .to_string(),
                    )
                } else {
                    None
                };

                let domain_name = symlink_domain
                    .clone()
                    .unwrap_or_else(|| pre_symlink_domain.clone())
                    .parse()?;

                if let Some(v) = self.server.r#virtual.get_mut(&domain_name) {
                    if pre_symlink_domain == "default" {
                        v.is_default = true;
                    }
                } else {
                    let domain_config = match Self::get_one_domain_config(&entry.path(), engine) {
                        Ok(domain_config) => domain_config,
                        Err(e) => {
                            eprintln!(
                                "Could not get configuration for the '{domain_name}' domain because: {e}.."
                            );
                            anyhow::bail!(e);
                        }
                    };

                    self.server.r#virtual.insert(
                        domain_name,
                        FieldServerVirtual {
                            is_default: domain_config.is_default || pre_symlink_domain == "default",
                            ..domain_config
                        },
                    );
                }
            }
        }

        Ok(())
    }

    fn get_one_domain_config(
        domain_dir: &std::path::Path,
        engine: &rhai::Engine,
    ) -> anyhow::Result<FieldServerVirtual> {
        let config_path = domain_dir.join("config.vsl");

        if config_path.exists() {
            let ast = engine.compile_file(config_path.clone()).with_context(|| {
                format!(
                    "Failed to compile configuration at '{}'",
                    config_path.display()
                )
            })?;

            let raw = engine.call_fn::<rhai::Map>(
                &mut rhai::Scope::new(),
                &ast,
                "on_domain_config",
                (FieldServerVirtual::default_json()?,),
            )?;

            let raw_json = serde_json::to_string(&raw).context("The configuration is malformed")?;
            let domain_config = &mut serde_json::Deserializer::from_str(&raw_json);

            match serde_path_to_error::deserialize(domain_config) {
                Ok(domain_config) => Ok(domain_config),
                Err(error) => anyhow::bail!(Self::format_error(&error)?),
            }
        } else {
            Ok(FieldServerVirtual::default())
        }
    }

    /// Tracing back the path where the error have been generated,
    /// and prints the missing pieces of configuration for json objects.
    fn format_error(
        error: &serde_path_to_error::Error<serde_json::Error>,
    ) -> anyhow::Result<String> {
        let path = error.path();
        let mut invalid_value_path =
            serde_json::to_value(&Self::default_with_current_user_and_group())
                .context("The configuration is malformed")?;

        // Tracing back the path where the error have been generated to get the type of the key.
        for segment in path.iter() {
            if let serde_path_to_error::Segment::Map { key } = segment {
                invalid_value_path = invalid_value_path
                    .get(key)
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
            }
        }

        Ok(
            // serde json only displays the Rust type when an error occurs, we need to
            // extract the fields from object types to make it clearer for the user.
            if let serde_json::Value::Object(object) = invalid_value_path {
                format!(
                "In the 'config.{}' configuration, expected an object with the fields {}, at line {} column {}.",
                error.path(),
                object
                    .into_iter()
                    .map(|(key, _)| format!("'{key}'"))
                    .collect::<Vec<_>>()
                    .join(", "),
                    error.inner().line(),
                    error.inner().column(),
            )
            } else {
                format!(
                    "In the 'config.{}' configuration, {}.",
                    error.path(),
                    error.inner()
                )
            },
        )
    }
}
