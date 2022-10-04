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

use crate::plugins::Plugin;

/// Native rust plugin used to register new functions to extend vSMTP rhai API using Rust.
pub trait Native: Plugin {
    // TODO: implement generic errors, probably using `type Err;`
    /// Register the API of a custom service.
    fn register(&self, builder: Builder) -> anyhow::Result<()>;
}

// NOTE: Do we want to expose the rest of the engine's API to the user, or is registering function enough ?
/// A builder used to register the rhai api of a plugin.
pub struct Builder<'re> {
    engine: &'re mut rhai::Engine,
}

impl<'re> Builder<'re> {
    /// Create a new builder from an engine instance.
    pub fn new(engine: &'re mut rhai::Engine) -> Self {
        Self { engine }
    }

    /// Add a rhai function to the rhai context of vSMTP.
    pub fn register_fn<A, R, S>(
        &mut self,
        name: impl AsRef<str> + Into<rhai::Identifier>,
        function: impl rhai::RegisterNativeFunction<A, R, S>,
    ) -> &mut Self {
        self.engine.register_fn(name, function);

        self
    }

    /// Add a module to the rhai context of vSMTP.
    pub fn register_global_module(&mut self, module: rhai::Module) -> &mut Self {
        self.engine.register_global_module(module.into());

        self
    }
}

// TODO: to remove, the user does not need this boilerplate.
/// Deserialize a rhai map to a specific type. Use this method to "parse"
/// your service parameters using [serde].
///
/// # Errors
/// * The parsing failed.
pub fn deserialize_rhai_map<T: serde::de::DeserializeOwned>(
    service_type: &str,
    map: rhai::Map,
) -> anyhow::Result<T> {
    rhai::serde::from_dynamic::<T>(&map.into())
        .map_err(|err| anyhow::anyhow!("failed to parse parameters for '{service_type}': {err}",))
}
