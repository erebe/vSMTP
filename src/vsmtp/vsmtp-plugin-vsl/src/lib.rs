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

//! This vSMTP plugin adds a superset of functions to the rhai scripting language,
//! including regex, ip objects, ip ranges, email addresses and so on.
//!
//! The Rule Engine of vSMTP will always register this plugin, you can use the [`object.rs`]
//! file to support vSL's types within your own plugin.

/// vSL objects, their implementation and their Rhai API. Enabled with the "objects" feature.
#[cfg(feature = "objects")]
pub mod objects;

/// Utils functions to interact with an unix system. Enabled with the "unix" feature.
#[cfg(feature = "unix")]
pub mod unix;

/// Build a module for the objects api that can be registered by a Rhai engine.
/// Enabled with the "objects" feature.
#[cfg(feature = "objects")]
pub fn object_module() -> rhai::Module {
    let mut module = rhai::Module::new();

    module
        .combine(rhai::exported_module!(objects::constructors))
        .combine(rhai::exported_module!(objects::utils))
        .combine(rhai::exported_module!(objects::comparisons))
        .set_id("vsl-objects");

    module
}

/// Build a module for the unix api that can be registered by a Rhai engine.
/// Enabled with the "unix" feature.
#[cfg(feature = "unix")]
pub fn unix_module() -> rhai::Module {
    rhai::exported_module!(unix)
}
