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

pub mod vsl;

// TODO: Implement Seal => https://crates.io/crates/sealed
/// A vSMTP plugin.
pub trait Plugin: Send + Sync {
    /// Get the name of the plugin.
    fn name(&self) -> &'static str;

    // FIXME: only use `vsmtp-plugin` env.
    /// Version of the plugin.
    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    // FIXME: only use `vsmtp-plugin` env.
    /// Rust version used to compile the plugin.
    fn rust_version(&self) -> &'static str {
        env!("CARGO_PKG_RUST_VERSION")
    }
}

// TODO:
// /// Declare a plugin type and its constructor.
// ///
// /// # Notes
// ///
// /// This works by automatically generating an `extern "Rust"` function with a
// /// pre-defined signature and symbol name. Therefore you will only be able to
// /// declare one plugin per library.
// #[macro_export]
// macro_rules! declare_plugin {
//     ($plugin_type:ty, $constructor:path) => {
//         #[no_mangle]
//         pub fn plugin_constructor() -> Box<dyn Plugin> {
//             // make sure the constructor is the correct type.
//             let constructor: fn() -> $plugin_type = $constructor;

//             Box::new(constructor())
//         }
//     };
// }
