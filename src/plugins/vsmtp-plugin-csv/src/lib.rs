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

//! # vSMTP CSV plugin

#![doc(html_no_source)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
//
#![warn(rust_2018_idioms)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(clippy::cargo)]

mod access;
mod api;
mod refresh;
mod service;

use rhai::{config::hashing::set_ahash_seed, exported_module, Module, Shared};

/// `rhai-dylib` will fetch this symbol to load the module into `vSMTP`.
///
/// # Panics
///
/// * the `rhai` hashing seed cannot be set.
#[allow(improper_ctypes_definitions)]
#[allow(unsafe_code)]
#[no_mangle]
#[inline]
pub extern "C" fn module_entrypoint() -> Shared<Module> {
    set_ahash_seed(Some([1, 2, 3, 4])).unwrap();

    #[cfg(debug_assertions)]
    {
        // Checking if TypeIDs are the same as the main program.
        dbg!(std::any::TypeId::of::<rhai::ImmutableString>());
    }

    exported_module!(api::csv_api).into()
}
