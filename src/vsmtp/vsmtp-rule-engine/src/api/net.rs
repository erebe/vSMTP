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

use crate::api::SharedObject;
use rhai::plugin::{
    Dynamic, FnAccess, FnNamespace, Module, NativeCallContext, PluginFunction, RhaiResult, TypeId,
};

pub use net::*;

/// Predefined network ip ranges.
#[rhai::plugin::export_module]
mod net {
    use vsmtp_plugin_vsl::api::objects::rg4;

    /// Return an ip range over "192.168.0.0/16".
    ///
    /// # Example
    ///
    /// ```ignore
    /// #{
    ///     rcpt: [
    ///         rule "anti relay" || { if ctx::client_ip() in net::rg_192() { state::next() } else { state::deny() } }
    ///     ]
    /// }
    /// ```
    #[must_use]
    #[rhai_fn(name = "rg_192")]
    pub fn rg_192() -> SharedObject {
        rg4("192.168.0.0/16").expect("valid range")
    }

    /// Return an ip range over "172.16.0.0/12".
    ///
    /// # Example
    ///
    /// ```ignore
    /// #{
    ///     rcpt: [
    ///         rule "anti relay" || { if ctx::client_ip() in net::rg_172() { state::next() } else { state::deny() } }
    ///     ]
    /// }
    /// ```
    #[must_use]
    #[rhai_fn(name = "rg_172")]
    pub fn rg_172() -> SharedObject {
        rg4("172.16.0.0/12").expect("valid range")
    }

    /// Return an ip range over "10.0.0.0/8".
    ///
    /// # Example
    ///
    /// ```ignore
    /// #{
    ///     rcpt: [
    ///         rule "anti relay" || { if ctx::client_ip() in net::rg_10() { state::next() } else { state::deny() } }
    ///     ]
    /// }
    /// ```
    #[must_use]
    #[rhai_fn(name = "rg_10")]
    pub fn rg_10() -> SharedObject {
        rg4("10.0.0.0/8").expect("valid range")
    }

    /// Return a list of non routable networks (net_192, net_172, and net_10).
    #[must_use]
    #[rhai_fn(name = "non_routable")]
    pub fn non_routable() -> rhai::Array {
        rhai::Array::from_iter([
            rhai::Dynamic::from(rg_192()),
            rhai::Dynamic::from(rg_172()),
            rhai::Dynamic::from(rg_10()),
        ])
    }
}
