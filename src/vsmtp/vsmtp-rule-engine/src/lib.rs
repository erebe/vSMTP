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

#![doc = include_str!("../README.md")]
#![doc(html_no_source)]
#![deny(missing_docs)]
//
#![warn(rust_2018_idioms)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(clippy::cargo)]
//
#![allow(clippy::use_self)]
// Triggered by `rust_2018_idioms` for the `rhai::NativeCallContext`.
// Rhai must do something with lifetimes in plugin modules to prevent
// a Clone impl on the context, but it fails if adding an anonymous lifetime.
#![allow(elided_lifetimes_in_paths)]

macro_rules! block_on {
    ($future:expr) => {
        tokio::task::block_in_place(move || tokio::runtime::Handle::current().block_on($future))
    };
}

/// DSL specifications for vsl.
mod dsl {
    /// Command plugin implementation.
    pub mod cmd;
    /// Rules implementation.
    pub mod directives;
    /// SMTP plugin implementation.
    pub mod smtp;
}

pub use dsl::cmd::new_module as new_module_cmd;
pub use dsl::smtp::new_module as new_module_smtp;

#[macro_use]
mod error;
mod execution_state;
mod rule_engine;
mod rule_state;
mod server_api;

pub use dsl::directives::Directive;
pub use execution_state::ExecutionStage;
pub use rule_engine::RuleEngine;
pub use rule_state::RuleState;

// TODO: restrain this to the rule engine import / allow only in cfg debug.
/// Build sub domain hierarchy configurations.
pub mod sub_domain_hierarchy;

#[cfg(test)]
mod tests;

/// Module containing the backend for the vsl's Rust API.
pub mod api {
    use crate::server_api::ServerAPI;
    use vsmtp_mail_parser::MessageBody;

    /// Error produced by the vsl's Rust API function calls.
    pub type EngineResult<T> = Result<T, Box<rhai::EvalAltResult>>;
    /// Alias for `ctx()`
    pub type Context = std::sync::Arc<std::sync::RwLock<vsmtp_common::Context>>;
    /// Alias for `msg()`
    pub type Message = std::sync::Arc<std::sync::RwLock<MessageBody>>;
    /// Alias for `srv()`
    pub type Server = std::sync::Arc<ServerAPI>;
    /// ``vSL`` object type implementation.
    pub use vsmtp_plugin_vsl::objects::{Object, SharedObject};

    /// Authentication systems.
    pub mod auth;
    /// Default return codes exposed by vsmtp.
    pub mod code;
    /// backend for DKIM functionality.
    pub mod dkim;
    /// backend for DMARC functionality.
    pub mod dmarc;
    /// API to interact with the DNS.
    pub mod dns;
    /// Functions used to change the content of the envelop.
    pub mod envelop;
    /// API to write of the message on disk.
    pub mod fs;
    /// Log a message of `level` in the `app` target, which will be written to the
    /// the fie you specified in the field `app.logs.filename` form the [`vsmtp_config::Config`].
    pub mod logging;
    /// Extensions for the [`MailContext`](vsmtp_common::Context) type.
    pub mod mail_context;
    /// Extensions for the [`MessageBody`](vsmtp_mail_parser::MessageBody) type.
    pub mod message;
    /// Default network ranges exposed by vsmtp.
    pub mod net;
    /// backend for SPF functionality.
    pub mod spf;
    /// State Engine & filtering backend.
    pub mod state;
    /// Functions to get date and time.
    pub mod time;
    /// API for the delivery methods.
    pub mod transports;
    /// Utility functions.
    pub mod utils;

    // TODO: add read/write variants and vsl_guard_ok macro.
    /// Fetch rule engine global variables by calling the rhai system functions.
    #[macro_export]
    macro_rules! get_global {
        ($ncc:expr, ctx) => {
            $ncc.call_fn::<$crate::api::Context>("ctx", ())
        };
        ($ncc:expr, srv) => {
            $ncc.call_fn::<$crate::api::Server>("srv", ())
        };
        ($ncc:expr, msg) => {
            $ncc.call_fn::<$crate::api::Message>("msg", ())
        };
    }

    /// Get vsmtp static modules.
    #[must_use]
    pub fn vsmtp_static_modules() -> [(&'static str, rhai::Module); 20] {
        [
            ("state", rhai::exported_module!(state)),
            ("envelop", rhai::exported_module!(envelop)),
            ("code", rhai::exported_module!(code)),
            ("net", rhai::exported_module!(net)),
            ("time", rhai::exported_module!(time)),
            ("dns", rhai::exported_module!(dns)),
            ("fs", rhai::exported_module!(fs)),
            ("logging", rhai::exported_module!(logging)),
            ("auth", rhai::exported_module!(auth)),
            ("spf", rhai::exported_module!(spf)),
            ("dkim", rhai::exported_module!(dkim)),
            ("dmarc", rhai::exported_module!(dmarc)),
            ("transport", rhai::exported_module!(transports)),
            ("utils", rhai::exported_module!(utils)),
            ("ctx", rhai::exported_module!(mail_context)),
            ("msg", rhai::exported_module!(message)),
            ("obj", vsmtp_plugin_vsl::object_module()),
            ("unix", vsmtp_plugin_vsl::unix_module()),
            ("cmd", crate::dsl::cmd::new_module()),
            ("smtp", crate::dsl::smtp::new_module()),
        ]
    }
}
