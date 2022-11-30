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

mod dsl {
    pub mod cmd;
    pub mod directives;
    pub mod smtp;
}

#[macro_use]
mod error;
mod rule_engine;
mod rule_state;
mod server_api;

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

    /// backend for DKIM functionality.
    pub mod dkim;
    /// backend for DMARC functionality.
    pub mod dmarc;
    /// Log a message of `level` in the `app` target, which will be written to the
    /// the fie you specified in the field `app.logs.filepath` form the [`vsmtp_config::Config`].
    pub mod logging;
    /// Extensions for the [`MailContext`](vsmtp_common::Context) type.
    pub mod mail_context;
    /// Extensions for the [`MessageBody`](vsmtp_mail_parser::MessageBody) type.
    pub mod message;
    /// Extensions for the [`MessageBody`](vsmtp_mail_parser::MessageBody) type.
    pub mod message_parsed;
    /// State Engine & filtering backend.
    pub mod rule_state;
    /// backend for SPF functionality.
    pub mod spf;
    /// API for the delivery methods.
    pub mod transports;
    /// Getter for common types
    pub mod types;
    /// utility methods.
    pub mod utils;
    /// API to write of the message on disk.
    pub mod write;

    rhai::def_package! {
        /// vsl's standard api.
        pub StandardVSLPackage(module) {
            rhai::packages::StandardPackage::init(module);

            module
                .combine(rhai::exported_module!(logging))
                .combine(rhai::exported_module!(dkim))
                .combine(rhai::exported_module!(dmarc))
                .combine(rhai::exported_module!(rule_state))
                .combine(rhai::exported_module!(spf))
                .combine(rhai::exported_module!(transports))
                .combine(rhai::exported_module!(utils))
                .combine(rhai::exported_module!(write))
                .combine(rhai::exported_module!(types))
                .combine(rhai::exported_module!(mail_context))
                .combine(rhai::exported_module!(message))
                .combine(rhai::exported_module!(message_parsed));
        }
    }
}
