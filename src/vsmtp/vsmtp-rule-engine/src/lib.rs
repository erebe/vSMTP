//! vSMTP rule engine
//!
//! vSMTP server is built with a runtime also called `rule engine`.
//! This runtime can execute code provided in our superset of the
//! <https://rhai.rs> language.
//!
//! The viridIT scripting language (vsl) is a simple language that allow
//! you to define `rules` and `object` to control the traffic on your MTA.
//!
//! Further details on the official book of vSMTP: <https://vsmtp.rs/reference/vSL/vsl.html>

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
    pub type EngineResult<T> = Result<T, Box<vsmtp_plugins::rhai::EvalAltResult>>;
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

    vsmtp_plugins::rhai::def_package! {
        /// vsl's standard api.
        pub StandardVSLPackage(module) {
            vsmtp_plugins::rhai::packages::StandardPackage::init(module);

            module
                .combine(vsmtp_plugins::rhai::exported_module!(logging))
                .combine(vsmtp_plugins::rhai::exported_module!(dkim))
                .combine(vsmtp_plugins::rhai::exported_module!(dmarc))
                .combine(vsmtp_plugins::rhai::exported_module!(rule_state))
                .combine(vsmtp_plugins::rhai::exported_module!(spf))
                .combine(vsmtp_plugins::rhai::exported_module!(transports))
                .combine(vsmtp_plugins::rhai::exported_module!(utils))
                .combine(vsmtp_plugins::rhai::exported_module!(write))
                .combine(vsmtp_plugins::rhai::exported_module!(types))
                .combine(vsmtp_plugins::rhai::exported_module!(mail_context))
                .combine(vsmtp_plugins::rhai::exported_module!(message))
                .combine(vsmtp_plugins::rhai::exported_module!(message_parsed));
        }
    }
}
