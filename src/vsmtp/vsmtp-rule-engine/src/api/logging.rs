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
    mem, Dynamic, EvalAltResult, FnAccess, FnNamespace, ImmutableString, Module, NativeCallContext,
    PluginFunction, Position, RhaiResult, TypeId,
};

pub use logging_rhai::*;

#[rhai::plugin::export_module]
mod logging_rhai {

    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "log")]
    #[doc(hidden)]
    pub fn log_str_obj(level: &str, message: SharedObject) {
        log(level, &message.to_string());
    }

    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "log")]
    #[doc(hidden)]
    pub fn log_obj_str(level: &mut SharedObject, message: &str) {
        log(&level.to_string(), message);
    }

    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "log")]
    #[doc(hidden)]
    pub fn log_obj_obj(level: &mut SharedObject, message: SharedObject) {
        log(&level.to_string(), &message.to_string());
    }

    /// # Examples
    ///
    /// ```
    /// # vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_incoming_rules(r#"
    /// #{
    ///   connect: [
    ///     action "log on connection (str/str)" || {
    ///       log("info", `[${date()}/${time()}] client=${client_ip()}`);
    ///     },
    ///     action "log on connection (str/obj)" || {
    ///       log("error", identifier("Ehllo world!"));
    ///     },
    ///     action "log on connection (obj/obj)" || {
    ///       const level = "trace";
    ///       const message = "connection established";
    ///
    ///       log(identifier(level), identifier(message));
    ///     },
    ///     action "log on connection (obj/str)" || {
    ///       const level = "warn";
    ///
    ///       log(identifier(level), "I love vsl!");
    ///     },
    ///   ],
    /// }
    /// # "#)?.build()));
    /// ```
    #[rhai_fn(global, name = "log")]
    // TODO: inject rule name #[tracing::instrument(name = %rule_name, skip_all)]
    #[allow(clippy::cognitive_complexity)]
    pub fn log(level: &str, message: &str) {
        match <tracing::Level as std::str::FromStr>::from_str(level) {
            Ok(level) => match level {
                tracing::Level::TRACE => {
                    tracing::trace!(message);
                }
                tracing::Level::DEBUG => {
                    tracing::debug!(message);
                }
                tracing::Level::INFO => {
                    tracing::info!(message);
                }
                tracing::Level::WARN => {
                    tracing::warn!(message);
                }
                tracing::Level::ERROR => {
                    tracing::error!(message);
                }
            },
            Err(e) => {
                tracing::warn!(
                    "level `{}` is invalid: `{}`. Message was: '{}'",
                    level,
                    e,
                    message,
                );
            }
        }
    }
}
