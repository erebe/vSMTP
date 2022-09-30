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

    /// # Examples
    ///
    /// ```
    /// vsmtp_test::vsl::run(r#"
    /// #{
    ///   connect: [
    ///     action "log on connection (obj/str)" || {
    ///       object message string = "Hello world!";
    ///
    ///       log("error", message);
    ///     },
    ///   ],
    /// }
    /// "#);
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "log")]
    #[doc = "overloaded as `log(level, message)`"]
    pub fn log_str_obj(level: &str, message: SharedObject) {
        log(level, &message.to_string());
    }

    /// # Examples
    ///
    /// ```
    /// vsmtp_test::vsl::run(r#"
    /// #{
    ///   connect: [
    ///     action "log on connection (obj/str)" || {
    ///       object level string = "warn";
    ///
    ///       log(level, "I love vsl!");
    ///     },
    ///   ],
    /// }
    /// "#);
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "log")]
    #[doc = "overloaded as `log(level, message)`"]
    pub fn log_obj_str(level: &mut SharedObject, message: &str) {
        log(&level.to_string(), message);
    }

    /// # Examples
    ///
    /// ```
    /// vsmtp_test::vsl::run(r#"
    /// #{
    ///   connect: [
    ///     action "log on connection (obj/obj)" || {
    ///       object level string = "trace";
    ///       object message string = "connection established";
    ///
    ///       log(level, message);
    ///     },
    ///   ],
    /// }
    /// "#);
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "log")]
    #[doc = "overloaded as `log(level, message)`"]
    pub fn log_obj_obj(level: &mut SharedObject, message: SharedObject) {
        log(&level.to_string(), &message.to_string());
    }

    /// # Examples
    ///
    /// ```
    /// vsmtp_test::vsl::run(r#"
    /// #{
    ///   connect: [
    ///     action "log on connection (str/str)" || {
    ///       log("info", "ehlo world");
    ///     },
    ///   ],
    /// }
    /// "#);
    /// ```
    #[rhai_fn(global, name = "log")]
    #[doc = "overloaded as `log(level, message)`"]
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
