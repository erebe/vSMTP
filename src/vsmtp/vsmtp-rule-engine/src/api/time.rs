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

use rhai::plugin::{
    Dynamic, FnAccess, FnNamespace, Module, NativeCallContext, PluginFunction, RhaiResult, TypeId,
};

const DATE_FORMAT: &[time::format_description::FormatItem<'_>] =
    time::macros::format_description!("[year]-[month]-[day]");
const TIME_FORMAT: &[time::format_description::FormatItem<'_>] =
    time::macros::format_description!("[hour]:[minute]:[second]");

pub use time_mod::*;

/// Utilities to get the current time and date.
#[rhai::plugin::export_module]
mod time_mod {
    /// Get the current time.
    ///
    /// ### Return
    ///
    /// * `string` - the current time.
    ///
    /// ### Effective smtp stage
    ///
    /// All of them.
    ///
    /// ### Examples
    ///
    /// ```text
    /// #{
    ///     preq: [
    ///        action "append info header" || {
    ///             msg::append_header("X-VSMTP", `email received by ${utils::hostname()} the ${time::date()} at ${time::now()}.`);
    ///        }
    ///     ]
    /// }
    /// ```
    #[must_use]
    pub fn now() -> String {
        let now = time::OffsetDateTime::now_utc();

        now.format(&TIME_FORMAT)
            .unwrap_or_else(|_| String::default())
    }

    /// Get the current date.
    ///
    /// ### Return
    ///
    /// * `string` - the current date.
    ///
    /// ### Effective smtp stage
    ///
    /// All of them.
    ///
    /// ### Examples
    ///
    /// ```text
    /// #{
    ///     preq: [
    ///        action "append info header" || {
    ///             msg::append_header("X-VSMTP", `email received by ${utils::hostname()} the ${time::date()}.`);
    ///        }
    ///     ]
    /// }
    /// ```
    #[must_use]
    pub fn date() -> String {
        let now = time::OffsetDateTime::now_utc();

        now.format(&DATE_FORMAT)
            .unwrap_or_else(|_| String::default())
    }
}
