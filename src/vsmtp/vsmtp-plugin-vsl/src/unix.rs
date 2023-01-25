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
    mem, Dynamic, FnAccess, FnNamespace, ImmutableString, Module, NativeCallContext,
    PluginFunction, RhaiResult, TypeId,
};

pub use unix::*;

/// Utility functions to interact with unix systems.
#[rhai::plugin::export_module]
mod unix {
    /// Check if a user exists on this server.
    ///
    /// ### Args
    ///
    /// * `name` - the name of the user.
    ///
    /// ### Return
    ///
    /// * `bool` - true if the user exists, false otherwise.
    ///
    /// ### Effective smtp stage
    ///
    /// All of them.
    ///
    /// ### Examples
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// if user_exist("john") {
    ///     print("john user found on the system.");
    ///     # throw "a john user seems to exist on this system.";
    /// } else {
    ///     print("john user does not exist.");
    ///     # return #{};
    /// }
    /// # "#)?.build()));
    /// ```
    #[must_use]
    #[rhai_fn(global, name = "user_exist")]
    pub fn user_exist(name: &str) -> bool {
        super::Impl::user_exist(name)
    }

    /// Check if a user exists on this server.
    ///
    /// ### Args
    ///
    /// * `name` - the name of the user.
    ///
    /// ### Return
    ///
    /// * `bool` - true if the user exists, false otherwise.
    ///
    /// ### Effective smtp stage
    ///
    /// All of them.
    ///
    /// ### Examples
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// if user_exist(identifier("john")) {
    ///     print("john user found on the system.");
    ///     # throw "a john user seems to exist on this system.";
    /// } else {
    ///     print("john user does not exist.");
    ///     # return #{};
    /// }
    /// # "#)?.build()));
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    #[must_use]
    #[doc(hidden)]
    #[cfg(all(feature = "unix", feature = "objects"))]
    #[rhai_fn(global, name = "user_exist")]
    pub fn user_exist_obj(name: crate::objects::SharedObject) -> bool {
        super::Impl::user_exist(&name.to_string())
    }

    /// Get the hostname of this machine.
    ///
    /// ### Return
    ///
    /// * `string` - the host name of the machine.
    ///
    /// ### Effective smtp stage
    ///
    /// All of them.
    ///
    /// ### Examples
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// print(`hostname of the system: ${hostname()}`);
    /// # return #{};
    /// # "#)?.build()));
    /// ```
    #[rhai_fn(global, return_raw)]
    pub fn hostname() -> Result<String, Box<rhai::EvalAltResult>> {
        hostname::get()
            .map_err::<Box<rhai::EvalAltResult>, _>(|err| {
                format!("failed to get system's hostname: {err}").into()
            })?
            .to_str()
            .map_or(
                Err("the system's hostname is not UTF-8 valid".into()),
                |host| Ok(host.to_string()),
            )
    }

    /// Fetch an environment variable from the current process.
    ///
    /// # Args
    ///
    /// * `variable` - the variable to fetch.
    ///
    /// # Returns
    ///
    /// * `string` - the value of the fetched variable.
    /// * `()`     - when the variable is not set,  when the variable contains the sign character (=) or the NUL character,
    /// or that the variable does not contain valid Unicode.
    ///
    /// # Example
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// // get the HOME environment variable.
    /// let home = unix::env("HOME");
    ///
    /// #       if home == () {
    /// #           throw `error: home variable not found: ${home}`;
    /// #       }
    ///
    /// // "VSMTP=ENV" is malformed, this will return the unit type '()'.
    /// let invalid = unix::env("VSMTP=ENV");
    ///
    /// #       if invalid != () {
    /// #           throw `error: malformed variable was accepted: ${invalid}`;
    /// #       }
    ///
    /// #       return #{};
    /// # "#)?.build()));
    /// ```
    #[must_use]
    #[rhai_fn(global, name = "env")]
    pub fn env_str(variable: &str) -> rhai::Dynamic {
        std::env::var(variable).map_or(rhai::Dynamic::UNIT, std::convert::Into::into)
    }

    /// Fetch an environment variable from the current process.
    ///
    /// # Args
    ///
    /// * `variable` - the variable to fetch.
    ///
    /// # Returns
    ///
    /// * `string` - the value of the fetched variable.
    /// * `()`     - when the variable is not set,  when the variable contains the sign character (=) or the NUL character,
    /// or that the variable does not contain valid Unicode.
    ///
    /// # Example
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// // get the HOME environment variable.
    /// let home = unix::env(identifier("HOME"));
    ///
    /// #       if home == () {
    /// #           throw `error: home variable not found: ${home}`;
    /// #       }
    ///
    /// // "VSMTP=ENV" is malformed, this will return the unit type '()'.
    /// let invalid = unix::env(identifier("VSMTP=ENV"));
    ///
    /// #       if invalid != () {
    /// #           throw `error: malformed variable was accepted: ${invalid}`;
    /// #       }
    ///
    /// #       return #{};
    /// # "#)?.build()));
    /// ```
    #[must_use]
    #[doc(hidden)]
    #[cfg(all(feature = "unix", feature = "objects"))]
    #[rhai_fn(global, name = "env", pure)]
    pub fn env_obj(variable: &mut crate::objects::SharedObject) -> rhai::Dynamic {
        std::env::var(variable.to_string()).map_or(rhai::Dynamic::UNIT, std::convert::Into::into)
    }
}

struct Impl;

impl Impl {
    // TODO: use UsersCache to optimize user lookup.
    fn user_exist(name: &str) -> bool {
        users::get_user_by_name(name).is_some()
    }
}
