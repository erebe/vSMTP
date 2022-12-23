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

use vsmtp_plugin_vsl::objects::Object;

use crate::api::{EngineResult, SharedObject};
use rhai::plugin::{
    mem, Dynamic, FnAccess, FnNamespace, ImmutableString, Module, NativeCallContext,
    PluginFunction, RhaiResult, TypeId,
};

pub use utils::*;

/// Utility functions to interact with the system.
#[rhai::plugin::export_module]
mod utils {
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
    /// #{
    ///   connect: [
    ///     rule "user_exist" || {
    ///       state::accept(`250 root exist ? ${if utils::user_exist("root") { "yes" } else { "no" }}`);
    ///     }
    ///   ],
    ///   mail: [
    ///     rule "user_exist (obj)" || {
    ///       state::accept(`250 ${utils::user_exist(ctx::mail_from())}`);
    ///     }
    ///   ]
    /// }
    /// # "#)?.build()));
    /// # use vsmtp_common::{status::Status, CodeID, Reply, ReplyCode::Code};
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::Connect].2, Status::Accept(either::Right(Reply::new(
    /// #  Code { code: 250 }, "root exist ? yes".to_string(),
    /// # ))));
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::MailFrom].2, Status::Accept(either::Right(Reply::new(
    /// #  Code { code: 250 }, "false".to_string(),
    /// # ))));
    /// ```
    #[must_use]
    #[rhai_fn(name = "user_exist")]
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
    /// #{
    ///   connect: [
    ///     rule "user_exist" || {
    ///       state::accept(`250 root exist ? ${if utils::user_exist("root") { "yes" } else { "no" }}`);
    ///     }
    ///   ],
    ///   mail: [
    ///     rule "user_exist (obj)" || {
    ///       state::accept(`250 ${utils::user_exist(ctx::mail_from())}`);
    ///     }
    ///   ]
    /// }
    /// # "#)?.build()));
    /// # use vsmtp_common::{status::Status, CodeID, Reply, ReplyCode::Code};
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::Connect].2, Status::Accept(either::Right(Reply::new(
    /// #  Code { code: 250 }, "root exist ? yes".to_string(),
    /// # ))));
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::MailFrom].2, Status::Accept(either::Right(Reply::new(
    /// #  Code { code: 250 }, "false".to_string(),
    /// # ))));
    /// ```
    #[doc(hidden)]
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(name = "user_exist")]
    pub fn user_exist_obj(name: SharedObject) -> bool {
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
    /// # vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///   connect: [
    ///     rule "hostname" || {
    ///       state::accept(`250 ${utils::hostname()}`);
    ///     }
    ///   ]
    /// }
    /// # "#)?.build()));
    /// ```
    #[rhai_fn(return_raw)]
    pub fn hostname() -> EngineResult<String> {
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

    /// Get the root domain (the registrable part)
    ///
    /// # Examples
    ///
    /// `foo.bar.example.com` => `example.com`
    #[rhai_fn()]
    #[must_use]
    pub fn get_root_domain(domain: &str) -> String {
        vsmtp_auth::get_root_domain(domain).map_or_else(|_| domain.to_string(), |root| root)
    }

    /// Get the root domain (the registrable part)
    ///
    /// # Examples
    ///
    /// `foo.bar.example.com` => `example.com`
    #[rhai_fn(name = "get_root_domain", pure, return_raw)]
    pub fn get_root_domain_obj(domain: &mut SharedObject) -> EngineResult<String> {
        match domain.as_ref() {
            Object::Fqdn(domain) => Ok(get_root_domain(domain)),
            _ => Err(format!("type `{}` is not a domain", domain.as_ref()).into()),
        }
    }
}

struct Impl;

impl Impl {
    // TODO: use UsersCache to optimize user lookup.
    fn user_exist(name: &str) -> bool {
        users::get_user_by_name(name).is_some()
    }
}
