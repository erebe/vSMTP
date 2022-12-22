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

use crate::api::{EngineResult, Server, SharedObject};
use anyhow::Context;
use rhai::plugin::{
    mem, Dynamic, FnAccess, FnNamespace, ImmutableString, Module, NativeCallContext,
    PluginFunction, RhaiResult, TypeId,
};

const DATE_FORMAT: &[time::format_description::FormatItem<'_>] =
    time::macros::format_description!("[year]-[month]-[day]");
const TIME_FORMAT: &[time::format_description::FormatItem<'_>] =
    time::macros::format_description!("[hour]:[minute]:[second]");

pub use utils_rhai::*;

#[rhai::plugin::export_module]
mod utils_rhai {

    /// Does the `name` correspond to an existing user in the system.
    ///
    /// # Examples
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///   connect: [
    ///     rule "user_exist" || {
    ///       accept(`250 root exist ? ${if user_exist("root") { "yes" } else { "no" }}`);
    ///     }
    ///   ],
    ///   mail: [
    ///     rule "user_exist (obj)" || {
    ///       accept(`250 ${user_exist(mail_from())}`);
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
    #[rhai_fn(global, name = "user_exist")]
    pub fn user_exist(name: &str) -> bool {
        super::Impl::user_exist(name)
    }

    #[doc(hidden)]
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "user_exist")]
    pub fn user_exist_obj(name: SharedObject) -> bool {
        super::Impl::user_exist(&name.to_string())
    }

    /// Get the hostname of the machine.
    ///
    /// # Examples
    ///
    /// ```
    /// # vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///   connect: [
    ///     rule "hostname" || {
    ///       accept(`250 ${hostname()}`);
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
    #[rhai_fn(global)]
    #[must_use]
    pub fn get_root_domain(domain: &str) -> String {
        vsmtp_auth::get_root_domain(domain).map_or_else(|_| domain.to_string(), |root| root)
    }

    #[doc(hidden)]
    #[rhai_fn(global, name = "get_root_domain", pure, return_raw)]
    pub fn get_root_domain_obj(domain: &mut SharedObject) -> EngineResult<String> {
        match domain.as_ref() {
            Object::Fqdn(domain) => Ok(get_root_domain(domain)),
            _ => Err(format!("type `{}` is not a domain", domain.as_ref()).into()),
        }
    }

    /// get the current time.
    #[must_use]
    pub fn time() -> String {
        let now = time::OffsetDateTime::now_utc();

        now.format(&TIME_FORMAT)
            .unwrap_or_else(|_| String::default())
    }

    /// get the current date.
    #[must_use]
    pub fn date() -> String {
        let now = time::OffsetDateTime::now_utc();

        now.format(&DATE_FORMAT)
            .unwrap_or_else(|_| String::default())
    }

    /// Perform a dns lookup using the root dns.
    ///
    /// # Errors
    ///
    /// * Root resolver was not found.
    /// * Lookup failed.
    ///
    /// # Examples
    ///
    /// ```
    /// # vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///   preq: [
    ///     action "lookup recipients" || {
    ///       let domain = "gmail.com";
    ///       let ips = lookup(domain);
    ///
    ///       print(`ips found for ${domain}`);
    ///       for ip in ips { print(`- ${ip}`); }
    ///     },
    ///   ],
    /// }
    /// # "#)?.build()));
    /// ```
    #[rhai_fn(global, name = "lookup", return_raw, pure)]
    pub fn lookup(server: &mut Server, name: &str) -> EngineResult<rhai::Array> {
        super::Impl::lookup(server, name)
    }

    #[doc(hidden)]
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "lookup", return_raw, pure)]
    pub fn lookup_obj(server: &mut Server, name: SharedObject) -> EngineResult<rhai::Array> {
        super::lookup(server, &name.to_string())
    }

    /// Perform a dns reverse lookup using the root dns.
    ///
    /// # Errors
    ///
    /// * Failed to convert the `ip` parameter from a string into an IP.
    /// * Reverse lookup failed.
    ///
    /// # Examples
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///   connect: [
    ///     rule "rlookup" || {
    ///       accept(`250 client ip: ${"127.0.0.1"} -> ${rlookup("127.0.0.1")}`);
    ///     }
    ///   ],
    /// }
    /// # "#)?.build()));
    /// # use vsmtp_common::{status::Status, CodeID, Reply, ReplyCode::Code};
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::Connect].2, Status::Accept(either::Right(Reply::new(
    /// #  Code { code: 250 }, "client ip: 127.0.0.1 -> [\"localhost.\"]".to_string(),
    /// # ))));
    /// ```
    #[rhai_fn(global, name = "rlookup", return_raw, pure)]
    pub fn rlookup(server: &mut Server, name: &str) -> EngineResult<rhai::Array> {
        super::Impl::rlookup(server, name)
    }

    #[doc(hidden)]
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "rlookup", return_raw, pure)]
    pub fn rlookup_obj(server: &mut Server, name: SharedObject) -> EngineResult<rhai::Array> {
        super::rlookup(server, &name.to_string())
    }
}

struct Impl;

impl Impl {
    // TODO: use UsersCache to optimize user lookup.
    fn user_exist(name: &str) -> bool {
        users::get_user_by_name(name).is_some()
    }

    // NOTE: should lookup & rlookup return an error if no record was found ?
    fn lookup(server: &mut Server, host: &str) -> EngineResult<rhai::Array> {
        let resolver = server.resolvers.get_resolver_root();

        Ok(block_on!(resolver.lookup_ip(host))
            .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?
            .into_iter()
            .map(|record| rhai::Dynamic::from(record.to_string()))
            .collect::<rhai::Array>())
    }

    fn rlookup(server: &mut Server, ip: &str) -> EngineResult<rhai::Array> {
        let ip = vsl_conversion_ok!(
            "ip address",
            <std::net::IpAddr as std::str::FromStr>::from_str(ip)
                .context("fail to parse ip address in rlookup")
        );
        let resolver = server.resolvers.get_resolver_root();

        Ok(block_on!(resolver.reverse_lookup(ip))
            .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?
            .into_iter()
            .map(|record| rhai::Dynamic::from(record.to_string()))
            .collect::<rhai::Array>())
    }
}
