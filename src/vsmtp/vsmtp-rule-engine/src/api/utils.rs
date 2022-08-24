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
use crate::api::{EngineResult, Server, SharedObject};
use rhai::plugin::{
    mem, Dynamic, FnAccess, FnNamespace, ImmutableString, Module, NativeCallContext,
    PluginFunction, RhaiResult, TypeId,
};
use vsmtp_common::re::anyhow::Context;
use vsmtp_common::re::lettre;

const DATE_FORMAT: &[time::format_description::FormatItem<'_>] =
    time::macros::format_description!("[year]-[month]-[day]");
const TIME_FORMAT: &[time::format_description::FormatItem<'_>] =
    time::macros::format_description!("[hour]:[minute]:[second]");

pub use utils_rhai::*;

#[rhai::plugin::export_module]
mod utils_rhai {
    use crate::dsl::object::Object;

    // TODO: not yet functional, the relayer cannot connect to servers.
    /// send a mail from a template.
    #[rhai_fn(return_raw)]
    pub fn send_mail(from: &str, to: rhai::Array, path: &str, relay: &str) -> EngineResult<()> {
        // TODO: email could be cached using an object. (obj mail "my_mail" "/path/to/mail")
        let email =
            std::fs::read_to_string(path).map_err::<Box<rhai::EvalAltResult>, _>(|err| {
                format!("failed to load email at {path}: {err:?}").into()
            })?;

        let envelop = lettre::address::Envelope::new(
            Some(from.parse().map_err::<Box<rhai::EvalAltResult>, _>(|err| {
                format!("sys::send_mail from parsing failed: {err:?}").into()
            })?),
            to.into_iter()
                // NOTE: address that couldn't be converted will be silently dropped.
                .filter_map(|rcpt| {
                    rcpt.try_cast::<String>()
                        .and_then(|s| s.parse::<lettre::Address>().map(Some).unwrap_or(None))
                })
                .collect(),
        )
        .map_err::<Box<rhai::EvalAltResult>, _>(|err| {
            format!("sys::send_mail envelop parsing failed {err:?}").into()
        })?;

        match lettre::Transport::send_raw(
            &lettre::SmtpTransport::relay(relay)
                .map_err::<Box<rhai::EvalAltResult>, _>(|err| {
                    format!("sys::send_mail failed to connect to relay: {err:?}").into()
                })?
                .build(),
            &envelop,
            email.as_bytes(),
        ) {
            Ok(_) => Ok(()),
            Err(err) => Err(format!("sys::send_mail failed to send: {err:?}").into()),
        }
    }

    /// use the user cache to check if a user exists on the system.
    #[must_use]
    #[rhai_fn(global, name = "user_exist")]
    pub fn user_exist_str(name: &str) -> bool {
        super::user_exist(name)
    }

    /// use the user cache to check if a user exists on the system.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "user_exist")]
    pub fn user_exist_obj(name: SharedObject) -> bool {
        super::user_exist(&name.to_string())
    }

    /// get the hostname of the machine.
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
        match vsmtp_auth::get_root_domain(domain) {
            Ok(root) => root,
            Err(_) => domain.to_string(),
        }
    }

    /// Get the root domain (the registrable part)
    #[rhai_fn(global, name = "get_root_domain", pure, return_raw)]
    pub fn get_root_domain_obj(domain: &mut SharedObject) -> EngineResult<String> {
        match domain.as_ref() {
            Object::Fqdn(domain) | Object::Str(domain) => Ok(get_root_domain(domain)),
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
    #[rhai_fn(global, name = "lookup", return_raw, pure)]
    pub fn lookup_str(server: &mut Server, name: &str) -> EngineResult<rhai::Array> {
        super::lookup(server, name)
    }

    /// Perform a dns lookup using the root dns.
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "lookup", return_raw, pure)]
    pub fn lookup_obj(server: &mut Server, name: SharedObject) -> EngineResult<rhai::Array> {
        super::lookup(server, &name.to_string())
    }

    /// Perform a dns lookup using the root dns.
    #[rhai_fn(global, name = "rlookup", return_raw, pure)]
    pub fn rlookup_str(server: &mut Server, name: &str) -> EngineResult<rhai::Array> {
        super::rlookup(server, name)
    }

    /// Perform a dns lookup using the root dns.
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "rlookup", return_raw, pure)]
    pub fn rlookup_obj(server: &mut Server, name: SharedObject) -> EngineResult<rhai::Array> {
        super::rlookup(server, &name.to_string())
    }
}

// TODO: use UsersCache to optimize user lookup.
fn user_exist(name: &str) -> bool {
    vsmtp_config::re::users::get_user_by_name(name).is_some()
}

// NOTE: should lookup & rlookup return an error if no record was found ?

/// Perform a dns lookup using the root dns.
///
/// # Errors
/// * Root resolver was not found.
/// * Lookup failed.
pub fn lookup(server: &mut Server, host: &str) -> EngineResult<rhai::Array> {
    let resolver = server
        .resolvers
        .get(&server.config.server.domain)
        .ok_or_else::<Box<rhai::EvalAltResult>, _>(|| "root resolver not found".into())?;

    Ok(vsmtp_common::re::tokio::task::block_in_place(move || {
        vsmtp_common::re::tokio::runtime::Handle::current().block_on(resolver.lookup_ip(host))
    })
    .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?
    .into_iter()
    .map(|record| rhai::Dynamic::from(record.to_string()))
    .collect::<rhai::Array>())
}

/// Perform a dns reverse lookup using the root dns.
///
/// # Errors
/// * Failed to convert the `ip` parameter from a string into an IP.
/// * Reverse lookup failed.
pub fn rlookup(server: &mut Server, ip: &str) -> EngineResult<rhai::Array> {
    let ip = vsl_conversion_ok!(
        "ip address",
        <std::net::IpAddr as std::str::FromStr>::from_str(ip)
            .context("fail to parse ip address in rlookup")
    );
    let resolver = server
        .resolvers
        .get(&server.config.server.domain)
        .ok_or_else::<Box<rhai::EvalAltResult>, _>(|| "root resolver not found".into())?;

    Ok(vsmtp_common::re::tokio::task::block_in_place(move || {
        vsmtp_common::re::tokio::runtime::Handle::current().block_on(resolver.reverse_lookup(ip))
    })
    .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?
    .into_iter()
    .map(|record| rhai::Dynamic::from(record.to_string()))
    .collect::<rhai::Array>())
}
