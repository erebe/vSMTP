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

use crate::api::{EngineResult, SharedObject};
use anyhow::Context;
use rhai::plugin::{
    mem, Dynamic, FnAccess, FnNamespace, ImmutableString, Module, NativeCallContext,
    PluginFunction, RhaiResult, TypeId,
};

pub use dns::*;

use super::Server;

/// Functions used to query the DNS.
#[rhai::plugin::export_module]
mod dns {
    use crate::get_global;

    /// Performs a dual-stack DNS lookup for the given hostname.
    ///
    /// ### Args
    ///
    /// * `host` - A valid hostname to search.
    ///
    /// ### Return
    ///
    /// * `array` - an array of IPs. The array is empty if no IPs were found for the host.
    ///
    /// ### Effective smtp stage
    ///
    /// All of them.
    ///
    /// # Errors
    ///
    /// * Root resolver was not found.
    /// * Lookup failed.
    ///
    /// ### Examples
    ///
    /// ```
    /// # vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///   preq: [
    ///     action "lookup recipients" || {
    ///       let domain = "gmail.com";
    ///       let ips = dns::lookup(domain);
    ///
    ///       print(`ips found for ${domain}`);
    ///       for ip in ips { print(`- ${ip}`); }
    ///     },
    ///   ],
    /// }
    /// # "#)?.build()));
    /// ```
    #[rhai_fn(name = "lookup", return_raw)]
    pub fn lookup(ncc: NativeCallContext, name: &str) -> EngineResult<rhai::Array> {
        super::Impl::lookup(&get_global!(ncc, srv)?, name)
    }

    /// Performs a dual-stack DNS lookup for the given hostname.
    ///
    /// ### Args
    ///
    /// * `host` - A valid hostname to search.
    ///
    /// ### Return
    ///
    /// * `array` - an array of IPs. The array is empty if no IPs were found for the host.
    ///
    /// ### Effective smtp stage
    ///
    /// All of them.
    ///
    /// # Errors
    ///
    /// * Root resolver was not found.
    /// * Lookup failed.
    ///
    /// ### Examples
    ///
    /// ```
    /// # vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///   preq: [
    ///     action "lookup recipients" || {
    ///       let domain = fqdn("gmail.com");
    ///       let ips = dns::lookup(domain);
    ///
    ///       print(`ips found for ${domain}`);
    ///       for ip in ips { print(`- ${ip}`); }
    ///     },
    ///   ],
    /// }
    /// # "#)?.build()));
    /// ```
    #[doc(hidden)]
    #[rhai_fn(name = "lookup", return_raw)]
    pub fn lookup_obj(ncc: NativeCallContext, name: SharedObject) -> EngineResult<rhai::Array> {
        super::lookup(ncc, &name.to_string())
    }

    /// Performs a reverse lookup for the given IP.
    ///
    /// ### Args
    ///
    /// * `ip` - The IP to query.
    ///
    /// ### Return
    ///
    /// * `array` - an array of FQDNs. The array is empty if nothing was found.
    ///
    /// ### Effective smtp stage
    ///
    /// All of them.
    ///
    /// # Errors
    ///
    /// * Failed to convert the `ip` parameter from a string into an IP.
    /// * Reverse lookup failed.
    ///
    /// ### Examples
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///   connect: [
    ///     rule "rlookup" || {
    ///       state::accept(`250 client ip: ${"127.0.0.1"} -> ${dns::rlookup("127.0.0.1")}`);
    ///     }
    ///   ],
    /// }
    /// # "#)?.build()));
    /// # use vsmtp_common::{status::Status, CodeID, Reply, ReplyCode::Code};
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::Connect].2, Status::Accept(either::Right(
    /// #  r#"250 client ip: 127.0.0.1 -> ["localhost."]"#.parse().unwrap(),
    /// # )));
    /// ```
    #[rhai_fn(name = "rlookup", return_raw)]
    pub fn rlookup(ncc: NativeCallContext, name: &str) -> EngineResult<rhai::Array> {
        super::Impl::rlookup(&get_global!(ncc, srv)?, name)
    }

    /// Performs a reverse lookup for the given IP.
    ///
    /// ### Args
    ///
    /// * `ip` - The IP to query.
    ///
    /// ### Return
    ///
    /// * `array` - an array of FQDNs. The array is empty if nothing was found.
    ///
    /// ### Effective smtp stage
    ///
    /// All of them.
    ///
    /// # Errors
    ///
    /// * Failed to convert the `ip` parameter from a string into an IP.
    /// * Reverse lookup failed.
    ///
    /// ### Examples
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///   connect: [
    ///     rule "rlookup" || {
    ///       state::accept(`250 client ip: ${"127.0.0.1"} -> ${dns::rlookup("127.0.0.1")}`);
    ///     }
    ///   ],
    /// }
    /// # "#)?.build()));
    /// # use vsmtp_common::{status::Status, CodeID, Reply, ReplyCode::Code};
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::Connect].2, Status::Accept(either::Right(
    /// #  r#"250 client ip: 127.0.0.1 -> ["localhost."]"#.parse().unwrap(),
    /// # )));
    /// ```
    #[doc(hidden)]
    #[rhai_fn(name = "rlookup", return_raw)]
    pub fn rlookup_obj(ncc: NativeCallContext, name: SharedObject) -> EngineResult<rhai::Array> {
        super::rlookup(ncc, &name.to_string())
    }
}

struct Impl;

impl Impl {
    // NOTE: should lookup & rlookup return an error if no record was found ?
    fn lookup(server: &Server, host: &str) -> EngineResult<rhai::Array> {
        let resolver = server.resolvers.get_resolver_root();

        Ok(block_on!(resolver.lookup_ip(host))
            .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?
            .into_iter()
            .map(|record| rhai::Dynamic::from(record.to_string()))
            .collect::<rhai::Array>())
    }

    fn rlookup(server: &Server, ip: &str) -> EngineResult<rhai::Array> {
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
