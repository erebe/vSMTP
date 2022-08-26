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

use crate::api::{EngineResult, Message, Object, Server};
use rhai::plugin::{
    mem, Dynamic, FnAccess, FnNamespace, ImmutableString, Module, NativeCallContext,
    PluginFunction, RhaiResult, TypeId,
};
use rhai::EvalAltResult;
use vsmtp_auth::dmarc;
use vsmtp_common::re::tokio;
use vsmtp_common::Address;

pub use dmarc_rhai::*;

#[rhai::plugin::export_module]
mod dmarc_rhai {
    use crate::api::SharedObject;

    /// Get the address of the sender in the message body, also known as RFC5322.From
    #[rhai_fn(global, return_raw, pure)]
    pub fn parse_rfc5322_from(message: &mut Message) -> EngineResult<SharedObject> {
        let guard = vsl_guard_ok!(message.read());
        let from = guard
            .get_header("From")
            .ok_or_else::<Box<EvalAltResult>, _>(|| "only one `From` header is allowed".into())?;

        let (begin, end) = (
            from.find('<').ok_or_else::<Box<EvalAltResult>, _>(|| {
                format!("format of From is unsupported `{from}`").into()
            })?,
            from.find('>').ok_or_else::<Box<EvalAltResult>, _>(|| {
                format!("format of From is unsupported `{from}`").into()
            })?,
        );

        <Address as std::str::FromStr>::from_str(&from[begin..end])
            .map(|addr| SharedObject::new(Object::Address(addr)))
            .map_err::<Box<EvalAltResult>, _>(|e| e.to_string().into())
    }

    /// Produce a debug output for the parsed [`dmarc::Record`]
    #[rhai_fn(global, pure)]
    pub fn to_debug(record: &mut dmarc::Record) -> String {
        format!("{record:#?}")
    }

    /// Get a valid DMARC record for the domain
    #[rhai_fn(global, pure, return_raw)]
    pub fn get_dmarc_record(server: &mut Server, domain: &str) -> EngineResult<dmarc::Record> {
        let resolver = server.resolvers.get(&server.config.server.domain).unwrap();

        let txt_record = tokio::task::block_in_place(move || {
            tokio::runtime::Handle::current()
                .block_on(resolver.txt_lookup(format!("_dmarc.{domain}")))
        })
        .map_err::<Box<EvalAltResult>, _>(|e| e.to_string().into())?;

        let records = txt_record
            .into_iter()
            .map(|i| <dmarc::Record as std::str::FromStr>::from_str(&i.to_string()));

        let first = records
            .into_iter()
            .next()
            .ok_or_else::<Box<EvalAltResult>, _>(|| {
                format!("no `_dmarc` record found for domain `{domain}`").into()
            })?
            .map_err::<Box<EvalAltResult>, _>(|e| e.to_string().into())?;

        Ok(first)
    }

    ///
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, pure)]
    pub fn dmarc_check(
        record: &mut dmarc::Record,
        rfc5322_from: &str,
        dkim_result: rhai::Map,
        spf_mail_from: &str,
        spf_result: &str,
    ) -> bool {
        let dkim_domain: String = match dkim_result
            .get("sdid")
            .cloned()
            .and_then(rhai::Dynamic::try_cast)
        {
            Some(domain) => domain,
            None => return false,
        };
        let dkim_status: String = match dkim_result
            .get("status")
            .cloned()
            .and_then(rhai::Dynamic::try_cast)
        {
            Some(status) => status,
            None => return false,
        };

        if record.dkim_is_aligned(rfc5322_from, &dkim_domain) && dkim_status == "pass" {
            return true;
        }

        if record.spf_is_aligned(rfc5322_from, spf_mail_from) && spf_result == "pass" {
            return true;
        }

        false
    }

    ///
    #[rhai_fn(global, get = "receiver_policy", pure)]
    pub fn receiver_policy(record: &mut dmarc::Record) -> String {
        record.get_policy()
    }
}
