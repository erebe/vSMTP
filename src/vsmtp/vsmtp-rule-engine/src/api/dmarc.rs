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

use crate::api::{EngineResult, Message, Server};
use rhai::plugin::{
    Dynamic, FnAccess, FnNamespace, Module, NativeCallContext, PluginFunction, RhaiResult, TypeId,
};
use rhai::EvalAltResult;
use vsmtp_common::Address;

pub use dmarc::*;

/// Domain-based message authentication, reporting and conformance implementation
/// specified by RFC 7489. (<https://www.rfc-editor.org/rfc/rfc7489>)
#[rhai::plugin::export_module]
mod dmarc {
    use crate::api::state;
    use crate::get_global;

    /// Apply the DMARC policy to the mail.
    ///
    /// # Effective smtp stage
    ///
    /// `preq` and onwards.
    ///
    /// # Example
    ///
    /// ```ignore
    /// #{
    ///   preq: [
    ///     rule "check dmarc" || { dmarc::check() },
    ///   ]
    /// }
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(name = "check", return_raw)]
    pub fn check(ncc: NativeCallContext) -> EngineResult<vsmtp_common::status::Status> {
        let msg = get_global!(ncc, msg)?;
        let srv = get_global!(ncc, srv)?;

        let rfc5322_from = super::parse_rfc5322_from(&msg)?;
        let rfc5322_from = rfc5322_from.domain();
        let record = get_dmarc_record(&srv, rfc5322_from)?;

        // tracing::warn!(%error, "DMARC record not found:");
        // return rule_state::next();
        let ctx = get_global!(ncc, ctx)?;

        let dkim = crate::api::dkim::Impl::verify_inner(
            &ctx, &msg, &srv, // TODO: only take `d == rfc5322_from`
            5, "cycle", 1000,
        )?;

        let spf = crate::api::spf::check(&ctx, &srv)?;
        let ctx = vsl_guard_ok!(ctx.read());

        let (hostname, sender, client_ip) = {
            (
                vsmtp_plugin_vsl::unix::hostname()?,
                vsl_generic_ok!(ctx.reverse_path()).clone(),
                ctx.client_addr().ip().to_string(),
            )
        };
        let sender_addr = sender.as_ref().map_or("null", |s| s.full());

        let header = format!(
            r#"{};
 dkim={}
 spf={}
 reason="{}"
 smtp.mailfrom={}"#,
            crate::api::utils::get_root_domain(ctx.server_name()),
            dkim.get("status")
                .map(std::string::ToString::to_string)
                .unwrap_or_default(),
            spf.result,
            crate::api::spf::key_value_list(&spf, &hostname, sender_addr, &client_ip),
            sender_addr
        );

        let dmarc_pass = dmarc_check(
            &record,
            rfc5322_from,
            &dkim,
            sender.as_ref().map_or("null", |s| s.domain()),
            spf.result.as_str(),
        );

        crate::api::message::Impl::prepend_header(
            &msg,
            "Authentication-Results",
            &format!(
                r#"${}
 dmarc={}"#,
                header,
                if dmarc_pass { "pass" } else { "fail" }
            ),
        )?;

        Ok(if dmarc_pass {
            state::next()
        } else {
            tracing::warn!(record = %record.receiver_policy, "DMARC check failed.");

            match record.receiver_policy {
                vsmtp_auth::dmarc::ReceiverPolicy::None => state::next(),
                vsmtp_auth::dmarc::ReceiverPolicy::Quarantine => state::quarantine_str("dmarc"),
                vsmtp_auth::dmarc::ReceiverPolicy::Reject => state::deny(/*code_...*/),
            }
        })
    }
}

fn dmarc_check(
    record: &vsmtp_auth::dmarc::Record,
    rfc5322_from: &str,
    dkim_result: &rhai::Map,
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

/// Get the address of the sender in the message body, also known as RFC5322.From
fn parse_rfc5322_from(msg: &Message) -> EngineResult<Address> {
    let from = vsl_guard_ok!(msg.read())
        .get_header("From")
        .ok_or_else::<Box<EvalAltResult>, _>(|| "only one `From` header is allowed".into())?;

    let from_parsed = match from
        .find('<')
        .and_then(|begin| from.find('>').map(|end| (begin, end)))
    {
        Some((start, end)) => &from[start..end],
        None => &from,
    };

    <Address as std::str::FromStr>::from_str(from_parsed)
        .map_err::<Box<EvalAltResult>, _>(|e| e.to_string().into())
}

fn get_dmarc_record(server: &Server, domain: &str) -> EngineResult<vsmtp_auth::dmarc::Record> {
    let resolver = server.resolvers.get_resolver_root();

    let txt_record =
        block_on!(resolver.txt_lookup(format!("_dmarc.{domain}")))
            .map_err::<Box<EvalAltResult>, _>(|e| e.to_string().into())?;

    let records = txt_record
        .into_iter()
        .map(|i| <vsmtp_auth::dmarc::Record as std::str::FromStr>::from_str(&i.to_string()));

    let first = records
        .into_iter()
        .next()
        .ok_or_else::<Box<EvalAltResult>, _>(|| {
            format!("no `_dmarc` record found for domain `{domain}`").into()
        })?
        .map_err::<Box<EvalAltResult>, _>(|e| e.to_string().into())?;

    Ok(first)
}
