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

use crate::api::{
    EngineResult, {Context, Server},
};
use rhai::plugin::{
    mem, Dynamic, FnAccess, FnNamespace, ImmutableString, Module, NativeCallContext,
    PluginFunction, RhaiResult, TypeId,
};

const AUTH_HEADER: &str = "Authentication-Results";
const SPF_HEADER: &str = "Received-SPF";

pub use spf::*;

/// Implementation of the Sender Policy Framework (SPF), described by RFC 4408. (<https://www.ietf.org/rfc/rfc4408.txt>)
#[rhai::plugin::export_module]
mod spf {
    use crate::api::{message::Impl, state};
    use vsmtp_common::status::Status;

    use crate::get_global;

    /// Check spf record following the Sender Policy Framework (RFC 7208).
    /// see https://datatracker.ietf.org/doc/html/rfc7208
    ///
    /// # Args
    ///
    /// * `header` - "spf" | "auth" | "both" | "none"
    /// * `policy` - "strict" | "soft"
    ///
    /// # Return
    /// * `deny(code550_7_23 | code550_7_24)` - an error occurred during lookup. (returned even when a softfail is received using the "strict" policy)
    /// * `next()` - the operation succeeded.
    ///
    /// # Effective smtp stage
    /// `rcpt` and onwards.
    ///
    /// # Errors
    /// * The `header` argument is not valid.
    /// * The `policy` argument is not valid.
    ///
    /// # Note
    /// `spf::check` only checks for the sender's identity, not the `helo` value.
    ///
    /// # Example
    /// ```ignore
    /// #{
    ///     mail: [
    ///        rule "check spf" || spf::check("spf", "soft")
    ///     ]
    /// }
    ///
    /// #{
    ///     mail: [
    ///         // if this check succeed, it wil return `next`.
    ///         // if it fails, it might return `deny` with a custom code
    ///         // (X.7.24 or X.7.25 for example)
    ///         //
    ///         // if you want to use the return status, just put the spf::check
    ///         // function on the last line of your rule.
    ///         rule "check spf 1" || {
    ///             log("debug", `running sender policy framework on ${ctx::mail_from()} identity ...`);
    ///             spf::check("spf", "soft")
    ///         },
    ///
    ///         // policy is set to "strict" by default.
    ///         rule "check spf 2" || spf::check("both"),
    ///     ],
    /// }
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(name = "check", return_raw)]
    pub fn check(ncc: NativeCallContext, header: &str, policy: &str) -> EngineResult<Status> {
        let ctx = get_global!(ncc, ctx)?;
        let srv = get_global!(ncc, srv)?;

        let query = super::check(&ctx, &srv)?;

        let msg = get_global!(ncc, msg)?;

        let (hostname, sender, client_ip) = {
            let ctx = vsl_guard_ok!(ctx.read());

            (
                crate::api::utils::hostname()?,
                vsl_generic_ok!(ctx.reverse_path()).clone(),
                ctx.client_addr().ip().to_string(),
            )
        };

        // TODO: The Received-SPF header field is a trace field
        // and SHOULD be prepended to the existing header, above the Received: field
        // It MUST appear above all other Received-SPF fields in the message.
        match header {
            // It is RECOMMENDED that SMTP receivers record the result"
            "spf" => Impl::prepend_header(
                &msg,
                SPF_HEADER,
                &super::spf_header(
                    &query,
                    &hostname,
                    sender.as_ref().map_or("null", |sender| sender.full()),
                    &client_ip,
                ),
            )?,
            "auth" => Impl::prepend_header(
                &msg,
                AUTH_HEADER,
                &super::auth_header(
                    &query,
                    &hostname,
                    sender.as_ref().map_or("null", |sender| sender.full()),
                    &client_ip,
                ),
            )?,
            "both" => {
                Impl::prepend_header(
                    &msg,
                    AUTH_HEADER,
                    &super::auth_header(
                        &query,
                        &hostname,
                        sender.as_ref().map_or("null", |sender| sender.full()),
                        &client_ip,
                    ),
                )?;
                Impl::prepend_header(
                    &msg,
                    SPF_HEADER,
                    &super::spf_header(
                        &query,
                        &hostname,
                        sender.as_ref().map_or("null", |sender| sender.full()),
                        &client_ip,
                    ),
                )?;
            }
            "none" => {}
            _ => {
                return Err(format!(
                    "spf 'header' argument must be 'spf', 'auth' or 'both', not '{header}'"
                )
                .into())
            }
        };

        if policy == "strict" {
            Ok(match query.result.as_str() {
                "pass" => state::next(),
                "temperror" | "permerror" => {
                    state::deny_with_code(&mut crate::api::code::c550_7_24())?
                }
                // "softfail" | "fail"
                _ => state::deny_with_code(&mut crate::api::code::c550_7_23())?,
            })
        } else if policy == "soft" {
            Ok(match query.result.as_str() {
                "pass" | "softfail" => state::next(),
                "temperror" | "permerror" => {
                    state::deny_with_code(&mut crate::api::code::c550_7_24())?
                }
                // "fail"
                _ => state::deny_with_code(&mut crate::api::code::c550_7_23())?,
            })
        } else {
            Err(format!("spf 'policy' argument must be 'strict' or 'soft', not '{policy}'").into())
        }
    }

    /// Check spf record following the Sender Policy Framework (RFC 7208).
    /// A wrapper with the policy set to "strict" by default.
    /// see <https://datatracker.ietf.org/doc/html/rfc7208>
    ///
    /// # Args
    ///
    /// * `header` - "spf" | "auth" | "both" | "none"
    ///
    /// # Return
    /// * `deny(code550_7_23 | code550_7_24)` - an error occurred during lookup. (returned even when a softfail is received using the "strict" policy)
    /// * `next()` - the operation succeeded.
    ///
    /// # Effective smtp stage
    ///
    /// `rcpt` and onwards.
    ///
    /// # Errors
    ///
    /// * The `header` argument is not valid.
    ///
    /// # Note
    ///
    /// `spf::check` only checks for the sender's identity, not the `helo` value.
    ///
    /// # Examples
    ///
    /// ```text
    /// #{
    ///     mail: [
    ///        rule "check spf relay" || spf::check(allowed_hosts),
    ///     ]
    /// }
    ///
    /// #{
    ///     mail: [
    ///         // if this check succeed, it wil return `next`.
    ///         // if it fails, it might return `deny` with a custom code
    ///         // (X.7.24 or X.7.25 for example)
    ///         //
    ///         // if you want to use the return status, just put the spf::check
    ///         // function on the last line of your rule.
    ///         rule "check spf 1" || {
    ///             log("debug", `running sender policy framework on ${ctx::mail_from()} identity ...`);
    ///             spf::check("spf", "soft")
    ///         },
    ///
    ///         // policy is set to "strict" by default.
    ///         rule "check spf 2" || spf::check("both"),
    ///     ],
    /// }
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(name = "check", return_raw)]
    pub fn check_with_header(ncc: NativeCallContext, header: &str) -> EngineResult<Status> {
        check(ncc, header, "strict")
    }

    /// WARNING: Low level API, use `spf::check` instead.
    ///
    /// Check spf record following the Sender Policy Framework (RFC 7208).
    /// see <https://datatracker.ietf.org/doc/html/rfc7208>
    ///
    /// # Return
    /// * `map` - the result of the spf check, contains the `result`, `mechanism` and `problem` keys.
    ///
    /// # Effective smtp stage
    ///
    /// `rcpt` and onwards.
    ///
    /// # Note
    ///
    /// `spf::check` only checks for the sender's identity, not the `helo` value.
    ///
    /// # Examples
    ///
    /// ```text
    /// #{
    ///     mail: [
    ///        rule "check spf relay" || {
    ///             const spf = spf::check_raw();
    ///
    ///             log("info", `spf results: ${spf.result}, mechanism: ${spf.mechanism}, problem: ${spf.problem}`)
    ///         },
    ///     ]
    /// }
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(name = "check_raw", return_raw)]
    pub fn check_raw(ncc: NativeCallContext) -> EngineResult<rhai::Map> {
        let ctx = get_global!(ncc, ctx)?;
        let srv = get_global!(ncc, srv)?;

        super::check(&ctx, &srv).map(|spf| result_to_map(&spf))
    }
}

/// Inner spf check implementation.
/// # Result
/// # Errors
/// # Panics
pub fn check(ctx: &Context, srv: &Server) -> EngineResult<vsmtp_auth::spf::Result> {
    use vsmtp_auth::viaspf;
    use vsmtp_common::ClientName;

    let (spf_sender, ip) = {
        let ctx = vsl_guard_ok!(ctx.read());
        let mail_from = ctx
            .reverse_path()
            .map_err::<Box<rhai::EvalAltResult>, _>(|_| "bad state".into())?;

        let spf_sender = vsl_generic_ok!(match mail_from {
            Some(mail_from) => viaspf::Sender::from_address(mail_from.full()),
            None => {
                let client_name = ctx
                    .client_name()
                    .map_err::<Box<rhai::EvalAltResult>, _>(|_| "bad state".into())?;
                match client_name {
                    ClientName::Domain(domain) => viaspf::Sender::from_domain(domain),
                    ClientName::Ip4(_) | ClientName::Ip6(_) => {
                        todo!("handle scenario where client_name is an IP address and reverse_path is null")
                    }
                }
            }
        });

        (spf_sender, ctx.client_addr().ip())
    };

    let resolver = srv.resolvers.get_resolver_root();

    let spf_result = block_on!(vsmtp_auth::spf::evaluate(resolver, ip, &spf_sender));

    vsl_guard_ok!(ctx.write())
        .set_spf(spf_result.clone())
        .unwrap();

    Ok(spf_result)
}

/// create key-value pairs of spf results
/// to inject into the spf or auth headers.
#[must_use]
pub fn key_value_list(
    spf: &vsmtp_auth::spf::Result,
    hostname: &str,
    sender: &str,
    client_ip: &str,
) -> String {
    format!(
        r#"receiver={};
 client-ip={};
 envelope_from={};
 identity=mailfrom;
 {}`
        "#,
        hostname,
        client_ip,
        sender,
        match &spf.details {
            vsmtp_auth::spf::Details::Mechanism(mechanism) => format!("mechanism={mechanism};"),
            vsmtp_auth::spf::Details::Problem(problem) => format!("problem={problem};"),
        },
    )
}

/// Record results in a spf header (RFC 7208-9)
fn spf_header(
    spf: &vsmtp_auth::spf::Result,
    hostname: &str,
    sender: &str,
    client_ip: &str,
) -> String {
    format!(
        "{} {}",
        spf.result,
        key_value_list(spf, hostname, sender, client_ip)
    )
}

/// Record results in the auth header (RFC 7208-9)
fn auth_header(
    spf: &vsmtp_auth::spf::Result,
    hostname: &str,
    sender: &str,
    client_ip: &str,
) -> String {
    format!(
        r#"{}; spf={}
 reason="{}"
 smtp.mailfrom={}"#,
        hostname,
        spf.result,
        key_value_list(spf, hostname, sender, client_ip),
        sender
    )
}

/// Create a rhai map from spf results.
fn result_to_map(spf: &vsmtp_auth::spf::Result) -> rhai::Map {
    rhai::Map::from_iter([
        ("result".into(), rhai::Dynamic::from(spf.result.clone())),
        match &spf.details {
            vsmtp_auth::spf::Details::Mechanism(mechanism) => {
                ("mechanism".into(), mechanism.into())
            }
            vsmtp_auth::spf::Details::Problem(error) => ("problem".into(), error.into()),
        },
    ])
}
