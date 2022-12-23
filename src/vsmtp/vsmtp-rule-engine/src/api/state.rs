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
use rhai::plugin::{
    mem, Dynamic, EvalAltResult, FnAccess, FnNamespace, ImmutableString, Module, NativeCallContext,
    PluginFunction, RhaiResult, TypeId,
};
use vsmtp_common::{status::Status, CodeID, Reply, ReplyOrCodeID};
use vsmtp_plugin_vsl::objects::Object;

fn reply_or_code_id_from_object(code: &SharedObject) -> EngineResult<ReplyOrCodeID> {
    match &**code {
        Object::Code(code) => Ok(ReplyOrCodeID::Right(code.clone())),
        object => Err(format!("parameter must be a code, not {}", object.as_ref()).into()),
    }
}

fn reply_or_code_id_from_string(code: &str) -> EngineResult<ReplyOrCodeID> {
    Ok(ReplyOrCodeID::Right(
        <Reply as std::str::FromStr>::from_str(code).map_err::<Box<EvalAltResult>, _>(|_| {
            format!("parameter must be a code, not {code:?}").into()
        })?,
    ))
}

pub use state::*;

/// Functions used to interact with the rule engine.
/// Use `states` in `rules` to deny, accept, or quarantine emails.
#[rhai::plugin::export_module]
mod state {

    /// Operator `==` for `Status`
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "==", pure)]
    pub fn eq_status_operator(status_1: &mut Status, status_2: Status) -> bool {
        *status_1 == status_2
    }

    /// Operator `!=` for `Status`
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "!=", pure)]
    pub fn neq_status_operator(status_1: &mut Status, status_2: Status) -> bool {
        !(*status_1 == status_2)
    }

    /// Convert a `Status` to a `String`
    #[rhai_fn(global, pure)]
    pub fn to_string(status: &mut Status) -> String {
        status.as_ref().to_string()
    }

    /// Convert a `Status` to a debug string
    #[rhai_fn(global, pure)]
    pub fn to_debug(status: &mut Status) -> String {
        status.as_ref().to_string()
    }

    /// Tell the rule engine to force accept the incoming transaction.
    /// This means that all rules following the one `faccept` is called
    /// will be ignored.
    ///
    /// Sends an 'Ok' code to the client. To customize the code to send,
    /// see `faccept(code)`.
    ///
    /// Use this return status when you are sure that
    /// the incoming client can be trusted.
    ///
    /// # Effective smtp stage
    ///
    /// all of them.
    ///
    /// # Example
    ///
    /// ```ignore
    /// #{
    ///     connect: [
    ///         // Here we imagine that "192.168.1.10" is a trusted source, so we can force accept
    ///         // any other rules that don't need to be run.
    ///         rule "check for trusted source" || if ctx::client_ip() == "192.168.1.10" { faccept() } else { state::next() },
    ///     ],
    ///
    ///     // The following rules will not be evaluated if `ctx::client_ip() == "192.168.1.10"` is true.
    ///     mail: [
    ///         rule "another rule" || {
    ///             // ... doing stuff
    ///         }
    ///     ],
    /// }
    /// ```
    #[must_use]
    pub const fn faccept() -> Status {
        Status::Faccept(ReplyOrCodeID::Left(CodeID::Ok))
    }

    /// Tell the rule engine to force accept the incoming transaction.
    /// This means that all rules following the one `faccept` is called
    /// will be ignored.
    ///
    /// Use this return status when you are sure that
    /// the incoming client can be trusted.
    ///
    /// # Args
    ///
    /// * `code` - a custom code using a `code` object to send to the client.
    ///
    /// # Error
    ///
    /// * The given parameter was not a code object.
    ///
    /// # Effective smtp stage
    ///
    /// all of them.
    ///
    /// # Example
    ///
    /// ```ignore
    /// #{
    ///     connect: [
    ///         // Here we imagine that "192.168.1.10" is a trusted source, so we can force accept
    ///         // any other rules that don't need to be run.
    ///         rule "check for trusted source" || if ctx::client_ip() == "192.168.1.10" { faccept(code(220, "Ok")) } else { state::next() },
    ///     ],
    ///
    ///     // The following rules will not be evaluated if `ctx::client_ip() == "192.168.1.10"` is true.
    ///     mail: [
    ///         rule "another rule" || {
    ///             // ... doing stuff
    ///         }
    ///     ],
    /// }
    /// ```
    #[rhai_fn(name = "faccept", return_raw, pure)]
    pub fn faccept_with_code(code: &mut SharedObject) -> EngineResult<Status> {
        reply_or_code_id_from_object(code).map(Status::Faccept)
    }

    /// Tell the rule engine to force accept the incoming transaction.
    /// This means that all rules following the one `faccept` is called
    /// will be ignored.
    ///
    /// Use this return status when you are sure that
    /// the incoming client can be trusted.
    ///
    /// # Args
    ///
    /// * `code` - a custom code as a string to send to the client.
    ///
    /// # Error
    ///
    /// * Could not parse the parameter as a valid SMTP reply code.
    ///
    /// # Effective smtp stage
    ///
    /// all of them.
    ///
    /// # Example
    /// ```ignore
    /// #{
    ///     connect: [
    ///         // Here we imagine that "192.168.1.10" is a trusted source, so we can force accept
    ///         // any other rules that don't need to be run.
    ///         rule "check for trusted source" || if ctx::client_ip() == "192.168.1.10" { faccept("220 Ok") } else { state::next() },
    ///     ],
    ///
    ///     // The following rules will not be evaluated if `ctx::client_ip() == "192.168.1.10"` is true.
    ///     mail: [
    ///         rule "another rule" || {
    ///             // ... doing stuff
    ///         }
    ///     ],
    /// }
    /// ```
    ///
    /// # Errors
    #[rhai_fn(name = "faccept", return_raw)]
    pub fn faccept_with_string(code: &str) -> EngineResult<Status> {
        reply_or_code_id_from_string(code).map(Status::Faccept)
    }

    /// Tell the rule engine to accept the incoming transaction for the current stage.
    /// This means that all rules following the one `accept` is called in the current stage
    /// will be ignored.
    ///
    /// # Effective smtp stage
    ///
    /// all of them.
    ///
    /// # Example
    ///
    /// ```ignore
    /// #{
    ///     connect: [
    ///         // "ignored checks" will be ignored because the previous rule returned accept.
    ///         rule "accept" || state::accept(),
    ///         action "ignore checks" || print("this will be ignored because the previous rule used state::accept()."),
    ///     ],
    ///
    ///     mail: [
    ///         // rule evaluation is resumed in the next stage.
    ///         rule "resume rules" || print("evaluation resumed!");
    ///     ]
    /// }
    /// ```
    #[must_use]
    pub const fn accept() -> Status {
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok))
    }

    /// Tell the rule engine to accept the incoming transaction for the current stage.
    /// This means that all rules following the one `accept` is called in the current stage
    /// will be ignored.
    ///
    /// # Args
    ///
    /// * `code` - A custom code using a `code` object to send to the client.
    ///
    /// # Error
    ///
    /// * The given parameter was not a code object.
    ///
    /// # Effective smtp stage
    ///
    /// all of them.
    ///
    /// # Example
    ///
    /// ```ignore
    /// #{
    ///     connect: [
    ///         // "ignored checks" will be ignored because the previous rule returned accept.
    ///         rule "accept" || state::accept(code(220, "Ok")),
    ///         action "ignore checks" || print("this will be ignored because the previous rule used state::accept()."),
    ///     ],
    ///
    ///     mail: [
    ///         // rule evaluation is resumed in the next stage.
    ///         rule "resume rules" || print("evaluation resumed!");
    ///     ]
    /// }
    /// ```
    #[rhai_fn(name = "accept", return_raw, pure)]
    pub fn accept_with_code(code: &mut SharedObject) -> EngineResult<Status> {
        reply_or_code_id_from_object(code).map(Status::Accept)
    }

    /// Tell the rule engine to accept the incoming transaction for the current stage.
    /// This means that all rules following the one `accept` is called in the current stage
    /// will be ignored.
    ///
    /// # Args
    ///
    /// * `code` - A custom code as a string to send to the client.
    ///
    /// # Error
    ///
    /// * Could not parse the parameter as a valid SMTP reply code.
    ///
    /// # Effective smtp stage
    ///
    /// all of them.
    ///
    /// # Example
    ///
    /// ```ignore
    /// #{
    ///     connect: [
    ///         // "ignored checks" will be ignored because the previous rule returned accept.
    ///         rule "accept" || state::accept(code(220, "Ok")),
    ///         action "ignore checks" || print("this will be ignored because the previous rule used state::accept()."),
    ///     ],
    ///
    ///     mail: [
    ///         // rule evaluation is resumed in the next stage.
    ///         rule "resume rules" || print("evaluation resumed!");
    ///     ]
    /// }
    /// ```
    #[rhai_fn(name = "accept", return_raw)]
    pub fn accept_with_string(code: &str) -> EngineResult<Status> {
        reply_or_code_id_from_string(code).map(Status::Accept)
    }

    /// Tell the rule engine that a rule succeeded. Following rules
    /// in the current stage will be executed.
    ///
    /// # Effective smtp stage
    ///
    /// all of them.
    ///
    /// # Example
    ///
    /// ```ignore
    /// #{
    ///     connect: [
    ///         // once "go to the next rule" is evaluated, the rule engine execute "another rule".
    ///         rule "go to the next rule" || state::next(),
    ///         action "another rule" || print("checking stuff ..."),
    ///     ],
    /// }
    /// ```
    #[must_use]
    pub const fn next() -> Status {
        Status::Next
    }

    /// Stop rules evaluation and/or send an error code to the client.
    /// The code sent is `554 - permanent problems with the remote server`.
    ///
    /// To use a custom code, see `deny(code)`.
    ///
    /// # Effective smtp stage
    ///
    /// all of them.
    ///
    /// # Example
    ///
    /// ```ignore
    /// #{
    ///     rcpt: [
    ///         rule "check for satan" || {
    ///            // The client is denied if a recipient's domain matches satan.org,
    ///            // this is a blacklist, sort-of.
    ///            if ctx::rcpt().domain == "satan.org" {
    ///                state::deny()
    ///            } else {
    ///                state::next()
    ///            }
    ///        },
    ///     ],
    /// }
    /// ```
    #[must_use]
    #[rhai_fn(global)]
    pub const fn deny() -> Status {
        Status::Deny(ReplyOrCodeID::Left(CodeID::Denied))
    }

    /// Stop rules evaluation and/or send an error code to the client.
    ///
    /// # Args
    ///
    /// * `code` - A custom code using a `code` object to send to the client.
    ///            See `code()` for more information.
    ///
    /// # Error
    ///
    /// * The given parameter was not a code object.
    ///
    /// # Effective smtp stage
    ///
    /// all of them.
    ///
    /// # Example
    ///
    /// ```ignore
    /// #{
    ///     rcpt: [
    ///         rule "check for satan" || {
    ///            // The client is denied if a recipient's domain matches satan.org,
    ///            // this is a blacklist, sort-of.
    ///            if ctx::rcpt().domain == "satan.org" {
    ///                state::deny(code(554, "permanent problems with the remote server"))
    ///            } else {
    ///                state::next()
    ///            }
    ///        },
    ///     ],
    /// }
    /// ```
    #[rhai_fn(name = "deny", return_raw, pure)]
    pub fn deny_with_code(code: &mut SharedObject) -> EngineResult<Status> {
        reply_or_code_id_from_object(code).map(Status::Deny)
    }

    /// Stop rules evaluation and/or send an error code to the client.
    ///
    /// # Args
    ///
    /// * `code` - A custom code as a string to send to the client.
    ///
    /// # Error
    ///
    /// * Could not parse the parameter as a valid SMTP reply code.
    ///
    /// # Effective smtp stage
    ///
    /// all of them.
    ///
    /// # Example
    ///
    /// ```ignore
    /// #{
    ///     rcpt: [
    ///         rule "check for satan" || {
    ///            // The client is denied if a recipient's domain matches satan.org,
    ///            // this is a blacklist, sort-of.
    ///            if ctx::rcpt().domain == "satan.org" {
    ///                state::deny("554 permanent problems with the remote server")
    ///            } else {
    ///                state::next()
    ///            }
    ///        },
    ///     ],
    /// }
    /// ```
    #[rhai_fn(name = "deny", return_raw)]
    pub fn deny_with_string(code: &str) -> EngineResult<Status> {
        reply_or_code_id_from_string(code).map(Status::Deny)
    }

    /// Ask the client to retry to send the current command by sending an information code.
    ///
    /// # Args
    ///
    /// * `code` - A custom code using a `code` object to send to the client.
    ///            See `code()` for more information.
    ///
    /// # Error
    ///
    /// * The given parameter was not a code object.
    ///
    /// # Effective smtp stage
    ///
    /// all of them.
    ///
    /// # Example
    ///
    /// ```ignore
    /// #{
    ///     connect: [
    ///         rule "please retry" || {
    ///            const info_code = code(451, "failed to understand you request, please retry.");
    ///            state::info(info_code)
    ///        },
    ///     ],
    /// }
    /// ```
    #[rhai_fn(name = "info", return_raw, pure)]
    pub fn info_with_code(code: &mut SharedObject) -> EngineResult<Status> {
        reply_or_code_id_from_object(code).map(Status::Info)
    }

    /// Ask the client to retry to send the current command by sending an information code.
    ///
    /// # Args
    ///
    /// * `code` - A custom code as a string to send to the client.
    ///
    /// # Error
    ///
    /// * Could not parse the parameter as a valid SMTP reply code.
    ///
    /// # Effective smtp stage
    ///
    /// all of them.
    ///
    /// # Example
    ///
    /// ```ignore
    /// #{
    ///     connect: [
    ///         rule "please retry" || {
    ///            state::info("451 failed to understand you request, please retry")
    ///        },
    ///     ],
    /// }
    /// ```
    #[rhai_fn(name = "info", return_raw)]
    pub fn info_with_string(code: &str) -> EngineResult<Status> {
        reply_or_code_id_from_string(code).map(Status::Info)
    }

    /// Skip all rules until the email is received and place the email in a
    /// quarantine queue. The email will never be sent to the recipients and
    /// will stop being processed after the `PreQ` stage.
    ///
    /// # Args
    ///
    /// * `queue` - the relative path to the queue where the email will be quarantined as a string.
    ///             This path will be concatenated to the `config.app.dirpath` field in
    ///             your root configuration.
    ///
    /// # Effective smtp stage
    ///
    /// all of them.
    ///
    /// # Example
    ///
    /// ```ignore
    /// import "services" as svc;
    ///
    /// #{
    ///     postq: [
    ///           delegate svc::clamsmtpd "check email for virus" || {
    ///               // the email is placed in quarantined if a virus is detected by
    ///               // a service.
    ///               if has_header("X-Virus-Infected") {
    ///                 state::quarantine("virus_queue")
    ///               } else {
    ///                 state::next()
    ///               }
    ///           }
    ///     ],
    /// }
    /// ```
    #[must_use]
    #[rhai_fn(name = "quarantine")]
    pub fn quarantine_str(queue: &str) -> Status {
        Status::Quarantine(queue.to_string())
    }
}
