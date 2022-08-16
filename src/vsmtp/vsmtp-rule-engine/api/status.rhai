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

/// Tell the rule engine to force accept the incoming transaction.
/// This means that all rules following the one `faccept` is called
/// will be ignored.
///
/// Use this return status when you are sure that
/// the incoming client can be trusted.
///
/// # Effective smtp stage
///
/// all of them.
///
/// # Example
/// ```js
/// #{
///     connect: [
///         // Here we imagine that "192.168.1.10" is a trusted source, so we can force accept
///         // any other rules that don't need to be run.
///         rule "check for trusted source" || if client_ip() == "192.168.1.10" { faccept() } else { next() },
///     ],
///
///     // The following rules will not be evaluated if `client_ip() == "192.168.1.10"` is true.
///     mail: [
///         rule "another rule" || {
///             // ... doing stuff
///         }
///     ],
/// }
///
/// # Module:Status
/// ```
fn faccept() { sys::faccept() }

/// Tell the rule engine to accept the incoming transaction for the current stage.
/// This means that all rules following the one `accept` is called in the current stage
/// will be ignored.
///
/// # Effective smtp stage
///
/// all of them.
///
/// # Example
/// ```js
/// #{
///     connect: [
///         // "ignored checks" will be ignored because the previous rule returned accept.
///         rule "accept" || accept(),
///         action "ignore checks" || print("this will be ignored because the previous rule used accept()."),
///     ],
///
///     mail: [
///         // rule evaluation is resumed in the next stage.
///         rule "resume rules" || print("evaluation resumed!");
///     ]
/// }
/// ```
///
/// # Module:Status
fn accept() { sys::accept() }

/// Tell the rule engine that a rule succeeded.
///
/// # Effective smtp stage
///
/// all of them.
///
/// # Example
/// ```js
/// #{
///     connect: [
///         // once "go to the next rule" is evaluated, the rule engine execute "another rule".
///         rule "go to the next rule" || next(),
///         action "another rule" || print("checking stuff ..."),
///     ],
/// }
/// ```
///
/// # Module:Status
fn next() { sys::next() }

/// Stop rules evaluation and/or send an error code to the client.
/// The code sent is `554 - permanent problems with the remote server`.
///
/// # Effective smtp stage
///
/// all of them.
///
/// # Example
/// ```js
/// #{
///     rcpt: [
///         rule "check for satan" || {
///            // The client is denied if a recipient's domain matches satan.org,
///            // this is a blacklist, sort-of.
///            if ctx().rcpt.domain == "satan.org" {
///                deny()
///            } else {
///                next()
///            }
///        },
///     ],
/// }
/// ```
///
/// # Module:Status
fn deny() { sys::deny() }

/// Stop rules evaluation and/or send a custom code to the client.
///
/// # Effective smtp stage
///
/// all of them.
///
/// # Example
/// ```js
/// #{
///     rcpt: [
///         rule "check for satan" || {
///            // a custom error code can be used with `deny`.
///            object error_code code = #{ code: 550, enhanced: "", text: "satan.org is not welcome here." };
///
///            // The client is denied if a recipient's domain matches satan.org,
///            // this is a blacklist, sort-of.
///            if ctx().rcpt.domain == "satan.org" {
///                deny(error_code)
///            } else {
///                next()
///            }
///        },
///     ],
/// }
/// ```
///
/// # Module:Status
fn deny(code) { sys::deny(code) }

/// Ask the client to retry to send the current command by sending an information code.
///
/// # Effective smtp stage
///
/// all of them.
///
/// # Example
/// ```js
/// #{
///     connect: [
///         rule "please retry" || {
///            object info_code code = #{ code: 451, enhanced: "", text: "failed to understand you request, please retry." };
///            info(info_code)
///        },
///     ],
/// }
/// ```
///
/// # Module:Status
fn info(code) { sys::info(code) }

/// Skip all rules until the email is received and place the email in a
/// quarantine queue.
///
/// # Args
///
/// * `queue` - the relative path to the queue where the email will be quarantined. This path will be concatenated to the [app.dirpath] field in your `vsmtp.toml`.
///
/// # Effective smtp stage
///
/// all of them.
///
/// # Example
/// ```js
/// import "services" as svc;
///
/// #{
///     postq: [
///           delegate svc::clamsmtpd "check email for virus" || {
///               // the email is placed in quarantined if a virus is detected by
///               // a service.
///               if has_header("X-Virus-Infected") {
///                 quarantine("virus_queue")
///               } else {
///                 next()
///               }
///           }
///     ],
/// }
/// ```
///
/// # Module:Status
fn quarantine(queue) { sys::quarantine(ctx(), queue) }
