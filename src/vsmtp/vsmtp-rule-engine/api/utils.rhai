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

//! ### Utils
//!
//! Those miscellaneous functions lets you query data from your system,
//! log stuff, perform dns lookups etc ...

/// get the domain used to identify a recipient.
/// check if the recipient passed as argument is part of the
/// domains (root & sni) of the server.
///
/// ### Args
///
/// * `rcpt` - the recipient to check, of type string | `object address` | rcpt.
///
/// ### Return
///
/// * `bool` - true of the recipient's domain is part of the server's root or sni domains, false otherwise.
///
/// ### Effective smtp stage
/// all of them, but should be use in the rcpt stage.
///
/// ### Example
/// ```js
/// #{
///     rcpt: [
///        rule "check rcpt domain" || if in_domain(rcpt()) { next() } else { deny() },
///     ]
/// }
///
/// ### Module:Utils
/// ```
fn in_domain(rcpt) {
    switch rcpt.type_of() {
        "alloc::sync::Arc<vsmtp_rule_engine::dsl::object::Object>" => {
            rcpt.domain in toml::server.virtual || rcpt.domain == toml::server.domain
        },
        "string" => {
            rcpt in toml::server.virtual || rcpt == toml::server.domain
        },
        _ => false,
    }
}

/// Log information to stdout in `nodaemon` mode or to a file.
///
/// ### Args
///
/// * `level` - the level of the message, can be "trace", "debug", "info", "warn" or "error".
/// * `message` - the message to log.
///
/// ### Effective smtp stage
///
/// All of them.
///
/// ### Example
/// ```js
/// #{
///     preq: [
///        action "log info" || log("info", "this is an informational log."),
///     ]
/// }
/// ```
///
/// ### Module:Utils
fn log(level, message) { sys::log(level, message) }

/// Export the current raw message to a file as an `eml` file.
/// The message id of the email is used to name the file.
///
/// ### Args
///
/// * `dir` - the directory where to store the email. Relative to the
/// application path.
///
/// ### Effective smtp stage
///
/// `preq` and onwards.
///
/// ### Example
/// ```js
/// #{
///     preq: [
///        action "write to file" || write("archives"),
///     ]
/// }
/// ```
///
/// ### Module:Utils
fn write(dir) { sys::write(srv(), ctx(), msg(), dir) }

/// Export the current message and the envelop to a file as a `json` file.
/// The message id of the email is used to name the file.
///
/// ### Args
///
/// * `dir` - the directory where to store the data. Relative to the
/// application path.
///
/// ### Effective smtp stage
///
/// `preq` and onwards.
///
/// ### Example
/// ```js
/// #{
///     preq: [
///        action "dump email" || dump("metadata"),
///     ]
/// }
/// ```
///
/// ### Module:Utils
fn dump(dir) { sys::dump(srv(), ctx(), dir) }

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
/// ### Example
/// ```js
/// #{
///     rcpt: [
///        action "check for local user" || {
///            if user_exist(rcpt().local_part) {
///                log("debug", `${rcpt().local_part} exists on disk.`);
///            }
///        }
///     ]
/// }
/// ```
///
/// ### Module:Utils
fn user_exist(name) { sys::user_exist(name) }

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
/// ### Example
/// ```js
/// #{
///     preq: [
///        action "append info header" || {
///             append_header("X-VSMTP", `email received by ${hostname()}.`);
///        }
///     ]
/// }
/// ```
///
/// ### Module:Utils
fn hostname() { sys::hostname() }

/// Get the current date.
///
/// ### Return
///
/// * `string` - the current date.
///
/// ### Effective smtp stage
///
/// All of them.
///
/// ### Example
/// ```js
/// #{
///     preq: [
///        action "append info header" || {
///             append_header("X-VSMTP", `email received by ${hostname()} the ${date()}.`);
///        }
///     ]
/// }
/// ```
///
/// ### Module:Utils
fn date() { sys::date() }

/// Get the current time.
///
/// ### Return
///
/// * `string` - the current time.
///
/// ### Effective smtp stage
///
/// All of them.
///
/// ### Example
/// ```js
/// #{
///     preq: [
///        action "append info header" || {
///             append_header("X-VSMTP", `email received by ${hostname()} the ${date()} at ${time()}.`);
///        }
///     ]
/// }
/// ```
///
/// ### Module:Utils
fn time() { sys::time() }

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
/// ### Example
/// ```js
/// #{
///     rcpt: [
///        action "perform lookup" || {
///             let domain = rcpt().domain;
///             let ips = lookup(domain);
///
///             print(`ips found for ${domain}`);
///             for ip in ips {
///                 print(`- ${ip}`);
///             }
///        }
///     ]
/// }
/// ```
///
/// ### Module:Utils
fn lookup(host) { sys::lookup(srv(), host) }

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
/// ### Example
/// ```js
/// #{
///     connect: [
///        action "perform reverse lookup" || {
///             let domains = rlookup(client_ip());
///
///             print(`domains found for ip ${client_ip()}`);
///             for domain in domains {
///                 print(`- ${domain}`);
///             }
///        }
///     ]
/// }
/// ```
///
/// ### Module:Utils
fn rlookup(ip) { sys::rlookup(srv(), ip) }
