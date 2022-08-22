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

/// Get the local part of an email address.
///
/// # Args
///
/// * `address` - the address to extract the local part from.
///
/// # Effective smtp stage
///
/// All of them.
///
/// # Example
/// ```js
/// #{
///     mail: [
///         // You can also use the `get_local_part(mail_from())` syntax.
///         action "display mail from identity" || {
///             log("info", `received a message from ${mail_from().local_part}.`);
///         }
///     ],
/// }
/// ```
///
/// # Module:Message
fn get_local_part() { this.local_part }

/// Get all local parts of the recipient list.
///
/// # Args
///
/// * `rcpt_list` - the recipient list.
///
/// # Effective smtp stage
///
/// `mail` and onwards.
///
/// # Example
/// ```js
/// #{
///     mail: [
///         action "display recipients usernames" || {
///             print("list of recipients user names:");
///
///             // You can also use the `get_local_parts(rcpt_list())` syntax.
///             for user in rcpt_list().local_parts {
///                 print(`- ${user}`);
///             }
///         }
///     ],
/// }
/// ```
///
/// # Module:Message
fn get_local_parts() { this.local_parts }

/// Get the domain of an email address.
///
/// # Args
///
/// * `address` - the address to extract the domain from.
///
/// # Effective smtp stage
///
/// All of them.
///
/// # Example
/// ```js
/// #{
///     mail: [
///         // You can also use the `get_domain(mail_from())` syntax.
///         action "display sender's domain" || {
///             log("info", `received a message from domain ${mail_from().domain}.`);
///         }
///     ],
/// }
/// ```
///
/// # Module:Message
fn get_domain() { this.domain }

/// Get all domains of the recipient list.
///
/// # Args
///
/// * `rcpt_list` - the recipient list.
///
/// # Effective smtp stage
///
/// `mail` and onwards.
///
/// # Example
/// ```js
/// #{
///     mail: [
///         action "display recipients domains" || {
///             print("list of recipients domains:");
///
///             // You can also use the `get_domains(rcpt_list())` syntax.
///             for domain in rcpt_list().domains {
///                 print(`- ${domain}`);
///             }
///         }
///     ],
/// }
/// ```
///
/// # Module:Message
fn get_domains() { this.domains }
