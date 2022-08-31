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

//! ### Transaction
//!
//! At each SMTP stage, data from the client is received via 'SMTP commands'.
//! This module lets you query the content of the commands.

/// Get the value of the `HELO/EHLO` command sent by the client.
///
/// ### Effective smtp stage
///
/// `helo` and onwards.
///
/// ### Return
///
/// * `string` - the value of the `HELO/EHLO` command.
///
/// ### Example
/// ```js
/// #{
///     helo: [
///        action "log info" || log("info", `${helo()}`),
///     ]
/// }
/// ```
///
/// ### Module:Transaction
fn helo() { ctx().helo }

/// Get the value of the `MAIL FROM` command sent by the client.
///
/// ### Effective smtp stage
///
/// `mail` and onwards.
///
/// ### Return
///
/// * `address` - the sender address.
///
/// ### Example
/// ```js
/// #{
///     helo: [
///        action "log info" || log("info", `${mail_from()}`),
///     ]
/// }
/// ```
///
/// ### Module:Transaction
fn mail_from() { ctx().mail_from }

/// Get the value of the current `RCPT TO` command sent by the client.
///
/// ### Effective smtp stage
///
/// `rcpt` and onwards. Please note that `rcpt()` will always return
/// the last recipient received in stages after the `rcpt` stage. Therefore,
/// this functions is best used in the `rcpt` stage.
///
/// ### Return
///
/// * `address` - the address of the received recipient.
///
/// ### Example
/// ```js
/// #{
///     rcpt: [
///        action "log recipients" || log("info", `new recipient: ${rcpt()}`),
///     ]
/// }
/// ```
///
/// ### Module:Transaction
fn rcpt() { ctx().rcpt }

/// Get the list of recipients received by the client.
///
/// ### Effective smtp stage
///
/// `rcpt` and onwards. Note that you will not have all recipients received
/// all at once in the `rcpt` stage. It is better to use this function
/// in the later stages.
///
/// ### Return
///
/// * `Array of addresses` - the list containing all recipients.
///
/// ### Example
/// ```js
/// #{
///     preq: [
///        action "log recipients" || log("info", `all recipients: ${rcpt_list()}`),
///     ]
/// }
/// ```
///
/// ### Module:Transaction
fn rcpt_list() { ctx().rcpt_list }

/// Get the time of reception of the email.
///
/// ### Effective smtp stage
///
/// `preq` and onwards.
///
/// ### Return
///
/// * `string` - the timestamp.
///
/// ### Example
/// ```js
/// #{
///     preq: [
///        action "receiving the email" || log("info", `time of reception: ${mail_timestamp()}`),
///     ]
/// }
/// ```
///
/// ### Module:Transaction
fn mail_timestamp() { ctx().mail_timestamp }

/// Get the unique id of the received message.
///
/// ### Effective smtp stage
///
/// `preq` and onwards.
///
/// ### Return
///
/// * `string` - the message id.
///
/// ### Example
/// ```js
/// #{
///     preq: [
///        action "message received" || log("info", `message id: ${message_id()}`),
///     ]
/// }
/// ```
///
/// ### Module:Transaction
fn message_id() { ctx().message_id }
