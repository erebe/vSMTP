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

//! # Internal
//!
//! A low level api to get access to internal functions of vsl.

/// WARNING: This is a low level function.
/// Get access to the email context.
///
/// # Note
/// This is used internally to provide encapsulation of vsl's features.
/// You should not use this function.
///
/// # Return
///
/// * `the context`
///
/// # Effective smtp stage
/// all of them.
///
/// # Example
/// ```js
/// #{
///     connect: [
///        action "client ip" || log("info", `client: {ctx().client_ip}`),
///     ]
/// }
/// ```
fn ctx() { CTX }

/// WARNING: This is a low level function.
/// Get access to the server context.
///
/// # Note
/// This is used internally to provide encapsulation of vsl's features.
/// You should not use this function.
///
/// # Return
///
/// * `the server api`
///
/// # Effective smtp stage
/// all of them.
///
/// # Example
/// ```js
/// #{
///     connect: [
///        action "raw lookup" || srv().lookup("example.com"),
///     ]
/// }
/// ```
fn srv() { SRV }

/// WARNING: This is a low level function.
/// Get access to the message.
///
/// # Note
/// This is used internally to provide encapsulation of vsl's features.
/// You should not use this function.
///
/// # Return
///
/// * `the message`
///
/// # Effective smtp stage
/// all of them.
///
/// # Example
/// ```js
/// #{
///     connect: [
///        action "raw message" || msg().rewrite_mail_from_message("john.doe@example.com"),
///     ]
/// }
/// ```
fn msg() { MSG }
