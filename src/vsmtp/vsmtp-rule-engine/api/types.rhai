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

//! # Types
//!
//! Those functions let you create and manipulate vsl types.


/// Create a new address from a string.
/// Can be useful to parse addresses from a database.
///
/// # Note
///
/// If you just need a static address, you can use the [`address` vsl object](https://vsmtp.rs/reference/vSL/objects.html).
///
/// ```js
/// object my_static_address address = "john.doe@example.com";
/// ```
///
/// # Args
///
/// * `address` - the string address to parse.
///
/// # Return
///
/// * `address` - a new address object.
///
/// # Errors
///
/// * The address is not valid.
///
/// # Effective smtp stage
///
/// All of them.
///
/// # Example
/// ```js
/// #{
///     rcpt: [
///        rule "check rcpt domain" || if in_domain(rcpt()) { next() } else { deny() },
///     ]
/// }
///
/// # Module:Types
/// ```
fn new_address(address) { sys::new_address(address) }
