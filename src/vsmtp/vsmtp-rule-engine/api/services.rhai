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

/// Get the value of a key in a database.
///
/// # Args
///
/// * `key` - the key to query.
///
/// # Return
///
/// * `Array of records` - an array containing the results.
///
/// # Effective smtp stage
///
/// All of them.
///
/// # Example
/// ```js
/// import "services" as svc;
///
/// #{
///     mail: [
///        action "fetch database" || {
///             let records = svc::my_database.get(mail_from());
///
///             if records.len() == 0 {
///                 log("debug", `${mail_from()} is not in my database`);
///             } else {
///                 log("debug", `${mail_from()} found in my database`);
///             }
///        }
///     ]
/// }
/// ```
///
/// # Module:Services
fn get(key) { this.db_query(key.to_string()) }

/// Set a record into a database.
///
/// # Args
///
/// * `record` - the record to set.
///
/// # Effective smtp stage
///
/// All of them.
///
/// # Example
/// ```js
/// import "services" as svc;
///
/// #{
///     mail: [
///        action "set sender in database" || {
///             svc::my_database.set(mail_from());
///        }
///     ]
/// }
/// ```
///
/// # Module:Services
fn set(record) { this.db_add(record) }

/// Remove a record from a database.
///
/// # Args
///
/// * `key` - the key to remove.
///
/// # Effective smtp stage
///
/// All of them.
///
/// # Example
/// ```js
/// import "services" as svc;
///
/// #{
///     mail: [
///        action "remove sender from database" || {
///             svc::my_database.rm(mail_from());
///        }
///     ]
/// }
/// ```
///
/// # Module:Services
fn rm(key) { this.db_rm(key.to_string()) }
