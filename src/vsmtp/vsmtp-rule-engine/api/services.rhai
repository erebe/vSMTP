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

//! ### Services
//!
//! Services are external programs that can be used via the functions available in this module.

/// Get the value of a key in a csv database.
///
/// ### Args
///
/// * `key` - the key to query.
///
/// ### Return
///
/// * `Array of records` - an array containing the results. If no record is found,
///                        an empty array is returned.
///
/// ### Effective smtp stage
///
/// All of them.
///
/// ### Example
/// ```js
/// import "services" as svc;
///
/// #{
///     mail: [
///        action "fetch database" || {
///             let records = svc::my_database.get(mail_from());
///
///             if records == [] {
///                 log("debug", `${mail_from()} is not in my database`);
///             } else {
///                 log("debug", `${mail_from()} found in my database: ${records}`);
///             }
///        }
///     ]
/// }
/// ```
///
/// ### Module:Services
fn get(key) { this.db_query(key.to_string()) }

/// Set a record into a csv database.
///
/// ### Args
///
/// * `record` - the record to set.
///
/// ### Effective smtp stage
///
/// All of them.
///
/// ### Example
/// ```js
/// import "services" as svc;
///
/// #{
///     mail: [
///        action "set sender in database" || {
///             svc::my_database.set([ mail_from() ]);
///        }
///     ]
/// }
/// ```
///
/// ### Module:Services
fn set(record) {
    this.db_add(record.map("to_string"))
}

/// Remove a record from a csv database.
///
/// ### Args
///
/// * `key` - the key to remove.
///
/// ### Effective smtp stage
///
/// All of them.
///
/// ### Example
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
/// ### Module:Services
fn rm(key) { this.db_rm(key.to_string()) }

/// Query a database.
///
/// ### Args
///
/// * `q` - the query to execute.
///
/// ### Effective smtp stage
///
/// All of them.
///
/// ### Example
///
/// ```js
/// service my_db db:mysql = #{
///     url: "mysql://localhost/?user=guest",
/// };
/// ```
///
/// ```js
/// import "services" as svc;
///
/// #{
///     connect: [
///        action "log database" || {
///             let version_record = svc::my_db.query("SELECT version();");
///             // Result is a array of maps: [ #{"version()": "'version-of-mysql'"} ]
///             log("trace", `Database version is ${version_record[0]["version()"]}`);
///
///             // Fetching a 'greylist' database with a 'sender' table containing the (user, domain, address) fields.
///             let senders = svc::my_db.query("SELECT * FROM greylist.sender");
///
///             // Iterate over rows.
///             for sender in senders {
///                 // You can access the columns values using Rhai's Map syntax:
///                 print(`name: ${sender.user}, domain: ${sender.domain}, address: ${sender.address}`);
///             }
///
///             // Populate the database with a new record.
///             svc::my_db.query(`INSERT INTO greylist.sender (user, domain, address) values ("john.doe", "example.com", "john.doe@example.com");`);
///        }
///     ]
/// }
/// ```
///
/// ### Module:Services
fn query(q) { this.db_query(q) }

/// Run a command from a `cmd` service with the default arguments provided in the service.
///
/// ### Effective smtp stage
///
/// All of them.
///
/// ### Example
///
/// ```js
/// // services.vsl
/// service echo cmd = #{
///     command: "echo",
///     args: ["-e", "new connection received\n"],
/// };
/// ```
///
/// ```js
/// // main.vsl
/// import "services" as svc;
///
/// #{
///     connect: [
///        action "echo incoming" || svc::echo.run(),
///     ]
/// }
/// ```
///
/// ### Module:Services
fn run() { this.cmd_run() }

/// Run a command from a `cmd` service with arguments.
/// This allows you to run a command with dynamic arguments.
///
/// ### Args
///
/// * `args` - an array of strings that will replace current command
///            arguments defined in the `args` field of a `cmd` service.
///
/// ### Effective smtp stage
///
/// All of them.
///
/// ### Example
///
/// ```js
/// // services.vsl
/// service echo cmd = #{
///     timeout: "2s",
///     command: "echo",
///     args: ["-e", "using cmd to print to stdout\r\n"],
/// };
/// ```
///
/// ```js
/// // main.vsl
/// import "services" as svc;
///
/// #{
///     rcpt: [
///        action "print recipient using command" || {
///             // prints all recipients using the `echo` command.
///             svc::echo.run(["-E", "-n", `new recipient: ${rcpt()}`]);
///        }
///     ]
/// }
/// ```
///
/// ### Module:Services
fn run(args) { this.cmd_run(args) }
