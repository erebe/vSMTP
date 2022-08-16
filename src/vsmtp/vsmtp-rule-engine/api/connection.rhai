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

/// Get the address of the client.
///
/// # Effective smtp stage
///
/// All of them.
///
/// # Return
///
/// * `string` - the client's address with the `ip:port` format.
///
/// # Example
/// ```js
/// #{
///     connect: [
///        action "log info" || log("info", `${client_address()}`),
///     ]
/// }
/// ```
///
/// # Module:Connection
fn client_address() { ctx().client_address }

/// Get the ip address of the client.
///
/// # Effective smtp stage
///
/// All of them.
///
/// # Return
///
/// * `string` - the client's ip address.
///
/// # Example
/// ```js
/// #{
///     connect: [
///        action "log info" || log("info", `${client_ip()}`),
///     ]
/// }
/// ```
///
/// # Module:Connection
fn client_ip() { ctx().client_ip }

/// Get the ip port of the client.
///
/// # Effective smtp stage
///
/// All of them.
///
/// # Return
///
/// * `int` - the client's port.
///
/// # Example
/// ```js
/// #{
///     connect: [
///        action "log info" || log("info", `${client_port()}`),
///     ]
/// }
/// ```
///
/// # Module:Connection
fn client_port() { ctx().client_port }

/// Get the full server address.
///
/// # Effective smtp stage
///
/// All of them.
///
/// # Return
///
/// * `string` - the server's address with the `ip:port` format.
///
/// # Example
/// ```js
/// #{
///     connect: [
///        action "log info" || log("info", `${server_address()}`),
///     ]
/// }
/// ```
///
/// # Module:Connection
fn server_address() { ctx().server_address }

/// Get the server's ip.
///
/// # Effective smtp stage
///
/// All of them.
///
/// # Return
///
/// * `string` - the server's ip.
///
/// # Example
/// ```js
/// #{
///     connect: [
///        action "log info" || log("info", `${server_ip()}`),
///     ]
/// }
/// ```
///
/// # Module:Connection
fn server_ip() { ctx().server_ip }

/// Get the server's port.
///
/// # Effective smtp stage
///
/// All of them.
///
/// # Return
///
/// * `string` - the server's port.
///
/// # Example
/// ```js
/// #{
///     connect: [
///        action "log info" || log("info", `${server_port()}`),
///     ]
/// }
/// ```
///
/// # Module:Connection
fn server_port() { ctx().server_port }

/// Get a the timestamp of the client's connection time.
///
/// # Effective smtp stage
///
/// All of them.
///
/// # Return
///
/// * `timestamp` - the connexion timestamp of the client.
///
/// # Example
/// ```js
/// #{
///     connect: [
///        action "log info" || log("info", `${connection_timestamp()}`),
///     ]
/// }
/// ```
///
/// # Module:Connection
fn connection_timestamp() { ctx().connection_timestamp }

/// Get the name of the server.
///
/// # Effective smtp stage
///
/// All of them.
///
/// # Return
///
/// * `string` - the name of the server.
///
/// # Example
/// ```js
/// #{
///     connect: [
///        action "log info" || log("info", `${server_name()}`),
///     ]
/// }
/// ```
///
/// # Module:Connection
fn server_name() { ctx().server_name }
