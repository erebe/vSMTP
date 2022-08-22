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

//! # Auth
//!
//! This module contains authentication mechanisms to secure your server.

/// Check if the client's connexion was secure.
///
/// # Effective smtp stage
///
/// `authenticate` only.
///
/// # Return
///
/// * `bool` - true if the client securely connected with the auth protocol, false otherwise.
///
/// # Example
/// ```js
/// #{
///     authenticate: [
///        action "log info" || log("info", `${is_secured()}`),
///     ]
/// }
/// ```
///
/// # Module:Auth
fn is_secured() { ctx().is_secured }

/// Check if the client is authenticated.
///
/// # Effective smtp stage
///
/// `authenticate` only.
///
/// # Return
///
/// * `bool` - true if the client succeeded to authenticate itself, false otherwise.
///
/// # Example
/// ```js
/// #{
///     authenticate: [
///        action "log info" || log("info", `${is_authenticated()}`),
///     ]
/// }
/// ```
///
/// # Module:Auth
fn is_authenticated() { ctx().is_authenticated }

/// Get authentication credentials from the client.
///
/// # Effective smtp stage
///
/// `authenticate` only.
///
/// # Return
///
/// * `Credentials` - the credentials of the client.
///
/// # Example
/// ```js
/// #{
///     authenticate: [
///        action "log info" || log("info", `${auth()}`),
///     ]
/// }
/// ```
///
/// # Module:Auth
fn auth() { ctx().auth }

/// Process the SASL authentication mechanism.
///
/// The current implementation support "PLAIN" mechanism, and will call the
/// `testsaslauthd` program to check the credentials.
///
/// The credentials will be verified depending on the mode of `saslauthd`.
///
/// A native implementation will be provided in the future.
///
/// # Module:Auth
fn authenticate() {
    switch ctx().auth.type {
        "Verify" => {
            service authd cmd = #{
                timeout: "1s",
                command: "testsaslauthd",
                args: ["-u", ctx().auth.authid, "-p", ctx().auth.authpass]
            };

            let result = authd.cmd_run();

            if result.has_signal {
                return false;
            }

            if result.has_code && result.code == 0 {
                accept()
            } else {
                deny()
            }

        },
        "Query" => {
            deny()
        }
    }
}
