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

use rhai::plugin::{
    Dynamic, FnAccess, FnNamespace, Module, NativeCallContext, PluginFunction, RhaiResult, TypeId,
};

pub use auth::*;
use vsmtp_common::status::Status;

use crate::api::state;

use super::EngineResult;

/// Authentication mechanisms and credential manipulation.
#[rhai::plugin::export_module]
mod auth {
    use crate::api::state;
    use crate::api::EngineResult;
    use crate::{get_global, ExecutionStage};
    use vsmtp_common::{auth::Credentials, status::Status};

    /// Process the SASL authentication mechanism.
    ///
    /// The current implementation support "PLAIN" mechanism, and will call the
    /// `testsaslauthd` program to check the credentials.
    ///
    /// The credentials will be verified depending on the mode of `saslauthd`.
    ///
    /// A native implementation will be provided in the future.
    #[rhai_fn(name = "unix_users", return_raw)]
    pub fn unix_users(ncc: NativeCallContext) -> EngineResult<Status> {
        let ctx = get_global!(ncc, ctx)?;
        let ctx = vsl_guard_ok!(ctx.read());

        match &ctx
            .auth()
            .as_ref()
            .expect("state cannot be empty")
            .credentials
        {
            Some(Credentials::Verify { authid, authpass }) => {
                super::execute_testsaslauthd(authid, authpass)
            }
            Some(Credentials::AnonymousToken { token }) => {
                tracing::warn!("Cannot authenticate unix user with an anonymous token");
                tracing::trace!(token);
                Ok(state::deny())
            }
            None => {
                tracing::warn!("No credentials found to authenticate a unix user with");
                Ok(state::deny())
            }
        }
    }

    /// Check if the client is authenticated.
    ///
    /// # Effective smtp stage
    ///
    /// `authenticate` stage only.
    ///
    /// # Return
    ///
    /// * `bool` - `true` if the client succeeded to authenticate itself, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// # vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     authenticate: [
    ///        action "log info" || log("info", `client authenticated: ${auth::is_authenticated()}`),
    ///     ]
    /// }
    /// # "#)?.build()));
    /// ```
    #[rhai_fn(name = "is_authenticated", return_raw)]
    pub fn is_authenticated(ncc: NativeCallContext) -> EngineResult<bool> {
        Ok(vsl_guard_ok!(get_global!(ncc, ctx)?.read())
            .auth()
            .is_some())
    }

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
    ///
    /// ```
    /// # vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     authenticate: [
    ///        action "log auth" || log("info", `${auth::credentials()}`),
    ///     ]
    /// }
    /// # "#)?.build()));
    /// ```
    #[rhai_fn(name = "credentials", return_raw)]
    pub fn credentials(ncc: NativeCallContext) -> EngineResult<Credentials> {
        Ok(vsl_missing_ok!(
            vsl_missing_ok!(
                vsl_guard_ok!(get_global!(ncc, ctx)?.read()).auth(),
                "auth",
                ExecutionStage::Authenticate
            )
            .credentials,
            "credentials",
            ExecutionStage::Authenticate
        )
        .clone())
    }

    /// Get the type of the `auth` property of the connection.
    ///
    /// # Effective smtp stage
    ///
    /// `authenticate` only.
    ///
    /// # Return
    ///
    /// * `String` - the credentials type.
    ///
    /// # Examples
    ///
    /// ```
    /// # vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     authenticate: [
    ///        action "log auth type" || {
    ///             let credentials = auth::credentials();
    ///
    ///             // Logs here will output 'Verify' or 'AnonymousToken'.
    ///             // depending on the authentication type.
    ///             log("info", `credentials type: ${credentials.type}`);
    ///         },
    ///     ]
    /// }
    /// # "#)?.build()));
    /// ```
    #[rhai_fn(global, get = "type", pure)]
    pub fn get_type(credentials: &mut Credentials) -> String {
        credentials.to_string()
    }

    /// Get the `authid` property of the connection.
    /// Can only be use on 'Verify' authentication typed credentials.
    ///
    /// # Effective smtp stage
    ///
    /// `authenticate` only.
    ///
    /// # Return
    ///
    /// * `String` - the authentication id.
    ///
    /// # Examples
    ///
    /// ```
    /// # vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     authenticate: [
    ///        action "log auth id" || {
    ///             let credentials = auth::credentials();
    ///             log("info", `credentials id: ${credentials.authid}`);
    ///         },
    ///     ]
    /// }
    /// # "#)?.build()));
    /// ```
    #[rhai_fn(global, get = "authid", return_raw, pure)]
    pub fn get_authid(credentials: &mut Credentials) -> EngineResult<String> {
        match credentials {
            Credentials::Verify { authid, .. } => Ok(authid.clone()),
            Credentials::AnonymousToken { .. } => {
                Err(format!("no `authid` available in credentials of type `{credentials}`").into())
            }
        }
    }

    /// Get the `authpass` property of the connection.
    /// Can only be use on 'Verify' authentication typed credentials.
    ///
    /// # Effective smtp stage
    ///
    /// `authenticate` only.
    ///
    /// # Return
    ///
    /// * `String` - the authentication password.
    ///
    /// # Examples
    ///
    /// ```
    /// # vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     authenticate: [
    ///        action "log auth pass" || {
    ///             let credentials = auth::credentials();
    ///             log("info", `credentials pass: ${credentials.authpass}`);
    ///         },
    ///     ]
    /// }
    /// # "#)?.build()));
    /// ```
    #[rhai_fn(global, get = "authpass", return_raw, pure)]
    pub fn get_authpass(credentials: &mut Credentials) -> EngineResult<String> {
        match credentials {
            Credentials::Verify { authpass, .. } => Ok(authpass.clone()),
            Credentials::AnonymousToken { .. } => Err(format!(
                "no `authpass` available in credentials of type `{credentials}`"
            )
            .into()),
        }
    }

    /// Get the `anonymous_token` property of the connection.
    /// Can only be use on 'AnonymousToken' authentication typed credentials.
    ///
    /// # Effective smtp stage
    ///
    /// `authenticate` only.
    ///
    /// # Return
    ///
    /// * `String` - the token.
    ///
    /// # Examples
    ///
    /// ```
    /// # vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     authenticate: [
    ///        action "log auth token" || {
    ///             let credentials = auth::credentials();
    ///             log("info", `credentials token: ${credentials.anonymous_token}`);
    ///         },
    ///     ]
    /// }
    /// # "#)?.build()));
    /// ```
    #[rhai_fn(global, get = "anonymous_token", return_raw, pure)]
    pub fn get_anonymous_token(credentials: &mut Credentials) -> EngineResult<String> {
        match credentials {
            Credentials::AnonymousToken { token } => Ok(token.clone()),
            Credentials::Verify { .. } => Err(format!(
                "no `anonymous_token` available in credentials of type `{credentials}`"
            )
            .into()),
        }
    }
}

fn execute_testsaslauthd(authid: &str, authpass: &str) -> EngineResult<Status> {
    let testsaslauthd = rhai::Shared::new(crate::dsl::cmd::service::Cmd {
        timeout: std::time::Duration::from_secs(1),
        user: None,
        group: None,
        command: "testsaslauthd".to_string(),
        args: Some(
            ["-u", authid, "-p", authpass]
                .into_iter()
                .map(std::borrow::ToOwned::to_owned)
                .collect::<Vec<_>>(),
        ),
    });

    let result = vsl_generic_ok!(testsaslauthd.run());

    if let Some(signal) = std::os::unix::prelude::ExitStatusExt::signal(&result) {
        tracing::warn!(
            signal = signal.to_string(),
            "authentication command received a signal"
        );
        return Ok(state::deny());
    }

    #[allow(clippy::option_if_let_else)]
    Ok(match result.code() {
        Some(code) if code == 0 => state::accept(),
        _ => state::deny(),
    })
}
