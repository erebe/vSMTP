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

use vsmtp_common::status::SmtpConnection;

use rhai::plugin::{
    mem, Dynamic, FnAccess, FnNamespace, NativeCallContext, PluginFunction, RhaiResult, TypeId,
};
use rhai::Module;

#[derive(Debug, serde::Deserialize)]
struct SmtpDelegatorParameters {
    /// The address to delegate the email to.
    address: std::net::SocketAddr,
    /// Timeout for the SMTP connection.
    #[serde(default = "default_timeout", with = "humantime_serde")]
    timeout: std::time::Duration,
}

#[derive(Debug, serde::Deserialize)]
struct SmtpParameters {
    /// Receiver socket.
    receiver: std::net::SocketAddr,
    /// Delegation parameters.
    delegator: SmtpDelegatorParameters,
}

const fn default_timeout() -> std::time::Duration {
    std::time::Duration::from_secs(30)
}

#[rhai::plugin::export_module]
pub mod smtp {
    use crate::api::EngineResult;

    type Smtp = rhai::Shared<crate::dsl::smtp::service::Smtp>;

    /// Connect to a third party software that accepts SMTP transactions.
    /// This module is used with the `delegate` keyword.
    ///
    /// # Args
    ///
    /// * `parameters` - a map of the following parameters:
    ///     * `delegator` - a map of the following parameters.
    ///         * `address` - the address to connect to the third-party software
    ///         * `timeout` - timeout between each SMTP commands. (optional, default: 30s)
    ///     * `receiver` - the socket to get back the result from.
    ///
    /// # Return
    ///
    /// A service used to delegate a message.
    ///
    /// # Error
    ///
    /// * The service failed to parse the command parameters.
    /// * The service failed to connect to the `delegator` address.
    ///
    /// # Example
    ///
    /// ```text
    /// // declared in /etc/vsmtp/services/smtp.vsl
    /// export const clamsmtpd = smtp::connect(#{
    ///     delegator: #{
    ///         // The service address to delegate to.
    ///         address: "127.0.0.1:10026",
    ///         // The time allowed between each message before timeout.
    ///         timeout: "2s",
    ///     },
    ///     // The address where vsmtp will gather the results of the delegation.
    ///     // The third party software should be configured to send the email back at this address.
    ///     receiver: "127.0.0.1:10024",
    /// });
    /// ```
    ///
    /// The service is then used in a rule file using the following syntax:
    ///
    /// ```text
    /// import "service/smtp" as srv;
    ///
    /// #{
    ///     postq: [
    ///         // this will delegate the email using the `clamsmtpd` service.
    ///         delegate srv::clamsmtpd "delegate antivirus processing" || {
    ///             // this is executed after the delegation results have been
    ///             // received on port 10024.
    ///         }
    ///     ]
    /// }
    /// ```
    #[rhai_fn(return_raw)]
    pub fn connect(parameters: rhai::Map) -> EngineResult<Smtp> {
        let parameters = rhai::serde::from_dynamic::<SmtpParameters>(&parameters.into())?;

        Ok(rhai::Shared::new(crate::dsl::smtp::service::Smtp {
            delegator: SmtpConnection(std::sync::Arc::new(std::sync::Mutex::new(
                lettre::SmtpTransport::builder_dangerous(
                    parameters.delegator.address.ip().to_string(),
                )
                .port(parameters.delegator.address.port())
                .timeout(Some(parameters.delegator.timeout))
                .build(),
            ))),
            receiver: parameters.receiver,
        }))
    }
}
