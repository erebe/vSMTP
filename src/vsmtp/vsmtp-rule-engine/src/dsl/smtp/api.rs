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

use vsmtp_common::transfer::SmtpConnection;

use lettre;
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

    /// Build a new SMTP service.
    #[rhai_fn(global, return_raw)]
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

    ///
    #[rhai_fn(global, pure)]
    pub fn to_string(cmd: &mut Smtp) -> String {
        cmd.to_string()
    }

    ///
    #[rhai_fn(global, pure)]
    pub fn to_debug(cmd: &mut Smtp) -> String {
        format!("{cmd:#?}")
    }
}
