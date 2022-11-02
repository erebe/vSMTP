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

use vsmtp_plugin_vsl::objects::Object;
use vsmtp_plugins::rhai;

use crate::api::{
    EngineResult, {Context, Server, SharedObject},
};
use rhai::plugin::{
    mem, Dynamic, FnAccess, FnNamespace, ImmutableString, Module, NativeCallContext,
    PluginFunction, RhaiResult, TypeId,
};
use vsmtp_common::{auth::Credentials, state::State, Address};

pub use mail_context_rhai::*;

#[rhai::plugin::export_module]
mod mail_context_rhai {

    /// Get the peer address of the client.
    #[rhai_fn(global, get = "client_address", return_raw, pure)]
    pub fn client_address(context: &mut Context) -> EngineResult<String> {
        Ok(vsl_guard_ok!(context.read()).client_addr().to_string())
    }

    /// Get the peer ip address of the client.
    #[rhai_fn(global, get = "client_ip", return_raw, pure)]
    pub fn client_ip(context: &mut Context) -> EngineResult<String> {
        Ok(vsl_guard_ok!(context.read()).client_addr().ip().to_string())
    }

    /// Get the peer port of the client.
    #[rhai_fn(global, get = "client_port", return_raw, pure)]
    pub fn client_port(context: &mut Context) -> EngineResult<rhai::INT> {
        Ok(rhai::INT::from(
            vsl_guard_ok!(context.read()).client_addr().port(),
        ))
    }

    /// Get the server address which served this connection.
    #[rhai_fn(global, get = "server_address", return_raw, pure)]
    pub fn server_address(context: &mut Context) -> EngineResult<String> {
        Ok(vsl_guard_ok!(context.read()).server_addr().to_string())
    }

    /// Get the server ip address which served this connection.
    #[rhai_fn(global, get = "server_ip", return_raw, pure)]
    pub fn server_ip(context: &mut Context) -> EngineResult<std::net::IpAddr> {
        Ok(vsl_guard_ok!(context.read()).server_addr().ip())
    }

    /// Get the server port which served this connection.
    #[rhai_fn(global, get = "server_port", return_raw, pure)]
    pub fn server_port(context: &mut Context) -> EngineResult<rhai::INT> {
        Ok(rhai::INT::from(
            vsl_guard_ok!(context.read()).server_addr().port(),
        ))
    }

    /// Get the timestamp when the client connected to the server.
    #[rhai_fn(global, get = "connection_timestamp", return_raw, pure)]
    pub fn connection_timestamp(context: &mut Context) -> EngineResult<time::OffsetDateTime> {
        Ok(*vsl_guard_ok!(context.read()).connection_timestamp())
    }

    /// Get server name under which the client has been served.
    #[rhai_fn(global, get = "server_name", return_raw, pure)]
    pub fn server_name(context: &mut Context) -> EngineResult<String> {
        Ok(vsl_guard_ok!(context.read()).server_name().to_owned())
    }

    /// Is the connection under TLS?
    #[rhai_fn(global, get = "is_secured", return_raw, pure)]
    pub fn is_secured(context: &mut Context) -> EngineResult<bool> {
        Ok(vsl_guard_ok!(context.read()).tls().is_some())
    }

    /// Has the connection validated the client credentials?
    #[rhai_fn(global, get = "is_authenticated", return_raw, pure)]
    pub fn is_authenticated(context: &mut Context) -> EngineResult<bool> {
        Ok(vsl_guard_ok!(context.read()).auth().is_some())
    }

    /// Get the `auth` property of the connection.
    #[rhai_fn(global, get = "auth", return_raw, pure)]
    pub fn auth(context: &mut Context) -> EngineResult<Credentials> {
        Ok(vsl_missing_ok!(
            vsl_guard_ok!(context.read()).auth(),
            "auth",
            State::Authenticate
        )
        .credentials
        .clone())
    }

    /// Get the type of the `auth` property of the connection.
    #[rhai_fn(global, get = "type", pure)]
    pub fn get_type(credentials: &mut Credentials) -> String {
        credentials.to_string()
    }

    /// Get the `authid` property of the connection.
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

    /// Get the domain named introduced by the client.
    #[rhai_fn(global, get = "helo", return_raw, pure)]
    pub fn helo(context: &mut Context) -> EngineResult<String> {
        Ok(vsl_missing_ok!(
            ref vsl_guard_ok!(context.read()).client_name(),
            "helo",
            State::Helo
        )
        .to_string())
    }

    /// Get the `MailFrom` envelope.
    #[rhai_fn(global, get = "mail_from", return_raw, pure)]
    pub fn mail_from(context: &mut Context) -> EngineResult<SharedObject> {
        let reverse_path = vsl_guard_ok!(context.read()).reverse_path().cloned();
        Ok(std::sync::Arc::new(Object::Address(vsl_missing_ok!(
            ref reverse_path,
            "mail_from",
            State::MailFrom
        ))))
    }

    /// Get the `RcptTo` envelope.
    #[rhai_fn(global, get = "rcpt_list", return_raw, pure)]
    pub fn rcpt_list(context: &mut Context) -> EngineResult<rhai::Array> {
        Ok(vsl_missing_ok!(
            vsl_guard_ok!(context.read()).forward_paths(),
            "rcpt_list",
            State::RcptTo
        )
        .iter()
        .map(|rcpt| rcpt.address.clone())
        .map(Object::Address)
        .map(std::sync::Arc::new)
        .map(rhai::Dynamic::from)
        .collect())
    }

    /// Get the lase element in the `RcptTo` envelope.
    #[rhai_fn(global, get = "rcpt", return_raw, pure)]
    pub fn rcpt(context: &mut Context) -> EngineResult<SharedObject> {
        Ok(std::sync::Arc::new(Object::Address(
            vsl_missing_ok!(
                vsl_missing_ok!(
                    vsl_guard_ok!(context.read()).forward_paths(),
                    "rcpt",
                    State::RcptTo
                )
                .last(),
                "rcpt",
                State::RcptTo
            )
            .address
            .clone(),
        )))
    }

    /// Get the timestamp when the client started to send the message.
    #[rhai_fn(global, get = "mail_timestamp", return_raw, pure)]
    pub fn mail_timestamp(context: &mut Context) -> EngineResult<time::OffsetDateTime> {
        Ok(**vsl_missing_ok!(
            vsl_guard_ok!(context.read()).mail_timestamp(),
            "mail_timestamp",
            State::MailFrom
        ))
    }

    /// Get the `message_id`
    #[rhai_fn(global, get = "message_id", return_raw, pure)]
    pub fn message_id(context: &mut Context) -> EngineResult<String> {
        Ok(vsl_missing_ok!(
            ref vsl_guard_ok!(context.read()).message_id(),
            "message_id",
            State::MailFrom
        )
        .to_string())
    }

    /// Convert a `Context` to a `String`.
    #[must_use]
    #[rhai_fn(global, name = "to_string", pure)]
    pub fn ctx_to_string(_: &mut Context) -> String {
        "MailContext".to_string()
    }

    /// Convert a `Context` to a debug string.
    #[rhai_fn(global, name = "to_debug", pure)]
    pub fn ctx_to_debug(context: &mut Context) -> String {
        ctx_to_string(context)
    }

    /// Convert a `Server` to a `String`.
    #[must_use]
    #[rhai_fn(global, name = "to_string", pure)]
    pub fn srv_to_string(_: &mut Server) -> String {
        "Server".to_string()
    }

    /// Convert a `Server` to a debug string.
    #[rhai_fn(global, name = "to_debug", pure)]
    pub fn srv_to_debug(context: &mut Server) -> String {
        srv_to_string(context)
    }

    /// Change the sender of the envelop.
    #[rhai_fn(global, name = "rewrite_mail_from_envelop", return_raw, pure)]
    pub fn rewrite_mail_from_envelop_str(
        context: &mut Context,
        new_addr: &str,
    ) -> EngineResult<()> {
        super::rewrite_mail_from_envelop(context, new_addr)
    }

    /// Change the sender of the envelop using an object.
    #[rhai_fn(global, name = "rewrite_mail_from_envelop", return_raw, pure)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn rewrite_mail_from_envelop_obj(
        context: &mut Context,
        new_addr: SharedObject,
    ) -> EngineResult<()> {
        super::rewrite_mail_from_envelop(context, &new_addr.to_string())
    }

    /// Replace a recipient of the envelop.
    #[rhai_fn(global, name = "rewrite_rcpt_envelop", return_raw, pure)]
    pub fn rewrite_rcpt_str_str(
        context: &mut Context,
        old_addr: &str,
        new_addr: &str,
    ) -> EngineResult<()> {
        super::rewrite_rcpt(context, old_addr, new_addr)
    }

    /// Replace a recipient of the envelop.
    #[rhai_fn(global, name = "rewrite_rcpt_envelop", return_raw, pure)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn rewrite_rcpt_obj_str(
        context: &mut Context,
        old_addr: SharedObject,
        new_addr: &str,
    ) -> EngineResult<()> {
        super::rewrite_rcpt(context, &old_addr.to_string(), new_addr)
    }

    /// Replace a recipient of the envelop.
    #[rhai_fn(global, name = "rewrite_rcpt_envelop", return_raw, pure)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn rewrite_rcpt_str_obj(
        context: &mut Context,
        old_addr: &str,
        new_addr: SharedObject,
    ) -> EngineResult<()> {
        super::rewrite_rcpt(context, old_addr, &new_addr.to_string())
    }

    /// Replace a recipient of the envelop.
    #[rhai_fn(global, name = "rewrite_rcpt_envelop", return_raw, pure)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn rewrite_rcpt_obj_obj(
        context: &mut Context,
        old_addr: SharedObject,
        new_addr: SharedObject,
    ) -> EngineResult<()> {
        super::rewrite_rcpt(context, &old_addr.to_string(), &new_addr.to_string())
    }

    /// add a recipient to the envelop.
    #[rhai_fn(global, name = "add_rcpt_envelop", return_raw, pure)]
    pub fn add_rcpt_envelop_str(context: &mut Context, new_addr: &str) -> EngineResult<()> {
        super::add_rcpt_envelop(context, new_addr)
    }

    /// add a recipient to the envelop.
    #[rhai_fn(global, name = "add_rcpt_envelop", return_raw, pure)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn add_rcpt_envelop_obj(context: &mut Context, new_addr: SharedObject) -> EngineResult<()> {
        super::add_rcpt_envelop(context, &new_addr.to_string())
    }

    /// remove a recipient from the envelop.
    #[rhai_fn(global, name = "remove_rcpt_envelop", return_raw, pure)]
    pub fn remove_rcpt_envelop_str(context: &mut Context, addr: &str) -> EngineResult<()> {
        super::remove_rcpt_envelop(context, addr)
    }

    /// remove a recipient from the envelop.
    #[rhai_fn(global, name = "remove_rcpt_envelop", return_raw, pure)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn remove_rcpt_envelop_obj(context: &mut Context, addr: SharedObject) -> EngineResult<()> {
        super::remove_rcpt_envelop(context, &addr.to_string())
    }
}

fn rewrite_mail_from_envelop(context: &mut Context, new_addr: &str) -> EngineResult<()> {
    vsl_guard_ok!(context.write())
        .set_reverse_path(vsl_conversion_ok!(
            "address",
            <Address as std::str::FromStr>::from_str(new_addr)
        ))
        .map_err(|e| e.to_string().into())
}

fn rewrite_rcpt(context: &mut Context, old_addr: &str, new_addr: &str) -> EngineResult<()> {
    let old_addr = vsl_conversion_ok!(
        "address",
        <Address as std::str::FromStr>::from_str(old_addr)
    );
    let new_addr = vsl_conversion_ok!(
        "address",
        <Address as std::str::FromStr>::from_str(new_addr)
    );

    let mut context = vsl_guard_ok!(context.write());
    context
        .remove_forward_path(&old_addr)
        .map_err::<Box<rhai::EvalAltResult>, _>(|e| e.to_string().into())?;
    context
        .add_forward_path(new_addr)
        .map_err::<Box<rhai::EvalAltResult>, _>(|e| e.to_string().into())?;

    Ok(())
}

fn add_rcpt_envelop(context: &mut Context, new_addr: &str) -> EngineResult<()> {
    vsl_guard_ok!(context.write())
        .add_forward_path(vsl_conversion_ok!(
            "address",
            <Address as std::str::FromStr>::from_str(new_addr)
        ))
        .map_err(|err| format!("failed to run `add_rcpt_envelop`: {err}").into())
}

fn remove_rcpt_envelop(context: &mut Context, addr: &str) -> EngineResult<()> {
    let addr = vsl_conversion_ok!("address", <Address as std::str::FromStr>::from_str(addr));

    let mut context = vsl_guard_ok!(context.write());
    context
        .remove_forward_path(&addr)
        .map_err::<Box<rhai::EvalAltResult>, _>(|e| e.to_string().into())?;
    Ok(())
}
