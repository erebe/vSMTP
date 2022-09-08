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
use crate::api::{
    EngineResult, {Context, Server},
};
use rhai::plugin::{
    mem, Dynamic, FnAccess, FnNamespace, Module, NativeCallContext, PluginFunction, RhaiResult,
    TypeId,
};
use vsmtp_auth::spf;

pub use security::*;

#[rhai::plugin::export_module]
mod security {

    /// evaluate a sender identity.
    /// the identity parameter can be 'helo', 'mail_from' or 'both'.
    ///
    /// # Results
    /// a rhai Map with:
    //    * result (String) : the result of an SPF evaluation.
    //    * cause  (String) : the "mechanism" that matched or the "problem" error (RFC 7208-9.1).
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(return_raw, pure)]
    pub fn check_spf(ctx: &mut Context, srv: Server) -> EngineResult<rhai::Map> {
        {
            let guard = vsl_guard_ok!(ctx.read());
            if let Some(previous_spf) = &guard.metadata.spf {
                return Ok(result_to_map(previous_spf.clone()));
            }
        }

        let (mail_from, ip) = {
            let ctx = vsl_guard_ok!(ctx.read());
            (
                ctx.envelop.mail_from.clone(),
                ctx.connection.client_addr.ip(),
            )
        };

        let resolver = srv.resolvers.get(&srv.config.server.domain).unwrap();

        match mail_from.full().parse() {
            Err(..) => Ok(rhai::Map::from_iter([("result".into(), "none".into())])),
            Ok(sender) => {
                let spf_result = tokio::task::block_in_place(move || {
                    tokio::runtime::Handle::current()
                        .block_on(vsmtp_auth::spf::evaluate(resolver, ip, &sender))
                });

                let mut guard = vsl_guard_ok!(ctx.write());
                guard.metadata.spf = Some(spf_result.clone());

                Ok(result_to_map(spf_result))
            }
        }
    }
}

fn result_to_map(spf_result: spf::Result) -> rhai::Map {
    rhai::Map::from_iter([
        ("result".into(), rhai::Dynamic::from(spf_result.result)),
        match spf_result.details {
            spf::Details::Mechanism(mechanism) => ("mechanism".into(), mechanism.into()),
            spf::Details::Problem(error) => ("problem".into(), error.into()),
        },
    ])
}
