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

use vsmtp_plugins::rhai;

use crate::api::{Context, EngineResult, SharedObject};
use rhai::plugin::{
    mem, Dynamic, EvalAltResult, FnAccess, FnNamespace, ImmutableString, Module, NativeCallContext,
    PluginFunction, RhaiResult, TypeId,
};
use vsmtp_common::{
    state::State,
    transfer::{ForwardTarget, Transfer},
};

pub use transports_rhai::*;

#[allow(clippy::needless_pass_by_value)]
#[rhai::plugin::export_module]
mod transports_rhai {

    /// Set the delivery method to [`Transfer::Forward`] for a single recipient.
    ///
    /// # Examples
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(r#"
    /// #{
    ///   rcpt: [
    ///     action "forward (str/str)" || {
    ///       add_rcpt_envelop("my.address@foo.com");
    ///       forward("my.address@foo.com", "127.0.0.1");
    ///     },
    ///     action "forward (obj/str)" || {
    ///       let rcpt = address("my.address@bar.com");
    ///       add_rcpt_envelop(rcpt);
    ///       forward(rcpt, "127.0.0.2");
    ///     },
    ///     action "forward (str/obj)" || {
    ///       let target = ip6("::1");
    ///       add_rcpt_envelop("my.address@baz.com");
    ///       forward("my.address@baz.com", target);
    ///     },
    ///     action "forward (obj/obj)" || {
    ///       let rcpt = address("my.address@boz.com");
    ///       add_rcpt_envelop(rcpt);
    ///       forward(rcpt, "127.0.0.4");
    ///     },
    ///   ],
    /// }
    /// # "#);
    ///
    /// # use vsmtp_common::{
    /// #   state::State,
    /// #   transfer::{ForwardTarget, Transfer, EmailTransferStatus},
    /// #   rcpt::Rcpt,
    /// #   Address,
    /// # };
    /// # for (rcpt, (addr, target)) in states[&State::RcptTo].0.forward_paths().unwrap().iter().zip([
    /// #     ("my.address@foo.com", "127.0.0.1"),
    /// #     ("my.address@bar.com", "127.0.0.2"),
    /// #     ("my.address@baz.com", "::1"),
    /// #     ("my.address@boz.com", "127.0.0.4")
    /// # ]) {
    /// #   assert_eq!(
    /// #     rcpt.address,
    /// #     Address::new_unchecked(addr.to_string())
    /// #   );
    /// #   assert_eq!(
    /// #     rcpt.transfer_method,
    /// #     Transfer::Forward(ForwardTarget::Ip(target.parse().unwrap()))
    /// #   );
    /// # }
    /// ```
    #[rhai_fn(global, name = "forward", return_raw, pure)]
    pub fn forward_str_str(context: &mut Context, rcpt: &str, forward: &str) -> EngineResult<()> {
        let forward = <ForwardTarget as std::str::FromStr>::from_str(forward)
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;

        set_transport_for_one(context, rcpt, &Transfer::Forward(forward))
    }

    /// Set the delivery method to [`Transfer::Forward`] for a single recipient.
    #[rhai_fn(global, name = "forward", return_raw, pure)]
    pub fn forward_obj_str(
        context: &mut Context,
        rcpt: SharedObject,
        forward: &str,
    ) -> EngineResult<()> {
        let forward = <ForwardTarget as std::str::FromStr>::from_str(forward)
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;

        set_transport_for_one(context, &rcpt.to_string(), &Transfer::Forward(forward))
    }

    /// Set the delivery method to [`Transfer::Forward`] for a single recipient.
    #[rhai_fn(global, name = "forward", return_raw, pure)]
    pub fn forward_str_obj(
        context: &mut Context,
        rcpt: &str,
        forward: SharedObject,
    ) -> EngineResult<()> {
        let forward = <ForwardTarget as std::str::FromStr>::from_str(&forward.to_string())
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;

        set_transport_for_one(context, rcpt, &Transfer::Forward(forward))
    }

    /// Set the delivery method to [`Transfer::Forward`] for a single recipient.
    #[rhai_fn(global, name = "forward", return_raw, pure)]
    pub fn forward_obj_obj(
        context: &mut Context,
        rcpt: SharedObject,
        forward: SharedObject,
    ) -> EngineResult<()> {
        let forward = <ForwardTarget as std::str::FromStr>::from_str(&forward.to_string())
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;

        set_transport_for_one(context, &rcpt.to_string(), &Transfer::Forward(forward))
    }

    /// Set the delivery method to [`Transfer::Forward`] for all recipients.
    #[rhai_fn(global, name = "forward_all", return_raw, pure)]
    pub fn forward_all_str(context: &mut Context, forward: &str) -> EngineResult<()> {
        let forward = <ForwardTarget as std::str::FromStr>::from_str(forward)
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;

        set_transport_foreach(context, &Transfer::Forward(forward))
    }

    /// Set the delivery method to [`Transfer::Forward`] for all recipients.
    #[rhai_fn(global, name = "forward_all", return_raw, pure)]
    pub fn forward_all_obj(context: &mut Context, forward: SharedObject) -> EngineResult<()> {
        let forward = <ForwardTarget as std::str::FromStr>::from_str(&forward.to_string())
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;

        set_transport_foreach(context, &Transfer::Forward(forward))
    }

    /// set the delivery method to [`Transfer::Deliver`] for a single recipient.
    #[rhai_fn(global, name = "deliver", return_raw, pure)]
    pub fn deliver_str(context: &mut Context, rcpt: &str) -> EngineResult<()> {
        set_transport_for_one(context, rcpt, &Transfer::Deliver)
    }

    /// set the delivery method to [`Transfer::Deliver`] for a single recipient.
    #[rhai_fn(global, name = "deliver", return_raw, pure)]
    pub fn deliver_obj(context: &mut Context, rcpt: SharedObject) -> EngineResult<()> {
        set_transport_for_one(context, &rcpt.to_string(), &Transfer::Deliver)
    }

    /// set the delivery method to [`Transfer::Deliver`] for all recipients.
    #[rhai_fn(global, return_raw, pure)]
    pub fn deliver_all(context: &mut Context) -> EngineResult<()> {
        set_transport_foreach(context, &Transfer::Deliver)
    }

    /// Set the delivery method to [`Transfer::Mbox`] for a single recipient.
    ///
    /// # Examples
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(r#"
    /// #{
    ///   rcpt: [
    ///     action "setup mbox" || {
    ///         const doe = address("doe@example.com");
    ///         add_rcpt_envelop(doe);
    ///         add_rcpt_envelop("a@example.com");
    ///         mbox(doe);
    ///         mbox("a@example.com");
    ///     },
    ///   ],
    /// }
    /// # "#);
    ///
    /// # use vsmtp_common::{
    /// #   state::State,
    /// #   transfer::{Transfer},
    /// #   rcpt::Rcpt,
    /// #   Address,
    /// # };
    /// # for (rcpt, addr) in states[&State::RcptTo].0.forward_paths().unwrap().iter().zip([
    /// #     "doe@example.com",
    /// #     "a@example.com",
    /// # ]) {
    /// #   assert_eq!(
    /// #     rcpt.address,
    /// #     Address::new_unchecked(addr.to_string())
    /// #   );
    /// #   assert_eq!(
    /// #     rcpt.transfer_method,
    /// #     Transfer::Mbox
    /// #   );
    /// # }
    /// ```
    #[rhai_fn(global, name = "mbox", return_raw, pure)]
    pub fn mbox_str(context: &mut Context, rcpt: &str) -> EngineResult<()> {
        set_transport_for_one(context, rcpt, &Transfer::Mbox)
    }

    /// set the delivery method to [`Transfer::Mbox`] for a single recipient.
    #[rhai_fn(global, name = "mbox", return_raw, pure)]
    pub fn mbox_obj(context: &mut Context, rcpt: SharedObject) -> EngineResult<()> {
        set_transport_for_one(context, &rcpt.to_string(), &Transfer::Mbox)
    }

    /// set the delivery method to [`Transfer::Mbox`] for all recipients.
    #[rhai_fn(global, return_raw, pure)]
    pub fn mbox_all(context: &mut Context) -> EngineResult<()> {
        set_transport_foreach(context, &Transfer::Mbox)
    }

    /// set the delivery method to [`Transfer::Maildir`] for a single recipient.
    #[rhai_fn(global, name = "maildir", return_raw, pure)]
    pub fn maildir_str(context: &mut Context, rcpt: &str) -> EngineResult<()> {
        set_transport_for_one(context, rcpt, &Transfer::Maildir)
    }

    /// set the delivery method to [`Transfer::Maildir`] for a single recipient.
    #[rhai_fn(global, name = "maildir", return_raw, pure)]
    pub fn maildir_obj(context: &mut Context, rcpt: SharedObject) -> EngineResult<()> {
        set_transport_for_one(context, &rcpt.to_string(), &Transfer::Maildir)
    }

    /// set the delivery method to [`Transfer::Maildir`] for all recipients.
    #[rhai_fn(global, return_raw, pure)]
    pub fn maildir_all(context: &mut Context) -> EngineResult<()> {
        set_transport_foreach(context, &Transfer::Maildir)
    }
}

fn set_transport_for_one(
    context: &mut Context,
    search: &str,
    method: &Transfer,
) -> EngineResult<()> {
    vsl_missing_ok!(
        ref vsl_guard_ok!(context.write()).forward_paths_mut(),
        "rcpt_list",
        State::RcptTo
    )
    .iter_mut()
    .find(|rcpt| rcpt.address.full() == search)
    .ok_or_else::<Box<EvalAltResult>, _>(|| format!("could not find rcpt '{}'", search).into())
    .map(|rcpt| rcpt.transfer_method = method.clone())
}

fn set_transport_foreach(context: &mut Context, method: &Transfer) -> EngineResult<()> {
    vsl_missing_ok!(
        ref vsl_guard_ok!(context.write()).forward_paths_mut(),
        "rcpt_list",
        State::RcptTo
    )
    .iter_mut()
    .for_each(|rcpt| rcpt.transfer_method = method.clone());

    Ok(())
}
