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

use crate::{
    api::{Context, EngineResult, SharedObject},
    ExecutionStage,
};
use rhai::plugin::{
    mem, Dynamic, EvalAltResult, FnAccess, FnNamespace, ImmutableString, Module, NativeCallContext,
    PluginFunction, RhaiResult, TypeId,
};
use vsmtp_common::transfer::{ForwardTarget, Transfer};

pub use transport::*;

/// Functions to configure delivery methods of emails.
#[allow(clippy::needless_pass_by_value)]
#[rhai::plugin::export_module]
mod transport {
    use crate::get_global;

    /// Set the delivery method to forwarding for a single recipient.
    /// After all rules are evaluated, forwarding will be used to deliver
    /// the email to the recipient.
    ///
    /// # Args
    ///
    /// * `rcpt` - the recipient to apply the method to.
    /// * `target` - the target to forward the email to.
    ///
    /// # Effective smtp stage
    ///
    /// All of them.
    ///
    /// # Examples
    /// ```ignore
    /// const rules = #{
    ///     delivery: [
    ///        action "setup forwarding" || transport::forward("john.doe@example.com", "mta-john.example.com"),
    ///     ]
    /// }
    /// ```
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     rcpt: [
    ///       action "forward (str/str)" || {
    ///         envelop::add_rcpt("my.address@foo.com");
    ///         transport::forward("my.address@foo.com", "127.0.0.1");
    ///       },
    ///       action "forward (obj/str)" || {
    ///         let rcpt = address("my.address@bar.com");
    ///         envelop::add_rcpt(rcpt);
    ///         transport::forward(rcpt, "127.0.0.2");
    ///       },
    ///       action "forward (str/obj)" || {
    ///         let target = ip6("::1");
    ///         envelop::add_rcpt("my.address@baz.com");
    ///         transport::forward("my.address@baz.com", target);
    ///       },
    ///       action "forward (obj/obj)" || {
    ///         let rcpt = address("my.address@boz.com");
    ///         envelop::add_rcpt(rcpt);
    ///         transport::forward(rcpt, ip4("127.0.0.4"));
    ///       },
    ///     ],
    /// }
    /// # "#)?.build()));
    ///
    /// # use vsmtp_common::{
    /// #   transfer::{ForwardTarget, Transfer, EmailTransferStatus},
    /// #   rcpt::Rcpt,
    /// #   Address,
    /// # };
    /// # for (rcpt, (addr, target)) in states[&vsmtp_rule_engine::ExecutionStage::RcptTo].0.forward_paths().unwrap().iter().zip([
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
    #[rhai_fn(name = "forward", return_raw)]
    pub fn forward(ncc: NativeCallContext, rcpt: &str, forward: &str) -> EngineResult<()> {
        let forward = <ForwardTarget as std::str::FromStr>::from_str(forward)
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;

        set_transport_for_one(&get_global!(ncc, ctx)?, rcpt, &Transfer::Forward(forward))
    }

    /// Set the delivery method to forwarding for a single recipient.
    /// After all rules are evaluated, forwarding will be used to deliver
    /// the email to the recipient.
    ///
    /// # Args
    ///
    /// * `rcpt` - the recipient to apply the method to.
    /// * `target` - the target to forward the email to.
    ///
    /// # Effective smtp stage
    ///
    /// All of them.
    ///
    /// # Examples
    /// ```ignore
    /// #{
    ///     delivery: [
    ///        action "setup forwarding" || transport::forward("john.doe@example.com", "mta-john.example.com"),
    ///     ]
    /// }
    /// ```
    #[rhai_fn(name = "forward", return_raw)]
    pub fn forward_obj_str(
        ncc: NativeCallContext,
        rcpt: SharedObject,
        forward: &str,
    ) -> EngineResult<()> {
        let forward = <ForwardTarget as std::str::FromStr>::from_str(forward)
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;

        set_transport_for_one(
            &get_global!(ncc, ctx)?,
            &rcpt.to_string(),
            &Transfer::Forward(forward),
        )
    }

    /// Set the delivery method to forwarding for a single recipient.
    /// After all rules are evaluated, forwarding will be used to deliver
    /// the email to the recipient.
    ///
    /// # Args
    ///
    /// * `rcpt` - the recipient to apply the method to.
    /// * `target` - the target to forward the email to.
    ///
    /// # Effective smtp stage
    ///
    /// All of them.
    ///
    /// # Examples
    /// ```ignore
    /// #{
    ///     delivery: [
    ///        action "setup forwarding" || transport::forward("john.doe@example.com", "mta-john.example.com"),
    ///     ]
    /// }
    /// ```
    #[rhai_fn(name = "forward", return_raw)]
    pub fn forward_str_obj(
        ncc: NativeCallContext,
        rcpt: &str,
        forward: SharedObject,
    ) -> EngineResult<()> {
        let forward = <ForwardTarget as std::str::FromStr>::from_str(&forward.to_string())
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;

        set_transport_for_one(&get_global!(ncc, ctx)?, rcpt, &Transfer::Forward(forward))
    }

    /// Set the delivery method to forwarding for a single recipient.
    /// After all rules are evaluated, forwarding will be used to deliver
    /// the email to the recipient.
    ///
    /// # Args
    ///
    /// * `rcpt` - the recipient to apply the method to.
    /// * `target` - the target to forward the email to.
    ///
    /// # Effective smtp stage
    ///
    /// All of them.
    ///
    /// # Examples
    /// ```ignore
    /// #{
    ///     delivery: [
    ///        action "setup forwarding" || transport::forward("john.doe@example.com", "mta-john.example.com"),
    ///     ]
    /// }
    /// ```
    #[rhai_fn(name = "forward", return_raw)]
    pub fn forward_obj_obj(
        ncc: NativeCallContext,
        rcpt: SharedObject,
        forward: SharedObject,
    ) -> EngineResult<()> {
        let forward = <ForwardTarget as std::str::FromStr>::from_str(&forward.to_string())
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;

        set_transport_for_one(
            &get_global!(ncc, ctx)?,
            &rcpt.to_string(),
            &Transfer::Forward(forward),
        )
    }

    /// Set the delivery method to forwarding for all recipients.
    /// After all rules are evaluated, forwarding will be used to deliver
    /// the email.
    ///
    /// # Args
    ///
    /// * `target` - the target to forward the email to.
    ///
    /// # Effective smtp stage
    ///
    /// All of them.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// #{
    ///     delivery: [
    ///        action "setup forwarding" || transport::forward_all("mta-john.example.com"),
    ///     ]
    /// }
    /// ```
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///   rcpt: [
    ///     action "forward_all" || {
    ///       envelop::add_rcpt("my.address@foo.com");
    ///       envelop::add_rcpt("my.address@bar.com");
    ///       transport::forward_all("127.0.0.1");
    ///     },
    ///     action "forward_all (obj)" || {
    ///       envelop::add_rcpt("my.address@foo2.com");
    ///       envelop::add_rcpt("my.address@bar2.com");
    ///       transport::forward_all(ip4("127.0.0.1"));
    ///     },
    ///   ],
    /// }
    /// # "#)?.build()));
    ///
    /// # use vsmtp_common::{
    /// #   transfer::{ForwardTarget, Transfer, EmailTransferStatus},
    /// #   rcpt::Rcpt,
    /// #   Address,
    /// # };
    /// # for (rcpt, addr) in states[&vsmtp_rule_engine::ExecutionStage::RcptTo].0.forward_paths().unwrap().iter().zip([
    /// #     "my.address@foo.com",
    /// #     "my.address@bar.com",
    /// # ]) {
    /// #   assert_eq!(
    /// #     rcpt.address,
    /// #     Address::new_unchecked(addr.to_string())
    /// #   );
    /// #   assert_eq!(
    /// #     rcpt.transfer_method,
    /// #     Transfer::Forward(ForwardTarget::Ip("127.0.0.1".parse().unwrap()))
    /// #   );
    /// # }
    /// ```
    #[rhai_fn(name = "forward_all", return_raw)]
    pub fn forward_all(ncc: NativeCallContext, forward: &str) -> EngineResult<()> {
        let forward = <ForwardTarget as std::str::FromStr>::from_str(forward)
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;

        set_transport_foreach(&get_global!(ncc, ctx)?, &Transfer::Forward(forward))
    }

    /// Set the delivery method to forwarding for all recipients.
    /// After all rules are evaluated, forwarding will be used to deliver
    /// the email.
    ///
    /// # Args
    ///
    /// * `target` - the target to forward the email to.
    ///
    /// # Effective smtp stage
    ///
    /// All of them.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// #{
    ///     delivery: [
    ///        action "setup forwarding" || transport::forward_all(fqdn("mta-john.example.com")),
    ///     ]
    /// }
    /// ```
    #[rhai_fn(name = "forward_all", return_raw)]
    pub fn forward_all_obj(ncc: NativeCallContext, forward: SharedObject) -> EngineResult<()> {
        let forward = <ForwardTarget as std::str::FromStr>::from_str(&forward.to_string())
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;

        set_transport_foreach(&get_global!(ncc, ctx)?, &Transfer::Forward(forward))
    }

    /// Set the delivery method to deliver for a single recipient.
    /// After all rules are evaluated, the email will be sent
    /// to the recipient using the domain of its address.
    ///
    /// # Args
    ///
    /// * `rcpt` - the recipient to apply the method to.
    ///
    /// # Effective smtp stage
    ///
    /// All of them.
    ///
    /// # Examples
    /// ```ignore
    /// #{
    ///     delivery: [
    ///        action "setup delivery" || transport::deliver("john.doe@example.com"),
    ///     ]
    /// }
    /// ```
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///   rcpt: [
    ///     action "deliver (str/str)" || {
    ///       envelop::add_rcpt("my.address@foo.com");
    ///       transport::deliver("my.address@foo.com");
    ///     },
    ///     action "deliver (obj/str)" || {
    ///       let rcpt = address("my.address@bar.com");
    ///       envelop::add_rcpt(rcpt);
    ///       transport::deliver(rcpt);
    ///     },
    ///     action "deliver (str/obj)" || {
    ///       let target = ip6("::1");
    ///       envelop::add_rcpt("my.address@baz.com");
    ///       transport::deliver("my.address@baz.com");
    ///     },
    ///     action "deliver (obj/obj)" || {
    ///       let rcpt = address("my.address@boz.com");
    ///       envelop::add_rcpt(rcpt);
    ///       transport::deliver(rcpt);
    ///     },
    ///   ],
    /// }
    /// # "#)?.build()));
    ///
    /// # use vsmtp_common::{
    /// #   transfer::{ForwardTarget, Transfer, EmailTransferStatus},
    /// #   rcpt::Rcpt,
    /// #   Address,
    /// # };
    /// # for (rcpt, addr) in states[&vsmtp_rule_engine::ExecutionStage::RcptTo].0.forward_paths().unwrap().iter().zip([
    /// #     "my.address@foo.com",
    /// #     "my.address@bar.com",
    /// #     "my.address@baz.com",
    /// #     "my.address@boz.com"
    /// # ]) {
    /// #   assert_eq!(
    /// #     rcpt.address,
    /// #     Address::new_unchecked(addr.to_string())
    /// #   );
    /// #   assert_eq!(
    /// #     rcpt.transfer_method,
    /// #     Transfer::Deliver
    /// #   );
    /// # }
    /// ```
    #[rhai_fn(name = "deliver", return_raw)]
    pub fn deliver(ncc: NativeCallContext, rcpt: &str) -> EngineResult<()> {
        set_transport_for_one(&get_global!(ncc, ctx)?, rcpt, &Transfer::Deliver)
    }

    /// Set the delivery method to deliver for a single recipient.
    /// After all rules are evaluated, the email will be sent
    /// to the recipient using the domain of its address.
    ///
    /// # Args
    ///
    /// * `rcpt` - the recipient to apply the method to.
    ///
    /// # Effective smtp stage
    ///
    /// All of them.
    ///
    /// # Example
    /// ```ignore
    /// #{
    ///     delivery: [
    ///        action "setup delivery" || transport::deliver(address("john.doe@example.com")),
    ///     ]
    /// }
    /// ```
    #[rhai_fn(name = "deliver", return_raw)]
    pub fn deliver_obj(ncc: NativeCallContext, rcpt: SharedObject) -> EngineResult<()> {
        set_transport_for_one(
            &get_global!(ncc, ctx)?,
            &rcpt.to_string(),
            &Transfer::Deliver,
        )
    }

    /// Set the delivery method to deliver for all recipients.
    /// After all rules are evaluated, the email will be sent
    /// to all recipients using the domain of their respective address.
    ///
    /// # Effective smtp stage
    ///
    /// All of them.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// #{
    ///     delivery: [
    ///        action "setup delivery" || transport::deliver_all(),
    ///     ]
    /// }
    /// ```
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///   rcpt: [
    ///     action "deliver_all" || {
    ///       envelop::add_rcpt("my.address@foo.com");
    ///       envelop::add_rcpt("my.address@bar.com");
    ///       transport::deliver_all();
    ///     },
    ///   ],
    /// }
    /// # "#)?.build()));
    ///
    /// # use vsmtp_common::{
    /// #   transfer::{ForwardTarget, Transfer, EmailTransferStatus},
    /// #   rcpt::Rcpt,
    /// #   Address,
    /// # };
    /// # for (rcpt, addr) in states[&vsmtp_rule_engine::ExecutionStage::RcptTo].0.forward_paths().unwrap().iter().zip([
    /// #     "my.address@foo.com",
    /// #     "my.address@bar.com",
    /// # ]) {
    /// #   assert_eq!(
    /// #     rcpt.address,
    /// #     Address::new_unchecked(addr.to_string())
    /// #   );
    /// #   assert_eq!(
    /// #     rcpt.transfer_method,
    /// #     Transfer::Deliver
    /// #   );
    /// # }
    /// ```
    #[rhai_fn(return_raw)]
    pub fn deliver_all(ncc: NativeCallContext) -> EngineResult<()> {
        set_transport_foreach(&get_global!(ncc, ctx)?, &Transfer::Deliver)
    }

    /// Set the delivery method to mbox for a recipient.
    /// After all rules are evaluated, the email will be stored
    /// locally in the mail box of the recipient if it exists on the server.
    ///
    /// # Args
    ///
    /// * `rcpt` - the recipient to apply the method to.
    ///
    /// # Effective smtp stage
    ///
    /// All of them.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// #{
    ///     delivery: [
    ///        action "setup mbox" || transport::mbox("john.doe@example.com"),
    ///     ]
    /// }
    /// ```
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///   rcpt: [
    ///     action "setup mbox" || {
    ///         const doe = address("doe@example.com");
    ///         envelop::add_rcpt(doe);
    ///         envelop::add_rcpt("a@example.com");
    ///         transport::mbox(doe);
    ///         transport::mbox("a@example.com");
    ///     },
    ///   ],
    /// }
    /// # "#)?.build()));
    ///
    /// # use vsmtp_common::{
    /// #   transfer::{Transfer},
    /// #   rcpt::Rcpt,
    /// #   Address,
    /// # };
    /// # for (rcpt, addr) in states[&vsmtp_rule_engine::ExecutionStage::RcptTo].0.forward_paths().unwrap().iter().zip([
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
    #[rhai_fn(name = "mbox", return_raw)]
    pub fn mbox(ncc: NativeCallContext, rcpt: &str) -> EngineResult<()> {
        set_transport_for_one(&get_global!(ncc, ctx)?, rcpt, &Transfer::Mbox)
    }

    /// Set the delivery method to mbox for a recipient.
    /// After all rules are evaluated, the email will be stored
    /// locally in the mail box of the recipient if it exists on the server.
    ///
    /// # Args
    ///
    /// * `rcpt` - the recipient to apply the method to.
    ///
    /// # Effective smtp stage
    ///
    /// All of them.
    ///
    /// # Example
    /// ```ignore
    /// #{
    ///     delivery: [
    ///        action "setup mbox" || transport::mbox(address("john.doe@example.com")),
    ///     ]
    /// }
    /// ```
    #[rhai_fn(name = "mbox", return_raw)]
    pub fn mbox_obj(ncc: NativeCallContext, rcpt: SharedObject) -> EngineResult<()> {
        set_transport_for_one(&get_global!(ncc, ctx)?, &rcpt.to_string(), &Transfer::Mbox)
    }

    /// Set the delivery method to mbox for all recipients.
    /// After all rules are evaluated, the email will be stored
    /// locally in the mail box of all recipients if they exists on the server.
    ///
    /// # Effective smtp stage
    ///
    /// All of them.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// #{
    ///     delivery: [
    ///        action "setup mbox" || transport::mbox_all(),
    ///     ]
    /// }
    /// ```
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///   rcpt: [
    ///     action "setup mbox" || {
    ///         const doe = address("doe@example.com");
    ///         envelop::add_rcpt(doe);
    ///         envelop::add_rcpt("a@example.com");
    ///         transport::mbox_all();
    ///     },
    ///   ],
    /// }
    /// # "#)?.build()));
    ///
    /// # use vsmtp_common::{
    /// #   transfer::{Transfer},
    /// #   rcpt::Rcpt,
    /// #   Address,
    /// # };
    /// # for (rcpt, addr) in states[&vsmtp_rule_engine::ExecutionStage::RcptTo].0.forward_paths().unwrap().iter().zip([
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
    #[rhai_fn(return_raw)]
    pub fn mbox_all(ncc: NativeCallContext) -> EngineResult<()> {
        set_transport_foreach(&get_global!(ncc, ctx)?, &Transfer::Mbox)
    }

    /// Set the delivery method to maildir for a recipient.
    /// After all rules are evaluated, the email will be stored
    /// locally in the `~/Maildir/new/` folder of the recipient's user if it exists on the server.
    ///
    /// # Args
    ///
    /// * `rcpt` - the recipient to apply the method to.
    ///
    /// # Effective smtp stage
    ///
    /// All of them.
    ///
    /// # Examples
    /// ```ignore
    /// #{
    ///     delivery: [
    ///        action "setup maildir" || transport::maildir("john.doe@example.com"),
    ///     ]
    /// }
    /// ```
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///   rcpt: [
    ///     action "setup maildir" || {
    ///         const doe = address("doe@example.com");
    ///         envelop::add_rcpt(doe);
    ///         envelop::add_rcpt("a@example.com");
    ///         transport::maildir(doe);
    ///         transport::maildir("a@example.com");
    ///     },
    ///   ],
    /// }
    /// # "#)?.build()));
    ///
    /// # use vsmtp_common::{
    /// #   transfer::{Transfer},
    /// #   rcpt::Rcpt,
    /// #   Address,
    /// # };
    /// # for (rcpt, addr) in states[&vsmtp_rule_engine::ExecutionStage::RcptTo].0.forward_paths().unwrap().iter().zip([
    /// #     "doe@example.com",
    /// #     "a@example.com",
    /// # ]) {
    /// #   assert_eq!(
    /// #     rcpt.address,
    /// #     Address::new_unchecked(addr.to_string())
    /// #   );
    /// #   assert_eq!(
    /// #     rcpt.transfer_method,
    /// #     Transfer::Maildir
    /// #   );
    /// # }
    /// ```
    #[rhai_fn(name = "maildir", return_raw)]
    pub fn maildir(ncc: NativeCallContext, rcpt: &str) -> EngineResult<()> {
        set_transport_for_one(&get_global!(ncc, ctx)?, rcpt, &Transfer::Maildir)
    }

    /// Set the delivery method to maildir for a recipient.
    /// After all rules are evaluated, the email will be stored
    /// locally in the `~/Maildir/new/` folder of the recipient's user if it exists on the server.
    ///
    /// # Args
    ///
    /// * `rcpt` - the recipient to apply the method to.
    ///
    /// # Effective smtp stage
    ///
    /// All of them.
    ///
    /// # Example
    /// ```ignore
    /// #{
    ///     delivery: [
    ///        action "setup maildir" || transport::maildir(address("john.doe@example.com")),
    ///     ]
    /// }
    /// ```
    #[rhai_fn(name = "maildir", return_raw)]
    pub fn maildir_obj(ncc: NativeCallContext, rcpt: SharedObject) -> EngineResult<()> {
        set_transport_for_one(
            &get_global!(ncc, ctx)?,
            &rcpt.to_string(),
            &Transfer::Maildir,
        )
    }

    /// Set the delivery method to maildir for all recipients.
    /// After all rules are evaluated, the email will be stored
    /// locally in each `~/Maildir/new` folder of they respective recipient
    /// if they exists on the server.
    ///
    /// # Effective smtp stage
    ///
    /// All of them.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// #{
    ///     delivery: [
    ///        action "setup maildir" || transport::maildir_all(),
    ///     ]
    /// }
    /// ```
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///   rcpt: [
    ///     action "setup maildir" || {
    ///         const doe = address("doe@example.com");
    ///         envelop::add_rcpt(doe);
    ///         envelop::add_rcpt("a@example.com");
    ///         transport::maildir_all();
    ///     },
    ///   ],
    /// }
    /// # "#)?.build()));
    ///
    /// # use vsmtp_common::{
    /// #   transfer::{Transfer},
    /// #   rcpt::Rcpt,
    /// #   Address,
    /// # };
    /// # for (rcpt, addr) in states[&vsmtp_rule_engine::ExecutionStage::RcptTo].0.forward_paths().unwrap().iter().zip([
    /// #     "doe@example.com",
    /// #     "a@example.com",
    /// # ]) {
    /// #   assert_eq!(
    /// #     rcpt.address,
    /// #     Address::new_unchecked(addr.to_string())
    /// #   );
    /// #   assert_eq!(
    /// #     rcpt.transfer_method,
    /// #     Transfer::Maildir
    /// #   );
    /// # }
    /// ```
    #[rhai_fn(return_raw)]
    pub fn maildir_all(ncc: NativeCallContext) -> EngineResult<()> {
        set_transport_foreach(&get_global!(ncc, ctx)?, &Transfer::Maildir)
    }
}

fn set_transport_for_one(context: &Context, search: &str, method: &Transfer) -> EngineResult<()> {
    vsl_missing_ok!(
        ref vsl_guard_ok!(context.write()).forward_paths_mut().ok(),
        "rcpt_list",
        ExecutionStage::RcptTo
    )
    .iter_mut()
    .find(|rcpt| rcpt.address.full() == search)
    .ok_or_else::<Box<EvalAltResult>, _>(|| format!("could not find rcpt '{search}'").into())
    .map(|rcpt| rcpt.transfer_method = method.clone())
}

fn set_transport_foreach(context: &Context, method: &Transfer) -> EngineResult<()> {
    vsl_missing_ok!(
        ref vsl_guard_ok!(context.write()).forward_paths_mut().ok(),
        "rcpt_list",
        ExecutionStage::RcptTo
    )
    .iter_mut()
    .for_each(|rcpt| rcpt.transfer_method = method.clone());

    Ok(())
}
