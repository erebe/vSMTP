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
    api::{EngineResult, SharedObject},
    get_global,
};
use rhai::plugin::{
    mem, Dynamic, EvalAltResult, FnAccess, FnNamespace, ImmutableString, Module, NativeCallContext,
    PluginFunction, RhaiResult, TypeId,
};
use vsmtp_common::Address;
use vsmtp_delivery::{Deliver, Forward, MBox, Maildir, SenderParameters};

pub use transport::*;

/// Functions to configure delivery methods of emails.
#[allow(clippy::needless_pass_by_value)]
#[rhai::plugin::export_module]
mod transport {

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
    ///
    /// ```
    /// # let rules = r#"
    /// #{
    ///     rcpt: [
    /// #      action "rm default value" || {
    /// #        envelop::rm_rcpt("recipient@testserver.com");
    /// #      },
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
    /// # "#;
    /// #
    /// # let states = vsmtp_test::vsl::run(|builder| Ok(builder
    /// #   .add_root_filter_rules("#{}")?
    /// #      .add_domain_rules("testserver.com".parse().unwrap())
    /// #        .with_incoming(rules)?
    /// #        .with_outgoing(rules)?
    /// #        .with_internal(rules)?
    /// #      .build()
    /// #   .build())
    /// # );
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::RcptTo].2, vsmtp_common::status::Status::Next);
    /// #
    /// # let config = vsmtp_test::config::local_test();
    /// #
    /// # use vsmtp_common::{Address, Target};
    /// # let forward_paths = states[&vsmtp_rule_engine::ExecutionStage::RcptTo].0.forward_paths().unwrap();
    /// # for (addr, (addr_expected, target)) in forward_paths.iter().zip([
    /// #     ("my.address@foo.com", "127.0.0.1"),
    /// #     ("my.address@bar.com", "127.0.0.2"),
    /// #     ("my.address@baz.com", "::1"),
    /// #     ("my.address@boz.com", "127.0.0.4")
    /// # ]) {
    /// #   assert_eq!(
    /// #     *addr,
    /// #     Address::new_unchecked(addr_expected.to_string())
    /// #   );
    /// #   let transport = std::sync::Arc::new(
    /// #     vsmtp_delivery::Forward::new(
    /// #       target.parse().unwrap(),
    /// #     )
    /// #   );
    /// #   let delivery = states[&vsmtp_rule_engine::ExecutionStage::RcptTo].0.delivery().unwrap();
    /// #   let bound = delivery.get(
    /// #       &vsmtp_common::transport::WrapperSerde::Ready(transport)
    /// #   ).unwrap();
    /// #   assert!(bound.iter().map(|(r, _)| r).any(|r| *r == *addr));
    /// # }
    /// ```
    ///
    /// Or with url:
    ///
    /// ```
    /// # let rules = r#"
    /// #{
    ///     rcpt: [
    /// #      action "rm default value" || {
    /// #        envelop::rm_rcpt("recipient@testserver.com");
    /// #        envelop::add_rcpt("my.address@foo.com");
    /// #      },
    ///       action "set forward" || {
    ///         let user = "root@domain.tld";
    ///         let pass = "xxxxxx";
    ///         let host = "smtp.domain.tld";
    ///         let port = 25;
    ///         transport::forward_all(`smtp://${user}:${pass}@${host}:${port}?tls=opportunistic`);
    ///       },
    ///    ]
    /// }
    /// # "#;
    /// #
    /// # let states = vsmtp_test::vsl::run(|builder| Ok(builder
    /// #   .add_root_filter_rules("#{}")?
    /// #      .add_domain_rules("testserver.com".parse().unwrap())
    /// #        .with_incoming(rules)?
    /// #        .with_outgoing(rules)?
    /// #        .with_internal(rules)?
    /// #      .build()
    /// #   .build())
    /// # );
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::RcptTo].2, vsmtp_common::status::Status::Next);
    /// # use vsmtp_common::Address;
    /// # let bound = states[&vsmtp_rule_engine::ExecutionStage::RcptTo].0.delivery().unwrap().get(
    /// # &vsmtp_common::transport::WrapperSerde::Ready(std::sync::Arc::new(
    /// #   vsmtp_delivery::Forward::new(
    /// #     vsmtp_delivery::SenderParameters {
    /// #       host: vsmtp_common::Target::Domain("smtp.domain.tld".parse().unwrap()),
    /// #       hello_name: None,
    /// #       port: 25,
    /// #       credentials: Some(("root@domain.tld".to_string(), "xxxxxx".to_string())),
    /// #       tls: vsmtp_delivery::TlsPolicy::StarttlsOpportunistic,
    /// #     }
    /// #   )
    /// # ))
    /// # ).unwrap();
    /// # for (addr, expected_addr) in states[&vsmtp_rule_engine::ExecutionStage::RcptTo].0.forward_paths().unwrap().iter().zip([
    /// #     "my.address@foo.com",
    /// # ]) {
    /// #   assert_eq!(
    /// #     *addr,
    /// #     Address::new_unchecked(expected_addr.to_string())
    /// #   );
    /// #   assert!(bound.iter().map(|(r, _)| r).any(|r| *r == *addr));
    /// # }
    /// ```
    #[rhai_fn(name = "forward", return_raw)]
    pub fn forward(ncc: NativeCallContext, rcpt: &str, forward: &str) -> EngineResult<()> {
        let params =
            <SenderParameters as std::str::FromStr>::from_str(forward)
                .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;

        let rcpt = <Address as std::str::FromStr>::from_str(rcpt)
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;

        let ctx = get_global!(ncc, ctx)?;
        let transport = std::sync::Arc::new(Forward::new(params));
        let mut guard = ctx.write().expect("mutex poisoned");
        guard
            .set_transport_for_one(&rcpt, transport)
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())
    }

    #[doc(hidden)]
    #[rhai_fn(name = "forward", return_raw)]
    pub fn forward_obj_str(
        ncc: NativeCallContext,
        rcpt: SharedObject,
        forward: &str,
    ) -> EngineResult<()> {
        let params =
            <SenderParameters as std::str::FromStr>::from_str(forward)
                .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;
        let rcpt = <Address as std::str::FromStr>::from_str(&rcpt.to_string())
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;

        let ctx = get_global!(ncc, ctx)?;

        let mut guard = ctx.write().expect("mutex poisoned");
        guard
            .set_transport_for_one(&rcpt, std::sync::Arc::new(Forward::new(params)))
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())
    }

    #[doc(hidden)]
    #[rhai_fn(name = "forward", return_raw)]
    pub fn forward_str_obj(
        ncc: NativeCallContext,
        rcpt: &str,
        forward: SharedObject,
    ) -> EngineResult<()> {
        let params = <SenderParameters as std::str::FromStr>::from_str(&forward.to_string())
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;
        let rcpt = <Address as std::str::FromStr>::from_str(rcpt)
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;

        let ctx = get_global!(ncc, ctx)?;
        let mut guard = ctx.write().expect("mutex poisoned");
        guard
            .set_transport_for_one(&rcpt, std::sync::Arc::new(Forward::new(params)))
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())
    }

    #[doc(hidden)]
    #[rhai_fn(name = "forward", return_raw)]
    pub fn forward_obj_obj(
        ncc: NativeCallContext,
        rcpt: SharedObject,
        forward: SharedObject,
    ) -> EngineResult<()> {
        let params = <SenderParameters as std::str::FromStr>::from_str(&forward.to_string())
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;
        let rcpt = <Address as std::str::FromStr>::from_str(&rcpt.to_string())
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;

        let ctx = get_global!(ncc, ctx)?;
        let mut guard = ctx.write().expect("mutex poisoned");
        guard
            .set_transport_for_one(&rcpt, std::sync::Arc::new(Forward::new(params)))
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())
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
    /// ```
    /// # let rules = r#"
    /// #{
    ///   rcpt: [
    /// #   action "rm default value" || {
    /// #     envelop::rm_rcpt("recipient@testserver.com");
    /// #   },
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
    /// # "#;
    ///
    /// # let states = vsmtp_test::vsl::run(|builder| Ok(builder
    /// #   .add_root_filter_rules("#{}")?
    /// #      .add_domain_rules("testserver.com".parse().unwrap())
    /// #        .with_incoming(rules)?
    /// #        .with_outgoing(rules)?
    /// #        .with_internal(rules)?
    /// #      .build()
    /// #   .build())
    /// # );
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::RcptTo].2, vsmtp_common::status::Status::Next);
    ///
    /// # use vsmtp_common::Address;
    /// # let bound = states[&vsmtp_rule_engine::ExecutionStage::RcptTo].0.delivery().unwrap().get(
    /// # &vsmtp_common::transport::WrapperSerde::Ready(std::sync::Arc::new(
    /// #   vsmtp_delivery::Forward::new(
    /// #     "127.0.0.1".parse().unwrap(),
    /// #   )
    /// # ))
    /// # ).unwrap();
    /// # for (addr, expected_addr) in states[&vsmtp_rule_engine::ExecutionStage::RcptTo].0.forward_paths().unwrap().iter().zip([
    /// #     "my.address@foo.com",
    /// #     "my.address@bar.com",
    /// # ]) {
    /// #   assert_eq!(
    /// #     *addr,
    /// #     Address::new_unchecked(expected_addr.to_string())
    /// #   );
    /// #   assert!(bound.iter().map(|(r, _)| r).any(|r| *r == *addr));
    /// # }
    /// ```
    #[rhai_fn(name = "forward_all", return_raw)]
    pub fn forward_all(ncc: NativeCallContext, forward: &str) -> EngineResult<()> {
        let params =
            <SenderParameters as std::str::FromStr>::from_str(forward)
                .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;

        let ctx = get_global!(ncc, ctx)?;
        let transport = std::sync::Arc::new(Forward::new(params));

        let mut guard = ctx.write().expect("mutex poisoned");
        guard
            .set_transport_foreach(transport)
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())
    }

    #[doc(hidden)]
    #[rhai_fn(name = "forward_all", return_raw)]
    pub fn forward_all_obj(ncc: NativeCallContext, forward: SharedObject) -> EngineResult<()> {
        let params = <SenderParameters as std::str::FromStr>::from_str(&forward.to_string())
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;

        let ctx = get_global!(ncc, ctx)?;
        let mut guard = ctx.write().expect("mutex poisoned");
        guard
            .set_transport_foreach(std::sync::Arc::new(Forward::new(params)))
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())
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
    ///
    /// ```
    /// # let rules = r#"
    /// #{
    ///   rcpt: [
    /// #   action "rm default value" || {
    /// #     envelop::rm_rcpt("recipient@testserver.com");
    /// #   },
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
    /// # "#;
    ///
    /// # let states = vsmtp_test::vsl::run(|builder| Ok(builder
    /// #   .add_root_filter_rules("#{}")?
    /// #      .add_domain_rules("testserver.com".parse().unwrap())
    /// #        .with_incoming(rules)?
    /// #        .with_outgoing(rules)?
    /// #        .with_internal(rules)?
    /// #      .build()
    /// #   .build())
    /// # );
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::RcptTo].2, vsmtp_common::status::Status::Next);
    ///
    /// # use vsmtp_common::Address;
    /// # for (addr, addr_expected) in states[&vsmtp_rule_engine::ExecutionStage::RcptTo].0.forward_paths().unwrap().iter().zip([
    /// #     "my.address@foo.com",
    /// #     "my.address@bar.com",
    /// #     "my.address@baz.com",
    /// #     "my.address@boz.com"
    /// # ]) {
    /// #   assert_eq!(
    /// #     *addr,
    /// #     Address::new_unchecked(addr_expected.to_string())
    /// #   );
    /// #   let transport = std::sync::Arc::new(
    /// #     vsmtp_delivery::Deliver::new(
    /// #       std::sync::Arc::new(trust_dns_resolver::TokioAsyncResolver::tokio_from_system_conf().unwrap()),
    /// #       std::sync::Arc::new(vsmtp_test::config::local_test())
    /// #     )
    /// #   );
    /// #   let bound = states[&vsmtp_rule_engine::ExecutionStage::RcptTo].0.delivery().unwrap().get(
    /// #     &vsmtp_common::transport::WrapperSerde::Ready(transport)
    /// #   ).unwrap();
    /// #   assert!(bound.iter().map(|(r, _)| r).any(|r| *r == *addr));
    /// # }
    /// ```
    #[rhai_fn(name = "deliver", return_raw)]
    pub fn deliver(ncc: NativeCallContext, rcpt: &str) -> EngineResult<()> {
        let rcpt = <Address as std::str::FromStr>::from_str(rcpt)
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;

        let ctx = get_global!(ncc, ctx)?;
        let srv = get_global!(ncc, srv)?;
        let mut guard = ctx.write().expect("mutex poisoned");
        guard
            .set_transport_for_one(
                &rcpt,
                std::sync::Arc::new(Deliver::new(
                    srv.resolvers.get_resolver_or_root(&rcpt.domain()),
                    srv.config.clone(),
                )),
            )
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())
    }

    #[doc(hidden)]
    #[rhai_fn(name = "deliver", return_raw)]
    pub fn deliver_obj(ncc: NativeCallContext, rcpt: SharedObject) -> EngineResult<()> {
        let rcpt = <Address as std::str::FromStr>::from_str(&rcpt.to_string())
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;

        let ctx = get_global!(ncc, ctx)?;
        let srv = get_global!(ncc, srv)?;

        let mut guard = ctx.write().expect("mutex poisoned");
        guard
            .set_transport_for_one(
                &rcpt,
                std::sync::Arc::new(Deliver::new(
                    srv.resolvers.get_resolver_or_root(&rcpt.domain()),
                    srv.config.clone(),
                )),
            )
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())
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
    /// # let rules = r#"
    /// #{
    ///   rcpt: [
    /// #      action "rm default value" || {
    /// #        envelop::rm_rcpt("recipient@testserver.com");
    /// #      },
    ///     action "deliver_all" || {
    ///       envelop::add_rcpt("my.address@foo.com");
    ///       envelop::add_rcpt("my.address@bar.com");
    ///       transport::deliver_all();
    ///     },
    ///   ],
    /// }
    /// # "#;
    ///
    /// # let states = vsmtp_test::vsl::run(|builder| Ok(builder
    /// #   .add_root_filter_rules("#{}")?
    /// #      .add_domain_rules("testserver.com".parse().unwrap())
    /// #        .with_incoming(rules)?
    /// #        .with_outgoing(rules)?
    /// #        .with_internal(rules)?
    /// #      .build()
    /// #   .build())
    /// # );
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::RcptTo].2, vsmtp_common::status::Status::Next);
    /// # use vsmtp_common::Address;
    /// # let transport = std::sync::Arc::new(
    /// #   vsmtp_delivery::Deliver::new(
    /// #     std::sync::Arc::new(trust_dns_resolver::TokioAsyncResolver::tokio_from_system_conf().unwrap()),
    /// #     std::sync::Arc::new(vsmtp_test::config::local_test())
    /// #   )
    /// # );
    /// # let bound = states[&vsmtp_rule_engine::ExecutionStage::RcptTo].0.delivery().unwrap().get(
    /// #   &vsmtp_common::transport::WrapperSerde::Ready(transport)
    /// # ).unwrap();
    /// # for (addr, expected_addr) in states[&vsmtp_rule_engine::ExecutionStage::RcptTo].0.forward_paths().unwrap().iter().zip([
    /// #     "my.address@foo.com",
    /// #     "my.address@bar.com",
    /// # ]) {
    /// #   assert_eq!(
    /// #     *addr,
    /// #     Address::new_unchecked(expected_addr.to_string())
    /// #   );
    /// #   assert!(bound.iter().map(|(r, _)| r).any(|r| *r == *addr));
    /// # }
    /// ```
    #[rhai_fn(return_raw)]
    pub fn deliver_all(ncc: NativeCallContext) -> EngineResult<()> {
        let ctx = get_global!(ncc, ctx)?;
        let srv = get_global!(ncc, srv)?;

        let mut guard = ctx.write().expect("mutex poisoned");
        guard
            .set_transport_foreach(std::sync::Arc::new(Deliver::new(
                srv.resolvers.get_resolver_root(),
                srv.config.clone(),
            )))
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())
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
    /// # let rules = r#"
    /// #{
    ///   rcpt: [
    /// #      action "rm default value" || {
    /// #        envelop::rm_rcpt("recipient@testserver.com");
    /// #      },
    ///     action "setup mbox" || {
    ///         const doe = address("doe@example.com");
    ///         envelop::add_rcpt(doe);
    ///         envelop::add_rcpt("a@example.com");
    ///         transport::mbox(doe);
    ///         transport::mbox("a@example.com");
    ///     },
    ///   ],
    /// }
    /// # "#;
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder
    /// #   .add_root_filter_rules("#{}")?
    /// #      .add_domain_rules("testserver.com".parse().unwrap())
    /// #        .with_incoming(rules)?
    /// #        .with_outgoing(rules)?
    /// #        .with_internal(rules)?
    /// #      .build()
    /// #   .build()));
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::RcptTo].2, vsmtp_common::status::Status::Next);
    ///
    /// # let transport = std::sync::Arc::new(vsmtp_delivery::MBox::new(None));
    /// # let bound = states[&vsmtp_rule_engine::ExecutionStage::RcptTo].0.delivery().unwrap().get(
    /// #   &vsmtp_common::transport::WrapperSerde::Ready(transport)
    /// # ).unwrap();
    /// # use vsmtp_common::Address;
    ///
    /// # for (addr, addr_expected) in states[&vsmtp_rule_engine::ExecutionStage::RcptTo].0.forward_paths().unwrap().iter().zip([
    /// #     "doe@example.com",
    /// #     "a@example.com",
    /// # ]) {
    /// #   assert_eq!(
    /// #     *addr,
    /// #     Address::new_unchecked(addr_expected.to_string())
    /// #   );
    /// #   assert!(bound.iter().map(|(r, _)| r).any(|r| *r == *addr));
    /// # }
    /// ```
    #[rhai_fn(name = "mbox", return_raw)]
    pub fn mbox(ncc: NativeCallContext, rcpt: &str) -> EngineResult<()> {
        let rcpt = <Address as std::str::FromStr>::from_str(rcpt)
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;

        let ctx = get_global!(ncc, ctx)?;
        let grp = get_global!(ncc, srv)?
            .config
            .server
            .system
            .group_local
            .clone();

        let mut guard = ctx.write().expect("mutex poisoned");
        guard
            .set_transport_for_one(&rcpt, std::sync::Arc::new(MBox::new(grp)))
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())
    }

    #[doc(hidden)]
    #[rhai_fn(name = "mbox", return_raw)]
    pub fn mbox_obj(ncc: NativeCallContext, rcpt: SharedObject) -> EngineResult<()> {
        let rcpt = <Address as std::str::FromStr>::from_str(&rcpt.to_string())
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;

        let ctx = get_global!(ncc, ctx)?;
        let grp = get_global!(ncc, srv)?
            .config
            .server
            .system
            .group_local
            .clone();

        let mut guard = ctx.write().expect("mutex poisoned");
        guard
            .set_transport_for_one(&rcpt, std::sync::Arc::new(MBox::new(grp)))
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())
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
    /// # let rules = r#"
    /// #{
    ///   rcpt: [
    /// #      action "rm default value" || {
    /// #        envelop::rm_rcpt("recipient@testserver.com");
    /// #      },
    ///     action "setup mbox" || {
    ///         const doe = address("doe@example.com");
    ///         envelop::add_rcpt(doe);
    ///         envelop::add_rcpt("a@example.com");
    ///         transport::mbox_all();
    ///     },
    ///   ],
    /// }
    /// # "#;
    /// # let states = vsmtp_test::vsl::run(|builder| Ok(builder
    /// #   .add_root_filter_rules("#{}")?
    /// #      .add_domain_rules("testserver.com".parse().unwrap())
    /// #        .with_incoming(rules)?
    /// #        .with_outgoing(rules)?
    /// #        .with_internal(rules)?
    /// #      .build()
    /// #   .build()));
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::RcptTo].2, vsmtp_common::status::Status::Next);
    ///
    /// # let transport = std::sync::Arc::new(vsmtp_delivery::MBox::new(None));
    /// # let bound = states[&vsmtp_rule_engine::ExecutionStage::RcptTo].0.delivery().unwrap().get(
    /// #   &vsmtp_common::transport::WrapperSerde::Ready(transport)
    /// # ).unwrap();
    ///
    /// # use vsmtp_common::Address;
    /// # for (addr, addr_expected) in states[&vsmtp_rule_engine::ExecutionStage::RcptTo].0.forward_paths().unwrap().iter().zip([
    /// #     "doe@example.com",
    /// #     "a@example.com",
    /// # ]) {
    /// #   assert_eq!(
    /// #     *addr,
    /// #     Address::new_unchecked(addr_expected.to_string())
    /// #   );
    /// #   assert!(bound.iter().map(|(r, _)| r).any(|r| *r == *addr));
    /// # }
    /// ```
    #[rhai_fn(return_raw)]
    pub fn mbox_all(ncc: NativeCallContext) -> EngineResult<()> {
        let ctx = get_global!(ncc, ctx)?;
        let grp = get_global!(ncc, srv)?
            .config
            .server
            .system
            .group_local
            .clone();

        let mut guard = ctx.write().expect("mutex poisoned");
        guard
            .set_transport_foreach(std::sync::Arc::new(MBox::new(grp)))
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())
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
    /// # let rules = r#"
    /// #{
    ///   rcpt: [
    /// #      action "rm default value" || {
    /// #        envelop::rm_rcpt("recipient@testserver.com");
    /// #      },
    ///     action "setup maildir" || {
    ///         const doe = address("doe@example.com");
    ///         envelop::add_rcpt(doe);
    ///         envelop::add_rcpt("a@example.com");
    ///         transport::maildir(doe);
    ///         transport::maildir("a@example.com");
    ///     },
    ///   ],
    /// }
    /// # "#;
    ///
    /// # let states = vsmtp_test::vsl::run(|builder| Ok(builder
    /// #   .add_root_filter_rules("#{}")?
    /// #      .add_domain_rules("testserver.com".parse().unwrap())
    /// #        .with_incoming(rules)?
    /// #        .with_outgoing(rules)?
    /// #        .with_internal(rules)?
    /// #      .build()
    /// #   .build()));
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::RcptTo].2, vsmtp_common::status::Status::Next);
    ///
    /// # use vsmtp_common::Address;
    /// # let transport = std::sync::Arc::new(vsmtp_delivery::Maildir::new(None));
    /// # let bound = states[&vsmtp_rule_engine::ExecutionStage::RcptTo].0.delivery().unwrap().get(
    /// #   &vsmtp_common::transport::WrapperSerde::Ready(transport)
    /// # ).unwrap();
    /// # for (addr, addr_expected) in states[&vsmtp_rule_engine::ExecutionStage::RcptTo].0.forward_paths().unwrap().iter().zip([
    /// #     "doe@example.com",
    /// #     "a@example.com",
    /// # ]) {
    /// #   assert_eq!(
    /// #     *addr,
    /// #     Address::new_unchecked(addr_expected.to_string())
    /// #   );
    /// #   assert!(bound.iter().map(|(r, _)| r).any(|r| *r == *addr));
    /// # }
    /// ```
    #[rhai_fn(name = "maildir", return_raw)]
    pub fn maildir(ncc: NativeCallContext, rcpt: &str) -> EngineResult<()> {
        let rcpt = <Address as std::str::FromStr>::from_str(rcpt)
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;

        let ctx = get_global!(ncc, ctx)?;
        let grp = get_global!(ncc, srv)?
            .config
            .server
            .system
            .group_local
            .clone();

        let mut guard = ctx.write().expect("mutex poisoned");
        guard
            .set_transport_for_one(&rcpt, std::sync::Arc::new(Maildir::new(grp)))
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())
    }

    #[doc(hidden)]
    #[rhai_fn(name = "maildir", return_raw)]
    pub fn maildir_obj(ncc: NativeCallContext, rcpt: SharedObject) -> EngineResult<()> {
        let rcpt = <Address as std::str::FromStr>::from_str(&rcpt.to_string())
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?;

        let ctx = get_global!(ncc, ctx)?;
        let grp = get_global!(ncc, srv)?
            .config
            .server
            .system
            .group_local
            .clone();

        let mut guard = ctx.write().expect("mutex poisoned");
        guard
            .set_transport_for_one(&rcpt, std::sync::Arc::new(Maildir::new(grp)))
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())
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
    /// # let rules = r#"
    /// #{
    ///   rcpt: [
    /// #      action "rm default value" || {
    /// #        envelop::rm_rcpt("recipient@testserver.com");
    /// #      },
    ///     action "setup maildir" || {
    ///         const doe = address("doe@example.com");
    ///         envelop::add_rcpt(doe);
    ///         envelop::add_rcpt("a@example.com");
    ///         transport::maildir_all();
    ///     },
    ///   ],
    /// }
    /// # "#;
    ///
    /// # let states = vsmtp_test::vsl::run(|builder| Ok(builder
    /// #   .add_root_filter_rules("#{}")?
    /// #      .add_domain_rules("testserver.com".parse().unwrap())
    /// #        .with_incoming(rules)?
    /// #        .with_outgoing(rules)?
    /// #        .with_internal(rules)?
    /// #      .build()
    /// #   .build()));
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::RcptTo].2, vsmtp_common::status::Status::Next);
    ///
    /// # use vsmtp_common::Address;
    /// # let transport = std::sync::Arc::new(vsmtp_delivery::Maildir::new(None));
    /// # let bound = states[&vsmtp_rule_engine::ExecutionStage::RcptTo].0.delivery().unwrap().get(
    /// #   &vsmtp_common::transport::WrapperSerde::Ready(transport)
    /// # ).unwrap();
    ///
    /// # for (addr, addr_expected) in states[&vsmtp_rule_engine::ExecutionStage::RcptTo].0.forward_paths().unwrap().iter().zip([
    /// #     "doe@example.com",
    /// #     "a@example.com",
    /// # ]) {
    /// #   assert_eq!(
    /// #     *addr,
    /// #     Address::new_unchecked(addr_expected.to_string())
    /// #   );
    /// #   assert!(bound.iter().map(|(r, _)| r).any(|r| *r == *addr));
    /// # }
    /// ```
    #[rhai_fn(return_raw)]
    pub fn maildir_all(ncc: NativeCallContext) -> EngineResult<()> {
        let ctx = get_global!(ncc, ctx)?;
        let grp = get_global!(ncc, srv)?
            .config
            .server
            .system
            .group_local
            .clone();

        let mut guard = ctx.write().expect("mutex poisoned");
        guard
            .set_transport_foreach(std::sync::Arc::new(Maildir::new(grp)))
            .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())
    }
}
