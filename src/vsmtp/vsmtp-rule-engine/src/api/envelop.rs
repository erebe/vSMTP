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
    api::{
        EngineResult, {Context, SharedObject},
    },
    get_global,
};
use rhai::plugin::{
    mem, Dynamic, FnAccess, FnNamespace, ImmutableString, Module, NativeCallContext,
    PluginFunction, RhaiResult, TypeId,
};
use vsmtp_common::Address;

pub use envelop::*;

/// Functions to inspect and mutate the SMTP envelop.
#[rhai::plugin::export_module]
mod envelop {
    /// Rewrite the sender received from the `MAIL FROM` command.
    ///
    /// # Args
    ///
    /// * `new_addr` - the new string sender address to set.
    ///
    /// # Effective smtp stage
    ///
    /// `mail` and onwards.
    ///
    /// # Examples
    ///
    /// ```
    /// # vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     preq: [
    ///        action "rewrite envelop" || envelop::rw_mail_from("unknown@example.com"),
    ///     ]
    /// }
    /// # "#)?.build()));
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(name = "rw_mail_from", return_raw)]
    pub fn rewrite_mail_from_envelop_str(
        ncc: NativeCallContext,
        new_addr: &str,
    ) -> EngineResult<()> {
        super::rewrite_mail_from_envelop(&mut get_global!(ncc, ctx)?, new_addr)
    }

    /// Rewrite the sender received from the `MAIL FROM` command.
    ///
    /// # Args
    ///
    /// * `new_addr` - the new sender address to set.
    ///
    /// # Effective smtp stage
    ///
    /// `mail` and onwards.
    ///
    /// # Examples
    ///
    /// ```
    /// # vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     preq: [
    ///        action "rewrite envelop" || envelop::rw_mail_from(address("unknown@example.com")),
    ///     ]
    /// }
    /// # "#)?.build()));
    /// ```
    #[rhai_fn(name = "rw_mail_from", return_raw)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn rewrite_mail_from_envelop_obj(
        ncc: NativeCallContext,
        new_addr: SharedObject,
    ) -> EngineResult<()> {
        super::rewrite_mail_from_envelop(&mut get_global!(ncc, ctx)?, &new_addr.to_string())
    }

    /// Replace a recipient received by a `RCPT TO` command.
    ///
    /// # Args
    ///
    /// * `old_addr` - the recipient to replace.
    /// * `new_addr` - the new address to use when replacing `old_addr`.
    ///
    /// # Effective smtp stage
    ///
    /// `rcpt` and onwards.
    ///
    /// # Examples
    ///
    /// ```
    /// # vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     preq: [
    ///        action "rewrite envelop" || envelop::rw_rcpt("john.doe@example.com", "john.main@example.com"),
    ///     ]
    /// }
    /// # "#)?.build()));
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(name = "rw_rcpt", return_raw)]
    pub fn rewrite_rcpt_str_str(
        ncc: NativeCallContext,
        old_addr: &str,
        new_addr: &str,
    ) -> EngineResult<()> {
        super::rewrite_rcpt(&mut get_global!(ncc, ctx)?, old_addr, new_addr)
    }

    /// Replace a recipient received by a `RCPT TO` command.
    ///
    /// # Args
    ///
    /// * `old_addr` - the recipient to replace.
    /// * `new_addr` - the new address to use when replacing `old_addr`.
    ///
    /// # Effective smtp stage
    ///
    /// `rcpt` and onwards.
    ///
    /// # Examples
    ///
    /// ```
    /// # vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     preq: [
    ///        action "rewrite envelop" || envelop::rw_rcpt(address("john.doe@example.com"), "john.main@example.com"),
    ///     ]
    /// }
    /// # "#)?.build()));
    /// ```
    #[rhai_fn(name = "rw_rcpt", return_raw)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn rewrite_rcpt_obj_str(
        ncc: NativeCallContext,
        old_addr: SharedObject,
        new_addr: &str,
    ) -> EngineResult<()> {
        super::rewrite_rcpt(&mut get_global!(ncc, ctx)?, &old_addr.to_string(), new_addr)
    }

    /// Replace a recipient received by a `RCPT TO` command.
    ///
    /// # Args
    ///
    /// * `old_addr` - the recipient to replace.
    /// * `new_addr` - the new address to use when replacing `old_addr`.
    ///
    /// # Effective smtp stage
    ///
    /// `rcpt` and onwards.
    ///
    /// # Examples
    ///
    /// ```
    /// # vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     preq: [
    ///        action "rewrite envelop" || envelop::rw_rcpt("john.doe@example.com", address("john.main@example.com")),
    ///     ]
    /// }
    /// # "#)?.build()));
    /// ```
    #[rhai_fn(name = "rw_rcpt", return_raw)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn rewrite_rcpt_str_obj(
        ncc: NativeCallContext,
        old_addr: &str,
        new_addr: SharedObject,
    ) -> EngineResult<()> {
        super::rewrite_rcpt(&mut get_global!(ncc, ctx)?, old_addr, &new_addr.to_string())
    }

    /// Replace a recipient received by a `RCPT TO` command.
    ///
    /// # Args
    ///
    /// * `old_addr` - the recipient to replace.
    /// * `new_addr` - the new address to use when replacing `old_addr`.
    ///
    /// # Effective smtp stage
    ///
    /// `rcpt` and onwards.
    ///
    /// # Examples
    ///
    /// ```
    /// # vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     preq: [
    ///        action "rewrite envelop" || envelop::rw_rcpt(address("john.doe@example.com"), address("john.main@example.com")),
    ///     ]
    /// }
    /// # "#)?.build()));
    /// ```
    #[rhai_fn(name = "rw_rcpt", return_raw)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn rewrite_rcpt_obj_obj(
        ncc: NativeCallContext,
        old_addr: SharedObject,
        new_addr: SharedObject,
    ) -> EngineResult<()> {
        super::rewrite_rcpt(
            &mut get_global!(ncc, ctx)?,
            &old_addr.to_string(),
            &new_addr.to_string(),
        )
    }

    /// Add a new recipient to the envelop. Note that this does not add
    /// the recipient to the `To` header. Use `msg::add_rcpt` for that.
    ///
    /// # Args
    ///
    /// * `rcpt` - the new recipient to add.
    ///
    /// # Effective smtp stage
    ///
    /// All of them.
    ///
    /// # Examples
    ///
    /// ```
    /// # vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     connect: [
    ///        // always deliver a copy of the message to "john.doe@example.com".
    ///        action "rewrite envelop" || envelop::add_rcpt("john.doe@example.com"),
    ///     ]
    /// }
    /// # "#)?.build()));
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(name = "add_rcpt", return_raw)]
    pub fn add_rcpt_envelop_str(ncc: NativeCallContext, new_addr: &str) -> EngineResult<()> {
        super::add_rcpt_envelop(&mut get_global!(ncc, ctx)?, new_addr)
    }

    /// Add a new recipient to the envelop. Note that this does not add
    /// the recipient to the `To` header. Use `msg::add_rcpt` for that.
    ///
    /// # Args
    ///
    /// * `rcpt` - the new recipient to add.
    ///
    /// # Effective smtp stage
    ///
    /// All of them.
    ///
    /// # Examples
    ///
    /// ```
    /// # vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     connect: [
    ///        // always deliver a copy of the message to "john.doe@example.com".
    ///        action "rewrite envelop" || envelop::add_rcpt(address("john.doe@example.com")),
    ///     ]
    /// }
    /// # "#)?.build()));
    /// ```
    #[rhai_fn(name = "add_rcpt", return_raw)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn add_rcpt_envelop_obj(
        ncc: NativeCallContext,
        new_addr: SharedObject,
    ) -> EngineResult<()> {
        super::add_rcpt_envelop(&mut get_global!(ncc, ctx)?, &new_addr.to_string())
    }

    /// Alias for `envelop::add_rcpt`.
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(name = "bcc", return_raw)]
    pub fn bcc_str(ncc: NativeCallContext, new_addr: &str) -> EngineResult<()> {
        super::add_rcpt_envelop_str(ncc, new_addr)
    }

    /// Alias for `envelop::add_rcpt`.
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(name = "bcc", return_raw)]
    pub fn bcc_obj(ncc: NativeCallContext, new_addr: SharedObject) -> EngineResult<()> {
        super::add_rcpt_envelop_obj(ncc, new_addr)
    }

    /// Remove a recipient from the envelop. Note that this does not remove
    /// the recipient from the `To` header. Use `msg::rm_rcpt` for that.
    ///
    /// # Args
    ///
    /// * `rcpt` - the recipient to remove.
    ///
    /// # Effective smtp stage
    ///
    /// All of them.
    ///
    /// # Examples
    ///
    /// ```
    /// # vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     preq: [
    ///        // never deliver to "john.doe@example.com".
    ///        action "rewrite envelop" || envelop::rm_rcpt("john.doe@example.com"),
    ///     ]
    /// }
    /// # "#)?.build()));
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(name = "rm_rcpt", return_raw)]
    pub fn remove_rcpt_envelop_str(ncc: NativeCallContext, addr: &str) -> EngineResult<()> {
        super::remove_rcpt_envelop(&mut get_global!(ncc, ctx)?, addr)
    }

    /// Remove a recipient from the envelop. Note that this does not remove
    /// the recipient from the `To` header. Use `msg::rm_rcpt` for that.
    ///
    /// # Args
    ///
    /// * `rcpt` - the recipient to remove.
    ///
    /// # Effective smtp stage
    ///
    /// All of them.
    ///
    /// # Examples
    ///
    /// ```
    /// # vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     preq: [
    ///        // never deliver to "john.doe@example.com".
    ///        action "rewrite envelop" || envelop::rm_rcpt(address("john.doe@example.com")),
    ///     ]
    /// }
    /// # "#)?.build()));
    /// ```
    #[rhai_fn(name = "rm_rcpt", return_raw)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn remove_rcpt_envelop_obj(ncc: NativeCallContext, addr: SharedObject) -> EngineResult<()> {
        super::remove_rcpt_envelop(&mut get_global!(ncc, ctx)?, &addr.to_string())
    }
}

fn rewrite_mail_from_envelop(context: &mut Context, new_addr: &str) -> EngineResult<()> {
    vsl_guard_ok!(context.write())
        .set_reverse_path(Some(vsl_conversion_ok!(
            "address",
            <Address as std::str::FromStr>::from_str(new_addr)
        )))
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
