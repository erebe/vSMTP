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
        EngineResult, {Message, SharedObject},
    },
    get_global,
};
use rhai::plugin::{
    mem, Dynamic, FnAccess, FnNamespace, ImmutableString, Module, NativeCallContext,
    PluginFunction, RhaiResult, TypeId,
};

pub use message::*;
use vsmtp_common::Address;

/// Inspect incoming messages.
#[rhai::plugin::export_module]
mod message {

    /// Generate the `.eml` representation of the message.
    #[rhai_fn(global, pure)]
    pub fn to_string(message: &mut Message) -> String {
        message
            .read()
            .expect("msg not poisoned")
            .inner()
            .to_string()
    }

    /// Checks if the message contains a specific header.
    ///
    /// # Args
    ///
    /// * `header` - the name of the header to search.
    ///
    /// # Effective smtp stage
    ///
    /// All of them, although it is most useful in the `preq` stage because the
    /// email is received at this point.
    ///
    /// # Examples
    ///
    /// ```
    /// // Message example.
    /// # let msg = vsmtp_mail_parser::MessageBody::try_from(concat!(
    /// "X-My-Header: foo\r\n",
    /// "Subject: Unit test are cool\r\n",
    /// "\r\n",
    /// "Hello world!\r\n",
    /// # )).unwrap();
    /// # let rules = r#"
    /// #{
    ///   preq: [
    ///     rule "check if header exists" || {
    ///       if msg::has_header("X-My-Header") && msg::has_header(identifier("Subject")) {
    ///         state::accept();
    ///       } else {
    ///         state::deny();
    ///       }
    ///     }
    ///   ]
    /// }
    /// # "#;
    /// # let states = vsmtp_test::vsl::run_with_msg(|builder| Ok(builder
    /// #   .add_root_filter_rules("#{}")?
    /// #      .add_domain_rules("testserver.com".parse().unwrap())
    /// #        .with_incoming(rules)?
    /// #        .with_outgoing(rules)?
    /// #        .with_internal(rules)?
    /// #      .build()
    /// #   .build()), Some(msg));
    /// # use vsmtp_common::{status::Status, CodeID};
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::PreQ].2, Status::Accept(either::Left(CodeID::Ok)));
    /// ```
    #[rhai_fn(name = "has_header", return_raw)]
    pub fn has_header(ncc: NativeCallContext, header: &str) -> EngineResult<bool> {
        Ok(vsl_guard_ok!(get_global!(ncc, msg)?.read())
            .get_header(header)
            .is_some())
    }

    #[doc(hidden)]
    #[rhai_fn(name = "has_header", return_raw)]
    pub fn has_header_obj(ncc: NativeCallContext, header: SharedObject) -> EngineResult<bool> {
        has_header(ncc, &header.to_string())
    }

    /// Count the number of headers with the given name.
    ///
    /// # Args
    ///
    /// * `header` - the name of the header to count.
    ///
    /// # Return
    ///
    /// * `number` - the number headers with the same name.
    ///
    /// # Effective smtp stage
    ///
    /// All of them, although it is most useful in the `preq` stage because this
    /// is when the email body is received.
    ///
    /// # Examples
    ///
    /// ```
    /// # let msg = vsmtp_mail_parser::MessageBody::try_from(concat!(
    /// "X-My-Header: foo\r\n",
    /// "X-My-Header: bar\r\n",
    /// "X-My-Header: baz\r\n",
    /// "Subject: Unit test are cool\r\n",
    /// "\r\n",
    /// "Hello world!\r\n",
    /// # )).unwrap();
    /// # let rules = r#"
    /// #{
    ///   preq: [
    ///     rule "count_header" || {
    ///       state::accept(`250 count is ${msg::count_header("X-My-Header")} and ${msg::count_header(identifier("Subject"))}`);
    ///     }
    ///   ]
    /// }
    /// # "#;
    /// # let states = vsmtp_test::vsl::run_with_msg(|builder| Ok(builder
    /// #   .add_root_filter_rules("#{}")?
    /// #      .add_domain_rules("testserver.com".parse().unwrap())
    /// #        .with_incoming(rules)?
    /// #        .with_outgoing(rules)?
    /// #        .with_internal(rules)?
    /// #      .build()
    /// #   .build()), Some(msg));
    /// # use vsmtp_common::{status::Status, CodeID, Reply, ReplyCode::Code};
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::PreQ].2, Status::Accept(either::Right(
    /// #  "250 count is 3 and 1\r\n".parse().unwrap()
    /// # )));
    /// ```
    #[rhai_fn(name = "count_header", return_raw)]
    pub fn count_header(ncc: NativeCallContext, header: &str) -> EngineResult<rhai::INT> {
        super::Impl::count_header(&get_global!(ncc, msg)?, header)
    }

    #[doc(hidden)]
    #[rhai_fn(name = "count_header", return_raw)]
    pub fn count_header_obj(
        ncc: NativeCallContext,
        header: SharedObject,
    ) -> EngineResult<rhai::INT> {
        super::Impl::count_header(&get_global!(ncc, msg)?, &header.to_string())
    }

    /// Get a specific header from the incoming message.
    ///
    /// # Args
    ///
    /// * `header` - the name of the header to get.
    ///
    /// # Return
    ///
    /// * `string` - the header value, or an empty string if the header was not found.
    ///
    /// # Effective smtp stage
    ///
    /// All of them, although it is most useful in the `preq` stage because this
    /// is when the email body is received.
    ///
    /// # Examples
    ///
    /// ```
    /// # let msg = r#"
    /// X-My-Header: 250 foo
    /// Subject: Unit test are cool
    ///
    /// Hello world!
    /// # "#
    /// ; // .eml ends here
    /// # let msg = vsmtp_mail_parser::MessageBody::try_from(msg[1..].replace("\n", "\r\n").as_str()).unwrap();
    ///
    /// let rules = r#"
    /// #{
    ///   preq: [
    ///     rule "get_header" || {
    ///       if msg::get_header("X-My-Header") != "250 foo"
    ///         || msg::get_header(identifier("Subject")) != "Unit test are cool" {
    ///         state::deny();
    ///       } else {
    ///         state::accept(`${msg::get_header("X-My-Header")} ${msg::get_header(identifier("Subject"))}`);
    ///       }
    ///     }
    ///   ]
    /// }
    /// # "#;
    /// # let states = vsmtp_test::vsl::run_with_msg(|builder| Ok(builder
    /// #   .add_root_filter_rules("#{}")?
    /// #      .add_domain_rules("testserver.com".parse().unwrap())
    /// #        .with_incoming(rules)?
    /// #        .with_outgoing(rules)?
    /// #        .with_internal(rules)?
    /// #      .build()
    /// #   .build()), Some(msg));
    /// # use vsmtp_common::{status::Status, CodeID, Reply, ReplyCode::Code};
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::PreQ].2, Status::Accept(either::Right(
    /// #  "250 foo Unit test are cool\r\n".parse().unwrap()
    /// # )));
    /// ```
    #[rhai_fn(name = "get_header", return_raw)]
    pub fn get_header(ncc: NativeCallContext, header: &str) -> EngineResult<String> {
        Ok(vsl_guard_ok!(get_global!(ncc, msg)?.read())
            .get_header(header)
            .unwrap_or_default())
    }

    #[doc(hidden)]
    #[rhai_fn(name = "get_header", return_raw)]
    pub fn get_header_obj(ncc: NativeCallContext, header: SharedObject) -> EngineResult<String> {
        get_header(ncc, &header.to_string())
    }

    /// Get a list of all headers.
    ///
    /// # Return
    ///
    /// * `array` - all of the headers found in the message.
    ///
    /// # Effective smtp stage
    ///
    /// All of them, although it is most useful in the `preq` stage because this
    /// is when the email body is received.
    ///
    /// # Examples
    ///
    /// ```
    /// # let msg = r#"
    /// X-My-Header: 250 foo
    /// Subject: Unit test are cool
    ///
    /// Hello world!
    /// # "#
    /// ; // .eml ends here
    /// # let msg = vsmtp_mail_parser::MessageBody::try_from(msg[1..].replace("\n", "\r\n").as_str()).unwrap();
    ///
    /// # let states = vsmtp_test::vsl::run_with_msg(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///   preq: [
    ///     rule "display headers" || {
    ///         log("info", `header: ${get_all_headers}`);
    ///     }
    ///   ]
    /// }
    /// # "#)?.build()), Some(msg));
    /// ```
    #[rhai_fn(name = "get_all_headers", return_raw)]
    pub fn get_all_headers(ncc: NativeCallContext) -> EngineResult<rhai::Array> {
        Ok(vsl_guard_ok!(get_global!(ncc, msg)?.read())
            .inner()
            .raw_headers()
            .iter()
            .map(|raw| rhai::Dynamic::from(raw.clone()))
            .collect())
    }

    /// Get a list of all values of a specific header from the incoming message.
    ///
    /// # Args
    ///
    /// * `header` - the name of the header to search.
    ///
    /// # Return
    ///
    /// * `array` - all header values, or an empty array if the header was not found.
    ///
    /// # Effective smtp stage
    ///
    /// All of them, although it is most useful in the `preq` stage because this
    /// is when the email body is received.
    ///
    /// # Examples
    ///
    /// ```
    /// # let msg = r#"
    /// X-My-Header: 250 foo
    /// Subject: Unit test are cool
    ///
    /// Hello world!
    /// # "#
    /// ; // .eml ends here
    /// # let msg = vsmtp_mail_parser::MessageBody::try_from(msg[1..].replace("\n", "\r\n").as_str()).unwrap();
    ///
    /// # let states = vsmtp_test::vsl::run_with_msg(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     postq: [
    ///         action "display return path" || {
    ///             log("info", msg::get_all_headers("Return-Path"));
    ///         }
    ///     ],
    /// }
    /// # "#)?.build()), Some(msg));
    /// ```
    #[rhai_fn(name = "get_all_headers", return_raw)]
    pub fn get_all_headers_str(ncc: NativeCallContext, name: &str) -> EngineResult<rhai::Array> {
        super::Impl::get_all_headers(&get_global!(ncc, msg)?, name)
    }

    #[doc(hidden)]
    #[rhai_fn(name = "get_all_headers", return_raw)]
    pub fn get_all_headers_obj(
        ncc: NativeCallContext,
        name: SharedObject,
    ) -> EngineResult<rhai::Array> {
        super::Impl::get_all_headers(&get_global!(ncc, msg)?, &name.to_string())
    }

    /// Get a list of all headers of a specific name with it's name and value
    /// separated by a column.
    ///
    /// # Args
    ///
    /// * `header` - the name of the header to search.
    ///
    /// # Return
    ///
    /// * `array` - all header values, or an empty array if the header was not found.
    ///
    /// # Effective smtp stage
    ///
    /// All of them, although it is most useful in the `preq` stage because this
    /// is when the email body is received.
    ///
    /// # Examples
    ///
    /// ```
    /// # let msg = r#"
    /// X-My-Header: 250 foo
    /// Subject: Unit test are cool
    ///
    /// Hello world!
    /// # "#
    /// ; // .eml ends here
    /// # let msg = vsmtp_mail_parser::MessageBody::try_from(msg[1..].replace("\n", "\r\n").as_str()).unwrap();
    ///
    /// # let states = vsmtp_test::vsl::run_with_msg(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     postq: [
    ///         action "display return path" || {
    ///             // Will display "Return-Path: value".
    ///             log("info", msg::get_header_untouched("Return-Path"));
    ///         }
    ///     ],
    /// }
    /// # "#)?.build()), Some(msg));
    /// ```
    #[rhai_fn(return_raw)]
    pub fn get_header_untouched(ncc: NativeCallContext, name: &str) -> EngineResult<rhai::Array> {
        super::Impl::get_header_untouched(&get_global!(ncc, msg)?, name)
    }

    /// Add a new header **at the end** of the header list in the message.
    ///
    /// # Args
    ///
    /// * `header` - the name of the header to append.
    /// * `value` - the value of the header to append.
    ///
    /// # Effective smtp stage
    ///
    /// All of them. Even though the email is not received at the current stage,
    /// vsmtp stores new headers and will add them on top of the ones received once
    /// the `preq` stage is reached.
    ///
    /// # Examples
    ///
    /// ```
    /// # let msg = vsmtp_mail_parser::MessageBody::try_from(concat!(
    /// "X-My-Header: 250 foo\r\n",
    /// "Subject: Unit test are cool\r\n",
    /// "\r\n",
    /// "Hello world!\r\n",
    /// # )).unwrap();
    /// # let rules = r#"
    /// #{
    ///   preq: [
    ///     rule "append_header" || {
    ///       msg::append_header("X-My-Header-2", "bar");
    ///       msg::append_header("X-My-Header-3", identifier("baz"));
    ///     }
    ///   ]
    /// }
    /// # "#;
    /// # let states = vsmtp_test::vsl::run_with_msg(|builder| Ok(builder
    /// #   .add_root_filter_rules("#{}")?
    /// #      .add_domain_rules("testserver.com".parse().unwrap())
    /// #        .with_incoming(rules)?
    /// #        .with_outgoing(rules)?
    /// #        .with_internal(rules)?
    /// #      .build()
    /// #   .build()), Some(msg));
    /// # assert_eq!(*states[&vsmtp_rule_engine::ExecutionStage::PreQ].1.inner().raw_headers(), vec![
    /// #   "X-My-Header: 250 foo\r\n".to_string(),
    /// #   "Subject: Unit test are cool\r\n".to_string(),
    /// #   "X-My-Header-2: bar\r\n".to_string(),
    /// #   "X-My-Header-3: baz\r\n".to_string(),
    /// # ]);
    /// ```
    #[rhai_fn(name = "append_header", return_raw)]
    pub fn append_header(ncc: NativeCallContext, header: &str, value: &str) -> EngineResult<()> {
        super::Impl::append_header(&get_global!(ncc, msg)?, &header, &value)
    }

    #[doc(hidden)]
    #[rhai_fn(name = "append_header", return_raw)]
    pub fn append_header_str_obj(
        ncc: NativeCallContext,
        header: &str,
        value: SharedObject,
    ) -> EngineResult<()> {
        super::Impl::append_header(&get_global!(ncc, msg)?, &header, &value.to_string())
    }

    /// Add a new header on top all other headers in the message.
    ///
    /// # Args
    ///
    /// * `header` - the name of the header to prepend.
    /// * `value` - the value of the header to prepend.
    ///
    /// # Effective smtp stage
    ///
    /// All of them. Even though the email is not received at the current stage,
    /// vsmtp stores new headers and will add them on top of the ones received once
    /// the `preq` stage is reached.
    ///
    /// # Examples
    ///
    /// ```
    /// # let msg = vsmtp_mail_parser::MessageBody::try_from(concat!(
    /// "X-My-Header: 250 foo\r\n",
    /// "Subject: Unit test are cool\r\n",
    /// "\r\n",
    /// "Hello world!\r\n",
    /// # )).unwrap();
    /// # let rules = r#"
    /// #{
    ///   preq: [
    ///     rule "prepend_header" || {
    ///       msg::prepend_header("X-My-Header-2", "bar");
    ///       msg::prepend_header("X-My-Header-3", identifier("baz"));
    ///     }
    ///   ]
    /// }
    /// # "#;
    /// # let states = vsmtp_test::vsl::run_with_msg(|builder| Ok(builder
    /// #   .add_root_filter_rules("#{}")?
    /// #      .add_domain_rules("testserver.com".parse().unwrap())
    /// #        .with_incoming(rules)?
    /// #        .with_outgoing(rules)?
    /// #        .with_internal(rules)?
    /// #      .build()
    /// #   .build()), Some(msg));
    /// # assert_eq!(*states[&vsmtp_rule_engine::ExecutionStage::PreQ].1.inner().raw_headers(), vec![
    /// #   "X-My-Header-3: baz\r\n".to_string(),
    /// #   "X-My-Header-2: bar\r\n".to_string(),
    /// #   "X-My-Header: 250 foo\r\n".to_string(),
    /// #   "Subject: Unit test are cool\r\n".to_string(),
    /// # ]);
    /// ```
    #[rhai_fn(name = "prepend_header", return_raw)]
    pub fn prepend_header(ncc: NativeCallContext, header: &str, value: &str) -> EngineResult<()> {
        super::Impl::prepend_header(&get_global!(ncc, msg)?, header, value)
    }

    #[doc(hidden)]
    #[rhai_fn(name = "prepend_header", return_raw)]
    pub fn prepend_header_str_obj(
        ncc: NativeCallContext,
        header: &str,
        value: SharedObject,
    ) -> EngineResult<()> {
        super::Impl::prepend_header(&get_global!(ncc, msg)?, header, &value.to_string())
    }

    /// Replace an existing header value by a new value, or append a new header
    /// to the message.
    ///
    /// # Args
    ///
    /// * `header` - the name of the header to set or add.
    /// * `value` - the value of the header to set or add.
    ///
    /// # Effective smtp stage
    ///
    /// All of them. Even though the email is not received at the current stage,
    /// vsmtp stores new headers and will add them on top to the ones received once
    /// the `preq` stage is reached.
    ///
    /// Be aware that if you want to set a header value from the original message,
    /// you must use `set_header` in the `preq` stage and onwards.
    ///
    /// # Examples
    ///
    /// ```
    /// # let msg = vsmtp_mail_parser::MessageBody::try_from(concat!(
    /// "Subject: The initial header value\r\n",
    /// "\r\n",
    /// "Hello world!\r\n",
    /// # )).unwrap();
    /// # let rules = r#"
    /// #{
    ///   preq: [
    ///     rule "set_header" || {
    ///       msg::set_header("Subject", "The header value has been updated");
    ///       msg::set_header("Subject", identifier("The header value has been updated again"));
    ///       state::accept(`250 ${msg::get_header("Subject")}`);
    ///     }
    ///   ]
    /// }
    /// # "#;
    /// # let states = vsmtp_test::vsl::run_with_msg(|builder| Ok(builder
    /// #   .add_root_filter_rules("#{}")?
    /// #      .add_domain_rules("testserver.com".parse().unwrap())
    /// #        .with_incoming(rules)?
    /// #        .with_outgoing(rules)?
    /// #        .with_internal(rules)?
    /// #      .build()
    /// #   .build()), Some(msg));
    /// # use vsmtp_common::{status::Status, CodeID, Reply, ReplyCode::Code};
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::PreQ].2, Status::Accept(either::Right(
    /// #  "250 The header value has been updated again\r\n".parse().unwrap()
    /// # )));
    /// ```
    #[rhai_fn(name = "set_header", return_raw)]
    pub fn set_header(ncc: NativeCallContext, header: &str, value: &str) -> EngineResult<()> {
        super::Impl::set_header(&get_global!(ncc, msg)?, header, value)
    }

    #[doc(hidden)]
    #[rhai_fn(name = "set_header", return_raw)]
    pub fn set_header_str_obj(
        ncc: NativeCallContext,
        header: &str,
        value: SharedObject,
    ) -> EngineResult<()> {
        super::Impl::set_header(&get_global!(ncc, msg)?, header, &value.to_string())
    }

    /// Replace an existing header name by a new value.
    ///
    /// # Args
    ///
    /// * `old` - the name of the header to rename.
    /// * `new` - the new new of the header.
    ///
    /// # Effective smtp stage
    ///
    /// All of them, although it is most useful in the `preq` stage because this
    /// is when the email body is received.
    ///
    /// # Examples
    ///
    /// ```
    /// # let msg = vsmtp_mail_parser::MessageBody::try_from(concat!(
    /// "Subject: The initial header value\r\n",
    /// "\r\n",
    /// "Hello world!\r\n",
    /// # )).unwrap();
    ///
    /// # let rules = r#"
    /// #{
    ///   preq: [
    ///     rule "rename_header" || {
    ///       msg::rename_header("Subject", "bob");
    ///       if msg::has_header("Subject") { return state::deny(); }
    ///
    ///       msg::rename_header("bob", identifier("Subject"));
    ///       if msg::has_header("bob") { return state::deny(); }
    ///
    ///       msg::rename_header(identifier("Subject"), "foo");
    ///       if msg::has_header("Subject") { return state::deny(); }
    ///
    ///       msg::rename_header(identifier("foo"), identifier("Subject"));
    ///       if msg::has_header("foo") { return state::deny(); }
    ///
    ///       state::accept(`250 ${msg::get_header("Subject")}`);
    ///     }
    ///   ]
    /// }
    /// # "#;
    /// # let states = vsmtp_test::vsl::run_with_msg(|builder| Ok(builder
    /// #   .add_root_filter_rules("#{}")?
    /// #      .add_domain_rules("testserver.com".parse().unwrap())
    /// #        .with_incoming(rules)?
    /// #        .with_outgoing(rules)?
    /// #        .with_internal(rules)?
    /// #      .build()
    /// #   .build()), Some(msg));
    /// # use vsmtp_common::{status::Status, CodeID, Reply, ReplyCode::Code};
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::PreQ].2, Status::Accept(either::Right(
    /// #  "250 The initial header value\r\n".parse().unwrap()
    /// # )));
    /// ```
    #[rhai_fn(name = "rename_header", return_raw)]
    pub fn rename_header(ncc: NativeCallContext, old: &str, new: &str) -> EngineResult<()> {
        super::Impl::rename_header(&get_global!(ncc, msg)?, old, new)
    }

    #[doc(hidden)]
    #[rhai_fn(name = "rename_header", return_raw)]
    pub fn rename_header_str_obj(
        ncc: NativeCallContext,
        old: &str,
        new: SharedObject,
    ) -> EngineResult<()> {
        super::Impl::rename_header(&get_global!(ncc, msg)?, old, &new.to_string())
    }

    #[doc(hidden)]
    #[rhai_fn(name = "rename_header", return_raw)]
    pub fn rename_header_obj_str(
        ncc: NativeCallContext,
        old: SharedObject,
        new: &str,
    ) -> EngineResult<()> {
        super::Impl::rename_header(&get_global!(ncc, msg)?, &old.to_string(), new)
    }

    #[doc(hidden)]
    #[rhai_fn(name = "rename_header", return_raw)]
    pub fn rename_header_obj_obj(
        ncc: NativeCallContext,
        old: SharedObject,
        new: SharedObject,
    ) -> EngineResult<()> {
        super::Impl::rename_header(&get_global!(ncc, msg)?, &old.to_string(), &new.to_string())
    }

    /// Get a copy of the whole email as a string.
    ///
    /// # Effective smtp stage
    ///
    /// `preq` and onwards.
    ///
    /// # Example
    ///
    /// ```
    /// # vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     postq: [
    ///        action "display email content" || log("trace", `email content: ${msg::mail()}`),
    ///     ]
    /// }
    /// # "#)?.build()));
    /// ```
    #[rhai_fn(name = "mail", return_raw)]
    pub fn mail(ncc: NativeCallContext) -> EngineResult<String> {
        Ok(vsl_guard_ok!(get_global!(ncc, msg)?.read())
            .inner()
            .to_string())
    }

    /// Remove an existing header from the message.
    ///
    /// # Args
    ///
    /// * `header` - the name of the header to remove.
    ///
    /// # Return
    ///
    /// * a boolean value, true if a header has been removed, false otherwise.
    ///
    /// # Effective smtp stage
    ///
    /// All of them, although it is most useful in the `preq` stage because this
    /// is when the email body is received.
    ///
    /// # Examples
    ///
    /// ```
    /// # let msg = vsmtp_mail_parser::MessageBody::try_from(concat!(
    /// "Subject: The initial header value\r\n",
    /// "\r\n",
    /// "Hello world!\r\n",
    /// # )).unwrap();
    /// # let rules = r#"
    /// #{
    ///   preq: [
    ///     rule "remove_header" || {
    ///       msg::rm_header("Subject");
    ///       if msg::has_header("Subject") { return state::deny(); }
    ///
    ///       msg::prepend_header("Subject-2", "Rust is good");
    ///       msg::rm_header(identifier("Subject-2"));
    ///
    ///       msg::prepend_header("Subject-3", "Rust is good !!!!!");
    ///
    ///       state::accept(`250 ${msg::get_header("Subject-3")}`);
    ///     }
    ///   ]
    /// }
    /// # "#;
    /// # let states = vsmtp_test::vsl::run_with_msg(|builder| Ok(builder
    /// #   .add_root_filter_rules("#{}")?
    /// #      .add_domain_rules("testserver.com".parse().unwrap())
    /// #        .with_incoming(rules)?
    /// #        .with_outgoing(rules)?
    /// #        .with_internal(rules)?
    /// #      .build()
    /// #   .build()), Some(msg));
    /// # use vsmtp_common::{ status::Status, CodeID, Reply, ReplyCode::Code};
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::PreQ].2, Status::Accept(either::Right(
    /// #  "250 Rust is good !!!!!\r\n".parse().unwrap()
    /// # )));
    /// ```
    #[rhai_fn(name = "rm_header", return_raw)]
    pub fn remove_header(ncc: NativeCallContext, header: &str) -> EngineResult<bool> {
        super::Impl::remove_header(&get_global!(ncc, msg)?, header)
    }

    #[doc(hidden)]
    #[rhai_fn(name = "rm_header", return_raw)]
    pub fn remove_header_obj(ncc: NativeCallContext, header: SharedObject) -> EngineResult<bool> {
        super::Impl::remove_header(&get_global!(ncc, msg)?, &header.to_string())
    }

    /// Change the sender's address in the `From` header of the message.
    ///
    /// # Args
    ///
    /// * `new_addr` - the new sender address to set.
    ///
    /// # Effective smtp stage
    ///
    /// `preq` and onwards.
    ///
    /// # Examples
    ///
    ///```
    /// # vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     preq: [
    ///        action "replace sender" || msg::rw_mail_from("john.server@example.com"),
    ///     ]
    /// }
    /// # "#)?.build()));
    /// ```
    #[rhai_fn(name = "rw_mail_from", return_raw)]
    pub fn rewrite_mail_from_message_str(
        ncc: NativeCallContext,
        new_addr: &str,
    ) -> EngineResult<()> {
        super::Impl::rewrite_mail_from_message(&get_global!(ncc, msg)?, new_addr)
    }

    #[doc(hidden)]
    #[rhai_fn(name = "rw_mail_from", return_raw)]
    pub fn rewrite_mail_from_message_obj(
        ncc: NativeCallContext,
        new_addr: SharedObject,
    ) -> EngineResult<()> {
        super::Impl::rewrite_mail_from_message(&get_global!(ncc, msg)?, &new_addr.to_string())
    }

    /// Replace a recipient by an other in the `To` header of the message.
    ///
    /// # Args
    ///
    /// * `old_addr` - the recipient to replace.
    /// * `new_addr` - the new address to use when replacing `old_addr`.
    ///
    /// # Effective smtp stage
    ///
    /// `preq` and onwards.
    ///
    /// # Examples
    ///
    /// ```
    /// # vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     preq: [
    ///        action "rewrite recipient" || msg::rw_rcpt("john.doe@example.com", "john-mta@example.com"),
    ///     ]
    /// }
    /// # "#)?.build()));
    /// ```
    #[rhai_fn(name = "rw_rcpt", return_raw)]
    pub fn rewrite_rcpt_message_str_str(
        ncc: NativeCallContext,
        old_addr: &str,
        new_addr: &str,
    ) -> EngineResult<()> {
        super::Impl::rewrite_rcpt_message(&get_global!(ncc, msg)?, old_addr, new_addr)
    }

    #[doc(hidden)]
    #[rhai_fn(name = "rw_rcpt", return_raw)]
    pub fn rewrite_rcpt_message_obj_str(
        ncc: NativeCallContext,
        old_addr: SharedObject,
        new_addr: &str,
    ) -> EngineResult<()> {
        super::Impl::rewrite_rcpt_message(&get_global!(ncc, msg)?, &old_addr.to_string(), new_addr)
    }

    #[doc(hidden)]
    #[rhai_fn(name = "rw_rcpt", return_raw)]
    pub fn rewrite_rcpt_message_str_obj(
        ncc: NativeCallContext,
        old_addr: &str,
        new_addr: SharedObject,
    ) -> EngineResult<()> {
        super::Impl::rewrite_rcpt_message(&get_global!(ncc, msg)?, old_addr, &new_addr.to_string())
    }

    #[doc(hidden)]
    #[rhai_fn(name = "rw_rcpt", return_raw)]
    pub fn rewrite_rcpt_message_obj_obj(
        ncc: NativeCallContext,
        old_addr: SharedObject,
        new_addr: SharedObject,
    ) -> EngineResult<()> {
        super::Impl::rewrite_rcpt_message(
            &get_global!(ncc, msg)?,
            &old_addr.to_string(),
            &new_addr.to_string(),
        )
    }

    /// Add a recipient to the `To` header of the message.
    ///
    /// # Args
    ///
    /// * `addr` - the recipient address to add to the `To` header.
    ///
    /// # Effective smtp stage
    ///
    /// `preq` and onwards.
    ///
    /// # Examples
    ///
    /// ```
    /// # vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     preq: [
    ///        action "update recipients" || msg::add_rcpt("john.doe@example.com"),
    ///     ]
    /// }
    /// # "#)?.build()));
    /// ```
    #[rhai_fn(name = "add_rcpt", return_raw)]
    pub fn add_rcpt_message_str(ncc: NativeCallContext, new_addr: &str) -> EngineResult<()> {
        super::Impl::add_rcpt_message(&get_global!(ncc, msg)?, new_addr)
    }

    #[doc(hidden)]
    #[rhai_fn(name = "add_rcpt", return_raw)]
    pub fn add_rcpt_message_obj(
        ncc: NativeCallContext,
        new_addr: SharedObject,
    ) -> EngineResult<()> {
        super::Impl::add_rcpt_message(&get_global!(ncc, msg)?, &new_addr.to_string())
    }

    /// Remove a recipient from the `To` header of the message.
    ///
    /// # Args
    ///
    /// * `addr` - the recipient to remove to the `To` header.
    ///
    /// # Effective smtp stage
    ///
    /// `preq` and onwards.
    ///
    /// # Examples
    ///
    /// ```
    /// # vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     preq: [
    ///        action "update recipients" || msg::rm_rcpt("john.doe@example.com"),
    ///     ]
    /// }
    /// # "#)?.build()));
    /// ```
    #[rhai_fn(name = "rm_rcpt", return_raw)]
    pub fn remove_rcpt_message_str(ncc: NativeCallContext, addr: &str) -> EngineResult<()> {
        super::Impl::remove_rcpt_message(&get_global!(ncc, msg)?, addr)
    }

    #[doc(hidden)]
    #[rhai_fn(name = "rm_rcpt", return_raw)]
    pub fn remove_rcpt_message_obj(ncc: NativeCallContext, addr: SharedObject) -> EngineResult<()> {
        super::Impl::remove_rcpt_message(&get_global!(ncc, msg)?, &addr.to_string())
    }
}

pub(super) struct Impl;

impl Impl {
    pub fn get_all_headers(message: &Message, name: &str) -> EngineResult<rhai::Array> {
        Ok(vsl_guard_ok!(message.read())
            .inner()
            .headers()
            .into_iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| rhai::Dynamic::from(value))
            .collect())
    }

    pub fn get_header_untouched(msg: &Message, name: &str) -> EngineResult<rhai::Array> {
        Ok(vsl_guard_ok!(msg.read())
            .inner()
            .headers()
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(key, value)| rhai::Dynamic::from(format!("{key}:{value}")))
            .collect::<Vec<_>>())
    }

    pub fn count_header<T>(message: &Message, header: &T) -> EngineResult<rhai::INT>
    where
        T: AsRef<str> + ?Sized,
    {
        vsl_guard_ok!(message.read())
            .count_header(header.as_ref())
            .try_into()
            .map_err::<Box<rhai::EvalAltResult>, _>(|_| "header count overflowed".into())
    }

    pub fn append_header<T, U>(message: &Message, header: &T, value: &U) -> EngineResult<()>
    where
        T: AsRef<str> + ?Sized,
        U: AsRef<str> + ?Sized,
    {
        vsl_guard_ok!(message.write()).append_header(header.as_ref(), value.as_ref());
        Ok(())
    }

    pub fn prepend_header<T, U>(message: &Message, header: &T, value: &U) -> EngineResult<()>
    where
        T: AsRef<str> + ?Sized,
        U: AsRef<str> + ?Sized,
    {
        vsl_guard_ok!(message.write()).prepend_header(header.as_ref(), value.as_ref());
        Ok(())
    }

    pub fn set_header<T, U>(message: &Message, header: &T, value: &U) -> EngineResult<()>
    where
        T: AsRef<str> + ?Sized,
        U: AsRef<str> + ?Sized,
    {
        vsl_guard_ok!(message.write()).set_header(header.as_ref(), value.as_ref());
        Ok(())
    }

    pub fn rename_header<T, U>(message: &Message, old: &T, new: &U) -> EngineResult<()>
    where
        T: AsRef<str> + ?Sized,
        U: AsRef<str> + ?Sized,
    {
        vsl_guard_ok!(message.write()).rename_header(old.as_ref(), new.as_ref());
        Ok(())
    }

    pub fn remove_header<T>(message: &Message, header: &T) -> EngineResult<bool>
    where
        T: AsRef<str> + ?Sized,
    {
        Ok(vsl_guard_ok!(message.write()).remove_header(header.as_ref()))
    }

    fn rewrite_mail_from_message(message: &Message, new_addr: &str) -> EngineResult<()> {
        let new_addr = vsl_conversion_ok!(
            "address",
            <Address as std::str::FromStr>::from_str(new_addr)
        );

        let mut writer = vsl_guard_ok!(message.write());
        vsl_parse_ok!(writer).rewrite_mail_from(new_addr.full());

        Ok(())
    }

    fn rewrite_rcpt_message(message: &Message, old_addr: &str, new_addr: &str) -> EngineResult<()> {
        let new_addr = vsl_conversion_ok!(
            "address",
            <Address as std::str::FromStr>::from_str(new_addr)
        );
        let old_addr = vsl_conversion_ok!(
            "address",
            <Address as std::str::FromStr>::from_str(old_addr)
        );

        let mut writer = vsl_guard_ok!(message.write());
        vsl_parse_ok!(writer).rewrite_rcpt(old_addr.full(), new_addr.full());
        Ok(())
    }

    fn add_rcpt_message(message: &Message, new_addr: &str) -> EngineResult<()> {
        let new_addr = vsl_conversion_ok!(
            "address",
            <Address as std::str::FromStr>::from_str(new_addr)
        );

        let mut writer = vsl_guard_ok!(message.write());
        vsl_parse_ok!(writer).add_rcpt(new_addr.full());
        Ok(())
    }

    fn remove_rcpt_message(message: &Message, addr: &str) -> EngineResult<()> {
        let addr = vsl_conversion_ok!("address", <Address as std::str::FromStr>::from_str(addr));

        let mut writer = vsl_guard_ok!(message.write());
        vsl_parse_ok!(writer).remove_rcpt(addr.full());
        Ok(())
    }
}
