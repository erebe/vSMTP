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

use crate::api::SharedObject;
use rhai::plugin::{
    Dynamic, FnAccess, FnNamespace, Module, NativeCallContext, PluginFunction, RhaiResult, TypeId,
};

pub use code::*;

/// Predefined codes for SMTP responses.
#[rhai::plugin::export_module]
mod code {
    use vsmtp_plugin_vsl::objects::constructors::code_enhanced;

    /// Return a relay access denied code.
    ///
    /// # Example
    ///
    /// ```
    /// # // Returning a access denied code in mail stage is stupid, but it works as an example.
    /// # // Could not make it work at the rcpt stage.
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     mail: [
    ///         // Will send "554 5.7.1 Relay access denied" to the client.
    ///         rule "anti relay" || { state::deny(code::c554_7_1()) }
    ///     ]
    /// }
    /// # "#)?.build()));
    /// # use vsmtp_common::{status::Status, CodeID, Reply, ReplyCode::Enhanced};
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::MailFrom].2, Status::Deny(either::Right(Reply::new(
    /// #  Enhanced { code: 554, enhanced: "5.7.1".to_string() }, "Relay access denied".to_string(),
    /// # ))));
    /// ```
    #[must_use]
    #[rhai_fn(name = "c554_7_1")]
    pub fn c554_7_1() -> SharedObject {
        code_enhanced(554, "5.7.1", "Relay access denied").expect("valid code")
    }

    /// Return a DKIM Failure code. (RFC 6376)
    /// DKIM signature not found.
    ///
    /// # Example
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     mail: [
    ///         // Will send "550 5.7.20 No passing DKIM signature found" to the client.
    ///         rule "deny with code" || { state::deny(code::c550_7_20()) }
    ///     ]
    /// }
    /// # "#)?.build()));
    /// # use vsmtp_common::{status::Status, CodeID, Reply, ReplyCode::Enhanced};
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::MailFrom].2, Status::Deny(either::Right(Reply::new(
    /// #  Enhanced { code: 550, enhanced: "5.7.20".to_string() }, "No passing DKIM signature found".to_string(),
    /// # ))));
    /// ```
    #[must_use]
    #[rhai_fn(name = "c550_7_20")]
    pub fn c550_7_20() -> SharedObject {
        code_enhanced(550, "5.7.20", "No passing DKIM signature found").expect("valid code")
    }

    /// Return a DKIM Failure code. (RFC 6376)
    /// No acceptable DKIM signature found.
    ///
    /// # Example
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     mail: [
    ///         // Will send "550 5.7.21 No acceptable DKIM signature found" to the client.
    ///         rule "deny with code" || { state::deny(code::c550_7_21()) }
    ///     ]
    /// }
    /// # "#)?.build()));
    /// # use vsmtp_common::{status::Status, CodeID, Reply, ReplyCode::Enhanced};
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::MailFrom].2, Status::Deny(either::Right(Reply::new(
    /// #  Enhanced { code: 550, enhanced: "5.7.21".to_string() }, "No acceptable DKIM signature found".to_string(),
    /// # ))));
    /// ```
    #[must_use]
    #[rhai_fn(name = "c550_7_21")]
    pub fn c550_7_21() -> SharedObject {
        code_enhanced(550, "5.7.21", "No acceptable DKIM signature found").expect("valid code")
    }

    /// Return a DKIM Failure code. (RFC 6376)
    /// No valid author matched DKIM signature found.
    ///
    /// # Example
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     mail: [
    ///         // Will send "550 5.7.22 No valid author-matched DKIM signature found" to the client.
    ///         rule "deny with code" || { state::deny(code::c550_7_22()) }
    ///     ]
    /// }
    /// # "#)?.build()));
    /// # use vsmtp_common::{status::Status, CodeID, Reply, ReplyCode::Enhanced};
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::MailFrom].2, Status::Deny(either::Right(Reply::new(
    /// #  Enhanced { code: 550, enhanced: "5.7.22".to_string() }, "No valid author-matched DKIM signature found".to_string(),
    /// # ))));
    /// ```
    #[must_use]
    #[rhai_fn(name = "c550_7_22")]
    pub fn c550_7_22() -> SharedObject {
        code_enhanced(
            550,
            "5.7.22",
            "No valid author-matched DKIM signature found",
        )
        .expect("valid code")
    }

    /// Return a SPF Failure code. (RFC 7208)
    /// Validation failed.
    ///
    /// # Example
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     mail: [
    ///         // Will send "550 5.7.23 SPF validation failed" to the client.
    ///         rule "deny with code" || { state::deny(code::c550_7_23()) }
    ///     ]
    /// }
    /// # "#)?.build()));
    /// # use vsmtp_common::{status::Status, CodeID, Reply, ReplyCode::Enhanced};
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::MailFrom].2, Status::Deny(either::Right(Reply::new(
    /// #  Enhanced { code: 550, enhanced: "5.7.23".to_string() }, "SPF validation failed".to_string(),
    /// # ))));
    /// ```
    #[must_use]
    #[rhai_fn(name = "c550_7_23")]
    pub fn c550_7_23() -> SharedObject {
        code_enhanced(550, "5.7.23", "SPF validation failed").expect("valid code")
    }

    /// Return a SPF Failure code. (RFC 7208)
    /// Validation error.
    ///
    /// # Example
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     mail: [
    ///         // Will send "550 5.7.24 SPF validation error" to the client.
    ///         rule "deny with code" || { state::deny(code::c550_7_24()) }
    ///     ]
    /// }
    /// # "#)?.build()));
    /// # use vsmtp_common::{status::Status, CodeID, Reply, ReplyCode::Enhanced};
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::MailFrom].2, Status::Deny(either::Right(Reply::new(
    /// #  Enhanced { code: 550, enhanced: "5.7.24".to_string() }, "SPF validation error".to_string(),
    /// # ))));
    /// ```
    #[must_use]
    #[rhai_fn(name = "c550_7_24")]
    pub fn c550_7_24() -> SharedObject {
        code_enhanced(550, "5.7.24", "SPF validation error").expect("valid code")
    }

    /// Return a reverse DNS Failure code.
    ///
    /// # Example
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     mail: [
    ///         // Will send "550 5.7.25 Reverse DNS validation failed" to the client.
    ///         rule "deny with code" || { state::deny(code::c550_7_25()) }
    ///     ]
    /// }
    /// # "#)?.build()));
    /// # use vsmtp_common::{status::Status, CodeID, Reply, ReplyCode::Enhanced};
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::MailFrom].2, Status::Deny(either::Right(Reply::new(
    /// #  Enhanced { code: 550, enhanced: "5.7.25".to_string() }, "Reverse DNS validation failed".to_string(),
    /// # ))));
    /// ```
    #[must_use]
    #[rhai_fn(name = "c550_7_25")]
    pub fn c550_7_25() -> SharedObject {
        code_enhanced(550, "5.7.25", "Reverse DNS validation failed").expect("valid code")
    }

    /// Return a multiple authentication failures code.
    ///
    /// # Example
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     mail: [
    ///         // Will send "500 5.7.26 Multiple authentication checks failed" to the client.
    ///         rule "deny with code" || { state::deny(code::c500_7_26()) }
    ///     ]
    /// }
    /// # "#)?.build()));
    /// # use vsmtp_common::{status::Status, CodeID, Reply, ReplyCode::Enhanced};
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::MailFrom].2, Status::Deny(either::Right(Reply::new(
    /// #  Enhanced { code: 500, enhanced: "5.7.26".to_string() }, "Multiple authentication checks failed".to_string(),
    /// # ))));
    /// ```
    #[must_use]
    #[rhai_fn(name = "c500_7_26")]
    pub fn c550_7_26() -> SharedObject {
        code_enhanced(500, "5.7.26", "Multiple authentication checks failed").expect("valid code")
    }

    /// Return a Null MX cod. (RFC 7505)
    /// The sender address has a null MX record.
    ///
    /// # Example
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     mail: [
    ///         // Will send "550 5.7.27 Sender address has null MX" to the client.
    ///         rule "deny with code" || { state::deny(code::c550_7_27()) }
    ///     ]
    /// }
    /// # "#)?.build()));
    /// # use vsmtp_common::{status::Status, CodeID, Reply, ReplyCode::Enhanced};
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::MailFrom].2, Status::Deny(either::Right(Reply::new(
    /// #  Enhanced { code: 550, enhanced: "5.7.27".to_string() }, "Sender address has null MX".to_string(),
    /// # ))));
    /// ```    
    #[must_use]
    #[rhai_fn(name = "c550_7_27")]
    pub fn c550_7_27() -> SharedObject {
        code_enhanced(550, "5.7.27", "Sender address has null MX").expect("valid code")
    }

    /// Return a Null MX cod. (RFC 7505)
    /// The recipient address has a null MX record.
    ///
    /// # Example
    ///
    /// ```
    /// # // Returning a access denied code in mail stage is stupid, but it works as an example.
    /// # // Could not make it work at the rcpt stage.
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     mail: [
    ///         // Will send "556 5.1.10 Recipient address has null MX" to the client.
    ///         rule "deny with code" || { state::deny(code::c556_1_10()) }
    ///     ]
    /// }
    /// # "#)?.build()));
    /// # use vsmtp_common::{status::Status, CodeID, Reply, ReplyCode::Enhanced};
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::MailFrom].2, Status::Deny(either::Right(Reply::new(
    /// #  Enhanced { code: 556, enhanced: "5.1.10".to_string() }, "Recipient address has null MX".to_string(),
    /// # ))));
    /// ```
    #[must_use]
    #[rhai_fn(name = "c556_1_10")]
    pub fn c556_1_10() -> SharedObject {
        code_enhanced(556, "5.1.10", "Recipient address has null MX").expect("valid code")
    }

    /// Return a greylisting code (<https://www.rfc-editor.org/rfc/rfc6647.html#section-2.1>)
    ///
    /// # Example
    ///
    /// ```
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     mail: [
    ///         // Will send "451 4.7.1 Sender is not authorized. Please try again." to the client.
    ///         rule "deny with code" || { state::deny(code::c451_7_1()) }
    ///     ]
    /// }
    /// # "#)?.build()));
    /// # use vsmtp_common::{status::Status, CodeID, Reply, ReplyCode::Enhanced};
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::MailFrom].2, Status::Deny(either::Right(Reply::new(
    /// #  Enhanced { code: 451, enhanced: "4.7.1".to_string() }, "Sender is not authorized. Please try again.".to_string(),
    /// # ))));
    /// ```
    #[must_use]
    #[rhai_fn(name = "c451_7_1")]
    pub fn greylist() -> SharedObject {
        code_enhanced(451, "4.7.1", "Sender is not authorized. Please try again.")
            .expect("valid code")
    }

    /// Multiple destination domains per transaction is unsupported code.
    ///
    /// # Example
    ///
    /// ```
    /// # // Returning a access denied code in mail stage is stupid, but it works as an example.
    /// # // Could not make it work at the rcpt stage.
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     mail: [
    ///         // Will send "451 4.3.0 Multiple destination domains per transaction is unsupported. Please try again." to the client.
    ///         rule "deny with code" || { state::deny(code::c451_3_0()) }
    ///     ]
    /// }
    /// # "#)?.build()));
    /// # use vsmtp_common::{status::Status, CodeID, Reply, ReplyCode::Enhanced};
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::MailFrom].2, Status::Deny(either::Right(Reply::new(
    /// #  Enhanced { code: 451, enhanced: "4.3.0".to_string() }, "Multiple destination domains per transaction is unsupported. Please try again.".to_string(),
    /// # ))));
    /// ```
    #[must_use]
    #[rhai_fn(name = "c451_3_0")]
    pub fn multi_destination() -> SharedObject {
        code_enhanced(
            451,
            "4.3.0",
            "Multiple destination domains per transaction is unsupported. Please try again.",
        )
        .expect("valid code")
    }

    /// Multiple destination domains per transaction is unsupported code.
    ///
    /// # Example
    ///
    /// ```
    /// # // Returning a access denied code in mail stage is stupid, but it works as an example.
    /// # // Could not make it work at the rcpt stage.
    /// # let states = vsmtp_test::vsl::run(
    /// # |builder| Ok(builder.add_root_filter_rules(r#"
    /// #{
    ///     mail: [
    ///         // Will send "550 5.1.1 No passing DKIM signature found" to the client.
    ///         rule "deny with code" || { state::deny(code::c550_1_1()) }
    ///     ]
    /// }
    /// # "#)?.build()));
    /// # use vsmtp_common::{status::Status, CodeID, Reply, ReplyCode::Enhanced};
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::MailFrom].2, Status::Deny(either::Right(Reply::new(
    /// #  Enhanced { code: 550, enhanced: "5.1.1".to_string() }, "The email account that you tried to reach does not exist. Please try again.".to_string(),
    /// # ))));
    /// ```
    #[must_use]
    #[rhai_fn(name = "c550_1_1")]
    pub fn unknown_account() -> SharedObject {
        code_enhanced(
            550,
            "5.1.1",
            "The email account that you tried to reach does not exist. Please try again.",
        )
        .expect("valid code")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes() {
        assert_eq!(
            code::c554_7_1().to_string(),
            "554 5.7.1 Relay access denied".to_string()
        );
        assert_eq!(
            code::c550_7_20().to_string(),
            "550 5.7.20 No passing DKIM signature found".to_string()
        );
        assert_eq!(
            code::c550_7_21().to_string(),
            "550 5.7.21 No acceptable DKIM signature found".to_string()
        );
        assert_eq!(
            code::c550_7_22().to_string(),
            "550 5.7.22 No valid author-matched DKIM signature found".to_string()
        );
        assert_eq!(
            code::c550_7_23().to_string(),
            "550 5.7.23 SPF validation failed".to_string()
        );
        assert_eq!(
            code::c550_7_24().to_string(),
            "550 5.7.24 SPF validation error".to_string()
        );
        assert_eq!(
            code::c550_7_25().to_string(),
            "550 5.7.25 Reverse DNS validation failed".to_string()
        );
        assert_eq!(
            code::c550_7_26().to_string(),
            "500 5.7.26 Multiple authentication checks failed".to_string()
        );
        assert_eq!(
            code::c550_7_27().to_string(),
            "550 5.7.27 Sender address has null MX".to_string()
        );
        assert_eq!(
            code::c556_1_10().to_string(),
            "556 5.1.10 Recipient address has null MX".to_string()
        );
        assert_eq!(
            code::greylist().to_string(),
            "451 4.7.1 Sender is not authorized. Please try again.".to_string()
        );
        assert_eq!(code::multi_destination().to_string(), "451 4.3.0 Multiple destination domains per transaction is unsupported. Please try again.".to_string());
        assert_eq!(
            code::unknown_account().to_string(),
            "550 5.1.1 The email account that you tried to reach does not exist. Please try again."
                .to_string()
        );
    }
}
