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

use crate::api::{Context, EngineResult, Message, Server};
use rhai::plugin::{
    mem, Dynamic, FnAccess, FnNamespace, ImmutableString, Module, NativeCallContext,
    PluginFunction, RhaiResult, TypeId,
};
use vsmtp_auth::dkim::{
    sign, verify, Canonicalization, PrivateKey, PublicKey, Signature, VerificationResult,
    VerifierError,
};
use vsmtp_mail_parser::MessageBody;

pub use dkim_rhai::*;

#[rhai::plugin::export_module]
mod dkim_rhai {

    /// Has the `ctx()` a DKIM signature verification result ?
    #[rhai_fn(global, get = "has_dkim_result", pure, return_raw)]
    pub fn has_dkim_result(ctx: &mut Context) -> EngineResult<bool> {
        let guard = vsl_guard_ok!(ctx.read());
        Ok(guard
            .dkim()
            .map_err::<Box<rhai::EvalAltResult>, _>(|_| "bad state".into())?
            .is_some())
    }

    /// Return the DKIM signature verification result in the `ctx()` or
    /// an error if no result is found.
    #[rhai_fn(global, get = "dkim_result", pure, return_raw)]
    pub fn dkim_result(ctx: &mut Context) -> EngineResult<rhai::Map> {
        let guard = vsl_guard_ok!(ctx.read());

        guard
            .dkim()
            .map_err::<Box<rhai::EvalAltResult>, _>(|_| "bad state".into())?
            .map_or_else(
                || Err("no `dkim_result` available".into()),
                |dkim_result| {
                    Ok(rhai::Map::from_iter([(
                        "status".into(),
                        dkim_result.status.clone().into(),
                    )]))
                },
            )
    }

    /// Store the result produced by the DKIM signature verification in the `ctx()`.
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, pure, return_raw)]
    pub fn store_dkim(ctx: &mut Context, result: rhai::Map) -> EngineResult<()> {
        let mut guard = vsl_guard_ok!(ctx.write());
        let result = VerificationResult {
            status: result
                .get("status")
                .ok_or_else::<Box<rhai::EvalAltResult>, _>(|| {
                    "`status` is missing in DKIM verification result".into()
                })?
                .to_string(),
        };

        guard.set_dkim(result).unwrap();
        Ok(())
    }

    /// get the dkim status from an error produced by this module
    #[rhai_fn(global, return_raw)]
    pub fn handle_dkim_error(err: rhai::Dynamic) -> EngineResult<String> {
        let type_name = err.type_name();
        let map = err
            .try_cast::<rhai::Map>()
            .ok_or_else::<Box<rhai::EvalAltResult>, _>(|| {
                format!("expected a map as error from dkim module, got `{type_name}`").into()
            })?;

        let r#type = map
            .get("type")
            .ok_or_else::<Box<rhai::EvalAltResult>, _>(|| {
                "expected a field `type` in dkim module's error".into()
            })?
            .clone()
            .try_cast::<String>()
            .ok_or_else::<Box<rhai::EvalAltResult>, _>(|| {
                "expected the field `type` to be a `string` in dkim's error".into()
            })?;

        let dkim_error = <DkimErrors as strum::IntoEnumIterator>::iter()
            .find(|i| {
                strum::EnumMessage::get_detailed_message(i)
                    .expect("`DkimErrors` must have a `detailed message` for each variant")
                    == r#type
            })
            .ok_or_else::<Box<rhai::EvalAltResult>, _>(|| {
                format!("unknown `DkimErrors` got: `{type}`").into()
            })?;

        Ok(strum::EnumMessage::get_message(&dkim_error)
            .expect("`DkimErrors` must have a `message` for each variant")
            .to_string())
    }

    /// Get the list of DKIM private keys associated with this sdid
    #[rhai_fn(global, pure)]
    pub fn get_private_keys(server: &mut Server, sdid: &str) -> rhai::Array {
        let dkim = server
            .config
            .server
            .r#virtual
            .get(sdid)
            .map_or_else(|| &server.config.server.dkim, |r#virtual| &r#virtual.dkim);
        dkim.as_ref().map_or_else(Vec::new, |dkim| {
            dkim.private_key
                .iter()
                .map(|key| rhai::Dynamic::from(key.inner.clone()))
                .collect()
        })
    }

    /// return the `sdid` property of the [`Signature`]
    #[rhai_fn(global, get = "sdid", pure)]
    pub fn sdid(signature: &mut Signature) -> String {
        signature.sdid.clone()
    }

    /// return the `auid` property of the [`Signature`]
    #[rhai_fn(global, get = "auid", pure)]
    pub fn auid(signature: &mut Signature) -> String {
        signature.auid.clone()
    }

    /// create a [`Signature`] from a `DKIM-Signature` header
    #[rhai_fn(global, return_raw)]
    pub fn parse_signature(input: &str) -> EngineResult<Signature> {
        super::Impl::parse_signature(input).map_err(Into::into)
    }

    /// Has the signature expired?
    ///
    /// return `true` if the argument are invalid (`epsilon` is negative)
    #[rhai_fn(global, pure)]
    pub fn has_expired(signature: &mut Signature, epsilon: rhai::INT) -> bool {
        epsilon
            .try_into()
            .map_or(true, |epsilon| signature.has_expired(epsilon))
    }

    /// A public key may contains a `debug flag`, used for testing purpose.
    #[rhai_fn(global, pure, get = "has_debug_flag")]
    pub fn has_debug_flag(key: &mut PublicKey) -> bool {
        key.has_debug_flag()
    }

    /// Get the list of public keys associated with this [`Signature`]
    ///
    /// The current implementation will make a TXT query on the dns of the signer
    ///
    /// `on_multiple_key_records` value can be `first` or `cycle` :
    /// * `first` return the first key found (one element array)
    /// * `cycle` return all the keys found
    #[rhai_fn(global, pure, return_raw)]
    pub fn get_public_key(
        server: &mut Server,
        signature: Signature,
        on_multiple_key_records: &str,
    ) -> EngineResult<rhai::Dynamic> {
        super::Impl::get_public_key(server, signature, on_multiple_key_records)
            .map(Into::into)
            .map_err(Into::into)
    }

    /// Operate the hashing of the `message`'s headers and body, and compare the result with the
    /// `signature` and `key` data.
    ///
    /// # Examples
    ///
    /// ```
    /// # let msg = r#"
    /// Received: from github.com (hubbernetes-node-54a15d2.ash1-iad.github.net [10.56.202.84])
    /// 	by smtp.github.com (Postfix) with ESMTPA id 19FB45E0B6B
    /// 	for <mlala@negabit.com>; Wed, 26 Oct 2022 14:30:51 -0700 (PDT)
    /// DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=github.com;
    /// 	s=pf2014; t=1666819851;
    /// 	bh=7gTTczemS/Aahap1SpEnunm4pAPNuUIg7fUzwEx0QUA=;
    /// 	h=Date:From:To:Subject:From;
    /// 	b=eAufMk7uj4R+bO5Nr4DymffdGdbrJNza1+eykatgZED6tBBcMidkMiLSnP8FyVCS9
    /// 	 /GSlXME6/YffAXg4JEBr2lN3PuLIf94S86U3VckuoQQQe1LPtHlnGW5ZwJgi6DjrzT
    /// 	 klht/6Pn1w3a2jdNSDccWhk5qlSOQX9JKnE7UD58=
    /// Date: Wed, 26 Oct 2022 14:30:51 -0700
    /// From: Mathieu Lala <noreply@github.com>
    /// To: mlala@negabit.com
    /// Message-ID: <viridIT/vSMTP/push/refs/heads/test/rule-engine/000000-c6459a@github.com>
    /// Subject: [viridIT/vSMTP] c6459a: test: add test on message
    /// Mime-Version: 1.0
    /// Content-Type: text/plain;
    ///  charset=UTF-8
    /// Content-Transfer-Encoding: 7bit
    /// Approved: =?UTF-8?Q?hello_there_=F0=9F=91=8B?=
    /// X-GitHub-Recipient-Address: mlala@negabit.com
    /// X-Auto-Response-Suppress: All
    ///
    ///   Branch: refs/heads/test/rule-engine
    ///   Home:   https://github.com/viridIT/vSMTP
    ///   Commit: c6459a4946395ba90182ce7181bdbc327994c038
    ///       https://github.com/viridIT/vSMTP/commit/c6459a4946395ba90182ce7181bdbc327994c038
    ///   Author: Mathieu Lala <m.lala@viridit.com>
    ///   Date:   2022-10-26 (Wed, 26 Oct 2022)
    ///
    ///   Changed paths:
    ///     M src/vsmtp/vsmtp-rule-engine/src/api/message.rs
    ///     M src/vsmtp/vsmtp-rule-engine/src/lib.rs
    ///     M src/vsmtp/vsmtp-test/src/vsl.rs
    ///
    ///   Log Message:
    ///   -----------
    ///   test: add test on message
    ///
    ///
    /// # "#
    /// ; // .eml ends here
    /// # let msg = vsmtp_mail_parser::MessageBody::try_from(msg[1..].replace("\n", "\r\n").as_str()).unwrap();
    ///
    /// # let states = vsmtp_test::vsl::run_with_msg(
    /// #    |builder| Ok(builder.add_root_incoming_rules(r#"
    /// #{
    ///   preq: [
    ///     rule "verify_dkim" || {
    ///       verify_dkim();
    ///       if !get_header("Authentication-Results").contains("dkim=pass") {
    ///         return deny();
    ///       }
    ///       // the result of dkim verification is cached, so this call will
    ///       // not recompute the signature and recreate a header
    ///       verify_dkim();
    ///
    ///       // FIXME: should be one
    ///       if count_header("Authentication-Results") != 2 {
    ///         return deny();
    ///       }
    ///
    ///       accept();
    ///     }
    ///   ]
    /// }
    /// # "#)?.build()), Some(msg));
    /// # use vsmtp_common::{status::Status, CodeID};
    /// # use vsmtp_rule_engine::ExecutionStage;
    /// # assert_eq!(states[&ExecutionStage::PreQ].2, Status::Accept(either::Left(CodeID::Ok)));
    /// ```
    ///
    /// Changing the header `Subject` will result in a dkim verification failure.
    ///
    /// ```
    /// # let msg = r#"
    /// Received: from github.com (hubbernetes-node-54a15d2.ash1-iad.github.net [10.56.202.84])
    /// 	by smtp.github.com (Postfix) with ESMTPA id 19FB45E0B6B
    /// 	for <mlala@negabit.com>; Wed, 26 Oct 2022 14:30:51 -0700 (PDT)
    /// DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=github.com;
    /// 	s=pf2014; t=1666819851;
    /// 	bh=7gTTczemS/Aahap1SpEnunm4pAPNuUIg7fUzwEx0QUA=;
    /// 	h=Date:From:To:Subject:From;
    /// 	b=eAufMk7uj4R+bO5Nr4DymffdGdbrJNza1+eykatgZED6tBBcMidkMiLSnP8FyVCS9
    /// 	 /GSlXME6/YffAXg4JEBr2lN3PuLIf94S86U3VckuoQQQe1LPtHlnGW5ZwJgi6DjrzT
    /// 	 klht/6Pn1w3a2jdNSDccWhk5qlSOQX9JKnE7UD58=
    /// Date: Wed, 26 Oct 2022 14:30:51 -0700
    /// From: Mathieu Lala <noreply@github.com>
    /// To: mlala@negabit.com
    /// Message-ID: <viridIT/vSMTP/push/refs/heads/test/rule-engine/000000-c6459a@github.com>
    /// Subject: Changing the header produce an invalid dkim verification
    /// Mime-Version: 1.0
    /// Content-Type: text/plain;
    ///  charset=UTF-8
    /// Content-Transfer-Encoding: 7bit
    /// Approved: =?UTF-8?Q?hello_there_=F0=9F=91=8B?=
    /// X-GitHub-Recipient-Address: mlala@negabit.com
    /// X-Auto-Response-Suppress: All
    ///
    ///   Branch: refs/heads/test/rule-engine
    ///   Home:   https://github.com/viridIT/vSMTP
    ///   Commit: c6459a4946395ba90182ce7181bdbc327994c038
    ///       https://github.com/viridIT/vSMTP/commit/c6459a4946395ba90182ce7181bdbc327994c038
    ///   Author: Mathieu Lala <m.lala@viridit.com>
    ///   Date:   2022-10-26 (Wed, 26 Oct 2022)
    ///
    ///   Changed paths:
    ///     M src/vsmtp/vsmtp-rule-engine/src/api/message.rs
    ///     M src/vsmtp/vsmtp-rule-engine/src/lib.rs
    ///     M src/vsmtp/vsmtp-test/src/vsl.rs
    ///
    ///   Log Message:
    ///   -----------
    ///   test: add test on message
    ///
    ///
    /// # "#
    /// ; // .eml ends here
    /// # let msg = vsmtp_mail_parser::MessageBody::try_from(msg[1..].replace("\n", "\r\n").as_str()).unwrap();
    ///
    /// # let states = vsmtp_test::vsl::run_with_msg(
    /// # |builder| Ok(builder.add_root_incoming_rules(r#"
    /// #{
    ///   preq: [
    ///     rule "verify_dkim" || {
    ///       verify_dkim();
    ///       if !get_header("Authentication-Results").contains("dkim=fail") {
    ///         return deny();
    ///       }
    ///       accept();
    ///     }
    ///   ]
    /// }
    /// # "#)?.build()), Some(msg));
    /// # use vsmtp_common::{status::Status, CodeID};
    /// # use vsmtp_rule_engine::ExecutionStage;
    /// # assert_eq!(states[&ExecutionStage::PreQ].2, Status::Accept(either::Left(CodeID::Ok)));
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, pure, return_raw)]
    pub fn verify_dkim(
        message: &mut Message,
        signature: Signature,
        key: PublicKey,
    ) -> EngineResult<()> {
        let guard = vsl_guard_ok!(message.read());

        super::Impl::verify_dkim(&guard, signature, key).map_err(Into::into)
    }

    /// Create a new signature of the message for the DKIM.
    ///
    /// # Examples
    ///
    /// ```
    /// # let msg = r#"
    /// Date: Wed, 26 Oct 2022 14:30:51 -0700
    /// From: Mathieu Lala <noreply@github.com>
    /// To: mlala@negabit.com
    /// Subject: Testing and documenting the dkim signature
    ///
    /// This message has not been signed yet, meaning someone could change it...
    /// # "#;
    /// ; // .eml ends here
    /// # let msg = vsmtp_mail_parser::MessageBody::try_from(msg[1..].replace("\n", "\r\n").as_str()).unwrap();
    ///
    /// # let mut rng = <rand_chacha::ChaCha12Rng as rand::SeedableRng>::seed_from_u64(0xCAFECAFE);
    /// # let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate a key");
    /// # let mut config = vsmtp_test::config::local_test();
    /// # config.server.dkim = Some(vsmtp_config::field::FieldDkim{
    /// #   private_key: vec![
    /// #     vsmtp_config::field::SecretFile {
    /// #       inner: std::sync::Arc::new(
    /// #         vsmtp_auth::dkim::PrivateKey::Rsa(Box::new(private_key))
    /// #       ),
    /// #       path: "./dummy".into(),
    /// #     }
    /// #   ]
    /// # });
    ///
    /// # let states = vsmtp_test::vsl::run_with_msg_and_config(
    /// # |builder| Ok(builder.add_root_incoming_rules(r#"
    /// #{
    ///   postq: [
    ///     action "add a DKIM signature" || {
    ///       for i in get_private_keys(srv(), "testserver.com") {
    ///         sign_dkim("2022-09", i, ["From", "To", "Date", "Subject", "From"], "simple/relaxed");
    ///       }
    ///     },
    ///     rule "check signature" || {
    ///       let signature = "v=1; a=rsa-sha256; d=testserver.com; s=2022-09;\r\n\
    ///           \tc=simple/relaxed; q=dns/txt; h=From:To:Date:Subject:From;\r\n\
    ///           \tbh=ATHiC1KD8OegIorswWts+SlujGUpgqR6pqXYlNWA01Y=;\r\n\tb=Ur\
    ///           /frdH3beyU3LRQMGBdI6OdxRvfpu+s04hmHcVkpBYzR4cXuDPByWpUCqhO4C\
    ///           sEwpPRDcWQtsCfuzSK1FTf7XCWgsKKGPmsdQ40pUviA0UrrzpIDIziMxSI/S\
    ///           8ohNnxvqxrtxZoN6Wo2lnQ+kYAATYxJPOjC57JIBJ89RGrf+6Wbvz6/PofcU\
    ///           9VwpylegZRU5Cial69lN2qaIkoVFOE9fz8ZIz9VV2A9Lh/xgKFM7eipBWCR6\
    ///           ZUU1HZTbSiqiL9Q6A823az/E2jqOUZXtsGK/Bo/vDjTV166d5vY34JA3189C\
    ///           x83Rbif9A/kdCO6C8gGK0WOasp5R0ONmVz41TaGQ==";
    ///
    ///       if get_header("DKIM-Signature") == signature {
    ///         accept()
    ///       } else {
    ///         deny()
    ///       }
    ///     }
    ///   ]
    /// }
    /// # "#)?.build()), Some(msg), config);
    ///
    /// # use vsmtp_common::{status::Status, CodeID};
    /// # assert_eq!(states[&vsmtp_rule_engine::ExecutionStage::PostQ].2, Status::Accept(either::Left(CodeID::Ok)));
    /// ```
    #[rhai_fn(global, pure, return_raw)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn generate_signature_dkim(
        message: &mut Message,
        context: Context,
        selector: &str,
        private_key: std::sync::Arc<PrivateKey>,
        headers_field: rhai::Array,
        canonicalization: &str,
    ) -> EngineResult<String> {
        let message_guard = vsl_guard_ok!(message.read());
        let context_guard = vsl_guard_ok!(context.read());

        match &*context_guard {
            vsmtp_common::Context::Finished(ctx) => super::Impl::generate_signature_dkim(
                &message_guard,
                &ctx.connect.server_name,
                selector,
                &private_key,
                &headers_field,
                canonicalization,
            )
            .map_err(Into::into),
            _ => Err("bad state".into()),
        }
    }
}

#[derive(Debug)]
struct DnsError(trust_dns_resolver::error::ResolveError);

impl Default for DnsError {
    fn default() -> Self {
        Self(trust_dns_resolver::error::ResolveError::from(
            trust_dns_resolver::error::ResolveErrorKind::Message("`default` invoked"),
        ))
    }
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, strum::EnumMessage, strum::EnumIter, thiserror::Error)]
enum DkimErrors {
    #[strum(message = "neutral", detailed_message = "signature_parsing_failed")]
    #[error("the parsing of the signature failed: `{inner}`")]
    SignatureParsingFailed {
        inner: <Signature as std::str::FromStr>::Err,
    },
    #[strum(message = "neutral", detailed_message = "key_parsing_failed")]
    #[error("the parsing of the public key failed: `{inner}`")]
    KeyParsingFailed {
        inner: <PublicKey as std::str::FromStr>::Err,
    },
    #[strum(message = "neutral", detailed_message = "invalid_argument")]
    #[error("invalid argument: `{inner}`")]
    InvalidArgument { inner: String },
    #[strum(message = "temperror", detailed_message = "temp_dns_error")]
    #[error("temporary dns error: `{inner}`")]
    TempDnsError { inner: DnsError },
    #[strum(message = "permerror", detailed_message = "perm_dns_error")]
    #[error("permanent dns error: `{inner}`")]
    PermDnsError { inner: DnsError },
    #[strum(message = "fail", detailed_message = "signature_mismatch")]
    #[error("the signature does not match: `{inner}`")]
    SignatureMismatch { inner: VerifierError },
}

impl From<DkimErrors> for Box<rhai::EvalAltResult> {
    fn from(this: DkimErrors) -> Self {
        Box::new(rhai::EvalAltResult::ErrorRuntime(
            rhai::Dynamic::from_map(rhai::Map::from_iter([
                (
                    "type".into(),
                    strum::EnumMessage::get_detailed_message(&this)
                        .expect("`DkimErrors` must have a `detailed message` for each variant")
                        .to_string()
                        .into(),
                ),
                ("inner".into(), rhai::Dynamic::from(this.to_string())),
            ])),
            rhai::Position::NONE,
        ))
    }
}

struct Impl;

impl Impl {
    #[tracing::instrument(ret, err)]
    pub fn parse_signature(input: &str) -> Result<Signature, DkimErrors> {
        <Signature as std::str::FromStr>::from_str(input)
            .map_err(|inner| DkimErrors::SignatureParsingFailed { inner })
    }

    #[tracing::instrument(ret, err)]
    fn verify_dkim(
        message: &MessageBody,
        signature: Signature,
        key: PublicKey,
    ) -> Result<(), DkimErrors> {
        verify(&signature, message.inner(), &key)
            .map_err(|inner| DkimErrors::SignatureMismatch { inner })
    }

    #[tracing::instrument(skip(server), ret, err)]
    fn get_public_key(
        server: &mut Server,
        signature: Signature,
        on_multiple_key_records: &str,
    ) -> Result<Vec<PublicKey>, DkimErrors> {
        const VALID_POLICY: [&str; 2] = ["first", "cycle"];
        if !VALID_POLICY.contains(&on_multiple_key_records) {
            return Err(DkimErrors::InvalidArgument {
                inner: format!(
                    "expected values in `[first, cycle]` but got `{on_multiple_key_records}`",
                ),
            });
        }

        let resolver = server.resolvers.get_resolver_root();

        let txt_record = tokio::task::block_in_place(move || {
            tokio::runtime::Handle::current()
                .block_on(resolver.txt_lookup(signature.get_dns_query()))
        })
        .map_err(|e| {
            use trust_dns_resolver::error::ResolveErrorKind;
            if matches!(
                e.kind(),
                ResolveErrorKind::Message(_)
                    | ResolveErrorKind::Msg(_)
                    | ResolveErrorKind::NoConnections
                    | ResolveErrorKind::NoRecordsFound { .. }
            ) {
                DkimErrors::PermDnsError { inner: DnsError(e) }
            } else {
                DkimErrors::TempDnsError { inner: DnsError(e) }
            }
        })?;

        let keys = txt_record
            .into_iter()
            .map(|i| <PublicKey as std::str::FromStr>::from_str(&i.to_string()));

        let keys = keys
            .collect::<Result<Vec<_>, <PublicKey as std::str::FromStr>::Err>>()
            .map_err(|inner| DkimErrors::KeyParsingFailed { inner })?;

        Ok(if on_multiple_key_records == "first" {
            keys.into_iter().next().map_or_else(Vec::new, |i| vec![i])
        } else {
            keys
        })
    }

    #[tracing::instrument(ret, err)]
    fn generate_signature_dkim(
        message: &MessageBody,
        sdid: &str,
        selector: &str,
        private_key: &PrivateKey,
        headers_field: &rhai::Array,
        canonicalization: &str,
    ) -> Result<String, DkimErrors> {
        let signature = sign(
            message.inner(),
            private_key,
            sdid.to_string(),
            selector.to_string(),
            <Canonicalization as std::str::FromStr>::from_str(canonicalization).map_err(|e| {
                DkimErrors::InvalidArgument {
                    inner: e.to_string(),
                }
            })?,
            headers_field.iter().map(ToString::to_string).collect(),
        )
        .map_err(|e| DkimErrors::InvalidArgument {
            inner: format!("the signature failed: `{e}`"),
        })?;

        Ok(signature.get_signature_value())
    }
}
