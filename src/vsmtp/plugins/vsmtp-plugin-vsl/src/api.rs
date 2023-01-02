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

use crate::objects::{Object, SharedObject};
use rhai::plugin::{
    mem, Dynamic, FnAccess, FnNamespace, ImmutableString, NativeCallContext, PluginFunction,
    RhaiResult, TypeId,
};
use rhai::Module;

/// Wrap a new object in it's sync/async wrapper.
macro_rules! new_object {
    ($object:expr) => {
        Ok(rhai::Shared::new(
            $object.map_err::<Box<rhai::EvalAltResult>, _>(|e| e.to_string().into())?,
        ))
    };
}

type RhaiResultOf<T> = Result<T, Box<rhai::EvalAltResult>>;

#[rhai::plugin::export_module]
/// vSL objects declaration functions.
pub mod objects {

    /// An object from the vSL rhai superset.
    pub type VSLObject = crate::objects::SharedObject;

    /// Build an ip4 address. (a.b.c.d)
    #[rhai_fn(global, return_raw)]
    pub fn ip4(ip: &str) -> RhaiResultOf<VSLObject> {
        new_object!(Object::new_ip4(ip))
    }

    /// Build an ip6 address. (x:x:x:x:x:x:x:x)
    #[rhai_fn(global, return_raw)]
    pub fn ip6(ip: &str) -> RhaiResultOf<VSLObject> {
        new_object!(Object::new_ip6(ip))
    }

    /// an ip v4 range. (a.b.c.d/range)
    #[rhai_fn(global, return_raw)]
    pub fn rg4(range: &str) -> RhaiResultOf<VSLObject> {
        new_object!(Object::new_rg4(range))
    }

    /// an ip v6 range. (x:x:x:x:x:x:x:x/range)
    #[rhai_fn(global, return_raw)]
    pub fn rg6(range: &str) -> RhaiResultOf<VSLObject> {
        new_object!(Object::new_rg6(range))
    }

    /// an email address (jones@foo.com)
    #[rhai_fn(global, return_raw)]
    pub fn address(address: &str) -> RhaiResultOf<VSLObject> {
        new_object!(Object::new_address(address))
    }

    /// a valid fully qualified domain name (foo.com)
    #[rhai_fn(global, return_raw)]
    pub fn fqdn(domain: &str) -> RhaiResultOf<VSLObject> {
        new_object!(Object::new_fqdn(domain))
    }

    /// a regex (^[a-z0-9.]+@foo.com$)
    #[rhai_fn(global, return_raw)]
    pub fn regex(regex: &str) -> RhaiResultOf<VSLObject> {
        new_object!(Object::new_regex(regex))
    }

    /// the content of a file.
    #[rhai_fn(global, return_raw)]
    pub fn file(path: &str, content_type: &str) -> RhaiResultOf<rhai::Array> {
        Object::new_file(path, content_type)
            .map_err::<Box<rhai::EvalAltResult>, _>(|e| e.to_string().into())
    }

    /// a user identifier.
    #[rhai_fn(global)]
    pub fn identifier(identifier: &str) -> VSLObject {
        rhai::Shared::new(Object::new_identifier(identifier))
    }

    /// A SMTP code with the code and message as parameter.
    #[rhai_fn(global, name = "code", return_raw)]
    pub fn code(code: rhai::INT, text: &str) -> RhaiResultOf<VSLObject> {
        Ok(rhai::Shared::new(Object::new_code(
            u16::try_from(code).map_err::<Box<rhai::EvalAltResult>, _>(|e| e.to_string().into())?,
            text,
        )))
    }

    /// A SMTP code with the code and message as parameter and an enhanced code.
    #[rhai_fn(global, name = "code", return_raw)]
    pub fn code_enhanced(code: rhai::INT, enhanced: &str, text: &str) -> RhaiResultOf<VSLObject> {
        Ok(rhai::Shared::new(Object::new_code_enhanced(
            u16::try_from(code).map_err::<Box<rhai::EvalAltResult>, _>(|e| e.to_string().into())?,
            enhanced,
            text,
        )))
    }
}

/// vSL objects utility methods.
#[rhai::plugin::export_module]
pub mod utils {
    use crate::api::objects::VSLObject;

    /// Get the local part of an email address.
    ///
    /// # Args
    ///
    /// * `address` - the address to extract the local part from.
    ///
    /// # Return
    ///
    /// * `String` - the local part.
    ///
    /// # Effective smtp stage
    ///
    /// All of them.
    ///
    /// # Examples
    ///
    /// ```text
    /// #{
    ///     mail: [
    ///         // You can also use the `get_local_part(ctx::mail_from())` syntax.
    ///         action "display mail from identity" || {
    ///             log("info", `received a message from ${ctx::mail_from().local_part}.`);
    ///         }
    ///     ],
    /// }
    /// ```
    #[rhai_fn(global, get = "local_part", return_raw, pure)]
    pub fn local_part(addr: &mut VSLObject) -> RhaiResultOf<String> {
        match &**addr {
            Object::Address(addr) => Ok(addr.local_part().to_string()),
            other => Err(format!("cannot extract local part for {} object", other.as_ref()).into()),
        }
    }

    /// Get the domain of an email address.
    ///
    /// # Args
    ///
    /// * `address` - the address to extract the domain from.
    ///
    /// # Effective smtp stage
    ///
    /// All of them.
    ///
    /// # Examples
    ///
    /// ```text
    /// #{
    ///     mail: [
    ///         // You can also use the `get_domain(ctx::mail_from())` syntax.
    ///         action "display sender's domain" || {
    ///             log("info", `received a message from domain ${ctx::mail_from().domain}.`);
    ///         }
    ///     ],
    /// }
    /// ```
    #[rhai_fn(global, get = "domain", return_raw, pure)]
    pub fn domain(addr: &mut VSLObject) -> RhaiResultOf<VSLObject> {
        match &**addr {
            Object::Address(addr) => Ok(rhai::Shared::new(Object::Fqdn(addr.domain().to_string()))),
            other => Err(format!("cannot extract domain for {} object", other.as_ref()).into()),
        }
    }

    // FIXME: prevent cloning by caching the result ?

    /// Get all local parts of the recipient list.
    ///
    /// # Args
    ///
    /// * `rcpt_list` - the recipient list.
    ///
    /// # Return
    ///
    /// * `array` - array of local parts.
    ///
    /// # Effective smtp stage
    ///
    /// `mail` and onwards.
    ///
    /// # Examples
    ///
    /// ```text
    /// #{
    ///     mail: [
    ///         action "display recipients usernames" || {
    ///             print("list of recipients user names:");
    ///
    ///             // You can also use the `get_local_parts(ctx::rcpt_list())` syntax.
    ///             for user in ctx::rcpt_list().local_parts {
    ///                 print(`- ${user}`);
    ///             }
    ///         }
    ///     ],
    /// }
    /// ```
    #[rhai_fn(global, get = "local_parts", return_raw, pure)]
    pub fn local_parts(container: &mut rhai::Array) -> RhaiResultOf<rhai::Array> {
        container
            .iter()
            .map(|item| {
                if item.is::<SharedObject>() {
                    match &*item.clone_cast::<SharedObject>() {
                        Object::Address(addr) => {
                            Ok(rhai::Dynamic::from(addr.local_part().to_string()))
                        }
                        other => Err(format!(
                            "cannot extract local part for non email address ({})",
                            other.as_ref()
                        )
                        .into()),
                    }
                } else if item.is::<String>() {
                    let item = item.clone_cast::<String>();

                    // NOTE: Using this instead of [`Object::new_address`] because it would need an extra match.
                    <vsmtp_common::Address as std::str::FromStr>::from_str(item.as_str())
                        .map(|addr| rhai::Dynamic::from(addr.local_part().to_string()))
                        .map_err::<Box<rhai::EvalAltResult>, _>(|e| e.to_string().into())
                } else {
                    Err(format!(
                        "cannot extract local part from a {} object.",
                        item.type_name()
                    )
                    .into())
                }
            })
            .collect()
    }

    /// Get all domains of the recipient list.
    ///
    /// # Args
    ///
    /// * `rcpt_list` - the recipient list.
    ///
    /// # Effective smtp stage
    ///
    /// `mail` and onwards.
    ///
    /// # Examples
    ///
    /// ```text
    /// #{
    ///     mail: [
    ///         action "display recipients domains" || {
    ///             print("list of recipients domains:");
    ///
    ///             // You can also use the `get_domains(ctx::rcpt_list())` syntax.
    ///             for domain in ctx::rcpt_list().domains {
    ///                 print(`- ${domain}`);
    ///             }
    ///         }
    ///     ],
    /// }
    /// ```
    #[rhai_fn(global, get = "domains", return_raw, pure)]
    pub fn domains(container: &mut rhai::Array) -> RhaiResultOf<rhai::Array> {
        container
            .iter()
            .map(|item| {
                if item.is::<SharedObject>() {
                    match &*item.clone_cast::<SharedObject>() {
                        Object::Address(addr) => Ok(rhai::Dynamic::from(addr.domain().to_string())),
                        other => Err(format!(
                            "cannot extract domain for non email address ({})",
                            other.as_ref()
                        )
                        .into()),
                    }
                } else if item.is::<String>() {
                    // TODO: handle rhai multi typed strings.
                    let item = item.clone_cast::<String>();

                    // NOTE: Using this instead of [`Object::new_address`] because it would need an extra match.
                    <vsmtp_common::Address as std::str::FromStr>::from_str(item.as_str())
                        .map(|addr| rhai::Dynamic::from(addr.domain().to_string()))
                        .map_err::<Box<rhai::EvalAltResult>, _>(|e| e.to_string().into())
                } else {
                    Err(format!("cannot extract domain from a {} object.", item.type_name()).into())
                }
            })
            .collect()
    }

    /// Convert a `SharedObject` to a `String`
    #[rhai_fn(global, name = "to_string", pure)]
    pub fn object_to_string(this: &mut VSLObject) -> String {
        this.to_string()
    }

    /// Convert a `SharedObject` to a debug string
    #[rhai_fn(global, name = "to_debug", pure)]
    pub fn object_to_debug(this: &mut VSLObject) -> String {
        format!("{:#?}", **this)
    }
}

/// vSL objects Eq method between each other and other types.
#[rhai::plugin::export_module]
pub mod comparisons {

    /// Operator `==` for `SharedObject`
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "==", pure)]
    pub fn object_is_self(this: &mut SharedObject, other: SharedObject) -> bool {
        **this == *other
    }

    /// Operator `!=` for `SharedObject`
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "!=", pure)]
    pub fn object_not_self(this: &mut SharedObject, other: SharedObject) -> bool {
        **this != *other
    }

    /// Operator `==` for `SharedObject` and `&str`
    #[rhai_fn(global, name = "==", return_raw, pure)]
    pub fn object_is_string(this: &mut SharedObject, s: &str) -> RhaiResultOf<bool> {
        internal_string_is_object(s, this)
    }

    /// Operator `!=` for `SharedObject` and `&str`
    #[rhai_fn(global, name = "!=", return_raw, pure)]
    pub fn object_not_string(this: &mut SharedObject, s: &str) -> RhaiResultOf<bool> {
        internal_string_is_object(s, this).map(|res| !res)
    }

    /// Operator `==` for `&str` and `SharedObject`
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "==", return_raw)]
    pub fn string_is_object(this: &str, other: SharedObject) -> RhaiResultOf<bool> {
        internal_string_is_object(this, &other)
    }

    /// Operator `!=` for `&str` and `SharedObject`
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "!=", return_raw)]
    pub fn string_not_object(this: &str, other: SharedObject) -> RhaiResultOf<bool> {
        internal_string_is_object(this, &other).map(|res| !res)
    }

    // NOTE: should this return an error if the string cannot be converted ?
    /// Operator `contains`
    #[rhai_fn(global, name = "contains", pure)]
    pub fn string_in_object(this: &mut SharedObject, s: &str) -> bool {
        this.contains_str(s)
    }

    /// Operator `contains`
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "contains", pure)]
    pub fn object_in_object(this: &mut SharedObject, other: SharedObject) -> bool {
        this.contains(&other)
    }

    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "contains", pure)]
    pub fn object_in_map(map: &mut rhai::Map, object: SharedObject) -> bool {
        // FIXME: impl Ord on Object to prevent cloning.
        map.contains_key(object.to_string().as_str())
    }
}

// the following methods are used to compare recursively deep objects
// using refs instead of shared rhai objects.
// FIXME: using generics here should be a good idea.
// TODO:  all comparison function should return an error in case of mismatching types ?

fn internal_string_is_object(this: &str, other: &Object) -> RhaiResultOf<bool> {
    match other {
        Object::Address(addr) => Ok(this == addr.full()),
        Object::Fqdn(fqdn) => Ok(this == fqdn.as_str()),
        Object::Regex(re) => Ok(re.is_match(this)),
        Object::Ip4(ip4) => Ok(this == ip4.to_string()),
        Object::Ip6(ip6) => Ok(this == ip6.to_string()),
        Object::Identifier(s) => Ok(this == s.as_str()),
        _ => Err(format!("a {other} object cannot be compared to a string").into()),
    }
}
