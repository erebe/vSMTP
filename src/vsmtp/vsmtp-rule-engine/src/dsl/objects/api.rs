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

use crate::api::Object;
use crate::vsl_generic_ok;
use rhai::plugin::{
    mem, Dynamic, FnAccess, FnNamespace, ImmutableString, NativeCallContext, PluginFunction,
    RhaiResult, TypeId,
};
use rhai::Module;

/// Wrap a new object in it's sync/async wrapper.
macro_rules! new_object {
    ($object:expr) => {
        Ok(rhai::Shared::new(vsl_generic_ok!($object)))
    };
}

#[rhai::plugin::export_module]
pub mod objects {

    pub type VSLObject = crate::api::SharedObject;

    /// Build an ip4 address. (a.b.c.d)
    #[rhai_fn(global, return_raw)]
    pub fn ip4(ip: &str) -> crate::api::EngineResult<VSLObject> {
        new_object!(Object::new_ip4(ip))
    }

    /// Build an ip6 address. (x:x:x:x:x:x:x:x)
    #[rhai_fn(global, return_raw)]
    pub fn ip6(ip: &str) -> crate::api::EngineResult<VSLObject> {
        new_object!(Object::new_ip6(ip))
    }

    /// an ip v4 range. (a.b.c.d/range)
    #[rhai_fn(global, return_raw)]
    pub fn rg4(range: &str) -> crate::api::EngineResult<VSLObject> {
        new_object!(Object::new_rg4(range))
    }

    /// an ip v6 range. (x:x:x:x:x:x:x:x/range)
    #[rhai_fn(global, return_raw)]
    pub fn rg6(range: &str) -> crate::api::EngineResult<VSLObject> {
        new_object!(Object::new_rg6(range))
    }

    /// an email address (jones@foo.com)
    #[rhai_fn(global, return_raw)]
    pub fn address(address: &str) -> crate::api::EngineResult<VSLObject> {
        new_object!(Object::new_address(address))
    }

    /// a valid fully qualified domain name (foo.com)
    #[rhai_fn(global, return_raw)]
    pub fn fqdn(domain: &str) -> crate::api::EngineResult<VSLObject> {
        new_object!(Object::new_fqdn(domain))
    }

    /// a regex (^[a-z0-9.]+@foo.com$)
    #[rhai_fn(global, return_raw)]
    pub fn regex(regex: &str) -> crate::api::EngineResult<VSLObject> {
        new_object!(Object::new_regex(regex))
    }

    /// the content of a file.
    #[rhai_fn(global, return_raw)]
    pub fn file(path: &str, content_type: &str) -> crate::api::EngineResult<VSLObject> {
        new_object!(Object::new_file(path, content_type))
    }

    /// a group of objects.
    #[rhai_fn(global)]
    pub fn group(group: rhai::Array) -> VSLObject {
        rhai::Shared::new(Object::new_group(group))
    }

    /// a user identifier.
    #[rhai_fn(global)]
    pub fn identifier(identifier: &str) -> VSLObject {
        rhai::Shared::new(Object::new_identifier(identifier))
    }

    /// A SMTP code with the code and message as parameter.
    #[rhai_fn(global, name = "code", return_raw)]
    pub fn code(code: rhai::INT, text: &str) -> crate::api::EngineResult<VSLObject> {
        Ok(rhai::Shared::new(Object::new_code(
            vsl_generic_ok!(u16::try_from(code)),
            text,
        )))
    }

    /// A SMTP code with the code and message as parameter and an enhanced code.
    #[rhai_fn(global, name = "code", return_raw)]
    pub fn code_enhanced(
        code: rhai::INT,
        text: &str,
        enhanced: &str,
    ) -> crate::api::EngineResult<VSLObject> {
        Ok(rhai::Shared::new(Object::new_code_enhanced(
            vsl_generic_ok!(u16::try_from(code)),
            text,
            enhanced,
        )))
    }
}
