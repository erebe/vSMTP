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
    EngineResult, {Message, SharedObject},
};
use rhai::plugin::{
    mem, Dynamic, FnAccess, FnNamespace, ImmutableString, Module, NativeCallContext,
    PluginFunction, RhaiResult, TypeId,
};

pub use message_rhai::*;

#[rhai::plugin::export_module]
mod message_rhai {

    /// check if a given header exists in the top level headers.
    #[rhai_fn(global, name = "has_header", return_raw, pure)]
    pub fn has_header_str(message: &mut Message, header: &str) -> EngineResult<bool> {
        Ok(vsl_guard_ok!(message.read()).get_header(header).is_some())
    }

    /// check if a given header exists in the top level headers.
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "has_header", return_raw, pure)]
    pub fn has_header_obj(message: &mut Message, header: SharedObject) -> EngineResult<bool> {
        Ok(vsl_guard_ok!(message.read())
            .get_header(&header.to_string())
            .is_some())
    }

    /// Count the number of headers with the given name.
    #[rhai_fn(global, name = "count_header", return_raw, pure)]
    pub fn count_header_str(message: &mut Message, header: &str) -> EngineResult<rhai::INT> {
        super::count_header(message, header)
    }

    /// Count the number of headers with the given name.
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "count_header", return_raw, pure)]
    pub fn count_header_obj(
        message: &mut Message,
        header: SharedObject,
    ) -> EngineResult<rhai::INT> {
        super::count_header(message, &header.to_string())
    }

    /// return the value of a header if it exists. Otherwise, returns an empty string.
    #[rhai_fn(global, name = "get_header", return_raw, pure)]
    pub fn get_header_str(message: &mut Message, header: &str) -> EngineResult<String> {
        Ok(vsl_guard_ok!(message.read())
            .get_header(header)
            .unwrap_or_default())
    }

    /// return the value of a header if it exists. Otherwise, returns an empty string.
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "get_header", return_raw, pure)]
    pub fn get_header_obj(message: &mut Message, header: SharedObject) -> EngineResult<String> {
        Ok(vsl_guard_ok!(message.read())
            .get_header(&header.to_string())
            .unwrap_or_default())
    }

    /// Return the complete list of headers.
    #[rhai_fn(global, name = "get_all_headers", return_raw, pure)]
    pub fn get_all_headers(message: &mut Message) -> EngineResult<rhai::Array> {
        Ok(vsl_guard_ok!(message.read())
            .inner()
            .raw_headers()
            .iter()
            .map(|raw| rhai::Dynamic::from(raw.clone()))
            .collect())
    }

    /// Return a list of headers bearing the `name` given as argument.
    #[rhai_fn(global, name = "get_all_headers", return_raw, pure)]
    pub fn get_all_headers_str(message: &mut Message, name: &str) -> EngineResult<rhai::Array> {
        super::get_all_headers(message, name)
    }

    /// Return a list of headers bearing the `name` given as argument.
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "get_all_headers", return_raw, pure)]
    pub fn get_all_headers_obj(
        message: &mut Message,
        name: SharedObject,
    ) -> EngineResult<rhai::Array> {
        super::get_all_headers(message, &name.to_string())
    }

    /// add a header to the end of the raw or parsed email contained in ctx.
    #[rhai_fn(global, name = "append_header", return_raw, pure)]
    pub fn append_header_str_str(
        message: &mut Message,
        header: &str,
        value: &str,
    ) -> EngineResult<()> {
        super::append_header(message, &header, &value)
    }

    /// add a header to the end of the raw or parsed email contained in ctx. (using an object)
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "append_header", return_raw, pure)]
    pub fn append_header_str_obj(
        message: &mut Message,
        header: &str,
        value: SharedObject,
    ) -> EngineResult<()> {
        super::append_header(message, &header, &value.to_string())
    }

    /// prepend a header to the raw or parsed email contained in ctx.
    #[rhai_fn(global, name = "prepend_header", return_raw, pure)]
    pub fn prepend_header_str_str(
        message: &mut Message,
        header: &str,
        value: &str,
    ) -> EngineResult<()> {
        super::prepend_header(message, header, value)
    }

    /// prepend a header to the raw or parsed email contained in ctx. (using an object)
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "prepend_header", return_raw, pure)]
    pub fn prepend_header_str_obj(
        message: &mut Message,
        header: &str,
        value: SharedObject,
    ) -> EngineResult<()> {
        super::prepend_header(message, header, &value.to_string())
    }

    /// set a header to the raw or parsed email contained in ctx.
    #[rhai_fn(global, name = "set_header", return_raw, pure)]
    pub fn set_header_str_str(
        message: &mut Message,
        header: &str,
        value: &str,
    ) -> EngineResult<()> {
        super::set_header(message, header, value)
    }

    /// set a header to the raw or parsed email contained in ctx.
    #[rhai_fn(global, name = "set_header", return_raw, pure)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn set_header_str_obj(
        message: &mut Message,
        header: &str,
        value: SharedObject,
    ) -> EngineResult<()> {
        super::set_header(message, header, &value.to_string())
    }

    /// set a header to the raw or parsed email contained in ctx.
    #[rhai_fn(global, name = "rename_header", return_raw, pure)]
    pub fn rename_header_str_str(message: &mut Message, old: &str, new: &str) -> EngineResult<()> {
        super::rename_header(message, old, new)
    }

    /// set a header to the raw or parsed email contained in ctx.
    #[rhai_fn(global, name = "rename_header", return_raw, pure)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn rename_header_str_obj(
        message: &mut Message,
        old: &str,
        new: SharedObject,
    ) -> EngineResult<()> {
        super::rename_header(message, old, &new.to_string())
    }

    /// set a header to the raw or parsed email contained in ctx.
    #[rhai_fn(global, name = "rename_header", return_raw, pure)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn rename_header_obj_str(
        message: &mut Message,
        old: SharedObject,
        new: &str,
    ) -> EngineResult<()> {
        super::rename_header(message, &old.to_string(), new)
    }

    /// set a header to the raw or parsed email contained in ctx.
    #[rhai_fn(global, name = "rename_header", return_raw, pure)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn rename_header_obj_obj(
        message: &mut Message,
        old: SharedObject,
        new: SharedObject,
    ) -> EngineResult<()> {
        super::rename_header(message, &old.to_string(), &new.to_string())
    }

    /// Get the message body as a string
    #[rhai_fn(global, get = "mail", return_raw, pure)]
    pub fn mail(this: &mut Message) -> EngineResult<String> {
        Ok(vsl_guard_ok!(this.read()).inner().to_string())
    }

    /// Remove a header from the raw or parsed email contained in ctx.
    #[rhai_fn(global, name = "remove_header", return_raw, pure)]
    pub fn remove_header_str(message: &mut Message, header: &str) -> EngineResult<bool> {
        super::remove_header(message, header)
    }

    /// Remove a header from the raw or parsed email contained in ctx.
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "remove_header", return_raw, pure)]
    pub fn remove_header_obj(message: &mut Message, header: SharedObject) -> EngineResult<bool> {
        super::remove_header(message, &header.to_string())
    }

    ///
    #[rhai_fn(global, return_raw, pure)]
    pub fn get_header_untouched(this: &mut Message, name: &str) -> EngineResult<rhai::Array> {
        let guard = vsl_guard_ok!(this.read());
        let name_lowercase = name.to_lowercase();

        Ok(guard
            .inner()
            .headers(true)
            .iter()
            .filter(|(key, _)| key.to_lowercase() == name_lowercase)
            .map(|(key, value)| rhai::Dynamic::from(format!("{key}:{value}")))
            .collect::<Vec<_>>())
    }
}

/// Return a list of headers bearing the `name` given as argument.
/// The `count` parameter specify the number of headers with the same name
/// to return.
fn get_all_headers(this: &mut Message, name: &str) -> EngineResult<rhai::Array> {
    let guard = vsl_guard_ok!(this.read());
    let name_lowercase = name.to_lowercase();

    Ok(guard
        .inner()
        .headers(true)
        .into_iter()
        .filter(|(key, _)| key.to_lowercase() == name_lowercase)
        .map(|(_, value)| rhai::Dynamic::from(value))
        .collect())
}

/// internal generic function to count the occurrence of a header.
fn count_header<T>(message: &mut Message, header: &T) -> EngineResult<rhai::INT>
where
    T: AsRef<str> + ?Sized,
{
    vsl_guard_ok!(message.read())
        .count_header(header.as_ref())
        .try_into()
        .map_err::<Box<rhai::EvalAltResult>, _>(|_| "header count overflowed".into())
}

/// internal generic function to append a header to the message.
fn append_header<T, U>(message: &mut Message, header: &T, value: &U) -> EngineResult<()>
where
    T: AsRef<str> + ?Sized,
    U: AsRef<str> + ?Sized,
{
    vsl_guard_ok!(message.write()).append_header(header.as_ref(), value.as_ref());
    Ok(())
}

/// internal generic function to prepend a header to the message.
fn prepend_header<T, U>(message: &mut Message, header: &T, value: &U) -> EngineResult<()>
where
    T: AsRef<str> + ?Sized,
    U: AsRef<str> + ?Sized,
{
    vsl_guard_ok!(message.write()).prepend_header(header.as_ref(), value.as_ref());
    Ok(())
}

/// internal generic function to set the value of a header.
fn set_header<T, U>(message: &mut Message, header: &T, value: &U) -> EngineResult<()>
where
    T: AsRef<str> + ?Sized,
    U: AsRef<str> + ?Sized,
{
    vsl_guard_ok!(message.write()).set_header(header.as_ref(), value.as_ref());
    Ok(())
}

/// internal generic function to rename a header.
fn rename_header<T, U>(message: &mut Message, old: &T, new: &U) -> EngineResult<()>
where
    T: AsRef<str> + ?Sized,
    U: AsRef<str> + ?Sized,
{
    vsl_guard_ok!(message.write()).rename_header(old.as_ref(), new.as_ref());
    Ok(())
}

/// internal generic function to remove a header.
fn remove_header<T>(message: &mut Message, header: &T) -> EngineResult<bool>
where
    T: AsRef<str> + ?Sized,
{
    Ok(vsl_guard_ok!(message.write()).remove_header(header.as_ref()))
}

#[cfg(test)]
mod test {
    use vsmtp_mail_parser::MessageBody;

    use super::*;
    use crate::dsl::object::Object;

    #[test]
    fn test_has_header_success() {
        let mut message = std::sync::Arc::new(std::sync::RwLock::new(MessageBody::default()));

        append_header_str_str(&mut message, "X-HEADER-1", "VALUE-1").unwrap();
        append_header_str_obj(
            &mut message,
            "X-HEADER-2",
            std::sync::Arc::new(Object::Str("VALUE-2".to_string())),
        )
        .unwrap();

        assert!(has_header_str(&mut message, "X-HEADER-1").unwrap());
        assert!(has_header_str(&mut message, "X-HEADER-2").unwrap());
        assert!(!has_header_str(&mut message, "X-HEADER-3").unwrap());
    }

    #[test]
    fn test_get_header_success() {
        let mut message = std::sync::Arc::new(std::sync::RwLock::new(MessageBody::default()));

        append_header_str_str(&mut message, "X-HEADER-1", "VALUE-1").unwrap();
        append_header_str_obj(
            &mut message,
            "X-HEADER-2",
            std::sync::Arc::new(Object::Str("VALUE-2".to_string())),
        )
        .unwrap();

        assert_eq!(
            get_header_str(&mut message, "X-HEADER-1").unwrap(),
            "VALUE-1"
        );
        assert_eq!(
            get_header_str(&mut message, "X-HEADER-2").unwrap(),
            "VALUE-2"
        );
        assert_eq!(get_header_str(&mut message, "X-HEADER-3").unwrap(), "");
    }

    #[test]
    fn test_append_header_success() {
        let mut message = std::sync::Arc::new(std::sync::RwLock::new(MessageBody::default()));

        append_header_str_str(&mut message, "X-HEADER-1", "VALUE-1").unwrap();
        append_header_str_obj(
            &mut message,
            "X-HEADER-2",
            std::sync::Arc::new(Object::Str("VALUE-2".to_string())),
        )
        .unwrap();

        assert_eq!(
            message.read().unwrap().get_header("X-HEADER-1").unwrap(),
            "VALUE-1"
        );
        assert_eq!(
            message.read().unwrap().get_header("X-HEADER-2").unwrap(),
            "VALUE-2"
        );
    }

    #[test]
    fn test_prepend_header_success() {
        let mut message = std::sync::Arc::new(std::sync::RwLock::new(MessageBody::default()));

        prepend_header_str_str(&mut message, "X-HEADER-1", "VALUE-1").unwrap();
        prepend_header_str_obj(
            &mut message,
            "X-HEADER-2",
            std::sync::Arc::new(Object::Str("VALUE-2".to_string())),
        )
        .unwrap();

        assert_eq!(
            message.read().unwrap().get_header("X-HEADER-1").unwrap(),
            "VALUE-1"
        );
        assert_eq!(
            message.read().unwrap().get_header("X-HEADER-2").unwrap(),
            "VALUE-2"
        );
    }

    #[test]
    fn test_set_header_success() {
        let mut message = std::sync::Arc::new(std::sync::RwLock::new(MessageBody::default()));

        set_header_str_str(&mut message, "X-HEADER", "VALUE-1").unwrap();
        assert_eq!(
            message.read().unwrap().get_header("X-HEADER").unwrap(),
            "VALUE-1"
        );

        set_header_str_obj(
            &mut message,
            "X-HEADER",
            std::sync::Arc::new(Object::Str("VALUE-2".to_string())),
        )
        .unwrap();

        assert_eq!(
            message.read().unwrap().get_header("X-HEADER").unwrap(),
            "VALUE-2"
        );

        assert_eq!(count_header(&mut message, "X-HEADER").unwrap(), 1);
    }
}
