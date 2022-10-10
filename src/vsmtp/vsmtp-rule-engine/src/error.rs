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
use vsmtp_common::state::State;
use vsmtp_plugins::rhai;

#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub enum CompilationError {
    Rule,
    Action,
    Stage,
}

impl CompilationError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Rule => {
                r#"failed to parse a rule.
    use the following syntax:

    rule "name" || {
        ... // your code to execute.
        sys::next() // must end with a status. (next, accept, faccept ...)
    },
"#
            }

            Self::Action => {
                r#"failed to parse an action.
    use the following syntax:

    action "name" || {
        ... // your code to execute.
    };
"#
            }

            Self::Stage => {
                r#"failed to parse a stage.
    declare stages this way:

    #{
        preq: [
            ...  // rules & actions
        ],

        delivery: [
            ...
        ]
    }
"#
            }
        }
    }
}

impl std::fmt::Display for CompilationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::error::Error for CompilationError {}

impl From<CompilationError> for Box<rhai::EvalAltResult> {
    fn from(err: CompilationError) -> Self {
        err.as_str().into()
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("a lock guard is poisoned: `{source}`")]
    PoisonedGuard { source: anyhow::Error },
    #[error(
        "the field: `{field}` is not defined yet, it only is available from the `{stage}` stage"
    )]
    MissingField { field: String, stage: State },
    #[error("failed to parse the message body, `{source}`")]
    ParseMessageBody { source: anyhow::Error },
    #[error("invalid type conversion expected: `{r#type}`, but got: `{source}`")]
    TypeError {
        r#type: &'static str,
        source: anyhow::Error,
    },
    #[error("vsl runtime error: `{message}`")]
    Generic { message: String },
}

#[macro_export]
/// An error formatting macro for rhai context similar to the [`anyhow::anyhow`] macro.
macro_rules! vsl_err {
    ($message:expr) => {
        Err(RuntimeError::Generic {
            message: format!($message),
        }
        .into::<Box<rhai::EvalAltResult>>())
    };
}

#[macro_export]
/// A bail macro for rhai context similar to [`anyhow::bail`] macro.
macro_rules! vsl_bail {
    ($message:expr) => {
        return vsl_err!(message);
    };
}

#[macro_export]
/// Transforms a generic error in a result into the rhai boxed eval alt result.
macro_rules! vsl_ok {
    ($result:expr) => {
        $result.map_err::<Box<rhai::EvalAltResult>, _>(|err| {
            RuntimeError::Generic {
                message: err.to_string(),
            }
            .into()
        })?
    };
}

#[macro_export]
/// Transforms a generic error into the rhai boxed eval alt result.
macro_rules! vsl_generic_ok {
    ($result:expr) => {
        $result.map_err::<Box<vsmtp_plugins::rhai::EvalAltResult>, _>(|e| e.to_string().into())?
    };
}

#[macro_export]
/// checks if the mutex is poisoned & return a rhai runtime error if it is.
macro_rules! vsl_guard_ok {
    ($guard:expr) => {
        $guard.map_err::<Box<vsmtp_plugins::rhai::EvalAltResult>, _>(|e| {
            $crate::error::RuntimeError::PoisonedGuard {
                source: anyhow::anyhow!("{e}"),
            }
            .into()
        })?
    };
}

macro_rules! vsl_missing_ok {
    ($option:expr, $field:expr, $stage:expr) => {
        $option
            .as_ref()
            .ok_or_else(|| $crate::error::RuntimeError::MissingField {
                field: $field.to_string(),
                stage: $stage,
            })?
    };
    (mut $option:expr, $field:expr,  $stage:expr) => {
        $option
            .as_mut()
            .ok_or_else(|| $crate::error::RuntimeError::MissingField {
                field: $field.to_string(),
                stage: $stage,
            })?
    };
}

macro_rules! vsl_parse_ok {
    ($message:expr) => {{
        $message
            .parsed::<vsmtp_mail_parser::MailMimeParser>()
            .map_err(|source| $crate::error::RuntimeError::ParseMessageBody { source })?
    }};
}

macro_rules! vsl_conversion_ok {
    ($type_:expr, $result:expr) => {
        $result.map_err(|source| $crate::error::RuntimeError::TypeError {
            r#type: $type_,
            source,
        })?
    };
}

impl From<RuntimeError> for Box<rhai::EvalAltResult> {
    fn from(err: RuntimeError) -> Self {
        err.to_string().into()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_error_formatting() {
        println!("{}", CompilationError::Rule);
        println!("{}", CompilationError::Action);
        println!("{}", CompilationError::Stage);

        println!("{:?}", CompilationError::Rule);
        println!("{:?}", CompilationError::Action);
        println!("{:?}", CompilationError::Stage);
    }

    #[test]
    fn test_error_from_rhai_error() {
        let rhai_err: Box<rhai::EvalAltResult> = CompilationError::Rule.into();
        println!("{}", rhai_err);
        let rhai_err: Box<rhai::EvalAltResult> = CompilationError::Action.into();
        println!("{}", rhai_err);
        let rhai_err: Box<rhai::EvalAltResult> = CompilationError::Stage.into();
        println!("{}", rhai_err);
    }
}
