use vsmtp_config::Config;

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
use crate::api::EngineResult;

use super::{cmd::parsing::CmdParser, smtp::parsing::SmtpParser, Parser};

/// parse a service using rhai's parser.
pub fn parse_service(
    symbols: &[rhai::ImmutableString],
    look_ahead: &str,
) -> Result<Option<rhai::ImmutableString>, rhai::ParseError> {
    match symbols.len() {
        // service keyword, then the name of it.
        1 | 2 => Ok(Some("$ident$".into())),
        // type of the service.
        3 => match symbols[2].as_str() {
            // for a regular service, next is the '=' token or ':' token in case of the db type.
            "cmd" | "smtp" | "db" => Ok(Some("$symbol$".into())),
            entry => Err(rhai::ParseError(
                Box::new(rhai::ParseErrorType::BadInput(
                    rhai::LexError::ImproperSymbol(
                        entry.into(),
                        format!("Improper service type '{}'.", entry),
                    ),
                )),
                rhai::Position::NONE,
            )),
        },
        4 => match symbols[3].as_str() {
            // ':' token for a database format, next is the actual format.
            ":" => Ok(Some("$ident$".into())),
            // '=' token for another service type, next is the options of the service.
            "=" => Ok(Some("$expr$".into())),
            entry => Err(rhai::ParseError(
                Box::new(rhai::ParseErrorType::BadInput(
                    rhai::LexError::ImproperSymbol(
                        entry.into(),
                        "Improper symbol when parsing service".to_string(),
                    ),
                )),
                rhai::Position::NONE,
            )),
        },
        5 => match symbols[4].as_str() {
            // database formats
            "csv" => Ok(Some("=".into())),
            #[cfg(feature = "mysql")]
            "mysql" => Ok(Some("=".into())),
            // an expression, in the case of a regular service, whe are done parsing.
            _ if symbols[3].as_str() == "=" => Ok(None),
            r#type => Err(rhai::ParseError(
                Box::new(rhai::ParseErrorType::BadInput(
                    rhai::LexError::ImproperSymbol(
                        "unknown database type (maybe you are missing a database feature ?)"
                            .to_string(),
                        r#type.to_string(),
                    ),
                )),
                rhai::Position::NONE,
            )),
        },
        6 => match symbols[5].as_str() {
            // the '=' token, next is the database options.
            "=" => Ok(Some("$expr$".into())),
            // option map for a service, we are done parsing.
            _ => Ok(None),
        },
        7 => Ok(None),
        _ => Err(rhai::ParseError(
            Box::new(rhai::ParseErrorType::BadInput(
                rhai::LexError::UnexpectedInput(format!(
                    "Improper service declaration: keyword '{}' unknown.",
                    look_ahead
                )),
            )),
            rhai::Position::NONE,
        )),
    }
}

/// parses the given syntax tree and construct a service from it.
pub fn create_service(
    context: &mut rhai::EvalContext<'_, '_, '_, '_, '_, '_, '_, '_, '_>,
    input: &[rhai::Expression<'_>],
    // NOTE: not used right now, but could be used to configure
    //       tls parameters for delegation (smtp service) separately from regular
    //       sockets config.
    //
    //       to remove if configured using vsl.
    _: &Config,
) -> EngineResult<rhai::Dynamic> {
    let service_name = input[0].get_string_value().unwrap().to_string();
    let service_type = input[1].get_string_value().unwrap().to_string();

    let service = match service_type.as_str() {
        "db" => {
            crate::dsl::service::databases::parse_database_service(context, input, &service_name)
        }
        _ => parse_regular_service(context, input, &service_name, &service_type),
    }?;

    let ptr = std::sync::Arc::new(service);

    // Pushing service in scope, preventing a "let _" statement,
    // and returning a reference to the object in case of a parent group.
    // Also, exporting the variable by default using `set_alias`.
    context
        .scope_mut()
        .push_constant(&service_name, ptr.clone())
        .set_alias(service_name, "");

    Ok(rhai::Dynamic::from(ptr))
}

/// open a file database using the csv crate.
fn parse_regular_service(
    context: &mut rhai::EvalContext<'_, '_, '_, '_, '_, '_, '_, '_, '_>,
    input: &[rhai::Expression<'_>],
    service_name: &str,
    service_type: &str,
) -> EngineResult<super::Service> {
    let options: rhai::Map = context
        .eval_expression_tree(&input[3])?
        .try_cast()
        .ok_or_else::<Box<rhai::EvalAltResult>, _>(|| {
            "service options must be declared with a rhai map `#{}`".into()
        })?;

    let regular_service_parsers: Vec<Box<dyn Parser>> =
        vec![Box::new(SmtpParser), Box::new(CmdParser)];

    regular_service_parsers
        .iter()
        .find(|parser| parser.service_type() == service_type)
        .ok_or_else::<Box<rhai::EvalAltResult>, _>(|| {
            format!("The '{service_type}' service type does not exist").into()
        })?
        .parse_service(service_name, options)
}
