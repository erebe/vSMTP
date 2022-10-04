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
use vsmtp_config::Config;

/// parse a service using rhai's parser.
pub fn parse_service(
    symbols: &[rhai::ImmutableString],
    look_ahead: &str,
    _state: &mut rhai::Dynamic,
) -> Result<Option<rhai::ImmutableString>, rhai::ParseError> {
    match symbols.len() {
        // service keyword, then the name of it.
        1 | 2 => Ok(Some("$ident$".into())),
        // type of the service.
        3 => Ok(Some("$symbol$".into())),
        4 => match symbols[3].as_str() {
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
        5 => Ok(None),
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

    let parameters: rhai::Map = context
        .eval_expression_tree(&input[3])?
        .try_cast()
        .ok_or_else::<Box<rhai::EvalAltResult>, _>(|| {
            "service options must be declared with a rhai map `#{}`".into()
        })?;

    // vsl_service_plugin_manager
    //     .plugins
    //     .iter()
    //     .find(|(_, plugin)| plugin.service_type_token() == service_type)
    //     .ok_or_else::<Box<rhai::EvalAltResult>, _>(|| {
    //         format!("The '{service_type}' service type does not exist").into()
    //     })?
    //     .1
    //     .register(service_name, parameters)
    //     .map_err(|err| err.to_string().into())

    let service = todo!("call the associated service plugin function to generate the service.");

    // let ptr = rhai::Shared::new(service);

    // // Pushing service in scope, preventing a "let _" statement,
    // // and returning a reference to the object in case of a parent group.
    // // Also, exporting the variable by default using `set_alias`.
    // context
    //     .scope_mut()
    //     .push_constant(&service_name, ptr.clone())
    //     .set_alias(service_name, "");

    // Ok(rhai::Dynamic::from(ptr))
}
