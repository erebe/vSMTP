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
use crate::{api::EngineResult, error::CompilationError};

pub fn create(
    context: &mut rhai::EvalContext<'_, '_, '_, '_, '_, '_>,
    input: &[rhai::Expression<'_>],
    _state: &rhai::Dynamic,
) -> EngineResult<rhai::Dynamic> {
    let service = context.eval_expression_tree(&input[0])?;
    let name = input[1]
        .get_literal_value::<rhai::ImmutableString>()
        .unwrap();
    let expr = context.eval_expression_tree(&input[2])?;

    Ok(rhai::Dynamic::from(
        [
            ("name".into(), rhai::Dynamic::from(name.clone())),
            ("service".into(), rhai::Dynamic::from(service)),
            ("type".into(), "delegate".into()),
        ]
        .into_iter()
        .chain(if expr.is::<rhai::Map>() {
            let properties = expr.cast::<rhai::Map>();

            if properties
                .get("evaluate")
                .filter(|f| f.is::<rhai::FnPtr>())
                .is_none()
            {
                return Err(
                    format!("'evaluate' function is missing from '{name}' delegation").into(),
                );
            }

            properties.into_iter()
        } else if expr.is::<rhai::FnPtr>() {
            rhai::Map::from_iter([("evaluate".into(), expr)]).into_iter()
        } else {
            return Err(format!(
                "a delegation must be a rhai::Map (#{{}}) or an anonymous function (|| {{}}){}",
                CompilationError::Action.as_str()
            )
            .into());
        })
        .collect::<rhai::Map>(),
    ))
}
