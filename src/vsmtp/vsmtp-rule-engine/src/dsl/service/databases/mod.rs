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

use super::{Parser, Service};
use crate::api::EngineResult;

pub mod csv;
#[cfg(feature = "mysql")]
pub mod mysql;

/// open a file database using the csv crate.
pub fn parse_database_service(
    context: &mut rhai::EvalContext<'_, '_, '_, '_, '_, '_, '_, '_, '_>,
    input: &[rhai::Expression<'_>],
    service_name: &str,
) -> EngineResult<Service> {
    let database_parsers: Vec<Box<dyn Parser>> = vec![
        Box::new(self::csv::parsing::CSVParser),
        #[cfg(feature = "mysql")]
        Box::new(self::mysql::parsing::MySQLParser),
    ];

    let database_type = input[3]
        .get_string_value()
        .ok_or_else::<Box<rhai::EvalAltResult>, _>(|| "failed to get database type".into())?;

    let mut options: rhai::Map = context
        .eval_expression_tree(&input[4])?
        .try_cast()
        .ok_or_else::<Box<rhai::EvalAltResult>, _>(|| {
            "database options must be declared with a rhai map `#{}`".into()
        })?;

    options.insert("name".into(), rhai::Dynamic::from(service_name.to_string()));

    database_parsers
        .iter()
        .find(|parser| parser.service_type() == database_type)
        .ok_or_else::<Box<rhai::EvalAltResult>, _>(|| {
            format!("unknown database type: {}", database_type).into()
        })?
        .parse_service(service_name, options)
}
