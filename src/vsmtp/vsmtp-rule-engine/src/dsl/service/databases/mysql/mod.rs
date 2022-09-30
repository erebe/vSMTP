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

pub mod connection_manager;
pub mod parsing;

use anyhow::{self, Context};
use mysql::prelude::Queryable;

pub fn query(
    pool: &r2d2::Pool<connection_manager::MySQLConnectionManager>,
    query: &str,
) -> anyhow::Result<Vec<rhai::Map>> {
    let result = pool
        .get()?
        .query::<mysql::Row, _>(query)
        .context("failed to execute query on sql database")?;

    let mut rows = Vec::with_capacity(result.len());

    for row in &result {
        let mut values = rhai::Map::new();

        for (index, column) in row.columns().iter().enumerate() {
            values.insert(
                column.name_str().into(),
                row.as_ref(index)
                    .ok_or_else(|| anyhow::anyhow!("failed to convert sql row value to string"))?
                    .as_sql(false)
                    .into(),
            );
        }

        rows.push(values);
    }

    Ok(rows)
}
