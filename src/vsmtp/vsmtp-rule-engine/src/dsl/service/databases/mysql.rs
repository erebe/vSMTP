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

use crate::{
    api::EngineResult,
    dsl::service::{get_or_default, Service},
};
use anyhow::Context;
use mysql::prelude::Queryable;

/// A r2d2 connection manager for mysql.
#[derive(Clone, Debug)]
pub struct MySQLConnectionManager {
    params: mysql::Opts,
}

impl MySQLConnectionManager {
    pub fn new(params: mysql::OptsBuilder) -> MySQLConnectionManager {
        MySQLConnectionManager {
            params: mysql::Opts::from(params),
        }
    }
}

impl r2d2::ManageConnection for MySQLConnectionManager {
    type Connection = mysql::Conn;
    type Error = mysql::Error;

    fn connect(&self) -> Result<mysql::Conn, mysql::Error> {
        mysql::Conn::new(self.params.clone())
    }

    fn is_valid(&self, conn: &mut mysql::Conn) -> Result<(), mysql::Error> {
        conn.query("SELECT version()").map(|_: Vec<String>| ())
    }

    fn has_broken(&self, conn: &mut mysql::Conn) -> bool {
        self.is_valid(conn).is_err()
    }
}

pub fn query(
    pool: &r2d2::Pool<MySQLConnectionManager>,
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

pub fn parse_mysql_database(db_name: &str, options: &rhai::Map) -> EngineResult<Service> {
    for key in ["url"] {
        if !options.contains_key(key) {
            return Err(format!("database {db_name} is missing the '{key}' option.").into());
        }
    }

    let mut url = options.get("url").unwrap().to_string();
    let timeout: std::time::Duration =
        get_or_default::<String>(db_name, options, "timeout", Some("30s".to_string()))?
            .parse::<humantime::Duration>()
            .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?
            .into();
    let connections = u32::try_from(get_or_default::<rhai::INT>(
        db_name,
        options,
        "connections",
        Some(4),
    )?)
    .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?;
    let user = options.get("user");
    let password = options.get("password");

    match (user, password) {
        (Some(user), Some(password)) => url = format!("{url}?user={user}&password={password}"),
        (Some(user), None) => url = format!("{url}?user={user}"),
        _ => {}
    };

    let opts = mysql::Opts::from_url(&url).unwrap();
    let builder = mysql::OptsBuilder::from_opts(opts);
    let manager = MySQLConnectionManager::new(builder);

    Ok(Service::MySQLDatabase {
        url,
        pool: r2d2::Pool::builder()
            .max_size(connections)
            .connection_timeout(timeout)
            .build(manager)
            .unwrap(),
    })
}
