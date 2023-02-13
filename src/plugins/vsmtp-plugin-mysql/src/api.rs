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

use anyhow::{self, Context};
use mysql::prelude::Queryable;
use rhai::plugin::{
    mem, Dynamic, FnAccess, FnNamespace, ImmutableString, Module, NativeCallContext,
    PluginFunction, RhaiResult, TypeId,
};
use vsmtp_rule_engine::rhai;

/// Parameters available for the mysql service. Used
/// with serde for easy parsing.
#[derive(Debug, serde::Deserialize)]
struct MySQLDatabaseParameters {
    pub url: String,
    #[serde(default = "default_timeout", with = "humantime_serde")]
    pub timeout: std::time::Duration,
    #[serde(default = "default_connections")]
    pub connections: rhai::INT,
}

const fn default_connections() -> rhai::INT {
    4
}

const fn default_timeout() -> std::time::Duration {
    std::time::Duration::from_secs(30)
}

/// A r2d2 connection manager for mysql.
#[derive(Clone, Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct ConnectionManager {
    params: mysql::Opts,
}

impl ConnectionManager {
    pub fn new(params: mysql::OptsBuilder) -> Self {
        Self {
            params: mysql::Opts::from(params),
        }
    }
}

impl r2d2::ManageConnection for ConnectionManager {
    type Connection = mysql::Conn;
    type Error = mysql::Error;

    fn connect(&self) -> Result<mysql::Conn, mysql::Error> {
        mysql::Conn::new(self.params.clone())
    }

    fn is_valid(&self, conn: &mut mysql::Conn) -> Result<(), mysql::Error> {
        mysql::prelude::Queryable::query(conn, "SELECT version()").map(|_: Vec<String>| ())
    }

    fn has_broken(&self, conn: &mut mysql::Conn) -> bool {
        self.is_valid(conn).is_err()
    }
}

/// A database connector based on mysql.
#[derive(Debug, Clone)]
pub struct MySQLConnector {
    /// The url to the database.
    pub url: String,
    /// connection pool for the database.
    pub pool: r2d2::Pool<ConnectionManager>,
}

impl MySQLConnector {
    pub fn query(&self, query: &str) -> anyhow::Result<Vec<rhai::Map>> {
        let result = self
            .pool
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
                        .ok_or_else(|| {
                            anyhow::anyhow!("failed to convert sql row value to string")
                        })?
                        .as_sql(false)
                        .into(),
                );
            }

            rows.push(values);
        }

        Ok(rows)
    }
}

/// This plugin exposes methods to open a pool of connexions to a mysql database using
/// Rhai.
#[rhai::plugin::export_module]
pub mod mysql_api {

    pub type MySQL = rhai::Shared<MySQLConnector>;

    /// Open a pool of connections to a MySQL database.
    ///
    /// # Args
    ///
    /// * `parameters` - a map of the following parameters:
    ///     * `url` - a string url to connect to the database.
    ///     * `timeout` - time allowed between each query to the database. (default: 30s)
    ///     * `connections` - Number of connections to open to the database. (default: 4)
    ///
    /// # Return
    ///
    /// A service used to query the database pointed by the `url` parameter.
    ///
    /// # Error
    ///
    /// * The service failed to connect to the database.
    ///
    /// # Example
    ///
    /// ```text
    /// // Import the plugin stored in the `plugins` directory.
    /// import "plugins/libvsmtp_plugin_mysql" as mysql;
    ///
    /// export const database = mysql::connect(#{
    ///     // Connect to a database on the system with the 'greylist-manager' user and 'my-password' password.
    ///     url: "mysql://localhost/?user=greylist-manager&password=my-password",
    ///     timeout: "1m",
    ///     connections: 1,
    /// });
    /// ```
    #[rhai_fn(global, return_raw)]
    pub fn connect(parameters: rhai::Map) -> Result<MySQL, Box<rhai::EvalAltResult>> {
        let parameters = rhai::serde::from_dynamic::<MySQLDatabaseParameters>(&parameters.into())?;

        let opts = mysql::Opts::from_url(&parameters.url)
            .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?;
        let builder = mysql::OptsBuilder::from_opts(opts);
        let manager = ConnectionManager::new(builder);

        Ok(rhai::Shared::new(MySQLConnector {
            url: parameters.url,
            pool: r2d2::Pool::builder()
                .max_size(
                    u32::try_from(parameters.connections)
                        .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?,
                )
                .connection_timeout(parameters.timeout)
                .build(manager)
                .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?,
        }))
    }

    /// Query the database.
    ///
    /// # Args
    ///
    /// * `query` - The query to execute.
    ///
    /// # Return
    ///
    /// A list of records.
    ///
    /// # Example
    ///
    /// Build a service in `services/database.vsl`;
    ///
    /// ```text
    /// // Import the plugin stored in the `plugins` directory.
    /// import "plugins/libvsmtp_plugin_mysql" as mysql;
    ///
    /// export const database = mysql::connect(#{
    ///     // Connect to a database on the system with the 'greylist-manager' user and 'my-password' password.
    ///     url: "mysql://localhost/?user=greylist-manager&password=my-password",
    ///     timeout: "1m",
    ///     connections: 1,
    /// });
    /// ```
    ///
    /// Query the database during filtering.
    ///
    /// ```text
    /// import "services/database" as srv;
    ///
    /// #{
    ///     connect: [
    ///         action "get records from my database" || {
    ///             // For the sake of this example, we assume that there is a populated
    ///             // table called 'my_table' in the database.
    ///             const records = srv::database.query("SELECT * FROM my_table");
    ///
    ///             // `records` is an array, we can run a for loop and print all records.
    ///             log("info", "fetching mysql records ...");
    ///             for record in records {
    ///                 log("info", ` -> ${record}`);
    ///             }
    ///         }
    ///     ],
    /// }
    /// ```
    #[rhai_fn(global, name = "query", return_raw, pure)]
    pub fn query_str(
        database: &mut MySQL,
        query: &str,
    ) -> Result<rhai::Array, Box<rhai::EvalAltResult>> {
        super::query(database, query)
    }

    /// Query the database.
    ///
    /// # Args
    ///
    /// * `query` - The query to execute.
    ///
    /// # Return
    ///
    /// A list of records.
    ///
    /// # Example
    ///
    /// Build a service in `services/database.vsl`;
    ///
    /// ```text
    /// // Import the plugin stored in the `plugins` directory.
    /// import "plugins/libvsmtp_plugin_mysql" as mysql;
    ///
    /// export const database = mysql::connect(#{
    ///     // Connect to a database on the system with the 'greylist-manager' user and 'my-password' password.
    ///     url: "mysql://localhost/?user=greylist-manager&password=my-password",
    ///     timeout: "1m",
    ///     connections: 1,
    /// });
    /// ```
    ///
    /// Query the database during filtering.
    ///
    /// ```text
    /// import "services/database" as srv;
    ///
    /// #{
    ///     connect: [
    ///         action "get records from my database" || {
    ///             // For the sake of this example, we assume that there is a populated
    ///             // table called 'my_table' in the database.
    ///             const records = srv::database.query("SELECT * FROM my_table");
    ///
    ///             // `records` is an array, we can run a for loop and print all records.
    ///             log("info", "fetching mysql records ...");
    ///             for record in records {
    ///                 log("info", ` -> ${record}`);
    ///             }
    ///         }
    ///     ],
    /// }
    /// ```
    #[rhai_fn(global, name = "query", return_raw, pure)]
    pub fn query_obj(
        database: &mut MySQL,
        query: vsmtp_rule_engine::api::SharedObject,
    ) -> Result<rhai::Array, Box<rhai::EvalAltResult>> {
        super::query(database, &query.to_string())
    }
}

/// Query a database.
fn query(
    database: &mysql_api::MySQL,
    query: &str,
) -> Result<rhai::Array, Box<rhai::EvalAltResult>> {
    database.query(query).map_or_else(
        |_| Ok(rhai::Array::default()),
        |record| Ok(record.into_iter().map(rhai::Dynamic::from).collect()),
    )
}
