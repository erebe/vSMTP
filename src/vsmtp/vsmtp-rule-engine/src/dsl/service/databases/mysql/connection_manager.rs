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

/// A r2d2 connection manager for mysql.
#[derive(Clone, Debug)]
#[allow(clippy::module_name_repetitions)]
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
        mysql::prelude::Queryable::query(conn, "SELECT version()").map(|_: Vec<String>| ())
    }

    fn has_broken(&self, conn: &mut mysql::Conn) -> bool {
        self.is_valid(conn).is_err()
    }
}
