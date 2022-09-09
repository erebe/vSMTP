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
    dsl::service::{deserialize_rhai_map, Parser, Service},
};

#[derive(Debug, serde::Deserialize)]
struct MySQLDatabaseParameters {
    url: String,
    #[serde(default = "default_timeout", with = "humantime_serde")]
    timeout: std::time::Duration,
    #[serde(default = "default_connections")]
    connections: rhai::INT,
}

const fn default_connections() -> rhai::INT {
    4
}

const fn default_timeout() -> std::time::Duration {
    std::time::Duration::from_secs(30)
}

pub struct MySQLParser;

impl Parser for MySQLParser {
    fn service_type(&self) -> &'static str {
        "mysql"
    }

    fn parse_service(&self, service: &str, parameters: rhai::Map) -> EngineResult<Service> {
        let parameters: MySQLDatabaseParameters =
            deserialize_rhai_map(service, self.service_type(), parameters)?;

        let opts = mysql::Opts::from_url(&parameters.url)
            .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?;
        let builder = mysql::OptsBuilder::from_opts(opts);
        let manager = super::connection_manager::MySQLConnectionManager::new(builder);

        Ok(Service::MySQLDatabase {
            name: service.to_string(),
            url: parameters.url,
            pool: r2d2::Pool::builder()
                .max_size(
                    u32::try_from(parameters.connections)
                        .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?,
                )
                .connection_timeout(parameters.timeout)
                .build(manager)
                .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?,
        })
    }
}
