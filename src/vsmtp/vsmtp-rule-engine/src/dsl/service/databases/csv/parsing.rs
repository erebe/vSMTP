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

use super::{access::AccessMode, refresh::Refresh};

#[derive(Debug, serde::Deserialize)]
struct CSVDatabaseParameters {
    /// Path to the csv file.
    connector: std::path::PathBuf,
    /// Write & read access modes.
    #[serde(default = "default_access")]
    access: AccessMode,
    /// Refresh policy.
    #[serde(default = "default_refresh")]
    refresh: Refresh,
    /// Delimiter used to separate fields.
    #[serde(default = "default_delimiter")]
    delimiter: char,
}

const fn default_access() -> AccessMode {
    AccessMode::ReadWrite
}

const fn default_refresh() -> Refresh {
    Refresh::Always
}

const fn default_delimiter() -> char {
    ','
}

pub struct CSVParser;

impl Parser for CSVParser {
    fn service_type(&self) -> &'static str {
        "csv"
    }

    fn parse_service(&self, service: &str, parameters: rhai::Map) -> EngineResult<Service> {
        let parameters: CSVDatabaseParameters =
            deserialize_rhai_map(service, self.service_type(), parameters)?;

        let fd = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .read(match parameters.access {
                AccessMode::ReadWrite | AccessMode::Read => true,
                AccessMode::Write => false,
            })
            .write(match parameters.access {
                AccessMode::ReadWrite | AccessMode::Write => true,
                AccessMode::Read => false,
            })
            .open(&parameters.connector)
            .map_err::<Box<rhai::EvalAltResult>, _>(|err| {
                format!(
                    "could not load database at {:?}: {}",
                    parameters.connector, err
                )
                .into()
            })?;

        Ok(Service::CSVDatabase {
            path: parameters.connector,
            delimiter: parameters.delimiter,
            access: parameters.access,
            refresh: parameters.refresh,
            fd,
        })
    }
}
