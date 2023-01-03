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

use vsmtp_plugin_vsl::objects::SharedObject;

use rhai::plugin::{
    mem, Dynamic, FnAccess, FnNamespace, ImmutableString, NativeCallContext, PluginFunction,
    RhaiResult, TypeId,
};
use rhai::Module;

use super::{access::AccessMode, refresh::Refresh};

#[derive(Debug, serde::Deserialize)]
pub struct CsvDatabaseParameters {
    /// Path to the Csv file.
    pub connector: std::path::PathBuf,
    /// Write & read access modes.
    #[serde(default = "default_access")]
    pub access: AccessMode,
    /// Refresh policy.
    #[serde(default = "default_refresh")]
    pub refresh: Refresh,
    /// Delimiter used to separate fields.
    #[serde(default = "default_delimiter")]
    pub delimiter: char,
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

#[rhai::plugin::export_module]
pub mod csv_api {

    type Csv = rhai::Shared<crate::service::Csv>;

    #[rhai_fn(global, return_raw)]
    pub fn csv(parameters: rhai::Map) -> Result<Csv, Box<rhai::EvalAltResult>> {
        let parameters = rhai::serde::from_dynamic::<CsvDatabaseParameters>(&parameters.into())?;

        let fd = std::sync::Arc::new(
            std::fs::OpenOptions::new()
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
                .map_err::<rhai::EvalAltResult, _>(|err| err.to_string().into())?,
        );

        Ok(rhai::Shared::new(crate::service::Csv {
            path: parameters.connector,
            delimiter: parameters.delimiter,
            access: parameters.access,
            refresh: parameters.refresh,
            fd,
        }))
    }

    ///
    #[rhai_fn(global, pure)]
    pub fn to_string(database: &mut Csv) -> String {
        database.to_string()
    }

    ///
    #[rhai_fn(global, pure)]
    pub fn to_debug(database: &mut Csv) -> String {
        format!("{database:#?}")
    }

    /// Add a record.
    #[rhai_fn(global, name = "set", return_raw, pure)]
    pub fn database_add(
        database: &mut Csv,
        record: rhai::Array,
    ) -> Result<(), Box<rhai::EvalAltResult>> {
        let record = record
            .into_iter()
            .map(rhai::Dynamic::try_cast)
            .collect::<Option<Vec<String>>>()
            .ok_or_else::<Box<rhai::EvalAltResult>, _>(|| {
                "all fields in a record must be strings".into()
            })?;

        database
            .add_record(&record)
            .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())
    }

    /// Remove a record.
    #[rhai_fn(global, name = "rm", return_raw, pure)]
    pub fn remove_str(database: &mut Csv, key: &str) -> Result<(), Box<rhai::EvalAltResult>> {
        super::remove(database, key)
    }

    /// Remove a record.
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "rm", return_raw, pure)]
    pub fn remove_obj(
        database: &mut Csv,
        key: SharedObject,
    ) -> Result<(), Box<rhai::EvalAltResult>> {
        super::remove(database, &key.to_string())
    }

    /// Query the database.
    #[rhai_fn(global, name = "get", return_raw, pure)]
    pub fn query_str(
        database: &mut Csv,
        key: &str,
    ) -> Result<rhai::Array, Box<rhai::EvalAltResult>> {
        super::query(database, key)
    }

    /// Query the database.
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "get", return_raw, pure)]
    pub fn query_obj(
        database: &mut Csv,
        key: SharedObject,
    ) -> Result<rhai::Array, Box<rhai::EvalAltResult>> {
        super::query(database, &key.to_string())
    }
}

fn query(
    database: &crate::service::Csv,
    query: &str,
) -> Result<rhai::Array, Box<rhai::EvalAltResult>> {
    database
        .query(query)
        .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())?
        .map_or_else(
            || Ok(rhai::Array::default()),
            |record| {
                Ok(record
                    .into_iter()
                    .map(|field| rhai::Dynamic::from(field.to_string()))
                    .collect())
            },
        )
}

fn remove(database: &crate::service::Csv, key: &str) -> Result<(), Box<rhai::EvalAltResult>> {
    database
        .remove_record(key)
        .map_err::<Box<rhai::EvalAltResult>, _>(|err| err.to_string().into())
}
