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
use std::io::Write;

use super::{access::AccessMode, refresh::Refresh};

/// A database connector based on the csv file format.
#[derive(Debug, Clone)]
pub struct Csv {
    /// A path to the file to open.
    pub path: std::path::PathBuf,
    /// Access mode to the database.
    pub access: AccessMode,
    /// Delimiter character to separate fields in records.
    pub delimiter: char,
    /// Database refresh mode.
    pub refresh: Refresh,
    /// Raw content of the database.
    pub fd: std::sync::Arc<std::fs::File>,
}

impl std::fmt::Display for Csv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "csv")
    }
}

impl Csv {
    /// Query a record matching the first element.
    pub fn query(&self, key: &str) -> anyhow::Result<Option<csv::StringRecord>> {
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(false)
            .trim(csv::Trim::All)
            .delimiter(u8::try_from(self.delimiter)?)
            .from_reader(&*self.fd);

        for record in reader.records() {
            match record {
                Ok(record) => {
                    if record.get(0).filter(|fst| *fst == key).is_some() {
                        return Ok(Some(record));
                    }
                }
                Err(err) => anyhow::bail!(
                    "tried to read from csv database {:?}, but an error occurred: {}",
                    self.path,
                    err
                ),
            };
        }

        Ok(None)
    }

    /// Add a record.
    pub fn add_record(&self, record: &[String]) -> anyhow::Result<()> {
        let mut writer = csv::WriterBuilder::new()
            .has_headers(false)
            .delimiter(u8::try_from(self.delimiter)?)
            .from_writer(&*self.fd);

        writer.write_record(record).context(format!(
            "failed to write to csv database at {:?}",
            self.path
        ))?;

        writer.flush().context(format!(
            "failed to write to csv database at {:?}",
            self.path
        ))?;

        Ok(())
    }

    /// Remove a record.
    pub fn remove_record(&self, key: &str) -> anyhow::Result<()> {
        let content = std::fs::read_to_string(&self.path)
            .context(format!("failed to read a csv database at {:?}", &self.path))?;

        let mut writer = std::io::BufWriter::new(
            std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&self.path)
                .context(format!("failed to open a csv database at {:?}", &self.path))?,
        );

        for line in content.lines() {
            if !line.starts_with(key) {
                writer
                    .write_vectored(&[
                        std::io::IoSlice::new(line.as_bytes()),
                        std::io::IoSlice::new(b"\n"),
                    ])
                    .context(format!(
                        "failed to update a csv database at {:?}",
                        &self.path
                    ))?;
            }
        }

        writer.flush().context(format!(
            "failed to update a csv database at {:?}",
            &self.path
        ))?;

        Ok(())
    }
}
