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

pub mod access;
pub mod parsing;
pub mod refresh;

use anyhow::{self, Context};
use std::io::Write;

/// query a record matching the first element.
pub fn query(
    path: &std::path::PathBuf,
    delimiter: char,
    _: &refresh::Refresh,
    fd: &std::fs::File,
    key: &str,
) -> anyhow::Result<Option<csv::StringRecord>> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .trim(csv::Trim::All)
        .delimiter(u8::try_from(delimiter)?)
        .from_reader(fd);

    for record in reader.records() {
        match record {
            Ok(record) => {
                if record.get(0).filter(|fst| *fst == key).is_some() {
                    return Ok(Some(record));
                }
            }
            Err(err) => anyhow::bail!(
                "tried to read from csv database {path:?}, but an error occurred: {err}"
            ),
        };
    }

    Ok(None)
}

/// add a record to the csv database.
pub fn add_record(
    path: &std::path::PathBuf,
    delimiter: char,
    fd: &std::fs::File,
    record: &[String],
) -> anyhow::Result<()> {
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .delimiter(u8::try_from(delimiter)?)
        .from_writer(fd);

    writer
        .write_record(record)
        .context(format!("failed to write to csv database at {path:?}"))?;

    writer
        .flush()
        .context(format!("failed to write to csv database at {path:?}"))?;

    Ok(())
}

/// remove a record from a csv database.
pub fn remove_record(path: &std::path::PathBuf, key: &str) -> anyhow::Result<()> {
    let content = std::fs::read_to_string(path)
        .context(format!("failed to read a csv database at {path:?}"))?;

    let mut writer = std::io::BufWriter::new(
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .context(format!("failed to open a csv database at {path:?}"))?,
    );

    for line in content.lines() {
        if !line.starts_with(key) {
            writer
                .write_vectored(&[
                    std::io::IoSlice::new(line.as_bytes()),
                    std::io::IoSlice::new(b"\n"),
                ])
                .context(format!("failed to update a csv database at {path:?}"))?;
        }
    }

    writer
        .flush()
        .context(format!("failed to update a csv database at {path:?}"))?;

    Ok(())
}
