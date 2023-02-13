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

/// Error while processing the TCP/IP stream.
#[derive(Debug, thiserror::Error)]
#[allow(clippy::exhaustive_enums)]
pub enum Error {
    /// The buffer is longer than expected.
    #[error("buffer is not supposed to be longer than {expected} bytes but got {got}")]
    BufferTooLong {
        /// Maximum size expected.
        expected: usize,
        /// Actual size.
        got: usize,
    },
    /// Other IO error.
    // TODO: enhance that
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// Invalid UTF-8.
    #[error("{0}")]
    Utf8(#[from] std::str::Utf8Error),
}
