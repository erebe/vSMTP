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

/// Type of SMTP connection.
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    Eq,
    PartialEq,
    Hash,
    strum::Display,
    strum::EnumString,
    serde_with::DeserializeFromStr,
    serde_with::SerializeDisplay,
)]
#[strum(serialize_all = "lowercase")]
#[non_exhaustive]
pub enum ConnectionKind {
    /// Connection coming for relay (MTA on port 25)
    /// see <https://datatracker.ietf.org/doc/html/rfc5321>
    #[default]
    Relay,
    /// Connection coming for submission (MSA on port 587)
    /// see <https://datatracker.ietf.org/doc/html/rfc6409>
    Submission,
    /// Connection coming for submissionS (MSA on port 465)
    /// see <https://datatracker.ietf.org/doc/html/rfc8314>
    Tunneled,
}
