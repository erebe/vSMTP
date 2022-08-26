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

///
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum Details {
    ///
    Mechanism(String),
    ///
    Problem(String),
}

/// The result of evaluating an SPF query.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Result {
    ///
    pub result: String,
    ///
    pub details: Details,
}

impl From<viaspf::QueryResult> for Result {
    fn from(other: viaspf::QueryResult) -> Self {
        Self {
            result: other.spf_result.to_string(),
            details: other
                .cause
                .map_or(
                    Details::Mechanism("default".to_string()),
                    |cause| match cause {
                        viaspf::SpfResultCause::Match(mechanism) => {
                            Details::Mechanism(mechanism.to_string())
                        }
                        viaspf::SpfResultCause::Error(error) => Details::Problem(error.to_string()),
                    },
                ),
        }
    }
}

///
pub async fn evaluate(
    resolver: &impl viaspf::lookup::Lookup,
    ip: std::net::IpAddr,
    sender: &viaspf::Sender,
) -> Result {
    viaspf::evaluate_sender(resolver, &viaspf::Config::default(), ip, sender, None)
        .await
        .into()
}
