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
pub struct CmdParameters {
    /// The command to execute in the subprocess
    command: String,
    /// Optional: parameters directly given to the executed program (argc, argv)
    args: Option<Vec<String>>,
    /// A duration after which the subprocess will be forced-kill
    #[serde(default = "default_timeout", with = "humantime_serde")]
    timeout: std::time::Duration,
    /// Optional: a user to run the subprocess under
    user: Option<String>,
    /// Optional: a group to run the subprocess under
    group: Option<String>,
}

const fn default_timeout() -> std::time::Duration {
    std::time::Duration::from_secs(30)
}

pub struct CmdParser;

impl Parser for CmdParser {
    fn service_type(&self) -> &'static str {
        "cmd"
    }

    fn parse_service(&self, service: &str, parameters: rhai::Map) -> EngineResult<Service> {
        let parameters: CmdParameters =
            deserialize_rhai_map(service, self.service_type(), parameters)?;

        Ok(Service::Cmd {
            timeout: parameters.timeout,
            user: parameters.user,
            group: parameters.group,
            command: parameters.command,
            args: parameters.args,
        })
    }
}
