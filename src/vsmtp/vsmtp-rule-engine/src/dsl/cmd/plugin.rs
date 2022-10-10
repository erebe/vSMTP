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

use vsmtp_plugins::{
    plugins::{
        vsl::native::{Builder, Native},
        Plugin,
    },
    rhai,
};

#[derive(Debug, serde::Deserialize)]
pub struct CmdParameters {
    /// The command to execute in the subprocess
    pub command: String,
    /// Optional: parameters directly given to the executed program (argc, argv)
    pub args: Option<Vec<String>>,
    /// A duration after which the subprocess will be forced-kill
    #[serde(default = "default_timeout", with = "humantime_serde")]
    pub timeout: std::time::Duration,
    /// Optional: a user to run the subprocess under
    pub user: Option<String>,
    /// Optional: a group to run the subprocess under
    pub group: Option<String>,
}

const fn default_timeout() -> std::time::Duration {
    std::time::Duration::from_secs(30)
}

pub struct Cmd;

impl Plugin for Cmd {
    fn name(&self) -> &'static str {
        "cmd"
    }
}

impl Native for Cmd {
    fn register(&self, mut builder: Builder<'_>) -> anyhow::Result<()> {
        builder.register_global_module(rhai::exported_module!(super::api::cmd));

        Ok(())
    }
}
