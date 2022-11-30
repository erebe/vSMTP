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

use rhai::plugin::{
    mem, Dynamic, FnAccess, FnNamespace, NativeCallContext, PluginFunction, RhaiResult, TypeId,
};

use rhai::Module;

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

#[rhai::plugin::export_module]
pub mod cmd {
    use crate::api::EngineResult;

    type Cmd = rhai::Shared<crate::dsl::cmd::service::Cmd>;

    #[rhai_fn(global, return_raw)]
    pub fn cmd(parameters: rhai::Map) -> EngineResult<Cmd> {
        let parameters = rhai::serde::from_dynamic::<CmdParameters>(&parameters.into())?;

        Ok(rhai::Shared::new(crate::dsl::cmd::service::Cmd {
            timeout: parameters.timeout,
            user: parameters.user,
            group: parameters.group,
            command: parameters.command,
            args: parameters.args,
        }))
    }

    ///
    #[rhai_fn(global, pure)]
    pub fn to_string(cmd: &mut Cmd) -> String {
        cmd.to_string()
    }

    ///
    #[rhai_fn(global, pure)]
    pub fn to_debug(cmd: &mut Cmd) -> String {
        format!("{cmd:#?}")
    }

    /// Execute the given command.
    #[rhai_fn(global, name = "run", return_raw, pure)]
    pub fn run(cmd: &mut Cmd) -> crate::api::EngineResult<rhai::Map> {
        cmd.run()
            .map_err::<Box<rhai::EvalAltResult>, _>(|e| e.to_string().into())
    }

    /// Execute the given command with dynamic arguments.
    #[rhai_fn(global, name = "run", return_raw, pure)]
    pub fn run_with_args(cmd: &mut Cmd, args: rhai::Array) -> crate::api::EngineResult<rhai::Map> {
        let args = args
            .into_iter()
            .map(rhai::Dynamic::try_cast)
            .collect::<Option<Vec<String>>>()
            .ok_or_else::<Box<rhai::EvalAltResult>, _>(|| {
                "all cmd arguments must be strings".into()
            })?;

        cmd.run_with_args(&args)
            .map_err::<Box<rhai::EvalAltResult>, _>(|e| e.to_string().into())
    }
}
