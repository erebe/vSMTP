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

#[derive(Debug, Clone)]
/// A service that executes commands.
pub struct Cmd {
    /// A duration after which the subprocess will be forced-kill
    pub timeout: std::time::Duration,
    /// Optional: a user to run the subprocess under
    pub user: Option<String>,
    /// Optional: a group to run the subprocess under
    pub group: Option<String>,
    /// The command to execute in the subprocess
    pub command: String,
    /// Optional: parameters directly given to the executed program (argc, argv)
    pub args: Option<Vec<String>>,
}

impl std::fmt::Display for Cmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cmd:{}", self.command)
    }
}

impl Cmd {
    /// run a cmd service.
    ///
    /// # Errors
    ///
    /// * if the user used to launch commands is not found.
    /// * if the group used to launch commands is not found.
    /// * if the cmd service failed to spawn.
    /// * if the cmd returned an error.
    pub fn run(&self) -> anyhow::Result<rhai::Map> {
        self.run_inner(self.args.as_ref().unwrap_or(&vec![]))
    }

    /// run a cmd service using dynamic arguments.
    ///
    /// # Errors
    ///
    /// * if the user used to launch commands is not found.
    /// * if the group used to launch commands is not found.
    /// * if the cmd service failed to spawn.
    /// * if the cmd returned an error.
    pub fn run_with_args(&self, args: &Vec<String>) -> anyhow::Result<rhai::Map> {
        self.run_inner(args)
    }

    /// # Errors
    ///
    /// * if the user used to launch commands is not found.
    /// * if the group used to launch commands is not found.
    /// * if the cmd service failed to spawn.
    /// * if the cmd returned an error.
    pub fn run_inner(&self, args: &Vec<String>) -> anyhow::Result<rhai::Map> {
        let mut child = std::process::Command::new(&self.command);

        child.args(args);

        if let Some(user_name) = &self.user {
            if let Some(user) = users::get_user_by_name(&user_name) {
                std::os::unix::prelude::CommandExt::uid(&mut child, user.uid());
            } else {
                anyhow::bail!("user not found: '{user_name}'")
            }
        }
        if let Some(group_name) = &self.group {
            if let Some(group) = users::get_group_by_name(group_name) {
                std::os::unix::prelude::CommandExt::gid(&mut child, group.gid());
            } else {
                anyhow::bail!("group not found: '{group_name}'")
            }
        }

        tracing::trace!(?child, "Running command.");

        let mut child = match child.spawn() {
            Ok(child) => child,
            Err(err) => anyhow::bail!("cmd process failed to spawn: {err:?}"),
        };

        let status = match wait_timeout::ChildExt::wait_timeout(&mut child, self.timeout) {
            Ok(status) => status.unwrap_or_else(|| {
                child.kill().expect("child has already exited");
                child.wait().expect("command wasn't running")
            }),

            Err(err) => anyhow::bail!("cmd unexpected error: {err:?}"),
        };

        let code = status.code().map(i64::from).map(rhai::Dynamic::from);
        let signal = std::os::unix::prelude::ExitStatusExt::signal(&status)
            .map(i64::from)
            .map(rhai::Dynamic::from);

        Ok(rhai::Map::from_iter([
            ("has_code".into(), rhai::Dynamic::from_bool(code.is_some())),
            ("code".into(), code.unwrap_or(rhai::Dynamic::UNIT)),
            (
                "has_signal".into(),
                rhai::Dynamic::from_bool(signal.is_some()),
            ),
            ("signal".into(), signal.unwrap_or(rhai::Dynamic::UNIT)),
        ]))
    }
}
