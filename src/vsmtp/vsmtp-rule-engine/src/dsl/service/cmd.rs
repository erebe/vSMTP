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

use crate::{api::EngineResult, dsl::service::Service};
use rhai::EvalAltResult;
use vsmtp_common::re::{anyhow, log};
use vsmtp_config::re::users;

pub fn parse_cmd_service(
    context: &mut rhai::EvalContext,
    input: &[rhai::Expression],
    service_name: &str,
) -> EngineResult<Service> {
    let options: rhai::Map = context
        .eval_expression_tree(&input[3])?
        .try_cast()
        .ok_or_else::<Box<rhai::EvalAltResult>, _>(|| "cmd service options must be a map".into())?;

    for key in ["timeout", "command"] {
        if !options.contains_key(key) {
            return Err(
                format!("cmd service {service_name} is missing the '{key}' option.").into(),
            );
        }
    }

    let timeout: std::time::Duration = options
        .get("timeout")
        .unwrap()
        .to_string()
        .parse::<vsmtp_config::re::humantime::Duration>()
        .map_err::<Box<EvalAltResult>, _>(|err| err.to_string().into())?
        .into();
    let command = options.get("command").unwrap().to_string();
    let user = options.get("user").map(std::string::ToString::to_string);
    let group = options.get("group").map(std::string::ToString::to_string);
    let args = options.get("args").and_then(|args| {
        args.clone()
            .into_array()
            .ok()
            .map(|args| args.into_iter().map(|arg| arg.to_string()).collect())
    });

    Ok(Service::Cmd {
        timeout,
        user,
        group,
        command,
        args,
    })
}

/// run a cmd service.
/// # Errors
///
/// * if the user used to launch commands is not found.
/// * if the group used to launch commands is not found.
/// * if the cmd service failed to spawn.
/// * if the cmd returned an error.
pub fn run(
    timeout: &std::time::Duration,
    command: &str,
    user: &Option<String>,
    group: &Option<String>,
    args: &Option<Vec<String>>,
) -> anyhow::Result<rhai::Map> {
    let mut child = std::process::Command::new(command);

    if let Some(args) = args {
        child.args(args);
    }

    if let Some(user_name) = user {
        if let Some(user) = users::get_user_by_name(&user_name) {
            std::os::unix::prelude::CommandExt::uid(&mut child, user.uid());
        } else {
            anyhow::bail!("user not found: '{user_name}'")
        }
    }
    if let Some(group_name) = group {
        if let Some(group) = users::get_group_by_name(group_name) {
            std::os::unix::prelude::CommandExt::gid(&mut child, group.gid());
        } else {
            anyhow::bail!("group not found: '{group_name}'")
        }
    }

    log::trace!("cmd running command: {child:#?}");

    let mut child = match child.spawn() {
        Ok(child) => child,
        Err(err) => anyhow::bail!("cmd process failed to spawn: {err:?}"),
    };

    let status = match wait_timeout::ChildExt::wait_timeout(&mut child, *timeout) {
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
