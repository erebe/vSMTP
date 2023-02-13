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
use anyhow::Context;
use vqueue::{cli::args::Args, GenericQueueManager};
use vsmtp_config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = <Args as clap::Parser>::parse();

    if args.version {
        println!(
            "{} v{}\ncommit: {}",
            clap::crate_name!(),
            clap::crate_version!(),
            env!("GIT_HASH")
        );
        return Ok(());
    }

    if let Some(command) = args.command {
        let config = args.config.as_ref().map_or_else(
            || Ok(Config::default()),
            |path| Config::from_vsl_file(path).context("Cannot parse the configuration"),
        )?;

        let config = std::sync::Arc::new(config);
        let manager = vqueue::fs::QueueManager::init(config, vec![])?;

        command.execute(manager).await
    } else {
        anyhow::bail!("no commands where specified")
    }
}
