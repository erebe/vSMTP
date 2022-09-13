use anyhow::Context;
use vqueue::{execute, Args};
use vsmtp_config::Config;

fn main() -> anyhow::Result<()> {
    let args = <Args as clap::StructOpt>::parse();

    if args.version {
        println!(
            "{} v{}\ncommit: {}",
            clap::crate_name!(),
            clap::crate_version!(),
            env!("GIT_HASH")
        );
        return Ok(());
    }

    let config = args.config.as_ref().map_or_else(
        || Ok(Config::default()),
        |config| {
            std::fs::read_to_string(&config)
                .context(format!("Cannot read file '{}'", config))
                .and_then(|f| Config::from_toml(&f).context("File contains format error"))
                .context("Cannot parse the configuration")
        },
    )?;

    if let Some(command) = args.command {
        execute(command, &config)
    } else {
        anyhow::bail!("no commands where specified")
    }
}
