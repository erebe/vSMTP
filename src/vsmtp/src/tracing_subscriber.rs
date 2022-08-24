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
use crate::Args;
use tracing_subscriber::fmt::writer::{MakeWriterExt, OptionalWriter};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use vsmtp_common::re::anyhow::{self, Context};
use vsmtp_config::Config;

struct SyslogWriter(syslog::Logger<syslog::LoggerBackend, syslog::Formatter3164>);

impl std::io::Write for SyslogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        syslog::LogFormat::format(
            &self.0.formatter,
            &mut self.0.backend,
            // TODO: handle severity
            syslog::Severity::LOG_WARNING,
            std::str::from_utf8(buf).unwrap_or("utf-8 error"),
        )
        .map(|_| buf.len())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.description()))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.backend.flush()
    }
}

struct MakeSyslogWriter;

impl<'a> fmt::MakeWriter<'a> for MakeSyslogWriter {
    // NOTE: if the syslog failed to initialize, is it written to stdout ?
    type Writer = fmt::writer::OptionalWriter<SyslogWriter>;

    fn make_writer(&self) -> Self::Writer {
        let formatter = syslog::Formatter3164 {
            facility: syslog::Facility::LOG_MAIL,
            hostname: None,
            ..Default::default()
        };

        match syslog::unix(formatter) {
            Err(e) => {
                eprintln!("Cannot initialize syslog: {e}");
                OptionalWriter::none()
            }
            Ok(logger) => OptionalWriter::some(SyslogWriter(logger)),
        }
    }
}

#[cfg(debug_assertions)]
macro_rules! get_fmt {
    () => {
        fmt::layer()
            .pretty()
            .with_file(true)
            .with_line_number(true)
            .with_thread_ids(true)
            .with_target(true)
            .with_ansi(false)
    };
}

#[cfg(not(debug_assertions))]
macro_rules! get_fmt {
    () => {
        fmt::layer()
            .compact()
            .with_thread_ids(false)
            .with_target(false)
            .with_ansi(false)
    };
}

/// Initialize the tracing subsystem.
///
/// # Errors
///
/// * The logs path in the configuration file are invalid.
/// * Failed to initialize the tracing subsystem.
pub fn initialize(args: &Args, config: &Config) -> anyhow::Result<()> {
    std::fs::create_dir_all(config.server.logs.filepath.clone())
        .context("Cannot create `server.logs` directory")?;

    let writer_backend = tracing_appender::rolling::daily(&config.server.logs.filepath, "vsmtp");
    let writer_backend = writer_backend.with_filter(|metadata| {
        metadata.target() != "vsmtp_rule_engine::api::logging::logging_rhai"
    });

    std::fs::create_dir_all(config.app.logs.filepath.clone())
        .context("Cannot create `app.logs` directory")?;

    let writer_app = tracing_appender::rolling::daily(&config.app.logs.filepath, "app");
    let writer_app = writer_app.with_filter(|metadata| {
        metadata.target() == "vsmtp_rule_engine::api::logging::logging_rhai"
    });

    let subscriber = tracing_subscriber::registry().with(
        EnvFilter::builder().try_from_env().unwrap_or_else(|_| {
            let mut e = EnvFilter::default();
            for i in &config.server.logs.level {
                e = e.add_directive(i.clone());
            }
            e
        }),
    );

    #[cfg(feature = "tokio_console")]
    let subscriber = subscriber.with(console_subscriber::spawn());

    let subscriber = subscriber
        .with(get_fmt!().with_writer(writer_backend))
        .with(get_fmt!().with_writer(writer_app));

    if args.no_daemon {
        subscriber
            .with(get_fmt!().with_writer(std::io::stdout).with_ansi(true))
            .try_init()
    } else {
        subscriber
            .with(get_fmt!().with_writer(MakeSyslogWriter).without_time())
            .try_init()
    }
    .map_err(|e| anyhow::anyhow!("{e}"))
}
