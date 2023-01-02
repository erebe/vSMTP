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
use vsmtp_common::collection;
use vsmtp_config::field::{FieldServerLogSystem, SyslogFormat, SyslogSocket};
use vsmtp_config::Config;

struct SyslogWriter {
    logger: either::Either<
        syslog::Logger<syslog::LoggerBackend, syslog::Formatter3164>,
        syslog::Logger<syslog::LoggerBackend, syslog::Formatter5424>,
    >,
}

impl std::io::Write for SyslogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.logger {
            either::Either::Left(ref mut logger) => syslog::LogFormat::format(
                &logger.formatter,
                &mut logger.backend,
                syslog::Severity::LOG_WARNING,
                std::str::from_utf8(buf).unwrap_or("utf-8 error").to_owned(),
            ),
            either::Either::Right(ref mut logger) => syslog::LogFormat::format(
                &logger.formatter,
                &mut logger.backend,
                syslog::Severity::LOG_WARNING,
                (
                    0,
                    collection! {},
                    std::str::from_utf8(buf).unwrap_or("utf-8 error").to_owned(),
                ),
            ),
        }
        .map(|_| buf.len())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.description()))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        either::for_both!(&mut self.logger, logger => logger.backend.flush())
    }
}

struct MakeSyslogWriter {
    config: (SyslogFormat, SyslogSocket),
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for MakeSyslogWriter {
    // NOTE: if the syslog failed to initialize, is it written to stdout ?
    type Writer = tracing_subscriber::fmt::writer::OptionalWriter<SyslogWriter>;

    fn make_writer(&self) -> Self::Writer {
        fn get_3164() -> syslog::Formatter3164 {
            syslog::Formatter3164 {
                facility: syslog::Facility::LOG_MAIL,
                hostname: None,
                ..Default::default()
            }
        }

        fn get_5424() -> syslog::Formatter5424 {
            syslog::Formatter5424 {
                facility: syslog::Facility::LOG_MAIL,
                hostname: None,
                ..Default::default()
            }
        }

        let result = match (self.config.0, &self.config.1) {
            (SyslogFormat::Rfc3164, SyslogSocket::Udp { local, server }) => {
                syslog::udp(get_3164(), local, server).map(|logger| {
                    tracing_subscriber::fmt::writer::OptionalWriter::some(SyslogWriter {
                        logger: either::Left(logger),
                    })
                })
            }
            (SyslogFormat::Rfc3164, SyslogSocket::Tcp { server }) => {
                syslog::tcp(get_3164(), server).map(|logger| {
                    tracing_subscriber::fmt::writer::OptionalWriter::some(SyslogWriter {
                        logger: either::Left(logger),
                    })
                })
            }
            #[allow(clippy::option_if_let_else)]
            (SyslogFormat::Rfc3164, SyslogSocket::Unix { path }) => match path {
                Some(custom_path) => syslog::unix_custom(get_3164(), custom_path).map(|logger| {
                    tracing_subscriber::fmt::writer::OptionalWriter::some(SyslogWriter {
                        logger: either::Left(logger),
                    })
                }),
                None => syslog::unix(get_3164()).map(|logger| {
                    tracing_subscriber::fmt::writer::OptionalWriter::some(SyslogWriter {
                        logger: either::Left(logger),
                    })
                }),
            },
            (SyslogFormat::Rfc5424, SyslogSocket::Udp { local, server }) => {
                syslog::udp(get_5424(), local, server).map(|logger| {
                    tracing_subscriber::fmt::writer::OptionalWriter::some(SyslogWriter {
                        logger: either::Right(logger),
                    })
                })
            }
            (SyslogFormat::Rfc5424, SyslogSocket::Tcp { server }) => {
                syslog::tcp(get_5424(), server).map(|logger| {
                    tracing_subscriber::fmt::writer::OptionalWriter::some(SyslogWriter {
                        logger: either::Right(logger),
                    })
                })
            }
            #[allow(clippy::option_if_let_else)]
            (SyslogFormat::Rfc5424, SyslogSocket::Unix { path }) => match path {
                Some(custom_path) => syslog::unix_custom(get_5424(), custom_path).map(|logger| {
                    tracing_subscriber::fmt::writer::OptionalWriter::some(SyslogWriter {
                        logger: either::Right(logger),
                    })
                }),
                None => syslog::unix(get_5424()).map(|logger| {
                    tracing_subscriber::fmt::writer::OptionalWriter::some(SyslogWriter {
                        logger: either::Right(logger),
                    })
                }),
            },
        };

        match result {
            Ok(logger) => logger,
            Err(e) => {
                eprintln!("{e}");
                tracing_subscriber::fmt::writer::OptionalWriter::none()
            }
        }
    }
}

#[cfg(debug_assertions)]
macro_rules! get_fmt {
    () => {
        tracing_subscriber::fmt::layer()
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
        tracing_subscriber::fmt::layer()
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
    use tracing_subscriber::{
        fmt::writer::MakeWriterExt, layer::SubscriberExt, util::SubscriberInitExt, Layer,
    };

    let server_logs = &config.server.logs.filename;

    let writer_backend = if let (Some(directory), Some(file_name)) = (
        server_logs.parent(),
        server_logs.file_name().and_then(std::ffi::OsStr::to_str),
    ) {
        tracing_appender::rolling::never(directory, file_name)
    } else {
        anyhow::bail!(
            "filepath for server logs at {server_logs:?} does not have a parent or is not valid"
        )
    };

    let writer_backend = writer_backend
        .with_filter(|metadata| metadata.target() != "vsmtp_rule_engine::api::logging::logging");

    let app_logs = &config.app.logs.filename;

    let writer_app = if let (Some(directory), Some(file_name)) = (
        app_logs.parent(),
        app_logs.file_name().and_then(std::ffi::OsStr::to_str),
    ) {
        tracing_appender::rolling::never(directory, file_name)
    } else {
        anyhow::bail!(
            "filepath for application logs at {app_logs:?} does not have a parent or is not valid"
        )
    };

    let writer_app = writer_app
        .with_filter(|metadata| metadata.target() == "vsmtp_rule_engine::api::logging::logging");

    let subscriber = tracing_subscriber::registry().with({
        let mut e = tracing_subscriber::EnvFilter::default();
        for i in &config.server.logs.level {
            e = e.add_directive(i.clone());
        }
        e
    });

    #[cfg(feature = "tokio_console")]
    let subscriber = subscriber.with(console_subscriber::spawn());

    let subscriber = subscriber
        .with(get_fmt!().with_writer(writer_backend))
        .with(get_fmt!().with_writer(writer_app));

    if let Some(system_log_config) = &config.server.logs.system {
        match &system_log_config {
            FieldServerLogSystem::Syslogd {
                level,
                format,
                socket,
            } => {
                let subscriber = subscriber.with(
                    get_fmt!()
                        .with_writer(
                            MakeSyslogWriter {
                                config: (*format, socket.clone()),
                            }
                            .with_max_level(*level),
                        )
                        .without_time(),
                );

                if args.stdout {
                    subscriber
                        .with(get_fmt!().with_writer(std::io::stdout).with_ansi(true))
                        .try_init()
                } else {
                    subscriber.try_init()
                }
            }
            FieldServerLogSystem::Journald { level } => {
                let level = *level;
                let subscriber = subscriber.with(
                    tracing_journald::layer()
                        .map_err(|e| anyhow::anyhow!("{e}"))?
                        .with_filter(tracing_subscriber::filter::filter_fn(move |i| {
                            *i.level() <= level
                        })),
                );

                if args.stdout {
                    subscriber
                        .with(get_fmt!().with_writer(std::io::stdout).with_ansi(true))
                        .try_init()
                } else {
                    subscriber.try_init()
                }
            }
        }
    } else if args.stdout {
        subscriber
            .with(get_fmt!().with_writer(std::io::stdout).with_ansi(true))
            .try_init()
    } else {
        subscriber.try_init()
    }
    .map_err(|e| anyhow::anyhow!("{e}"))
}
