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
use crate::{delivery, processing, ProcessMessage, Server};
use anyhow::Context;
use vsmtp_common::transport::{AbstractTransport, DeserializerFn, DESERIALIZER_SYMBOL_NAME};
use vsmtp_config::{Config, DnsResolvers};
use vsmtp_delivery::{Deliver, Forward, MBox, Maildir};
use vsmtp_rule_engine::RuleEngine;

fn init_runtime<F>(
    sender: tokio::sync::mpsc::Sender<()>,
    name: impl Into<String>,
    worker_thread_count: usize,
    future: F,
    timeout: Option<std::time::Duration>,
) -> anyhow::Result<std::thread::JoinHandle<anyhow::Result<()>>>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let name = name.into();

    let name_park = name.clone();
    let name_unpark = name.clone();
    let name_start = name.clone();
    let name_stop = name.clone();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_thread_count)
        .enable_all()
        .thread_name(format!("{name}-child"))
        .on_thread_park(move || tracing::trace!("{}-child goes idle", name_park))
        .on_thread_unpark(move || tracing::trace!("{}-child starts executing tasks", name_unpark))
        .on_thread_start(move || tracing::trace!("{}-child start", name_start))
        .on_thread_stop(move || tracing::trace!("{}-child stop", name_stop))
        .build()?;

    std::thread::Builder::new()
        .name(format!("{name}-main"))
        .spawn(move || {
            let name_rt = name.clone();
            runtime.block_on(async move {
                tracing::info!(name = name_rt, "Runtime started successfully.");

                match timeout {
                    Some(duration) => {
                        tokio::time::timeout(duration, future).await.unwrap_err();
                    }
                    None => future.await,
                }
            });

            sender.blocking_send(())?;
            Ok(())
        })
        .map_err(anyhow::Error::new)
}

#[allow(unsafe_code)]
#[tracing::instrument]
fn load_plugin(path: &std::path::Path) -> Vec<libloading::Library> {
    let mut libs = vec![];

    let dir = match std::fs::read_dir(path) {
        Ok(dir) => dir,
        Err(e) => {
            tracing::warn!(%e);
            return libs;
        }
    };
    for i in dir {
        match i {
            Err(e) => tracing::warn!(%e),
            Ok(dir_entry) => match unsafe { libloading::Library::new(dir_entry.path()) } {
                Ok(lib) => {
                    libs.push(lib);
                }
                Err(e) => tracing::warn!(%e),
            },
        }
    }
    libs
}

fn get_transport_deserializer(libs: &[libloading::Library]) -> Vec<DeserializerFn> {
    libs.iter()
        .filter_map(|lib| {
            #[allow(unsafe_code)]
            match unsafe { lib.get::<DeserializerFn>(DESERIALIZER_SYMBOL_NAME.as_bytes()) } {
                Ok(symbol) => {
                    tracing::trace!(?lib, "`DeserializerFn` symbol found");
                    Some(*symbol)
                }
                Err(e) => {
                    tracing::trace!(?lib, %e);
                    None
                }
            }
        })
        .chain([
            <Deliver as AbstractTransport>::get_symbol(),
            <Forward as AbstractTransport>::get_symbol(),
            <Maildir as AbstractTransport>::get_symbol(),
            <MBox as AbstractTransport>::get_symbol(),
        ])
        .collect::<Vec<_>>()
}

/// Start the `vSMTP` server's runtime
///
/// # Errors
///
#[allow(clippy::module_name_repetitions)]
pub fn start_runtime(
    config: Config,
    sockets: (
        Vec<std::net::TcpListener>,
        Vec<std::net::TcpListener>,
        Vec<std::net::TcpListener>,
    ),
    timeout: Option<std::time::Duration>,
) -> anyhow::Result<()> {
    let config = std::sync::Arc::new(config);

    let libs = load_plugin(
        &config
            .path
            .clone()
            .expect("has been set at this point")
            .parent()
            .expect("config is not at `/` level")
            .join("plugins"),
    );
    let transport_deserializer = get_transport_deserializer(&libs);

    let mut error_handler = tokio::sync::mpsc::channel::<()>(3);

    let (delivery_channel, working_channel) = (
        tokio::sync::mpsc::channel::<ProcessMessage>(config.server.queues.delivery.channel_size),
        tokio::sync::mpsc::channel::<ProcessMessage>(config.server.queues.working.channel_size),
    );

    let queue_manager = <vqueue::fs::QueueManager as vqueue::GenericQueueManager>::init(
        config.clone(),
        transport_deserializer,
    )?;

    let resolvers = std::sync::Arc::new(
        DnsResolvers::from_config(&config).context("could not initialize dns")?,
    );

    let rule_engine = std::sync::Arc::new(RuleEngine::new(
        config.clone(),
        resolvers,
        queue_manager.clone(),
    )?);

    let _tasks_delivery = init_runtime(
        error_handler.0.clone(),
        "delivery",
        config.server.system.thread_pool.delivery,
        delivery::start(
            config.clone(),
            rule_engine.clone(),
            queue_manager.clone(),
            delivery_channel.1,
        ),
        timeout,
    )?;

    let _tasks_processing = init_runtime(
        error_handler.0.clone(),
        "processing",
        config.server.system.thread_pool.processing,
        processing::start(
            rule_engine.clone(),
            queue_manager.clone(),
            working_channel.1,
            delivery_channel.0.clone(),
        ),
        timeout,
    )?;

    let _tasks_receiver = init_runtime(
        error_handler.0.clone(),
        "receiver",
        config.server.system.thread_pool.receiver,
        async move {
            let server = match Server::new(
                config.clone(),
                rule_engine.clone(),
                queue_manager.clone(),
                working_channel.0.clone(),
                delivery_channel.0.clone(),
            ) {
                Ok(server) => server,
                Err(error) => {
                    tracing::error!(%error, "Receiver build failure.");
                    return;
                }
            };
            if let Err(error) = server.listen(sockets).await {
                tracing::error!(%error, "Receiver failure.");
            }
        },
        timeout,
    );

    let error_handler_sig = error_handler.0.clone();
    let mut signals = signal_hook::iterator::Signals::new([
        // Send by `systemctl stop` (and then sending `SIGKILL`)
        signal_hook::consts::SIGTERM,
        // Ctrl+C on a terminal
        signal_hook::consts::SIGINT,
    ])?;
    let _signal_handler = std::thread::spawn(move || {
        for sig in signals.forever() {
            tracing::warn!(signal = sig, "Stopping vSMTP server.");
            error_handler_sig
                .blocking_send(())
                .expect("failed to send terminating instruction");
        }
    });

    error_handler.1.blocking_recv();

    Ok(())

    // if the runtime panicked (receiver/processing/delivery)
    // .join() would return an error,
    // but the join is CPU heavy and he blocking (so we can't join all of them)
    // for i in [tasks_receiver, tasks_delivery, tasks_processing] {
    //     i.join().map_err(|e| anyhow::anyhow!("{e:?}"))??;
    // }
}

#[cfg(test)]
mod tests {
    use vsmtp_test::config;

    use super::*;

    #[test]
    fn basic() {
        start_runtime(
            config::local_test(),
            (
                vec![std::net::TcpListener::bind("0.0.0.0:22001").unwrap()],
                vec![std::net::TcpListener::bind("0.0.0.0:22002").unwrap()],
                vec![std::net::TcpListener::bind("0.0.0.0:22003").unwrap()],
            ),
            Some(std::time::Duration::from_millis(100)),
        )
        .unwrap();
    }
}
