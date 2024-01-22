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
    channel_message::ProcessMessage, on_mail::MailHandler, receiver::handler::Handler,
    ValidationVSL,
};
use anyhow::Context;
use ppp::v2::Addresses;
use ppp::{v2, HeaderResult, PartialResult};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio::io::AsyncReadExt;
use tokio_rustls::rustls;
use tokio_stream::StreamExt;
use tracing::error;
use vqueue::GenericQueueManager;
use vsmtp_common::CodeID;
use vsmtp_config::{get_rustls_config, Config};
use vsmtp_protocol::{AcceptArgs, ConnectionKind};
use vsmtp_rule_engine::RuleEngine;

/// TCP/IP server
pub struct Server {
    config: std::sync::Arc<Config>,
    tls_config: Option<std::sync::Arc<rustls::ServerConfig>>,
    rule_engine: std::sync::Arc<RuleEngine>,
    queue_manager: std::sync::Arc<dyn GenericQueueManager>,
    working_sender: tokio::sync::mpsc::Sender<ProcessMessage>,
    delivery_sender: tokio::sync::mpsc::Sender<ProcessMessage>,
}

/// Create a `TCPListener` ready to be listened to
///
/// # Errors
///
/// * failed to bind to the socket address
/// * failed to set the listener to non blocking
pub fn socket_bind_anyhow<A: std::net::ToSocketAddrs + std::fmt::Debug>(
    addr: A,
) -> anyhow::Result<std::net::TcpListener> {
    let socket = std::net::TcpListener::bind(&addr)
        .with_context(|| format!("Failed to bind socket on addr: '{addr:?}'"))?;

    socket
        .set_nonblocking(true)
        .with_context(|| format!("Failed to set non-blocking socket on addr: '{addr:?}'"))?;

    Ok(socket)
}

type ListenerStreamItem = std::io::Result<(tokio::net::TcpStream, std::net::SocketAddr)>;

fn listener_to_stream(
    listener: &tokio::net::TcpListener,
) -> impl tokio_stream::Stream<Item = ListenerStreamItem> + '_ {
    async_stream::try_stream! {
        loop {
            yield listener.accept().await?;
        }
    }
}

impl Server {
    /// Create a server with the configuration provided, and the sockets already bound
    ///
    /// # Errors
    ///
    /// * `spool_dir` does not exist and failed to be created
    /// * cannot convert sockets to `[tokio::net::TcpListener]`
    /// * cannot initialize [rustls] config
    pub fn new(
        config: std::sync::Arc<Config>,
        rule_engine: std::sync::Arc<RuleEngine>,
        queue_manager: std::sync::Arc<dyn GenericQueueManager>,
        working_sender: tokio::sync::mpsc::Sender<ProcessMessage>,
        delivery_sender: tokio::sync::mpsc::Sender<ProcessMessage>,
    ) -> anyhow::Result<Self> {
        if !config.server.queues.dirpath.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .create(&config.server.queues.dirpath)?;
        }

        Ok(Self {
            tls_config: if let Some(smtps) = &config.server.tls {
                Some(std::sync::Arc::new(get_rustls_config(
                    smtps,
                    &config.server.r#virtual,
                )?))
            } else {
                None
            },
            rule_engine,
            queue_manager,
            config,
            working_sender,
            delivery_sender,
        })
    }

    #[tracing::instrument(name = "handle-client", skip_all, fields(client = %client_addr, server = %server_addr))]
    async fn handle_client(
        &self,
        client_counter: std::sync::Arc<std::sync::atomic::AtomicI64>,
        kind: ConnectionKind,
        mut stream: tokio::net::TcpStream,
        client_addr: std::net::SocketAddr,
        server_addr: std::net::SocketAddr,
    ) {
        tracing::info!(%kind, "Connection accepted.");

        if self.config.server.client_count_max != -1
            && client_counter.load(std::sync::atomic::Ordering::SeqCst)
                >= self.config.server.client_count_max
        {
            tracing::warn!(
                max = self.config.server.client_count_max,
                "Connection count max reached, rejecting connection.",
            );

            if let Err(error) = tokio::io::AsyncWriteExt::write_all(
                &mut stream,
                self.config
                    .server
                    .smtp
                    .codes
                    .get(&CodeID::ConnectionMaxReached)
                    .expect("ill-formed configuration")
                    .as_ref()
                    .as_bytes(),
            )
            .await
            {
                tracing::error!(%error, "Code delivery failure.");
            }

            if let Err(error) = tokio::io::AsyncWriteExt::shutdown(&mut stream).await {
                tracing::error!(%error, "Closing connection failure.");
            }
            return;
        }

        client_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let session = Self::serve(
            AcceptArgs::new(
                client_addr,
                stream.local_addr().expect("retrieve local address"),
                time::OffsetDateTime::now_utc(),
                uuid::Uuid::new_v4(),
                kind,
            ),
            stream,
            self.tls_config.clone(),
            self.config.clone(),
            self.rule_engine.clone(),
            self.queue_manager.clone(),
            self.working_sender.clone(),
            self.delivery_sender.clone(),
        );
        let client_counter_copy = client_counter.clone();
        tokio::spawn(async move {
            let _err = session.await;

            client_counter_copy.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        });
    }

    /// Main loop of `vSMTP`'s server
    ///
    /// # Errors
    ///
    /// * failed to convert sockets to `[tokio::net::TcpListener]`
    #[tracing::instrument(skip_all)]
    pub async fn listen(
        self,
        sockets: (
            Vec<std::net::TcpListener>,
            Vec<std::net::TcpListener>,
            Vec<std::net::TcpListener>,
        ),
    ) -> anyhow::Result<()> {
        fn to_tokio(
            s: Vec<std::net::TcpListener>,
        ) -> std::io::Result<Vec<tokio::net::TcpListener>> {
            s.into_iter()
                .map(tokio::net::TcpListener::from_std)
                .collect::<std::io::Result<Vec<tokio::net::TcpListener>>>()
        }

        if self.config.server.tls.is_none() && !sockets.2.is_empty() {
            tracing::warn!(
                "No TLS configuration provided, listening on submissions protocol (port 465) will cause issue"
            );
        }

        let client_counter = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0));

        let (listener, listener_submission, listener_tunneled) = (
            to_tokio(sockets.0)?,
            to_tokio(sockets.1)?,
            to_tokio(sockets.2)?,
        );

        let mut map = tokio_stream::StreamMap::new();
        for (kind, sockets) in [
            (ConnectionKind::Relay, &listener),
            (ConnectionKind::Submission, &listener_submission),
            (ConnectionKind::Tunneled, &listener_tunneled),
        ] {
            for listener in sockets {
                let accept = listener_to_stream(listener);
                let transform = tokio_stream::StreamExt::map(accept, move |client| (kind, client));

                map.insert(
                    listener.local_addr().expect("retrieve local address"),
                    Box::pin(transform),
                );
            }
        }

        tracing::info!(
            interfaces = ?map.keys().collect::<Vec<_>>(),
            "Listening for clients.",
        );

        while let Some((server_addr, (kind, client))) =
            tokio_stream::StreamExt::next(&mut map).await
        {
            let (mut stream, _client_addr) = client?;

            // unwrap proxy protocol
            let mut buffer = [0; 1024];
            let mut header = loop {
                let read = stream.peek(&mut buffer).await?;
                let header = ppp::v2::Header::try_from(&buffer[..read]);
                if header.is_complete() {
                    break header?.to_owned();
                }
            };
            let _ = stream
                .read_exact(&mut buffer[..header.header.len()])
                .await?;

            let (server_addr, client_addr) = match header.addresses {
                Addresses::IPv4(ip) => (
                    SocketAddr::V4(SocketAddrV4::new(
                        ip.destination_address,
                        ip.destination_port,
                    )),
                    SocketAddr::V4(SocketAddrV4::new(ip.source_address, ip.source_port)),
                ),
                Addresses::IPv6(ip) => (
                    SocketAddr::V6(SocketAddrV6::new(
                        ip.destination_address,
                        ip.destination_port,
                        0,
                        0,
                    )),
                    SocketAddr::V6(SocketAddrV6::new(ip.source_address, ip.source_port, 0, 0)),
                ),
                Addresses::Unix(_) | Addresses::Unspecified => {
                    error!("Unsupported address family for proxy_protocol");
                    continue;
                }
            };

            self.handle_client(
                client_counter.clone(),
                kind,
                stream,
                client_addr,
                server_addr,
            )
            .await;
        }
        Ok(())
    }

    ///
    /// # Errors
    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(skip_all, err, fields(uuid = %args.uuid))]
    pub async fn serve(
        args: AcceptArgs,
        tcp_stream: tokio::net::TcpStream,
        tls_config: Option<std::sync::Arc<rustls::ServerConfig>>,
        config: std::sync::Arc<Config>,
        rule_engine: std::sync::Arc<RuleEngine>,
        queue_manager: std::sync::Arc<dyn GenericQueueManager>,
        working_sender: tokio::sync::mpsc::Sender<ProcessMessage>,
        delivery_sender: tokio::sync::mpsc::Sender<ProcessMessage>,
    ) -> anyhow::Result<()> {
        let smtp_handler = Handler::new(
            Box::new(MailHandler {
                working_sender,
                delivery_sender,
            }),
            config.clone(),
            tls_config,
            rule_engine,
            queue_manager,
        );
        let smtp_receiver = vsmtp_protocol::Receiver::<_, ValidationVSL, _, _>::new(
            tcp_stream,
            args.kind,
            smtp_handler,
            config.server.smtp.error.soft_count,
            config.server.smtp.error.hard_count,
            config.server.message_size_limit,
        );
        let smtp_stream = smtp_receiver.into_stream(
            args.client_addr,
            args.server_addr,
            args.timestamp,
            args.uuid,
        );
        tokio::pin!(smtp_stream);

        while matches!(smtp_stream.next().await, Some(Ok(()))) {}

        log::info!("Connection closed cleanly.");
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use crate::{socket_bind_anyhow, ProcessMessage, Server};
    use vsmtp_config::DnsResolvers;
    use vsmtp_rule_engine::RuleEngine;
    use vsmtp_test::config;

    macro_rules! listen_with {
        ($addr:expr, $addr_submission:expr, $addr_submissions:expr, $timeout:expr, $client_count_max:expr) => {{
            let config = std::sync::Arc::new({
                let mut config = config::local_test();
                config.server.interfaces.addr = $addr;
                config.server.interfaces.addr_submission = $addr_submission;
                config.server.interfaces.addr_submissions = $addr_submissions;
                config.server.client_count_max = $client_count_max;
                config
            });

            let queue_manager = <vqueue::temp::QueueManager as vqueue::GenericQueueManager>::init(
                config.clone(),
                vec![],
            )
            .unwrap();

            let resolvers = std::sync::Arc::new(DnsResolvers::from_config(&config).unwrap());

            let delivery = tokio::sync::mpsc::channel::<ProcessMessage>(
                config.server.queues.delivery.channel_size,
            );

            let working = tokio::sync::mpsc::channel::<ProcessMessage>(
                config.server.queues.working.channel_size,
            );

            let s = Server::new(
                config.clone(),
                std::sync::Arc::new(
                    RuleEngine::new(config.clone(), resolvers, queue_manager.clone()).unwrap(),
                ),
                queue_manager,
                working.0,
                delivery.0,
            )
            .unwrap();

            tokio::time::timeout(
                std::time::Duration::from_millis($timeout),
                s.listen((
                    config
                        .server
                        .interfaces
                        .addr
                        .iter()
                        .cloned()
                        .map(socket_bind_anyhow)
                        .collect::<anyhow::Result<Vec<std::net::TcpListener>>>()
                        .unwrap(),
                    config
                        .server
                        .interfaces
                        .addr_submission
                        .iter()
                        .cloned()
                        .map(socket_bind_anyhow)
                        .collect::<anyhow::Result<Vec<std::net::TcpListener>>>()
                        .unwrap(),
                    config
                        .server
                        .interfaces
                        .addr_submissions
                        .iter()
                        .cloned()
                        .map(socket_bind_anyhow)
                        .collect::<anyhow::Result<Vec<std::net::TcpListener>>>()
                        .unwrap(),
                )),
            )
            .await
            .unwrap_err();
        }};
    }

    #[tokio::test]
    async fn basic() {
        listen_with![
            vec!["0.0.0.0:10021".parse().unwrap()],
            vec!["0.0.0.0:10588".parse().unwrap()],
            vec!["0.0.0.0:10466".parse().unwrap()],
            10,
            1
        ];
    }

    #[ignore]
    #[test_log::test(tokio::test(flavor = "multi_thread", worker_threads = 8))]
    async fn one_client_max_ok() {
        let server = tokio::spawn(async move {
            listen_with![
                vec!["127.0.0.1:10016".parse().unwrap()],
                vec!["127.0.0.1:10578".parse().unwrap()],
                vec!["127.0.0.1:10456".parse().unwrap()],
                500,
                1
            ];
        });

        let client = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            let mail = lettre::Message::builder()
                .from("NoBody <nobody@domain.tld>".parse().unwrap())
                .reply_to("Yuin <yuin@domain.tld>".parse().unwrap())
                .to("Hei <hei@domain.tld>".parse().unwrap())
                .subject("Happy new year")
                .body(String::from("Be happy!"))
                .unwrap();

            let sender = lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous(
                "127.0.0.1",
            )
            .port(10016)
            .build();

            lettre::AsyncTransport::send(&sender, mail).await
        });

        let (client, server) = tokio::join!(client, server);
        server.unwrap();

        dbg!(client
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap()
            .message()
            .collect::<Vec<_>>());

        assert_eq!(client.unwrap().unwrap().message().next().unwrap(), "Ok");
    }

    // FIXME: randomly fail the CI
    /*
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn one_client_max_err() {
        let server = tokio::spawn(async move {
            listen_with![
                vec!["127.0.0.1:10006".parse().unwrap()],
                vec!["127.0.0.1:10568".parse().unwrap()],
                vec!["127.0.0.1:10446".parse().unwrap()],
                1000,
                1
            ];
        });

        let now = tokio::time::Instant::now();
        let until = now
            .checked_add(std::time::Duration::from_millis(100))
            .unwrap();

        let client = tokio::spawn(async move {
            tokio::time::sleep_until(until).await;
            let mail = lettre::Message::builder()
                .from("NoBody <nobody@domain.tld>".parse().unwrap())
                .reply_to("Yuin <yuin@domain.tld>".parse().unwrap())
                .to("Hei <hei@domain.tld>".parse().unwrap())
                .subject("Happy new year")
                .body(String::from("Be happy!"))
                .unwrap();

            let sender = lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous(
                "127.0.0.1",
            )
            .port(10006)
            .build();

            lettre::AsyncTransport::send(&sender, mail).await
        });

        let client2 = tokio::spawn(async move {
            tokio::time::sleep_until(until).await;
            let mail = lettre::Message::builder()
                .from("NoBody <nobody2@domain.tld>".parse().unwrap())
                .reply_to("Yuin <yuin@domain.tld>".parse().unwrap())
                .to("Hei <hei@domain.tld>".parse().unwrap())
                .subject("Happy new year")
                .body(String::from("Be happy!"))
                .unwrap();

            let sender = lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous(
                "127.0.0.1",
            )
            .port(10006)
            .build();

            lettre::AsyncTransport::send(&sender, mail).await
        });

        let (server, client, client2) = tokio::join!(server, client, client2);
        server.unwrap();

        let client1 = format!("{}", client.unwrap().unwrap_err());
        let client2 = format!("{}", client2.unwrap().unwrap_err());

        // one of the client has been denied on connection, but we cant know which one
        let ok1_failed2 = client1
            == "permanent error (554): permanent problems with the remote server"
            && client2 == "permanent error (554): Cannot process connection, closing";
        let ok2_failed1 = client2
            == "permanent error (554): permanent problems with the remote server"
            && client1 == "permanent error (554): Cannot process connection, closing";

        assert!(ok1_failed2 || ok2_failed1);
    }
    */
}
