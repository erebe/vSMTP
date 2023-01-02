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

use vqueue::GenericQueueManager;
use vsmtp_common::CodeID;
use vsmtp_mail_parser::MessageBody;

/// used for testing, does not do anything once the email is received.
#[derive(Default, Clone)]
pub struct DefaultMailHandler {
    _phantom: std::marker::PhantomData<u32>,
}

#[async_trait::async_trait]
impl vsmtp_server::OnMail for DefaultMailHandler {
    async fn on_mail(
        &mut self,
        _: Box<vsmtp_common::ContextFinished>,
        _: MessageBody,
        _: std::sync::Arc<dyn GenericQueueManager>,
    ) -> CodeID {
        CodeID::Ok
    }
}

/// run a connection and assert output produced by `vSMTP` and `expected_output`
#[macro_export]
macro_rules! run_test {
    (
        input = $input:expr,
        expected = $expected:expr
        $(, starttls = $server_name_starttls:expr => $secured_input:expr)?
        $(, tunnel = $server_name_tunnel:expr)?
        $(, config = $config:expr)?
        $(, config_arc = $config_arc:expr)?
        $(, mail_handler = $mail_handler:expr)?
        $(, hierarchy_builder = $hierarchy_builder:expr)?
        $(,)?
    ) => {{
        async fn upgrade_tls(server_name: &str, stream: tokio::net::TcpStream) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
            const TEST_SERVER_CERT: &str = "src/template/certs/certificate.crt";
            const TEST_SERVER_KEY: &str = "src/template/certs/private_key.rsa.key";

            let mut reader = std::io::BufReader::new(std::fs::File::open(TEST_SERVER_CERT).unwrap());

            let pem = rustls_pemfile::certs(&mut reader)
                .unwrap()
                .into_iter()
                .map(tokio_rustls::rustls::Certificate)
                .collect::<Vec<_>>();

            let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
            for i in pem {
                root_store.add(&i).unwrap();
            }

            let client_config = std::sync::Arc::new(tokio_rustls::rustls::ClientConfig::builder()
                .with_safe_default_cipher_suites()
                .with_safe_default_kx_groups()
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(root_store)
                .with_no_client_auth());

            let connector = tokio_rustls::TlsConnector::from(client_config.clone());
            connector
                .connect(tokio_rustls::rustls::ServerName::try_from(server_name).unwrap(), stream)
                .await
                .unwrap()
        }

        let expected: Vec<String> = $expected.into_iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let input: Vec<String> = $input.into_iter().map(|s| s.to_string()).collect::<Vec<_>>();

        $( let secured_input: Vec<String> = $secured_input.into_iter().map(|s| s.to_string()).collect::<Vec<_>>(); )?

        $( let server_name: &str = $server_name_tunnel; )?
        $( let server_name: &str = $server_name_starttls; )?

        let (socket_server, server_addr) = loop {
            let port = rand::random::<u32>().rem_euclid(65535 - 1025) + 1025;
            let server_addr: std::net::SocketAddr = format!("0.0.0.0:{port}").parse().expect("valid address");
            match tokio::net::TcpListener::bind(server_addr.clone()).await {
                Ok(socket_server) => break (socket_server, server_addr),
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => (),
                Err(e) => panic!("{}", e),
            };
        };

        let config: std::sync::Arc<vsmtp_config::Config> =  {
            let _f = || std::sync::Arc::new($crate::config::local_test());      $(
            let _f = || std::sync::Arc::new($config);                       )?  $(
            let _f = || $config_arc;                                        )?
            _f()
        };

        let queue_manager =
            <vqueue::temp::QueueManager as vqueue::GenericQueueManager>::init(config.clone()).unwrap();

        let queue_manager_cloned = std::sync::Arc::clone(&queue_manager);

        let server = tokio::spawn(async move {
            let mail_handler = { // Box<dyn OnMail + Send>
                let _f = || $crate::receiver::DefaultMailHandler::default();    $(
                let _f = || $mail_handler;                                      )?
                Box::new(_f())
            };

            let kind = {
                let _f = || vsmtp_protocol::ConnectionKind::Relay;                  $(
                let _f = || {
                    #[allow(clippy::no_effect)]
                    $server_name_tunnel;
                    vsmtp_protocol::ConnectionKind::Tunneled
                };)?
                _f()
            };

            let resolvers = std::sync::Arc::new(vsmtp_config::DnsResolvers::from_config(&config).unwrap());

            let rule_engine: std::sync::Arc<vsmtp_rule_engine::RuleEngine> = {
                let _f = || vsmtp_rule_engine::RuleEngine::new(
                    config.clone(), resolvers.clone(), queue_manager.clone()
                ).unwrap();                                         $(
                let _f = || vsmtp_rule_engine::RuleEngine::with_hierarchy(
                    config.clone(), $hierarchy_builder,
                    resolvers.clone(), queue_manager.clone()
                ).unwrap();                                         )?
                std::sync::Arc::new(_f())
            };

            let smtp_handler = vsmtp_server::Handler::new(
                mail_handler,
                config.clone(),
                {
                    let _tls_config = Option::<std::sync::Arc<tokio_rustls::rustls::ServerConfig>>::None;
                    $( #[allow(clippy::no_effect)] $server_name_tunnel;

                    let _tls_config = config.server.tls.as_ref().map(|tls| {
                        arc!(vsmtp_config::get_rustls_config(
                            tls, &config.server.r#virtual,
                        ).unwrap())
                    }); )?

                    $( #[allow(clippy::no_effect)] $server_name_starttls;

                    let _tls_config = config.server.tls.as_ref().map(|tls| {
                        arc!(vsmtp_config::get_rustls_config(
                            tls, &config.server.r#virtual,
                        ).unwrap())
                    }); )?

                    _tls_config
                },
                rule_engine,
                queue_manager.clone(),
            );
            let (client_stream, client_addr) = socket_server.accept().await.unwrap();

            let smtp_receiver = vsmtp_protocol::Receiver::<_, vsmtp_server::ValidationVSL, _, _>::new(
                client_stream,
                kind,
                smtp_handler,
                config.server.smtp.error.soft_count,
                config.server.smtp.error.hard_count,
                config.server.message_size_limit,
            );
            let smtp_stream = smtp_receiver.into_stream(
                client_addr,
                server_addr,
                time::OffsetDateTime::now_utc(),
                uuid::Uuid::new_v4()
            );
            tokio::pin!(smtp_stream);

            while matches!(tokio_stream::StreamExt::next(&mut smtp_stream).await, Some(Ok(()))) {}
        });

        let client = tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;
            use tokio::io::AsyncWriteExt;
            let stream = tokio::net::TcpStream::connect(server_addr)
                .await
                .unwrap();

            $( let stream = {
                #[allow(clippy::no_effect)] $server_name_tunnel;
                upgrade_tls(server_name, stream).await
            }; )?
            let mut stream = tokio::io::BufReader::new(stream);

            let mut output = vec![];
            let mut line_to_send = input.iter().cloned();

            loop {
                let mut line_received = String::new();
                // read until '\n' or '\r\n'
                if stream.read_line(&mut line_received).await.map_or(true, |l| l == 0) {
                    break;
                }

                output.push(line_received);
                if output.last().unwrap().chars().nth(3) == Some('-') { continue; }
                match line_to_send.next() {
                    Some(line) => stream.write_all(line.as_bytes()).await.unwrap(),
                    None => break,
                }
            }
            $(
                #[allow(clippy::no_effect)] $server_name_starttls;

                if !output.last().unwrap().starts_with("220 ") {
                    todo!();
                }

                let stream = upgrade_tls(server_name, stream.into_inner()).await;
                let mut stream = tokio::io::BufReader::new(stream);

                let mut line_to_send = secured_input.iter().cloned();

                stream.write_all(line_to_send.next().unwrap().as_bytes()).await.unwrap();

                loop {
                    let mut line_received = String::new();
                    // read until '\n' or '\r\n'
                    if stream.read_line(&mut line_received).await.map_or(true, |l| l == 0) {
                        break;
                    }

                    output.push(line_received);
                    if output.last().unwrap().chars().nth(3) == Some('-') { continue; }
                    match line_to_send.next() {
                        Some(line) => stream.write_all(line.as_bytes()).await.unwrap(),
                        None => break,
                    }
                }
            )?

            output
        });

        let (client, server) = tokio::join!(client, server);
        let (client, _server) = (client.unwrap(), server.unwrap());

        pretty_assertions::assert_eq!(expected, client);

        queue_manager_cloned
    }};
    (
        fn $name:ident,
        input = $input:expr,
        expected = $expected:expr
        $(, starttls = $server_name_starttls:expr => $secured_input:expr)?
        $(, tunnel = $server_name_tunnel:expr)?
        $(, config = $config:expr)?
        $(, config_arc = $config_arc:expr)?
        $(, mail_handler = $mail_handler:expr)?
        $(, hierarchy_builder = $hierarchy_builder:expr)?
        $(,)?
    ) => {
        #[test_log::test(tokio::test(flavor = "multi_thread", worker_threads = 2))]
        async fn $name() {
            run_test! {
                input = $input,
                expected = $expected
                $(, starttls = $server_name_starttls => $secured_input)?
                $(, tunnel = $server_name_tunnel)?
                $(, config = $config)?
                $(, config_arc = $config_arc)?
                $(, mail_handler = $mail_handler)?
                $(, hierarchy_builder = $hierarchy_builder)?
            };
        }
    };
}
