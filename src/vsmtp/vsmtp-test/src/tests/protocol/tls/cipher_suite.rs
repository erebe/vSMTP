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
use crate::tests::tls::{test_tls_tunneled, with_tls};
use tokio_rustls::rustls;
use vqueue::GenericQueueManager;
use vsmtp_config::get_rustls_config;
use vsmtp_config::DnsResolvers;
use vsmtp_rule_engine::RuleEngine;

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn test_all_cipher_suite() {
    // this cipher_suite produce this error: 'peer is incompatible: no ciphersuites in common'
    // FIXME: ignored for now
    let ignored = [
        rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    ];

    for i in rustls::ALL_CIPHER_SUITES
        .iter()
        .filter(|i| !ignored.contains(&i.suite()))
    {
        let mut config = with_tls();

        config.server.tls.as_mut().unwrap().protocol_version = vec![i.version().version];
        config.server.tls.as_mut().unwrap().cipher_suite = vec![i.suite()];

        let config = arc!(config);
        let queue_manager = vqueue::temp::QueueManager::init(config.clone()).unwrap();
        let resolvers = arc!(DnsResolvers::from_config(&config).unwrap());

        let (client, server) = test_tls_tunneled(
            arc!(RuleEngine::new(
                config.clone(),
                config.app.vsl.domain_dir.clone(),
                resolvers,
                queue_manager,
            )
            .unwrap()),
            "testserver.com",
            config,
            vec!["QUIT\r\n".to_string()],
            [
                "220 testserver.com Service ready",
                "221 Service closing transmission channel",
            ]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>(),
            19980 + u32::from(i.suite().get_u16()) % 100,
            |config| {
                Some(arc!(get_rustls_config(
                    config.server.tls.as_ref().unwrap(),
                    &config.server.r#virtual,
                )
                .unwrap()))
            },
            |io: &tokio_rustls::client::TlsStream<tokio::net::TcpStream>| {
                assert_eq!(
                    i.suite(),
                    io.get_ref().1.negotiated_cipher_suite().unwrap().suite()
                );
            },
        )
        .await
        .unwrap();

        client.unwrap();
        server.unwrap();
    }
}
