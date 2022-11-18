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
use super::get_tls_config;
use crate::run_test;
use vsmtp_config::field::{FieldServerVirtual, FieldServerVirtualTls, TlsSecurityLevel};

run_test! {
    fn simple,
    input = [
        "NOOP\r\n",
        "HELO client.com\r\n",
        "MAIL FROM:<foo@bar>\r\n",
        "RCPT TO:<bar@foo>\r\n",
        "DATA\r\n",
        ".\r\n",
        "QUIT\r\n",
    ],
    expected = [
        "220 testserver.com Service ready\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
        "250 Ok\r\n",
        "221 Service closing transmission channel\r\n",
    ],
    tunnel = "testserver.com",
    config = {
        let mut config = get_tls_config();
        config.server.tls.as_mut().unwrap().security_level = TlsSecurityLevel::Encrypt;
        config
    },
}

run_test! {
    fn starttls_under_tunnel,
    input = [
        "NOOP\r\n",
        "STARTTLS\r\n",
        "QUIT\r\n",
    ],
    expected = [
        "220 testserver.com Service ready\r\n",
        "250 Ok\r\n",
        "554 5.5.1 Error: TLS already active\r\n",
        "221 Service closing transmission channel\r\n",
    ],
    tunnel = "testserver.com",
    config = {
        let mut config = get_tls_config();
        config.server.tls.as_mut().unwrap().security_level = TlsSecurityLevel::Encrypt;
        config
    },
}

run_test! {
    fn sni,
    input = [
        "NOOP\r\n",
    ],
    expected = [
        // FIXME: supposed to have "second.testserver.com"
        "220 testserver.com Service ready\r\n",
        "250 Ok\r\n",
    ],
    tunnel = "second.testserver.com",
    config = {
        let mut config = get_tls_config();
        config.app.vsl.dirpath = Some("./src/template/sni".into());
        config.server.tls.as_mut().unwrap().security_level = TlsSecurityLevel::Encrypt;
        config.server.r#virtual.insert(
            "second.testserver.com".to_string(),
            FieldServerVirtual {
                tls: Some(
                    FieldServerVirtualTls::from_path(
                        "src/template/certs/sni/second.certificate.crt",
                        "src/template/certs/sni/second.private_key.rsa.key",
                    )
                    .unwrap(),
                ),
                dns: None,
                dkim: None,
            },
        );
        config
    },
}

#[should_panic]
#[test_log::test(tokio::test(flavor = "multi_thread", worker_threads = 2))]
async fn config_ill_formed() {
    run_test! {
        input = [ "NOOP\r\n", ],
        expected = [ "", ],
        tunnel = "testserver.com",
        config = {
            let mut config = get_tls_config();
            config.server.tls = None;
            config
        }
    };
}
