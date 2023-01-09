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

use crate::run_test;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use vsmtp_config::field::FieldServerVirtual;
use vsmtp_config::field::FieldServerVirtualTls;
use vsmtp_config::Config;

fn get_tls_auth_config() -> Config {
    Config::builder()
        .with_version_str("<1.0.0")
        .unwrap()
        .without_path()
        .with_server_name("testserver.com")
        .with_user_group_and_default_system("root", "root")
        .unwrap()
        .with_ipv4_localhost()
        .with_default_logs_settings()
        .with_spool_dir_and_default_queues("./tmp/spool")
        .with_tls()
        .unwrap()
        .with_default_smtp_options()
        .with_default_smtp_error_handler()
        .with_default_smtp_codes()
        .with_safe_auth(-1)
        .with_app_at_location("./tmp/app")
        .with_vsl("./src/template/auth/domain-enabled")
        .with_default_app_logs()
        .with_system_dns()
        .without_virtual_entries()
        .validate()
        .unwrap()
}

run_test! {
    fn simple,
    input = [
        "EHLO client.com\r\n",
        "AUTH PLAIN\r\n",
        &format!("{}\r\n", STANDARD.encode("\0hello\0world")),
        "MAIL FROM:<foo@bar>\r\n",
        "RCPT TO:<bar@foo>\r\n",
        "DATA\r\n",
        ".\r\n",
        "QUIT\r\n",
    ],
    expected = [
        "220 testserver.com Service ready\r\n",
        "250-testserver.com\r\n",
        "250-AUTH PLAIN LOGIN CRAM-MD5\r\n",
        "250-8BITMIME\r\n",
        "250 SMTPUTF8\r\n",
        "334 \r\n",
        "235 2.7.0 Authentication succeeded\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
        "250 Ok\r\n",
        "221 Service closing transmission channel\r\n",
    ],
    tunnel = "testserver.com",
    config = {
        let mut config = get_tls_auth_config();
        config.app.vsl.domain_dir = Some("./src/template/sni".into());
        config.server.r#virtual.insert(
            "testserver.com".to_string(),
            FieldServerVirtual {
                tls: Some(
                    FieldServerVirtualTls::from_path(
                        "src/template/certs/certificate.crt",
                        "src/template/certs/private_key.rsa.key",
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
