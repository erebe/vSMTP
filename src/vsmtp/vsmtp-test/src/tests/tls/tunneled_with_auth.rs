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
use super::{test_tls_tunneled_with_auth, TEST_SERVER_CERT, TEST_SERVER_KEY};
use vsmtp_config::{get_rustls_config, Config};

fn get_tls_auth_config() -> Config {
    Config::builder()
        .with_version_str("<1.0.0")
        .unwrap()
        .with_server_name("testserver.com")
        .with_user_group_and_default_system("root", "root")
        .unwrap()
        .with_ipv4_localhost()
        .with_default_logs_settings()
        .with_spool_dir_and_default_queues("./tmp/spool")
        .with_safe_tls_config(TEST_SERVER_CERT, TEST_SERVER_KEY)
        .unwrap()
        .with_default_smtp_options()
        .with_default_smtp_error_handler()
        .with_default_smtp_codes()
        .with_safe_auth(true, -1)
        .with_app_at_location("./tmp/app")
        .with_vsl("./src/tests/empty_main.vsl")
        .with_default_app_logs()
        .with_system_dns()
        .without_virtual_entries()
        .validate()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn simple() {
    let mut config = get_tls_auth_config();
    config.app.vsl.filepath = Some("./src/tests/auth.vsl".into());

    let (client, server) = test_tls_tunneled_with_auth(
        "testserver.com",
        std::sync::Arc::new(config),
        [
            "EHLO client.com\r\n",
            "AUTH PLAIN\r\n",
            &format!("{}\r\n", base64::encode("\0hello\0world")),
            "MAIL FROM:<foo@bar>\r\n",
            "RCPT TO:<bar@foo>\r\n",
            "DATA\r\n",
            ".\r\n",
            "QUIT\r\n",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>(),
        [
            "220 testserver.com Service ready",
            "250-testserver.com",
            "250-AUTH PLAIN LOGIN CRAM-MD5",
            "250-8BITMIME",
            "250 SMTPUTF8",
            "334 ",
            "235 2.7.0 Authentication succeeded",
            "250 Ok",
            "250 Ok",
            "354 Start mail input; end with <CRLF>.<CRLF>",
            "250 Ok",
            "221 Service closing transmission channel",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>(),
        20456,
        |config| {
            Some(std::sync::Arc::new(
                get_rustls_config(
                    config.server.tls.as_ref().unwrap(),
                    &config.server.r#virtual,
                )
                .unwrap(),
            ))
        },
        |_| (),
    )
    .await
    .unwrap();

    client.unwrap();
    server.unwrap();
}
