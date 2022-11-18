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
use vsmtp_config::field::TlsSecurityLevel;

// TODO: add a test starttls + sni

run_test! {
    fn simple,
    input = [
        "EHLO client.com\r\n",
        "STARTTLS\r\n"
    ],
    expected = [
        "220 testserver.com Service ready\r\n",
        "250-testserver.com\r\n",
        "250-STARTTLS\r\n",
        "250-8BITMIME\r\n",
        "250 SMTPUTF8\r\n",
        "220 TLS go ahead\r\n",
        "250-testserver.com\r\n",
        "250-8BITMIME\r\n",
        "250 SMTPUTF8\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
        "250 Ok\r\n",
        "221 Service closing transmission channel\r\n",
    ],
    starttls = "testserver.com" => [
        "EHLO client.com\r\n",
        "MAIL FROM:<foo@bar>\r\n",
        "RCPT TO:<bar@foo>\r\n",
        "DATA\r\n",
        ".\r\n",
        "QUIT\r\n",
    ],
    config = {
        let mut config = get_tls_config();
        config.server.tls.as_mut().unwrap().security_level = TlsSecurityLevel::Encrypt;
        config
    },
}

run_test! {
    fn double_starttls,
    input = [
        "EHLO client.com\r\n",
        "STARTTLS\r\n"
    ],
    expected = [
        "220 testserver.com Service ready\r\n",
        "250-testserver.com\r\n",
        "250-STARTTLS\r\n",
        "250-8BITMIME\r\n",
        "250 SMTPUTF8\r\n",
        "220 TLS go ahead\r\n",
        "250-testserver.com\r\n",
        "250-8BITMIME\r\n",
        "250 SMTPUTF8\r\n",
        "554 5.5.1 Error: TLS already active\r\n",
        "221 Service closing transmission channel\r\n",
    ],
    starttls = "testserver.com" => [
        "EHLO secured.client.com\r\n",
        "STARTTLS\r\n",
        "QUIT\r\n"
    ],
    config = {
        let mut config = get_tls_config();
        config.server.tls.as_mut().unwrap().security_level = TlsSecurityLevel::Encrypt;
        config
    },
}

run_test! {
    fn starttls_disabled,
    input = [
        "EHLO foobar\r\n",
        "STARTTLS\r\n",
        "QUIT\r\n"
    ],
    expected = [
        "220 testserver.com Service ready\r\n",
        "250-testserver.com\r\n",
        "250-STARTTLS\r\n",
        "250-8BITMIME\r\n",
        "250 SMTPUTF8\r\n",
        "454 TLS not available due to temporary reason\r\n",
        "221 Service closing transmission channel\r\n",
    ]
}

run_test! {
    fn starttls_disabled_but_encrypted_required,
    input = [
        "EHLO foobar\r\n",
        "MAIL FROM: <foo@bar>\r\n",
        "QUIT\r\n"
    ],
    expected = [
        "220 testserver.com Service ready\r\n",
        "250-testserver.com\r\n",
        "250-STARTTLS\r\n",
        "250-8BITMIME\r\n",
        "250 SMTPUTF8\r\n",
        "530 Must issue a STARTTLS command first\r\n",
        "221 Service closing transmission channel\r\n",
    ],
    config = {
        let mut config = get_tls_config();
        config.server.tls.as_mut().unwrap().security_level = TlsSecurityLevel::Encrypt;
        config
    }
}

#[should_panic]
#[test_log::test(tokio::test(flavor = "multi_thread", worker_threads = 2))]
async fn config_ill_formed() {
    run_test! {
        input = [ "NOOP\r\n", ],
        expected = [ "", ],
        starttls = "testserver.com" => [ "" ],
        config = {
            let mut config = get_tls_config();
            config.server.tls = None;
            config
        }
    };
}
