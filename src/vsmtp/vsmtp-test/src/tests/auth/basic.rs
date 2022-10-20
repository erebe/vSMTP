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
use crate::tests::auth::{safe_auth_config, unsafe_auth_config};
use vqueue::GenericQueueManager;
use vsmtp_common::mail_context::Finished;
use vsmtp_common::{addr, mail_context::MailContext, CodeID};
use vsmtp_mail_parser::MessageBody;
use vsmtp_server::Connection;
use vsmtp_server::OnMail;

run_test! {
    err fn plain_in_clair_secured,
    input = concat![
        "EHLO foo\r\n",
        "AUTH PLAIN\r\n"
    ],
    expected = [
        "220 testserver.com Service ready\r\n",
        "250-testserver.com\r\n",
        "250-AUTH \r\n",
        "250-STARTTLS\r\n",
        "250-8BITMIME\r\n",
        "250 SMTPUTF8\r\n",
        "538 5.7.11 Encryption required for requested authentication mechanism\r\n",
    ].concat(),
    config = safe_auth_config(),,,,
}

run_test! {
    fn plain_in_clair_unsecured,
    input = [
        "EHLO client.com\r\n",
        &format!("AUTH PLAIN {}\r\n", base64::encode(format!("\0{}\0{}", "hello", "world"))),
        "MAIL FROM:<foo@bar>\r\n",
        "RCPT TO:<joe@doe>\r\n",
        "DATA\r\n",
        ".\r\n",
        "QUIT\r\n"
    ].concat(),
    expected = [
        "220 testserver.com Service ready\r\n",
        "250-testserver.com\r\n",
        "250-AUTH PLAIN LOGIN CRAM-MD5 ANONYMOUS\r\n",
        "250-STARTTLS\r\n",
        "250-8BITMIME\r\n",
        "250 SMTPUTF8\r\n",
        "235 2.7.0 Authentication succeeded\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
        "250 Ok\r\n",
        "221 Service closing transmission channel\r\n"
    ].concat(),
    config = unsafe_auth_config(),,
    mail_handler = {
        struct T;

        #[async_trait::async_trait]
        impl OnMail for T {
            async fn on_mail<
                S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
            >(
                &mut self,
                _: &mut Connection<S>,
                mail: Box<MailContext<Finished>>,
                _: MessageBody,
                _: std::sync::Arc<dyn GenericQueueManager>,
            ) -> CodeID {
                assert_eq!(mail.client_name(), "client.com");
                assert_eq!(mail.reverse_path().full(), "foo@bar");
                assert_eq!(*mail.forward_paths(), vec![addr!("joe@doe").into()]);
                CodeID::Ok
            }
        }

        T
    },,
}

run_test! {
    multi fn login_in_clair_unsecured,
    input = [
        "EHLO client.com\r\n",
        "AUTH LOGIN\r\n",
        &format!("{}\r\n", base64::encode("hello")),
        &format!("{}\r\n", base64::encode("world")),
        "MAIL FROM:<foo@bar>\r\n",
        "RCPT TO:<joe@doe>\r\n",
        "DATA\r\n",
        ".\r\n",
        "QUIT\r\n"
    ].concat(),
    expected = [
        "220 testserver.com Service ready\r\n",
        "250-testserver.com\r\n",
        "250-AUTH PLAIN LOGIN CRAM-MD5 ANONYMOUS\r\n",
        "250-STARTTLS\r\n",
        "250-8BITMIME\r\n",
        "250 SMTPUTF8\r\n",
        &format!("334 {}\r\n", base64::encode("User Name\0")),
        &format!("334 {}\r\n", base64::encode("Password\0")),
        "235 2.7.0 Authentication succeeded\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
        "250 Ok\r\n",
        "221 Service closing transmission channel\r\n"
    ].concat(),
    config = unsafe_auth_config(),,
    mail_handler = {
        struct T;

        #[async_trait::async_trait]
        impl OnMail for T {
            async fn on_mail<
                S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
            >(
                &mut self,
                _: &mut Connection<S>,
                mail: Box<MailContext<Finished>>,
                _: MessageBody,
                _: std::sync::Arc<dyn GenericQueueManager>,
            ) -> CodeID {
                assert_eq!(mail.client_name(), "client.com");
                assert_eq!(mail.reverse_path().full(), "foo@bar");
                assert_eq!(*mail.forward_paths(), vec![addr!("joe@doe").into()]);
                CodeID::Ok
            }
        }

        T
    },,
}

run_test! {
    fn anonymous_in_clair_unsecured,
    input = [
        "EHLO client.com\r\n",
        &format!("AUTH ANONYMOUS {}\r\n", base64::encode("my-anonymous-token")),
        "MAIL FROM:<foo@bar>\r\n",
        "RCPT TO:<joe@doe>\r\n",
        "DATA\r\n",
        ".\r\n",
        "QUIT\r\n"
    ].concat(),
    expected = [
        "220 testserver.com Service ready\r\n",
        "250-testserver.com\r\n",
        "250-AUTH PLAIN LOGIN CRAM-MD5 ANONYMOUS\r\n",
        "250-STARTTLS\r\n",
        "250-8BITMIME\r\n",
        "250 SMTPUTF8\r\n",
        "235 2.7.0 Authentication succeeded\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
        "250 Ok\r\n",
        "221 Service closing transmission channel\r\n"
    ].concat(),
    config = unsafe_auth_config(),,
    mail_handler = {
        struct T;

        #[async_trait::async_trait]
        impl OnMail for T {
            async fn on_mail<
                S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
            >(
                &mut self,
                _: &mut Connection<S>,
                mail: Box<MailContext<Finished>>,
                _: MessageBody,
                _: std::sync::Arc<dyn GenericQueueManager>,
            ) -> CodeID {
                assert_eq!(mail.client_name(), "client.com");
                assert_eq!(mail.reverse_path().full(), "foo@bar");
                assert_eq!(*mail.forward_paths(), vec![addr!("joe@doe").into()]);
                CodeID::Ok
            }
        }

        T
    },,
}

run_test! {
    fn plain_in_clair_unsecured_utf8,
    input = [
        "EHLO client.com\r\n",
        &format!("AUTH PLAIN {}\r\n", base64::encode(format!("\0{}\0{}", "héllo", "wÖrld"))),
        "MAIL FROM:<foo@bar>\r\n",
        "RCPT TO:<joe@doe>\r\n",
        "DATA\r\n",
        ".\r\n",
        "QUIT\r\n"
    ].concat(),
    expected = [
        "220 testserver.com Service ready\r\n",
        "250-testserver.com\r\n",
        "250-AUTH PLAIN LOGIN CRAM-MD5 ANONYMOUS\r\n",
        "250-STARTTLS\r\n",
        "250-8BITMIME\r\n",
        "250 SMTPUTF8\r\n",
        "235 2.7.0 Authentication succeeded\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
        "250 Ok\r\n",
        "221 Service closing transmission channel\r\n"
    ].concat(),
    config = unsafe_auth_config(),,
    mail_handler = {
        struct T;

        #[async_trait::async_trait]
        impl OnMail for T {
            async fn on_mail<
                S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
            >(
                &mut self,
                _: &mut Connection<S>,
                mail: Box<MailContext<Finished>>,
                _: MessageBody,
                _: std::sync::Arc<dyn GenericQueueManager>,
            ) -> CodeID {
                assert_eq!(mail.client_name(), "client.com");
                assert_eq!(mail.reverse_path().full(), "foo@bar");
                assert_eq!(*mail.forward_paths(), vec![addr!("joe@doe").into()]);
                CodeID::Ok
            }
        }

        T
    },,
}

run_test! {
    err fn plain_in_clair_invalid_credentials,
    input = [
        "EHLO client.com\r\n",
        &format!("AUTH PLAIN {}\r\n", base64::encode(format!("\0{}\0{}", "foo", "bar"))),
        "MAIL FROM:<foo@bar>\r\n",
        "RCPT TO:<joe@doe>\r\n",
        "DATA\r\n",
        ".\r\n",
        "QUIT\r\n"
    ].concat(),
    expected = [
        "220 testserver.com Service ready\r\n",
        "250-testserver.com\r\n",
        "250-AUTH PLAIN LOGIN CRAM-MD5 ANONYMOUS\r\n",
        "250-STARTTLS\r\n",
        "250-8BITMIME\r\n",
        "250 SMTPUTF8\r\n",
        "535 5.7.8 Authentication credentials invalid\r\n"
    ].concat(),
    config = unsafe_auth_config(),,,,
}

run_test! {
    err fn plain_in_clair_unsecured_cancel,
    input = [
        "EHLO client.com\r\n",
        "AUTH PLAIN\r\n",
        "*\r\n",
        "AUTH PLAIN\r\n",
        "*\r\n",
        "AUTH PLAIN\r\n",
        "*\r\n",
        "AUTH PLAIN\r\n",
        "*\r\n",
    ].concat(),
    expected = [
        "220 testserver.com Service ready\r\n",
        "250-testserver.com\r\n",
        "250-AUTH PLAIN LOGIN CRAM-MD5 ANONYMOUS\r\n",
        "250-STARTTLS\r\n",
        "250-8BITMIME\r\n",
        "250 SMTPUTF8\r\n",
        "334 \r\n",
        "501 Authentication canceled by client\r\n",
        "334 \r\n",
        "501 Authentication canceled by client\r\n",
        "334 \r\n",
        "501 Authentication canceled by client\r\n",
        "334 \r\n",
        "530 5.7.0 Authentication required\r\n"
    ].concat(),
    config = {
        let mut config = unsafe_auth_config();
        config.server.smtp.auth.as_mut().unwrap().attempt_count_max = 3;
        config
    },,,,
}

run_test! {
    fn plain_in_clair_unsecured_bad_base64,
    input = [
        "EHLO client.com\r\n",
        "AUTH PLAIN foobar\r\n",
        "MAIL FROM:<foo@bar>\r\n",
        "QUIT\r\n"
    ].concat(),
    expected = [
        "220 testserver.com Service ready\r\n",
        "250-testserver.com\r\n",
        "250-AUTH PLAIN LOGIN CRAM-MD5 ANONYMOUS\r\n",
        "250-STARTTLS\r\n",
        "250-8BITMIME\r\n",
        "250 SMTPUTF8\r\n",
        "501 5.5.2 Invalid, not base64\r\n",
        "503 Bad sequence of commands\r\n",
        "221 Service closing transmission channel\r\n"
    ].concat(),
    config = unsafe_auth_config(),,,,
}

run_test! {
    fn plain_in_clair_unsecured_without_initial_response,
    input = [
        "EHLO client.com\r\n",
        "AUTH PLAIN\r\n",
        &format!("{}\r\n", base64::encode(format!("\0{}\0{}", "hello", "world"))),
        "MAIL FROM:<foo@bar>\r\n",
        "RCPT TO:<joe@doe>\r\n",
        "DATA\r\n",
        ".\r\n",
        "QUIT\r\n"
    ].concat(),
    expected = [
        "220 testserver.com Service ready\r\n",
        "250-testserver.com\r\n",
        "250-AUTH PLAIN LOGIN CRAM-MD5 ANONYMOUS\r\n",
        "250-STARTTLS\r\n",
        "250-8BITMIME\r\n",
        "250 SMTPUTF8\r\n",
        // See https://datatracker.ietf.org/doc/html/rfc4422#section-5 2.a
        "334 \r\n",
        "235 2.7.0 Authentication succeeded\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
        "250 Ok\r\n",
        "221 Service closing transmission channel\r\n"
    ].concat(),
    config = unsafe_auth_config(),,
    mail_handler = {
        struct T;

        #[async_trait::async_trait]
        impl OnMail for T {
            async fn on_mail<
                S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
            >(
                &mut self,
                _: &mut Connection<S>,
                mail: Box<MailContext<Finished>>,
                _: MessageBody,
                _: std::sync::Arc<dyn GenericQueueManager>,
            ) -> CodeID {
                assert_eq!(mail.client_name(), "client.com");
                assert_eq!(mail.reverse_path().full(), "foo@bar");
                assert_eq!(*mail.forward_paths(), vec![addr!("joe@doe").into()]);
                CodeID::Ok
            }
        }

        T
    },,
}

run_test! {
    fn no_auth_with_authenticated_policy,
    input = [
        "EHLO client.com\r\n",
        "MAIL FROM:<foo@bar>\r\n",
        "QUIT\r\n",
    ].concat(),
    expected = [
        "220 testserver.com Service ready\r\n",
        "250-testserver.com\r\n",
        "250-AUTH PLAIN LOGIN CRAM-MD5 ANONYMOUS\r\n",
        "250-STARTTLS\r\n",
        "250-8BITMIME\r\n",
        "250 SMTPUTF8\r\n",
        "530 5.7.0 Authentication required\r\n",
        "221 Service closing transmission channel\r\n"
    ].concat(),
    config = {
        let mut config = unsafe_auth_config();
        config
            .server
            .smtp
            .auth
            .as_mut()
            .unwrap()
            .must_be_authenticated = true;
        config
    },,,,
}

run_test! {
    err fn client_must_not_start,
    input = [
        "EHLO client.com\r\n",
        "AUTH LOGIN foobar\r\n",
        "MAIL FROM:<foo@bar>\r\n",
    ].concat(),
    expected = [
        "220 testserver.com Service ready\r\n",
        "250-testserver.com\r\n",
        "250-AUTH PLAIN LOGIN CRAM-MD5 ANONYMOUS\r\n",
        "250-STARTTLS\r\n",
        "250-8BITMIME\r\n",
        "250 SMTPUTF8\r\n",
        "501 5.7.0 Client must not start with this mechanism\r\n"
    ].concat(),
    config = unsafe_auth_config(),,,,
}
