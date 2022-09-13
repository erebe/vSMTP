/*
 * vSMTP mail transfer agent
 * Copyright (C) 2022 viridIT SAS
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or any later version.
 *
 *  This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see https://www.gnu.org/licenses/.
 *
*/
use crate::test_receiver;
use vqueue::GenericQueueManager;
use vsmtp_common::addr;
use vsmtp_common::mail_context::MailContext;
use vsmtp_common::CodeID;
use vsmtp_mail_parser::MessageBody;
use vsmtp_server::Connection;
use vsmtp_server::OnMail;

#[tokio::test]
async fn test_message() {
    #[derive(Clone)]
    struct T;

    #[async_trait::async_trait]
    impl OnMail for T {
        async fn on_mail<
            S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
        >(
            &mut self,
            _: &mut Connection<S>,
            mail: Box<MailContext>,
            body: MessageBody,
            _: std::sync::Arc<dyn GenericQueueManager>,
        ) -> CodeID {
            assert_eq!(mail.envelop.helo, "foo");
            assert_eq!(mail.envelop.mail_from.full(), "john.doe@example.com");
            assert_eq!(mail.envelop.rcpt, vec![addr!("green@example.com").into()]);

            assert!(body.get_header("X-Connect").is_some());
            assert_eq!(
                body.get_header("X-Info"),
                Some("email processed by me.".to_string())
            );

            assert_eq!(
                body.get_header("From"),
                Some("anonymous@example.com".to_string())
            );

            assert_eq!(
                body.get_header("To"),
                Some("anonymous@example.com, john.doe@example.com".to_string())
            );

            CodeID::Ok
        }
    }

    let toml = include_str!("../../../../../../examples/message/vsmtp.toml");
    let config = vsmtp_config::Config::from_toml(toml).unwrap();

    // testing the forward rule.
    assert!(test_receiver! {
        with_config => config.clone(),
        [
            "HELO foo\r\n",
            "MAIL FROM: <john.doe@example.com>\r\n",
            "RCPT TO: <someone@example.com>\r\n",
            "DATA\r\n",
            "Date: 0\r\n",
            "From: john.doe@example.com\r\n",
            "Subject: FWD: you account has been suspended\r\n",
            ".\r\n",
        ].concat(),
        [
            "220 testserver.com Service ready\r\n",
            "250 Ok\r\n",
            "250 Ok\r\n",
            "250 Ok\r\n",
            "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
            "501  this server does not accept FWD messages\r\n"
        ]
        .concat()
    }
    .is_ok());

    assert!(test_receiver! {
        on_mail => &mut T { },
        with_config => config,
        [
            "HELO foo\r\n",
            "MAIL FROM: <john.doe@example.com>\r\n",
            "RCPT TO: <green@example.com>\r\n",
            "DATA\r\n",
            "Date: 0\r\n",
            "From: john.doe@example.com\r\n",
            "To: green@example.com\r\n",
            "Subject: you account has been suspended\r\n",
            ".\r\n",
            "QUIT\r\n",
        ].concat(),
        [
            "220 testserver.com Service ready\r\n",
            "250 Ok\r\n",
            "250 Ok\r\n",
            "250 Ok\r\n",
            "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
            "250 Ok\r\n",
            "221 Service closing transmission channel\r\n"
        ]
        .concat()
    }
    .is_ok());
}
