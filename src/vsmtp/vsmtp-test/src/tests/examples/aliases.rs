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
use vsmtp_common::{addr, mail_context::MailContext, CodeID};
use vsmtp_mail_parser::MessageBody;
use vsmtp_server::Connection;
use vsmtp_server::OnMail;

#[tokio::test]
async fn test_aliases() {
    #[derive(Clone)]
    struct MailHandler;

    #[async_trait::async_trait]
    impl OnMail for MailHandler {
        async fn on_mail<
            S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
        >(
            &mut self,
            _: &mut Connection<S>,
            ctx: Box<MailContext>,
            _: MessageBody,
            _: std::sync::Arc<dyn GenericQueueManager>,
        ) -> CodeID {
            assert_eq!(
                ctx.envelop.rcpt,
                vec![
                    addr!("john@gmail.com").into(),
                    addr!("oliver@mydomain.com").into(),
                    addr!("john.doe@mydomain.com").into(),
                ]
            );

            CodeID::Ok
        }
    }

    let toml = include_str!("../../../../../../examples/alias/vsmtp.toml");
    let config = vsmtp_config::Config::from_toml(toml).unwrap();

    assert!(test_receiver! {
        on_mail => &mut MailHandler { },
        with_config => config.clone(),
        [
            "HELO foo\r\n",
            "MAIL FROM: <someone@example.com>\r\n",
            "RCPT TO: <jenny@mydomain.com>\r\n",
            "RCPT TO: <joe@mydomain.com>\r\n",
            "RCPT TO: <john@gmail.com>\r\n",
            "RCPT TO: <oliver@mydomain.com>\r\n",
            "DATA\r\n",
            "From: <someone@example.com>\r\n",
            "To: jenny@mydomain.com, joe@mydomain.com, john@gmail.com, oliver@mydomain.com\r\n",
            "Subject: test\r\n",
            "\r\n",
            "test\r\n",
            ".\r\n",
            "QUIT\r\n"
        ].concat(),
        [
            "220 mydomain.com Service ready\r\n",
            "250 Ok\r\n",
            "250 Ok\r\n",
            "250 Ok\r\n",
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
