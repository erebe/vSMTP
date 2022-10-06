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
use vqueue::GenericQueueManager;
use vsmtp_common::mail_context::MailContext;
use vsmtp_common::CodeID;
use vsmtp_mail_parser::MessageBody;
use vsmtp_server::Connection;
use vsmtp_server::OnMail;

use crate::run_test;

const TOML: &str = include_str!("../../../../../../examples/family/vsmtp.toml");

run_test! {
    fn test_family_setup1,
    input = concat![
        "HELO example.com\r\n",
        "MAIL FROM:<a@spam-domain.org>\r\n",
    ],
    expected = concat![
        "220 doe-family.com Service ready\r\n",
        "250 Ok\r\n",
        "554 permanent problems with the remote server\r\n",
    ],
    config = vsmtp_config::Config::from_toml(TOML).unwrap(),,,,
}

run_test! {
    fn test_family_setup_2,
    input = concat![
        "HELO example.com\r\n",
        "MAIL FROM:<a@example.com>\r\n",
        "RCPT TO:<jenny.doe@doe-family.com>\r\n",
        "RCPT TO:<somebody.else@example.com>\r\n",
        "DATA\r\n",
        "Date: Wed, 6 Dec 2000 05:55:00 -0800 (PST)\r\n",
        "From: a@example.com\r\n",
        "To: jenny.doe@doe-family.com, somebody.else@example.com\r\n",
        "Subject: Hi from France!\r\n",
        "\r\n",
        "Hey Jenny ! It's been a while since ....\r\n",
        ".\r\n",
        "QUIT\r\n"
    ],
    expected = concat![
        "220 doe-family.com Service ready\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
        "250 Ok\r\n",
        "221 Service closing transmission channel\r\n"
    ],
    config = vsmtp_config::Config::from_toml(TOML).unwrap(),,
    mail_handler = {
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
                ctx.envelop
                    .rcpt
                    .iter()
                    .find(|rcpt| rcpt.address.full() == "jane.doe@doe-family.com")
                    .unwrap();

                CodeID::Ok
            }
        }

        MailHandler
    },,
}
