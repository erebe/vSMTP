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
use vsmtp_common::ContextFinished;
use vsmtp_common::{addr, CodeID};
use vsmtp_mail_parser::BodyType;
use vsmtp_mail_parser::Mail;
use vsmtp_mail_parser::MailHeaders;
use vsmtp_mail_parser::MessageBody;
use vsmtp_server::OnMail;

macro_rules! test_lang {
    ($lang_code:expr) => {{

        struct T;

        #[async_trait::async_trait]
        impl OnMail for T {
            async fn on_mail(
                &mut self,
                mail: Box<ContextFinished>,
                mut message: MessageBody,
                _: std::sync::Arc<dyn GenericQueueManager>,
            ) -> CodeID {

                assert_eq!(mail.helo.client_name.to_string(), "foobar");
                assert_eq!(mail.mail_from.reverse_path, Some(addr!("john@doe")));
                assert_eq!(*mail.rcpt_to.forward_paths, vec![addr!("aa@bb").into()]);

                pretty_assertions::assert_eq!(
                    *message
                        .parsed::<vsmtp_mail_parser::MailMimeParser>()
                        .unwrap(),
                    Mail {
                        headers: MailHeaders([
                            ("from", "john doe <john@doe>"),
                            ("subject", "ar"),
                            ("to", "aa@bb"),
                            ("message-id", "<xxx@localhost.com>"),
                            ("date", "Tue, 30 Nov 2021 20:54:27 +0100"),
                        ]
                        .into_iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect::<Vec<_>>()),
                        body: BodyType::Regular(
                            include_str!($lang_code)
                                .lines()
                                .map(str::to_string)
                                .map(|s| if s.starts_with("..") {
                                    s[1..].to_string()
                                } else {
                                    s
                                })
                                .collect::<Vec<_>>()
                        )
                    }
                );
                CodeID::Ok
            }
        }

        crate::run_test! {
            input = [
                "HELO foobar\r\n",
                "MAIL FROM:<john@doe>\r\n",
                "RCPT TO:<aa@bb>\r\n",
                "DATA\r\n",
                &[
                    "from: john doe <john@doe>\r\n",
                    "subject: ar\r\n",
                    "to: aa@bb\r\n",
                    "message-id: <xxx@localhost.com>\r\n",
                    "date: Tue, 30 Nov 2021 20:54:27 +0100\r\n",
                    "\r\n",
                    &include_str!($lang_code).lines().map(str::to_string).collect::<Vec<_>>().join("\r\n"),
                    // adding a "\r\n" after the mail because [`join`] don t add after the final element
                    "\r\n",
                    ".\r\n",
                ].concat(),
                "QUIT\r\n",
            ],
            expected = [
                "220 testserver.com Service ready\r\n",
                "250 Ok\r\n",
                "250 Ok\r\n",
                "250 Ok\r\n",
                "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
                "250 Ok\r\n",
                "221 Service closing transmission channel\r\n",
            ],
            mail_handler = T,
        }
    }};
}

#[tokio::test]
async fn test_receiver_utf8_zh() {
    test_lang!("../../template/mail/zh.txt");
}

#[tokio::test]
async fn test_receiver_utf8_el() {
    test_lang!("../../template/mail/el.txt");
}

#[tokio::test]
async fn test_receiver_utf8_ar() {
    test_lang!("../../template/mail/ar.txt");
}

#[tokio::test]
async fn test_receiver_utf8_ko() {
    test_lang!("../../template/mail/ko.txt");
}
