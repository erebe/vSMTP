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
use crate::run_test;
use vqueue::GenericQueueManager;
use vsmtp_common::addr;
use vsmtp_common::CodeID;
use vsmtp_common::{ContextFinished, TransactionType};
use vsmtp_mail_parser::MessageBody;
use vsmtp_server::OnMail;

const CONFIG: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../examples/message/vsmtp.vsl"
);

run_test! {
    fn test_message_1,
    input = [
        "HELO foo\r\n",
        "MAIL FROM: <john.doe@example.com>\r\n",
        "RCPT TO: <someone@example.com>\r\n",
        "DATA\r\n",
        concat!(
            "Date: 0\r\n",
            "From: john.doe@example.com\r\n",
            "Subject: FWD: you account has been suspended\r\n",
            ".\r\n",
        )
    ],
    expected = [
        "220 testserver.com Service ready\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
        "501 this server does not accept FWD messages\r\n"
    ],
    config = vsmtp_config::Config::from_vsl_file(CONFIG).unwrap(),
}

run_test! {
    fn test_message_2,
    input = [
        "HELO foo\r\n",
        "MAIL FROM: <john.doe@example.com>\r\n",
        "RCPT TO: <green@example.com>\r\n",
        "RCPT TO: <grey@example.com>\r\n",
        "DATA\r\n",
        concat!(
            "Date: 0\r\n",
            "From: john.doe@example.com\r\n",
            "To: green@example.com, grey@example.com\r\n",
            "Subject: you account has been suspended\r\n",
            ".\r\n",
        ),
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
        "221 Service closing transmission channel\r\n"
    ],
    config = vsmtp_config::Config::from_vsl_file(CONFIG).unwrap(),
    mail_handler = {
        struct T;

        #[async_trait::async_trait]
        impl OnMail for T {
            async fn on_mail(
                &mut self,
                mail: Box<ContextFinished>,
                body: MessageBody,
                _: std::sync::Arc<dyn GenericQueueManager>,
            ) -> CodeID {

                match mail.rcpt_to.transaction_type {
                    TransactionType::Internal => {

                        println!("Internal");

                        assert_eq!(mail.helo.client_name.to_string(), "foo");
                        assert_eq!(mail.mail_from.reverse_path, Some(addr!("john.doe@example.com")));
                        assert!(
                            mail.rcpt_to.delivery
                                .values()
                                .flatten()
                                .map(|(addr, _)| addr)
                                .cloned()
                                .eq([
                                    addr!("green@example.com"),
                                    addr!("grey@example.com")
                                ])
                        );

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
                            Some("anonymous@example.com, grey@example.com, john.doe@example.com".to_string())
                        );
                    },
                    TransactionType::Outgoing { domain } => {
                        println!("Outgoing");

                        assert_eq!(domain, "example.com".parse().unwrap());
                        assert_eq!(mail.rcpt_to.forward_paths.len(), 0);
                    },
                    TransactionType::Incoming(_) => panic!("The email should be internal & outgoing"),
                }

                CodeID::Ok
            }
        }
        T
    },
}
