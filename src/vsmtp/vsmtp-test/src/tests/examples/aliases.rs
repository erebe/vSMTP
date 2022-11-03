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
use vsmtp_common::mail_context::{Finished, TransactionType};
use vsmtp_common::{addr, mail_context::MailContext, CodeID};
use vsmtp_mail_parser::MessageBody;
use vsmtp_server::Connection;
use vsmtp_server::OnMail;

use crate::run_test;

// TODO: add examples with outgoing & internal transaction types.
run_test! {
    fn test_aliases,
    input = concat![
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
    ],
    expected = concat![
        "220 mydomain.com Service ready\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        // fallback called because gmail.com isn't handled.
        "554 5.7.1 Relay access denied\r\n",
        "250 Ok\r\n",
        "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
        "250 Ok\r\n",
        "221 Service closing transmission channel\r\n"
    ],
    config = vsmtp_config::Config::from_vsl_file(std::path::PathBuf::from_iter([
        env!("CARGO_MANIFEST_DIR"),
        "../../../examples/alias/vsmtp.vsl"
    ]))
    .unwrap(),,
    mail_handler = {
        struct MailHandler;

        #[async_trait::async_trait]
        impl OnMail for MailHandler {
            async fn on_mail<
                S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
            >(
                &mut self,
                _: &mut Connection<S>,
                ctx: Box<MailContext<Finished>>,
                _: MessageBody,
                _: std::sync::Arc<dyn GenericQueueManager>,
            ) -> CodeID {
                let fp = ctx.forward_paths();

                assert_eq!(fp.len(), 2);
                assert_eq!(ctx.transaction_type(), &TransactionType::Incoming(Some("mydomain.com".to_owned())));

                assert_eq!(fp[0].address, addr!("oliver@mydomain.com"));

                // FIXME: logical error: adding a recipient with `add_rcpt_envelop` should take
                //        the `transaction_type` field into account, which it does not do for now.
                assert_eq!(fp[1].address, addr!("john.doe@mydomain.com"));
                // assert_eq!(fp[1].transaction_type, TransactionType::Incoming(Some("mydomain.com".to_owned())));

                CodeID::Ok
            }
        }

        MailHandler
    },,
}
