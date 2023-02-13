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
use vqueue::GenericQueueManager;
use vsmtp_common::addr;
use vsmtp_common::Address;
use vsmtp_common::ClientName;
use vsmtp_common::CodeID;
use vsmtp_common::ContextFinished;
use vsmtp_mail_parser::MessageBody;
use vsmtp_server::OnMail;

// TODO: add SMTPUTF8
// TODO: add errors tests

#[rstest::rstest]
#[case("<foo@bar>", Some("foo@bar"))]
#[case::null("<>", None)]
#[case::null_with_body("<> BODY=8BITMIME", None)]
#[case::whitespace_before("       <foo@bar>", Some("foo@bar"))]
#[case::whitespace_after("<foo@bar>           ", Some("foo@bar"))]
#[case::bit7("<foo@bar> BODY=7BIT", Some("foo@bar"))]
#[case::bitmime8("<foo@bar> BODY=8BITMIME", Some("foo@bar"))]
#[case::bit7_whitespace("<foo@bar>      BODY=7BIT", Some("foo@bar"))]
#[case::bitmime8_whitespace("      <foo@bar>      BODY=8BITMIME   ", Some("foo@bar"))]
#[trace]
fn test(#[case] mail_from: &str, #[case] reverse_path: Option<&str>) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let reverse_path = reverse_path.map(|s| addr!(s));

    runtime.block_on(async move {
        run_test! {
            input = [
                "EHLO foobar\r\n",
                &format!("MAIL FROM:{mail_from}\r\n"),
                "RCPT TO:<bar@foo>\r\n",
                "DATA\r\n",
                ".\r\n",
            ],
            expected = [
                "220 testserver.com Service ready\r\n",
                "250-testserver.com\r\n",
                "250-STARTTLS\r\n",
                "250-8BITMIME\r\n",
                "250 SMTPUTF8\r\n",
                "250 Ok\r\n",
                "250 Ok\r\n",
                "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
                "250 Ok\r\n",
            ],
            mail_handler = {
                struct T {
                    reverse_path: Option<Address>,
                }

                #[async_trait::async_trait]
                impl OnMail for T {
                    async fn on_mail(
                        &mut self,
                        ctx: Box<ContextFinished>,
                        _: MessageBody,
                        _: std::sync::Arc<dyn GenericQueueManager>,
                    ) -> CodeID {
                        assert_eq!(ctx.helo.client_name, ClientName::Domain("foobar".parse().unwrap()));
                        assert_eq!(ctx.mail_from.reverse_path, self.reverse_path);

                        CodeID::Ok
                    }
                }

                T {
                    reverse_path,
                }
            }
        }
    });
}
