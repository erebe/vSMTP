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
// use crate::run_test;
// use vqueue::GenericQueueManager;
// use vsmtp_common::addr;
// use vsmtp_common::mail_context::Finished;
// use vsmtp_common::mail_context::MailContext;
// use vsmtp_common::CodeID;
// use vsmtp_mail_parser::MessageBody;
// use vsmtp_server::Connection;
// use vsmtp_server::OnMail;

// TODO: this example needs to be re-worked with the new

// const CONFIG: &str = concat!(
//     env!("CARGO_MANIFEST_DIR"),
//     "/../../../examples/message/vsmtp.vsl"
// );

// run_test! {
//     fn test_message_1,
//     input = [
//         "HELO foo\r\n",
//         "MAIL FROM: <john.doe@example.com>\r\n",
//         "RCPT TO: <someone@example.com>\r\n",
//         "DATA\r\n",
//         "Date: 0\r\n",
//         "From: john.doe@example.com\r\n",
//         "Subject: FWD: you account has been suspended\r\n",
//         ".\r\n",
//     ].concat(),
//     expected = [
//         "220 testserver.com Service ready\r\n",
//         "250 Ok\r\n",
//         "250 Ok\r\n",
//         "250 Ok\r\n",
//         "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
//         "501 this server does not accept FWD messages\r\n"
//     ]
//     .concat(),
//     config = vsmtp_config::Config::from_vsl_file(CONFIG).unwrap(),,,,
// }

// run_test! {
//     fn test_message_2,
//     input = [
//         "HELO foo\r\n",
//         "MAIL FROM: <john.doe@example.com>\r\n",
//         "RCPT TO: <green@example.com>\r\n",
//         "DATA\r\n",
//         "Date: 0\r\n",
//         "From: john.doe@example.com\r\n",
//         "To: green@example.com\r\n",
//         "Subject: you account has been suspended\r\n",
//         ".\r\n",
//         "QUIT\r\n",
//     ].concat(),
//     expected = [
//         "220 testserver.com Service ready\r\n",
//         "250 Ok\r\n",
//         "250 Ok\r\n",
//         "250 Ok\r\n",
//         "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
//         "250 Ok\r\n",
//         "221 Service closing transmission channel\r\n"
//     ]
//     .concat(),
//     config = vsmtp_config::Config::from_vsl_file(CONFIG).unwrap(),,
//     mail_handler = {
//         struct T;

//         #[async_trait::async_trait]
//         impl OnMail for T {
//             async fn on_mail<
//                 S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
//             >(
//                 &mut self,
//                 _: &mut Connection<S>,
//                 mail: Box<MailContext<Finished>>,
//                 body: MessageBody,
//                 _: std::sync::Arc<dyn GenericQueueManager>,
//             ) -> CodeID {
//                 assert_eq!(mail.client_name(), "foo");
//                 assert_eq!(mail.reverse_path().full(), "john.doe@example.com");
//                 assert_eq!(*mail.forward_paths(), vec![addr!("green@example.com").into()]);

//                 assert!(body.get_header("X-Connect").is_some());
//                 assert_eq!(
//                     body.get_header("X-Info"),
//                     Some("email processed by me.".to_string())
//                 );

//                 assert_eq!(
//                     body.get_header("From"),
//                     Some("anonymous@example.com".to_string())
//                 );

//                 assert_eq!(
//                     body.get_header("To"),
//                     Some("anonymous@example.com, john.doe@example.com".to_string())
//                 );

//                 CodeID::Ok
//             }
//         }
//         T
//     },,
// }
