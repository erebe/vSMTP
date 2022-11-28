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
use vsmtp_common::ClientName;
use vsmtp_common::CodeID;
use vsmtp_common::ContextFinished;
use vsmtp_mail_parser::MessageBody;
use vsmtp_server::OnMail;

fn to_args(client_name: &ClientName) -> String {
    match client_name {
        ClientName::Domain(domain) => domain.clone(),
        ClientName::Ip4(ip) => format!("[{ip}]"),
        ClientName::Ip6(ip) => format!("[IPv6:{ip}]"),
    }
}

macro_rules! to_tab {
    ($e:expr) => {
        $e.into_iter().map(|s| s.to_string()).collect::<Vec<_>>()
    };
}

#[rstest::rstest]
#[case::no_space(
    None,
    None,
    to_tab!(["{verb}\r\n"]),
    to_tab!(["500 Syntax error command unrecognized\r\n"]),
)]
#[case::no_arg(
    None,
    None,
    to_tab!(["{verb} \r\n"]),
    to_tab!(["501 Syntax error in parameters or arguments\r\n"]),
)]
#[case::whitespace_before(
    None,
    None,
    to_tab!([" \t  {verb} {client_name}\r\n"]),
    to_tab!(["500 Syntax error command unrecognized\r\n"]),
)]
// TODO: whitespace between and after could be fine..? should we emit a warning?
#[case::whitespace_between(
    None,
    None,
    to_tab!(["{verb}  \t   \t  {client_name}\r\n"]),
    to_tab!(["501 Syntax error in parameters or arguments\r\n"]),
)]
#[case::whitespace_after(
    None,
    None,
    to_tab!(["{verb} {client_name}\t     \t\r\n"]),
    to_tab!(["501 Syntax error in parameters or arguments\r\n"]),
)]
#[case::bad_domain(
    None,
    None,
    to_tab!(["{verb} not\\a.valid\"domain\r\n"]),
    to_tab!(["501 Syntax error in parameters or arguments\r\n"]),
)]
#[case::bad_ip4(
    None,
    None,
    to_tab!(["{verb} 0.0.0.0\r\n"]),
    to_tab!(["501 Syntax error in parameters or arguments\r\n"]),
)]
#[case::two_word(
    None,
    None,
    to_tab!(["{verb} one two\r\n"]),
    to_tab!(["501 Syntax error in parameters or arguments\r\n"]),
)]
#[case::too_long(
    None,
    None,
    to_tab!([["{verb} ", &"a".repeat(1000), "\r\n"].concat()]),
    to_tab!(["501 Syntax error in parameters or arguments\r\n"]),
)]
#[case(
    Some("HELO"),
    Some(ClientName::Domain("mydomain.com".to_string())),
    to_tab!([
        "{verb} {client_name}\r\n",
        "MAIL FROM:<mailbox@mydomain.com>\r\n",
        "RCPT TO:<mailbox@mydomain.com>\r\n",
        "DATA\r\n",
        ".\r\n"
    ]),
    to_tab!([
        "250 Ok\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
        "250 Ok\r\n",
    ]),
)]
#[case(
    Some("EHLO"),
    None,
    to_tab!([
        "{verb} {client_name}\r\n",
        "MAIL FROM:<mailbox@mydomain.com>\r\n",
        "RCPT TO:<mailbox@mydomain.com>\r\n",
        "DATA\r\n",
        ".\r\n"
    ]),
    to_tab!([
        "250-testserver.com\r\n",
        "250-STARTTLS\r\n",
        "250-8BITMIME\r\n",
        "250 SMTPUTF8\r\n",
        "250 Ok\r\n",
        "250 Ok\r\n",
        "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
        "250 Ok\r\n",
    ]),
)]
#[trace]
fn test(
    #[values("HELO", "EHLO")] verb: &str,
    #[case] verb_user: Option<&str>,
    #[values(
        ClientName::Domain("mydomain.com".to_string()),
        ClientName::Ip4("0.0.0.0".parse().unwrap()),
        ClientName::Ip6("0011:2233:4455:6677:8899:aabb:ccdd:eeff".parse().unwrap())
    )]
    client_name: ClientName,
    #[case] client_name_user: Option<ClientName>,
    #[case] input: Vec<String>,
    #[case] expected: Vec<String>,
) {
    std::thread::sleep(std::time::Duration::from_micros(100));

    let verb = verb_user.unwrap_or(verb);
    let using_deprecated = verb == "HELO";

    let client_name = client_name_user.unwrap_or(client_name);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async move {
        run_test! {
            input = input.iter()
                .map(|s| s
                    .replace("{verb}", verb)
                    .replace("{client_name}", &to_args(&client_name))
                )
                .collect::<Vec<String>>(),
            expected = std::iter::once("220 testserver.com Service ready\r\n".to_string())
                .chain(expected.into_iter())
                .collect::<Vec<String>>(),
            mail_handler = {
                struct T {
                    client_name: ClientName,
                    using_deprecated: bool,
                }

                #[async_trait::async_trait]
                impl OnMail for T {
                    async fn on_mail(
                        &mut self,
                        ctx: Box<ContextFinished>,
                        _: MessageBody,
                        _: std::sync::Arc<dyn GenericQueueManager>,
                    ) -> CodeID {
                        assert_eq!(ctx.helo.client_name, self.client_name);
                        assert_eq!(ctx.helo.using_deprecated, self.using_deprecated);
                        CodeID::Ok
                    }
                }

                T { client_name, using_deprecated }
            }
        };
    });
}
