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
use vqueue::FilesystemQueueManagerExt;

run_test! {
    fn test_logs,
    input = [
        "NOOP\r\n",
        "QUIT\r\n"
    ],
    expected = [
        "220 testserver.com Service ready\r\n",
        "250 Ok\r\n",
        "221 Service closing transmission channel\r\n",
    ],
    hierarchy_builder = |builder| {
        Ok(builder.add_root_filter_rules(r#"#{
                    connect: [
                      rule "test_connect" || {
                        log("trace", `${ctx::client_ip()}`);
                        if ctx::client_ip() is "127.0.0.1" { state::next() } else { state::deny() }
                      }
                    ],
                  }
                  "#,)?.build())
    },
}

const CTX_TEMPLATE: &str = concat!(
    "{\n",
    "  \"Finished\": {\n",
    // "    \"client_addr\": \"{client_addr}\",\n",
    // "    \"server_addr\": \"{server_addr}\",\n",
    "    \"server_name\": \"testserver.com\",\n",
    "    \"skipped\": null,\n",
    "    \"tls\": null,\n",
    "    \"auth\": null,\n",
    "    \"client_name\": \"foo\",\n",
    "    \"using_deprecated\": false,\n",
    "    \"reverse_path\": \"john@doe.com\",\n",
    "    \"message_uuid\": \"{message_uuid}\",\n",
    "    \"outgoing\": false,\n",
    "    \"forward_paths\": [\n",
    "      {\n",
    "        \"address\": \"green@foo.net\",\n",
    "        \"transfer_method\": \"deliver\",\n",
    "        \"email_status\": {\n",
    "          \"waiting\": {\n",
    "          }\n",
    "        }\n",
    "      }\n",
    "    ],\n",
    "    \"transaction_type\": {\n",
    "      \"incoming\": null\n",
    "    },\n",
    "    \"dkim\": null,\n",
    "    \"spf\": null\n",
    "  }\n",
    "}"
);

const RULE: &str = r#"
#{
  {stage}: [
    rule "write to disk preq" || {
        msg::prepend_header("X-VSMTP-INIT", "done.");
      {action}("tests/generated/{action}");
      state::accept()
    },
  ],

  preq: [
    action "write to disk preq" || {
        msg::prepend_header("X-VSMTP-INIT", "done.");
      {action}("tests/generated/{action}");
      state::accept()
    },
  ],
}"#;

#[ignore = "this just be implemented in a better way"]
#[rstest::rstest]
#[tokio::test]
async fn context_write(
    #[values("write", "dump")] action: &'static str,
    #[values("mail", "preq")] stage: &'static str,
) {
    let q = run_test! {
        input = [
            "EHLO foo\r\n",
            "MAIL FROM:<john@doe.com>\r\n",
            "RCPT TO:<green@foo.net>\r\n",
            "DATA\r\n",
            concat!(
                "From: john doe <john@doe.com>\r\n",
                "To: green@foo.net\r\n",
                "Subject: test email\r\n",
                "\r\n",
                "This is a raw email.\r\n",
                ".\r\n",
            ),
            "QUIT\r\n",
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
            "221 Service closing transmission channel\r\n",
        ],
        hierarchy_builder = |builder| {
            Ok(builder.add_root_filter_rules(&RULE.replace("{action}", action).replace("{stage}", stage))?.build())
        },
    };

    let dirpath = q
        .get_config()
        .app
        .dirpath
        .join(format!("tests/generated/{action}"));
    // one entry exists, but we don't know its name.
    for i in std::fs::read_dir(&dirpath).unwrap() {
        let path = i.unwrap().path();
        let msg = std::fs::read_to_string(&path).unwrap();
        match action {
            "write" => pretty_assertions::assert_eq!(
                msg,
                concat![
                    "X-VSMTP-INIT: done.\r\n",
                    "From: john doe <john@doe.com>\r\n",
                    "To: green@foo.net\r\n",
                    "Subject: test email\r\n",
                    "\r\n",
                    "This is a raw email.\r\n"
                ]
            ),
            "dump" => pretty_assertions::assert_eq!(
                msg.lines()
                    .filter(|i| ![
                        "mail_timestamp",
                        "connect_timestamp",
                        "timestamp",
                        "client_addr",
                        "server_addr"
                    ]
                    .into_iter()
                    .any(|p| i.contains(p)))
                    .collect::<Vec<_>>()
                    .join("\n"),
                CTX_TEMPLATE.replace(
                    "{message_uuid}",
                    path.file_stem().unwrap().to_str().unwrap()
                )
            ),
            _ => unreachable!(),
        }
    }

    std::fs::remove_dir_all(&dirpath).unwrap();
}

/*
use crate::rule_engine::RuleEngine;
use crate::rule_state::RuleState;
use crate::tests::helpers::{get_default_config, get_default_state};
use vsmtp_common::mail_context::{Empty, MailContext};
use vsmtp_common::rcpt::Rcpt;
use vsmtp_common::transfer::ForwardTarget;
use vsmtp_common::{addr, CodeID, ReplyOrCodeID};
use vsmtp_common::{
    mail_context::MessageMetadata, state::State, status::Status, transfer::Transfer,
};
use vsmtp_config::field::FieldServerVirtual;
use vsmtp_config::DnsResolvers;
use vsmtp_mail_parser::{MailMimeParser, MessageBody};
use vsmtp_test::config::{local_msg, local_test};

#[test]
fn test_users() {
    let re = RuleEngine::new(
        std::sync::Arc::new(vsmtp_config::Config::default()),
        Some(rules_path!["actions", "utils.vsl"]),
    )
    .unwrap();
    let (mut state, _) = get_default_state("./tmp/app");

    assert_eq!(
        re.run_when(&mut state, State::Delivery),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)),
    );
}

*/
/*

#[test]
fn test_hostname() {
    let re = RuleEngine::new(
        std::sync::Arc::new(vsmtp_config::Config::default()),
        Some(rules_path!["actions", "utils.vsl"]),
    )
    .unwrap();
    let (mut state, _) = get_default_state("./tmp/app");

    assert_eq!(
        re.run_when(&mut state, State::PostQ),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_lookup() {
    let mut config = vsmtp_config::Config::default();
    config.server.queues.dirpath = "./tmp/spool".into();
    config.app.dirpath = "./tmp/app".into();

    let config = std::sync::Arc::new(config);
    let re = RuleEngine::new(config.clone(), Some(rules_path!["actions", "utils.vsl"])).unwrap();
    let resolvers = std::sync::Arc::new(DnsResolvers::from_config(&config).unwrap());
    let queue_manager =
        <vqueue::temp::QueueManager as vqueue::GenericQueueManager>::init(config.clone()).unwrap();

    let mut state = RuleState::with_context(
        &re,
        MailContext::<Empty>::connect("".parse().unwrap(), "".parse().unwrap(), "".to_string())
            .helo("".to_string())
            .mail_from(addr!("foo@bar"))
            .rcpt_to(vec![
                Rcpt::new(addr!("john.doe@example.com")),
                Rcpt::new(addr!("foo.bar@localhost")),
            ])
            .finish()
            .into(),
        local_msg(),
    );

    assert_eq!(
        re.run_when(&mut state, State::RcptTo),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)),
    );
}

#[test]
fn test_in_domain_and_server_name() {
    let (mut state, config) = get_default_state("./tmp/app");
    let re = RuleEngine::new(config, Some(rules_path!["actions", "utils.vsl"])).unwrap();

    assert_eq!(
        re.run_when(&mut state, State::Connect),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)),
    );
}

#[test]
fn test_in_domain_and_server_name_sni() {
    let mut config = get_default_config("./tmp/app");
    config.server.r#virtual = std::collections::BTreeMap::from_iter([
        ("example.com".to_string(), FieldServerVirtual::default()),
        ("doe.com".to_string(), FieldServerVirtual::default()),
        ("green.com".to_string(), FieldServerVirtual::default()),
    ]);
    let config = std::sync::Arc::new(config);

    let re = RuleEngine::new(config.clone(), Some(rules_path!["actions", "utils.vsl"])).unwrap();
    let resolvers = std::sync::Arc::new(DnsResolvers::from_config(&config).unwrap());
    let queue_manager =
        <vqueue::temp::QueueManager as vqueue::GenericQueueManager>::init(config.clone()).unwrap();

    let mut state = RuleState::with_context(
        &re,
        MailContext::<Empty>::connect("".parse().unwrap(), "".parse().unwrap(), "".to_string())
            .helo("".to_string())
            .mail_from(addr!("foo@bar"))
            .rcpt_to(vec![
                Rcpt::new(addr!("john.doe@example.com")),
                Rcpt::new(addr!("foo.bar@localhost")),
            ])
            .finish()
            .into(),
        local_msg(),
    );

    assert_eq!(
        re.run_when(&mut state, State::PreQ),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)),
    );
}
*/
