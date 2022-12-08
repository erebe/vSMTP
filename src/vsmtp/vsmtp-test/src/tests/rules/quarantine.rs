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
use vsmtp_rule_engine::ExecutionStage;
use vsmtp_server::ProcessMessage;

const QUARANTINE_RULE: &str = r#"
#{
    {stage}: [
        rule "quarantine john" || {
            quarantine("john/{stage}")
        }
    ]
}
"#;

async fn actual_test(stage: ExecutionStage) {
    let (delivery_sender, _d) = tokio::sync::mpsc::channel::<ProcessMessage>(1);
    let (working_sender, _w) = tokio::sync::mpsc::channel::<ProcessMessage>(1);

    let rules = QUARANTINE_RULE.replace("{stage}", &stage.to_string());

    let queue_manager = run_test! {
        input = [
            "HELO foobar\r\n",
            "MAIL FROM:<john.doe@mydomain.com>\r\n",
            "RCPT TO:<aa@mydomain.com>\r\n",
            "DATA\r\n",
            concat!(
                "from: 'abc'\r\n",
                "to: 'def'\r\n",
                ".\r\n",
            ),
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
        mail_handler = vsmtp_server::MailHandler::new(working_sender, delivery_sender),
        hierarchy_builder = move |builder| Ok(
            builder
                .add_root_incoming_rules(&rules.clone())?
                .build()
            ),
    };

    assert_eq!(
        std::fs::read_dir(vqueue::FilesystemQueueManagerExt::get_queue_path(
            &*queue_manager,
            &vqueue::QueueID::Quarantine {
                name: format!("john/{stage}")
            }
        ))
        .unwrap()
        .count(),
        1
    );
}

#[rstest::rstest]
#[test_log::test(tokio::test)]
async fn test_quarantine(
    #[values(
        // TODO
        ExecutionStage::Connect,
        ExecutionStage::Helo,
        ExecutionStage::MailFrom,
        ExecutionStage::RcptTo,
        ExecutionStage::PreQ,
        // ExecutionStage::PostQ,
        // ExecutionStage::Delivery
    )]
    stage: ExecutionStage,
) {
    actual_test(stage).await;
}
