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
use vsmtp_common::state::State;
use vsmtp_server::ProcessMessage;

const QUARANTINE_RULE: &str = r#"
#{
    {stage}: [
        rule "quarantine john" || {
            quarantine("john")
        }
    ]
}
"#;

async fn actual_test(stage: State) {
    let config = std::sync::Arc::new(crate::config::local_test());

    let (delivery_sender, _d) =
        tokio::sync::mpsc::channel::<ProcessMessage>(config.server.queues.delivery.channel_size);

    let (working_sender, _w) =
        tokio::sync::mpsc::channel::<ProcessMessage>(config.server.queues.working.channel_size);

    let queue_manager = run_test! {
        input = [
            "HELO foobar\r\n",
            "MAIL FROM:<john.doe@example.com>\r\n",
            "RCPT TO:<aa@bb>\r\n",
            "DATA\r\n",
            "from: 'abc'\r\n",
            "to: 'def'\r\n",
            ".\r\n",
            "QUIT\r\n",
        ]
        .concat(),
        expected = [
            "220 testserver.com Service ready\r\n",
            "250 Ok\r\n",
            "250 Ok\r\n",
            "250 Ok\r\n",
            "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
            "250 Ok\r\n",
            "221 Service closing transmission channel\r\n",
        ]
        .concat(),,
        config_arc = config.clone(),
        mail_handler = vsmtp_server::MailHandler::new(working_sender, delivery_sender),
        hierarchy_builder = move |builder| Ok(
            builder
                // not ideal since some stages won't ever be run in main / fallback, but it works fine that way.
                .add_main_rules(&QUARANTINE_RULE.replace("{stage}", &stage.to_string()))?
                .add_fallback_rules(&QUARANTINE_RULE.replace("{stage}", &stage.to_string()))?
                .build()
            ),
    }
    .unwrap();

    assert_eq!(
        std::fs::read_dir(vqueue::FilesystemQueueManagerExt::get_queue_path(
            &*queue_manager,
            &vqueue::QueueID::Quarantine {
                name: "john".to_string()
            }
        ))
        .unwrap()
        .count(),
        1
    );
}

#[rstest::rstest]
#[tokio::test]
async fn test_quarantine(
    #[values(
        // State::Connect,
        // State::Helo,
        // State::Authenticate,
        State::MailFrom,
        State::RcptTo,
        State::PreQ
    )]
    stage: State,
) {
    actual_test(stage).await;
}
