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

use vsmtp_common::{
    mail_context::{ConnectionContext, MailContext, MessageMetadata},
    state::State,
    Envelop,
};
use vsmtp_mail_parser::MessageBody;
use vsmtp_rule_engine::RuleEngine;

///
pub fn run(vsl: &str) {
    let config = vsmtp_config::Config::default();
    let rule_engine = RuleEngine::from_script(&config, vsl).expect("Cannot create rule engine");

    let _output = rule_engine.just_run_when(
        State::Connect,
        &config,
        std::sync::Arc::new(vsmtp_common::collection! {}),
        MailContext {
            connection: ConnectionContext {
                timestamp: std::time::SystemTime::now(),
                credentials: None,
                server_name: "testserver.com".to_string(),
                server_addr: "127.0.0.1:25".parse().expect(""),
                client_addr: "127.0.0.1:5977".parse().expect(""),
                is_authenticated: false,
                is_secured: false,
                error_count: 0,
                authentication_attempt: 0,
            },
            envelop: Envelop {
                helo: "client.testserver.com".to_string(),
                mail_from: "client@client.testserver.com".parse().expect(""),
                rcpt: vec![],
            },
            metadata: MessageMetadata {
                timestamp: None,
                message_id: None,
                skipped: None,
                spf: None,
                dkim: None,
            },
        },
        MessageBody::new(
            [
                "From: NoBody <nobody@domain.tld>",
                "Reply-To: Yuin <yuin@domain.tld>",
                "To: Hei <hei@domain.tld>",
                "Subject: Happy new year",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            "Be happy!".to_string(),
        ),
    );
}
