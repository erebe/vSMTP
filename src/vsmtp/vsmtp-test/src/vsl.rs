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

use crate::config::{local_ctx, local_msg, local_test};
use vqueue::GenericQueueManager;
use vsmtp_common::mail_context::MailContextAPI;
use vsmtp_common::state::State;
use vsmtp_common::status::Status;
use vsmtp_config::DnsResolvers;
use vsmtp_mail_parser::MessageBody;
use vsmtp_rule_engine::RuleEngine;

///
#[must_use]
pub fn run(
    vsl: &'static str,
) -> std::collections::HashMap<State, (MailContextAPI, MessageBody, Status, Option<Status>)> {
    let config = arc!(local_test());
    let queue_manager = vqueue::temp::QueueManager::init(config.clone()).expect("queue_manager");
    let resolvers = arc!(DnsResolvers::from_config(&config).expect("resolvers"));

    let rule_engine =
        RuleEngine::from_script(config, vsl, resolvers, queue_manager).expect("rule engine");

    let mut out = std::collections::HashMap::<
        State,
        (MailContextAPI, MessageBody, Status, Option<Status>),
    >::new();
    for i in [
        State::Connect,
        State::Helo,
        State::MailFrom,
        State::RcptTo,
        State::PreQ,
        State::PostQ,
    ] {
        out.insert(i, rule_engine.just_run_when(i, local_ctx(), local_msg()));
    }
    out
}
