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
pub fn run_with_msg(
    vsl: &'static str,
    msg: Option<MessageBody>,
) -> std::collections::HashMap<State, (MailContextAPI, MessageBody, Status, Option<Status>)> {
    let config = arc!(local_test());
    let queue_manager = vqueue::temp::QueueManager::init(config.clone()).expect("queue_manager");
    let resolvers = arc!(DnsResolvers::from_config(&config).expect("resolvers"));

    let rule_engine = std::sync::Arc::new(
        RuleEngine::from_script(config, vsl, resolvers, queue_manager).expect("rule engine"),
    );

    let msg = msg.unwrap_or_else(local_msg);

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
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let re = rule_engine.clone();
        let msg = msg.clone();

        let state = runtime.block_on(async move { re.just_run_when(i, local_ctx(), msg) });
        out.insert(i, state);
    }
    out
}

///
#[must_use]
pub fn run(
    vsl: &'static str,
) -> std::collections::HashMap<State, (MailContextAPI, MessageBody, Status, Option<Status>)> {
    run_with_msg(vsl, None)
}
