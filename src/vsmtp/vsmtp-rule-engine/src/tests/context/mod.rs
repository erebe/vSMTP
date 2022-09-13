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
use crate::{rule_engine::RuleEngine, rule_state::RuleState, tests::helpers::get_default_config};
use vsmtp_common::{
    addr, auth::Credentials, mail_context::MessageMetadata, rcpt::Rcpt, state::State,
    status::Status, CodeID, ReplyOrCodeID,
};

#[test]
fn test_context() {
    let config = get_default_config("./tmp/app");
    let config = std::sync::Arc::new(config);
    let re = RuleEngine::new(config.clone(), Some(rules_path!["main.vsl"])).unwrap();
    let resolvers = std::sync::Arc::new(std::collections::HashMap::new());

    let queue_manager =
        <vqueue::fs::QueueManager as vqueue::GenericQueueManager>::init(config.clone()).unwrap();
    let mut state = RuleState::new(config, resolvers, queue_manager, &re);

    state.context().write().unwrap().envelop.mail_from = addr!("replace@example.com");
    state.context().write().unwrap().connection.credentials = Some(Credentials::AnonymousToken {
        token: "token_abcdef".to_string(),
    });

    assert_eq!(
        re.run_when(&mut state, State::Authenticate),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)),
    );

    state
        .context()
        .write()
        .unwrap()
        .envelop
        .rcpt
        .push(Rcpt::new(addr!("test@example.com")));

    assert_eq!(
        re.run_when(&mut state, State::RcptTo),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)),
    );

    state.context().write().unwrap().metadata = MessageMetadata {
        timestamp: None,
        message_id: None,
        skipped: None,
        spf: None,
        dkim: None,
    };

    assert_eq!(
        re.run_when(&mut state, State::PreQ),
        Status::Accept(ReplyOrCodeID::Left(CodeID::Ok)),
    );

    assert_eq!(
        "john.doe@example.com",
        state.context().read().unwrap().envelop.mail_from.full()
    );

    assert_eq!(
        vec![
            Rcpt::new(addr!("test@example.com")),
            Rcpt::new(addr!("replace4@example.com")),
            Rcpt::new(addr!("add4@example.com"))
        ],
        state.context().read().unwrap().envelop.rcpt
    );
}
