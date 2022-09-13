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
use vsmtp_common::state::State;
use vsmtp_rule_engine::RuleEngine;

///
pub fn run(vsl: &'static str) {
    let config = std::sync::Arc::new(local_test());
    let rule_engine =
        RuleEngine::from_script(config.clone(), vsl).expect("Cannot create rule engine");

    let queue_manager =
        <vqueue::fs::QueueManager as vqueue::GenericQueueManager>::init(config.clone())
            .expect("queue manager");

    let _output = rule_engine.just_run_when(
        State::Connect,
        config,
        std::sync::Arc::new(vsmtp_common::collection! {}),
        queue_manager,
        local_ctx(),
        local_msg(),
    );
}
