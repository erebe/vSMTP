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
mod errors;

use crate::RuleEngine;
use vqueue::GenericQueueManager;
use vsmtp_config::DnsResolvers;
use vsmtp_test::config::local_test;

const TIME: &str = r#"
print(time().to_string());
print(time().to_debug());
print(date().to_string());
print(date().to_debug());

#{}
"#;

#[test]
fn time_api() {
    let config = std::sync::Arc::new(local_test());
    let queue_manger = vqueue::temp::QueueManager::init(config.clone()).unwrap();
    let dns_resolvers = std::sync::Arc::new(DnsResolvers::from_config(&config).unwrap());

    RuleEngine::with_hierarchy(
        config,
        |builder| {
            Ok(builder
                .add_main_rules("#{}")?
                .add_fallback_rules(TIME)?
                .build())
        },
        dns_resolvers,
        queue_manger,
    )
    .unwrap();
}
