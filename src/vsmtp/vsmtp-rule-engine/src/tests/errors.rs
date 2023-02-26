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

use crate::RuleEngine;
use vqueue::GenericQueueManager;
use vsmtp_config::DnsResolvers;
use vsmtp_test::config::local_test;

const BAD_RULE_MAP: &str = r#"let foo = "bar""#;

const BAD_MAP_STAGE: &str = r#"#{ foo: [] }"#;

const BAD_RULE_SYNTAX: &str = r#"
#{
  helo: {
    rule "child rule missing evaluate" #{
      description: "this rule does not contain the mandatory 'evaluate' anonymous function"
    }
  }
}"#;

const BAD_RULE_SYNTAX_2: &str = r#"
#{
  helo: {
    rule "bad rule" "wrong syntax"
  }
}"#;

const BAD_ACTION_SYNTAX: &str = r#"
#{
  helo: {
    action "child action missing evaluate" #{
      description: "this rule does not contain the mandatory 'evaluate' anonymous function"
    }
  }
}
#}"#;

const BAD_ACTION_SYNTAX_2: &str = r#"
#{
  helo: {
    action "bad action" "wrong syntax"
  }
}"#;

// TODO: also test the error message (using https://docs.rs/tracing-test/latest/tracing_test)

#[rstest::rstest]
fn compile_errored(
    #[values(
        BAD_RULE_MAP,
        BAD_MAP_STAGE,
        BAD_RULE_SYNTAX,
        BAD_RULE_SYNTAX_2,
        BAD_ACTION_SYNTAX,
        BAD_ACTION_SYNTAX_2
    )]
    script: &'static str,
) {
    let config = std::sync::Arc::new(local_test());
    let queue_manger = vqueue::temp::QueueManager::init(config.clone(), vec![]).unwrap();
    let dns_resolvers = std::sync::Arc::new(DnsResolvers::from_config(&config).unwrap());

    RuleEngine::with_hierarchy(
        |builder| Ok(builder.add_root_filter_rules(script)?.build()),
        config,
        dns_resolvers,
        queue_manger,
    )
    .unwrap_err();
}
