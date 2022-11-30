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

pub mod api;
pub mod service;

/// Create a new command module.
pub fn new_module() -> rhai::Shared<rhai::Module> {
    rhai::exported_module!(api::cmd).into()
}

#[cfg(test)]
mod tests {
    use vsmtp_config::DnsResolvers;
    use vsmtp_test::config::local_test;

    use crate::RuleEngine;

    const VSL: &str = r#"
const my_command = cmd(#{
    command: "echo",
    args: [ "-n", "executing a command from vSMTP!" ],
    timeout: "15s",
    user: "vsmtp",
    group: "vsmtp",
});

#{}
"#;

    #[test]
    fn parse() {
        let config = std::sync::Arc::new(local_test());
        let queue_manger =
            <vqueue::temp::QueueManager as vqueue::GenericQueueManager>::init(config.clone())
                .unwrap();
        let dns_resolvers = std::sync::Arc::new(DnsResolvers::from_config(&config).unwrap());

        RuleEngine::with_hierarchy(
            config,
            |builder| Ok(builder.add_root_incoming_rules(VSL)?.build()),
            dns_resolvers,
            queue_manger,
        )
        .unwrap();
    }

    #[test]
    fn run() {
        let config = std::sync::Arc::new(local_test());
        let queue_manger =
            <vqueue::temp::QueueManager as vqueue::GenericQueueManager>::init(config.clone())
                .unwrap();
        let dns_resolvers = std::sync::Arc::new(DnsResolvers::from_config(&config).unwrap());

        RuleEngine::with_hierarchy(
            config,
            |builder| {
                Ok(builder
                    .add_root_incoming_rules(include_str!("test/main.vsl"))?
                    .build())
            },
            dns_resolvers,
            queue_manger,
        )
        .unwrap();
    }
}
