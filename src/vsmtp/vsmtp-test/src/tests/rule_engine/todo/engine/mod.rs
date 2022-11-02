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
/*
use crate::{rule_engine::RuleEngine, rule_state::RuleState, tests::helpers::get_default_state};
use vsmtp_common::{
    mail_context::{ConnectionContext, MailContext, MessageMetadata},
    state::State,
    status::Status,
    CodeID, Envelop, ReplyOrCodeID,
};
use vsmtp_config::DnsResolvers;
use vsmtp_mail_parser::MessageBody;

#[test]
fn test_engine_errors() {
    let re = RuleEngine::new(
        std::sync::Arc::new(vsmtp_config::Config::default()),
        Some(rules_path!["error_handling", "main.vsl"]),
    )
    .unwrap();
    let (mut state, _) = get_default_state("./tmp/app");

    assert_eq!(
        re.run_when(&mut state, State::Connect),
        Status::Deny(ReplyOrCodeID::Left(CodeID::Denied))
    );
    assert_eq!(
        re.run_when(&mut state, State::Helo),
        Status::Deny(ReplyOrCodeID::Left(CodeID::Denied))
    );
    assert_eq!(
        re.run_when(&mut state, State::MailFrom),
        Status::Deny(ReplyOrCodeID::Left(CodeID::Denied))
    );
}

#[test]
fn test_rule_state() {
    let mut config = vsmtp_config::Config::builder()
        .with_version_str("<1.0.0")
        .unwrap()
        .with_server_name_and_client_count("testserver.com", 32)
        .with_user_group_and_default_system("root", "root")
        .unwrap()
        .with_ipv4_localhost()
        .with_default_logs_settings()
        .with_spool_dir_and_default_queues("./tmp/spool")
        .without_tls_support()
        .with_default_smtp_options()
        .with_default_smtp_error_handler()
        .with_default_smtp_codes()
        .without_auth()
        .with_default_app()
        .with_vsl("./src/tests/ignore_vsl")
        .with_default_app_logs()
        .with_system_dns()
        .without_virtual_entries()
        .validate()
        .unwrap();

    config.server.queues.dirpath = "./tmp/spool".into();
    config.app.dirpath = "./tmp/app".into();

    let config = std::sync::Arc::new(config);

    let rule_engine = RuleEngine::from_script(config.clone(), "#{}").unwrap();
    let resolvers = std::sync::Arc::new(DnsResolvers::from_config(&config).unwrap());

    let queue_manager =
        <vqueue::temp::QueueManager as vqueue::GenericQueueManager>::init(config.clone()).unwrap();

    let state = RuleState::new(
        config.clone(),
        resolvers.clone(),
        queue_manager.clone(),
        &rule_engine,
    );
    let state_with_context = RuleState::with_context(
        &rule_engine,
        MailContext::connect(
            "127.0.0.1:26".parse().unwrap(),
            "127.0.0.1:25".parse().unwrap(),
            "testserver.com".to_string(),
        )
        .helo("test".to_string())
        .mail_from("a@a.a".to_string()),
        MessageBody::default(),
    );

    assert_eq!(
        state.context().read().unwrap().connection.client_addr.ip(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))
    );
    assert_eq!(
        state_with_context
            .context()
            .read()
            .unwrap()
            .connection
            .client_addr
            .ip(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
    );
}
*/
