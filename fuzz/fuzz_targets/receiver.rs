#![no_main]
use libfuzzer_sys::fuzz_target;
use vqueue::GenericQueueManager;
use vsmtp_common::{
    mail_context::{Finished, MailContext},
    CodeID, ConnectionKind,
};
use vsmtp_config::{Config, DnsResolvers};
use vsmtp_mail_parser::MessageBody;
use vsmtp_rule_engine::RuleEngine;
use vsmtp_server::{Connection, OnMail};
use vsmtp_test::receiver::Mock;

struct FuzzOnMail;

#[async_trait::async_trait]
impl OnMail for FuzzOnMail {
    async fn on_mail<
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
    >(
        &mut self,
        _: &mut Connection<S>,
        _: Box<MailContext<Finished>>,
        _: MessageBody,
        _: std::sync::Arc<dyn GenericQueueManager>,
    ) -> CodeID {
        CodeID::Ok
    }
}

fuzz_target!(|data: &[u8]| {
    let mut config = Config::builder()
        .with_version_str("<1.0.0")
        .unwrap()
        .without_path()
        .with_hostname()
        .with_default_system()
        .with_ipv4_localhost()
        .with_default_logs_settings()
        .with_spool_dir_and_default_queues("./tmp/fuzz")
        .without_tls_support()
        .with_default_smtp_options()
        .with_default_smtp_error_handler()
        .with_default_smtp_codes()
        .without_auth()
        .with_app_at_location("./tmp/app")
        .with_vsl("./main.vsl")
        .with_default_app_logs()
        .with_system_dns()
        .without_virtual_entries()
        .validate()
        .unwrap();
    config.server.smtp.error.soft_count = -1;
    config.server.smtp.error.hard_count = -1;

    let config = std::sync::Arc::new(config);

    let mut written_data = Vec::new();
    let mut mock = Mock::new(data.to_vec(), &mut written_data);
    let mut conn = Connection::new(
        ConnectionKind::Relay,
        "0.0.0.0:0".parse().unwrap(),
        "0.0.0.0:0".parse().unwrap(),
        config.clone(),
        &mut mock,
    );
    let queue_manager =
        <vqueue::temp::QueueManager as vqueue::GenericQueueManager>::init(config.clone()).unwrap();

    let dns_resolvers = std::sync::Arc::new(
        DnsResolvers::from_config(&config).expect("failed to build dns resolvers"),
    );

    let re = std::sync::Arc::new(
        RuleEngine::new(config, None, dns_resolvers.clone(), queue_manager.clone())
            .expect("failed to build rule engine"),
    );

    let _ = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(conn.receive(None, re, dns_resolvers, queue_manager, &mut FuzzOnMail));
});
