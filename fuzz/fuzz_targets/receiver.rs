#![no_main]
use libfuzzer_sys::fuzz_target;
use vqueue::GenericQueueManager;
use vsmtp_common::{mail_context::MailContext, CodeID, ConnectionKind};
use vsmtp_config::Config;
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
        _: Box<MailContext>,
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
        .with_default_app()
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

    let re = std::sync::Arc::new(
        RuleEngine::new(config.clone(), None).expect("failed to build rule engine"),
    );

    let queue_manager =
        <vqueue::fs::QueueManager as vqueue::GenericQueueManager>::init(config).unwrap();

    let _ = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(conn.receive(
            None,
            re,
            std::sync::Arc::new(std::collections::HashMap::new()),
            queue_manager,
            &mut FuzzOnMail,
        ));
});
