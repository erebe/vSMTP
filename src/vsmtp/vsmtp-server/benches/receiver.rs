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
use criterion::{
    criterion_group, criterion_main, measurement::WallTime, Bencher, BenchmarkId, Criterion,
};
use vqueue::GenericQueueManager;
use vsmtp_common::CodeID;
use vsmtp_common::ContextFinished;
use vsmtp_config::Config;
use vsmtp_mail_parser::MessageBody;
use vsmtp_server::OnMail;
use vsmtp_test::run_test;

#[derive(Clone)]
struct DefaultMailHandler;

#[async_trait::async_trait]
impl OnMail for DefaultMailHandler {
    async fn on_mail(
        &mut self,
        _: Box<ContextFinished>,
        _: MessageBody,
        _: std::sync::Arc<dyn GenericQueueManager>,
    ) -> CodeID {
        CodeID::Ok
    }
}

fn get_test_config() -> std::sync::Arc<Config> {
    std::sync::Arc::new(
        Config::builder()
            .with_version_str("<1.0.0")
            .unwrap()
            .without_path()
            .with_server_name("testserver.com")
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
            .with_vsl("./benches/main.vsl")
            .with_default_app_logs()
            .with_system_dns()
            .without_virtual_entries()
            .validate()
            .unwrap(),
    )
}

fn make_bench(
    b: &mut Bencher<WallTime>,
    (input, output, config): &(Vec<String>, Vec<String>, std::sync::Arc<Config>),
) {
    b.to_async(tokio::runtime::Runtime::new().unwrap())
        .iter(|| async {
            let _ = run_test! {
                input = input,
                expected = output,
                config_arc = config.clone(),
                mail_handler = DefaultMailHandler,
            };
        })
}

fn criterion_benchmark(c: &mut Criterion) {
    {
        c.bench_with_input(
            BenchmarkId::new("receiver", 0),
            &(
                vec![
                    "HELO foobar\r\n".to_string(),
                    "MAIL FROM:<john@doe>\r\n".to_string(),
                    "RCPT TO:<aa@bb>\r\n".to_string(),
                    "DATA\r\n".to_string(),
                    ".\r\n".to_string(),
                    "QUIT\r\n".to_string(),
                ],
                vec![
                    "220 testserver.com Service ready\r\n".to_string(),
                    "250 Ok\r\n".to_string(),
                    "250 Ok\r\n".to_string(),
                    "250 Ok\r\n".to_string(),
                    "354 Start mail input; end with <CRLF>.<CRLF>\r\n".to_string(),
                    "250 Ok\r\n".to_string(),
                    "221 Service closing transmission channel\r\n".to_string(),
                ],
                get_test_config(),
            ),
            make_bench,
        );
    }

    c.bench_with_input(
        BenchmarkId::new("receiver", 1),
        &(
            vec!["foo\r\n".to_string()],
            vec![
                "220 testserver.com Service ready\r\n".to_string(),
                "501 Syntax error in parameters or arguments\r\n".to_string(),
            ],
            get_test_config(),
        ),
        make_bench,
    );
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
