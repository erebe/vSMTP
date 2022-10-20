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

use vqueue::GenericQueueManager;
use vsmtp_common::CodeID;
use vsmtp_mail_parser::MessageBody;
use vsmtp_server::{Connection, OnMail};

/// A type implementing Write+Read to emulate sockets
#[derive(Debug)]
pub struct Mock<'a, T: AsRef<[u8]> + Unpin> {
    read_cursor: std::io::Cursor<T>,
    write_cursor: std::io::Cursor<&'a mut Vec<u8>>,
}

impl<'a, T: AsRef<[u8]> + Unpin> Mock<'a, T> {
    /// Create an new instance
    pub fn new(read: T, write: &'a mut Vec<u8>) -> Self {
        Self {
            read_cursor: std::io::Cursor::new(read),
            write_cursor: std::io::Cursor::new(write),
        }
    }
}

impl<T: AsRef<[u8]> + Unpin> tokio::io::AsyncRead for Mock<'_, T> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.read_cursor).poll_read(cx, buf)
    }
}

impl<T: AsRef<[u8]> + Unpin> tokio::io::AsyncWrite for Mock<'_, T> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        std::task::Poll::Ready(std::io::Write::write(&mut self.write_cursor, buf))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(std::io::Write::flush(&mut self.write_cursor))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// used for testing, does not do anything once the email is received.
#[derive(Default)]
pub struct DefaultMailHandler {
    _phantom: std::marker::PhantomData<u32>,
}

#[async_trait::async_trait]
impl OnMail for DefaultMailHandler {
    async fn on_mail<
        S: tokio::io::AsyncWrite + tokio::io::AsyncRead + Send + Unpin + std::fmt::Debug,
    >(
        &mut self,
        _: &mut Connection<S>,
        _: Box<vsmtp_common::mail_context::MailContext<vsmtp_common::mail_context::Finished>>,
        _: MessageBody,
        _: std::sync::Arc<dyn GenericQueueManager>,
    ) -> CodeID {
        CodeID::Ok
    }
}

/// run a connection and assert output produced by `vSMTP` and `expected_output`
// TODO: handle trailing comma correctly
#[macro_export]
macro_rules! run_test {
    (
        input = $input:expr,
        expected = $expected:expr,
        $(config = $config:expr)?,
        $(config_arc = $config_arc:expr)?,
        $(mail_handler = $mail_handler:expr)?,
        $(rule_script = $rule_script:expr)?,
    ) => {{
        let expected: String = $expected.to_string();
        let input: Vec<u8> = $input.as_bytes().to_vec();
        let config: std::sync::Arc<vsmtp_config::Config> =  {
            let _f = || std::sync::Arc::new($crate::config::local_test());  $(
            let _f = || std::sync::Arc::new($config);                       )? $(
            let _f = || $config_arc;                       )?
            _f()
        };
        let mut mail_handler = { // Box<dyn OnMail + Send>
            let _f = || $crate::receiver::DefaultMailHandler::default();    $(
            let _f = || $mail_handler;                                      )?
            Box::new(_f())
        };

        let mut written_data = Vec::new();
        let mut mock = $crate::receiver::Mock::new(input, &mut written_data);
        let mut conn = vsmtp_server::Connection::new(
            vsmtp_common::ConnectionKind::Relay,
            "127.0.0.1:53844".parse().expect("ip is valid"),
            "127.0.0.1:53845".parse().expect("ip is valid"),
            config.clone(),
            &mut mock,
        );

        let resolvers = std::sync::Arc::new(vsmtp_config::DnsResolvers::from_config(&config).unwrap());
        let queue_manager =
            <vqueue::temp::QueueManager as vqueue::GenericQueueManager>::init(config.clone()).unwrap();

        let rule_engine: std::sync::Arc<vsmtp_rule_engine::RuleEngine> = {
            let _f = || vsmtp_rule_engine::RuleEngine::new(
                config.clone(), config.app.vsl.filepath.clone(), resolvers.clone(), queue_manager.clone()
            ).unwrap();                                         $(
            let _f = || vsmtp_rule_engine::RuleEngine::from_script(
                config.clone(), $rule_script, resolvers.clone(), queue_manager.clone()
            ).unwrap();                                         )?
            std::sync::Arc::new(_f())
        };

        let result = conn
            .receive(
                None,
                rule_engine,
                resolvers,
                queue_manager.clone(),
                &mut *mail_handler,
            )
            .await;

        tokio::io::AsyncWriteExt::flush(&mut conn.inner.inner)
            .await
            .unwrap();

        pretty_assertions::assert_eq!(
            expected,
            std::str::from_utf8(&written_data).unwrap(),
        );

        #[allow(clippy::question_mark)]
        if let Err(e) = result {
            Err(e)
        } else {
            Ok((queue_manager))
        }
    }};
    (fn $name:ident,
        input = $input:expr,
        expected = $expected:expr,
        $(config = $config:expr)?,
        $(config_arc = $config_arc:expr)?,
        $(mail_handler = $mail_handler:expr)?,
        $(rule_script = $rule_script:expr)?,
    ) => {
        #[tokio::test]
        async fn $name() {
            run_test! {
                input = $input,
                expected = $expected,
                $(config = $config)?,
                $(config_arc = $config_arc)?,
                $(mail_handler = $mail_handler)?,
                $(rule_script = $rule_script)?,
            }
            .unwrap();
        }
    };
    (err fn $name:ident,
        input = $input:expr,
        expected = $expected:expr,
        $(config = $config:expr)?,
        $(config_arc = $config_arc:expr)?,
        $(mail_handler = $mail_handler:expr)?,
        $(rule_script = $rule_script:expr)?,
    ) => {
        #[tokio::test]
        async fn $name() {
            run_test! {
                input = $input,
                expected = $expected,
                $(config = $config)?,
                $(config_arc = $config_arc)?,
                $(mail_handler = $mail_handler)?,
                $(rule_script = $rule_script)?,
            }
            .unwrap_err();
        }
    };
    (multi fn $name:ident,
        input = $input:expr,
        expected = $expected:expr,
        $(config = $config:expr)?,
        $(config_arc = $config_arc:expr)?,
        $(mail_handler = $mail_handler:expr)?,
        $(rule_script = $rule_script:expr)?,
    ) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() {
            run_test! {
                input = $input,
                expected = $expected,
                $(config = $config)?,
                $(config_arc = $config_arc)?,
                $(mail_handler = $mail_handler)?,
                $(rule_script = $rule_script)?,
            }
            .unwrap();
        }
    };
}
