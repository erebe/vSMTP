#[cfg(test)]
mod tests {

    use crate::integration::protocol::get_test_config;
    use vsmtp::{
        config::server_config::{InnerSMTPConfig, InnerTlsConfig, ServerConfig, TlsSecurityLevel},
        model::mail::MailContext,
        resolver::DataEndResolver,
        rules::address::Address,
        smtp::code::SMTPReplyCode,
        test_helpers::{test_receiver, DefaultResolverTest},
    };

    // see https://datatracker.ietf.org/doc/html/rfc5321#section-4.3.2

    #[tokio::test]
    async fn test_receiver_1() {
        struct T;

        #[async_trait::async_trait]
        impl DataEndResolver for T {
            async fn on_data_end(
                _: &ServerConfig,
                ctx: &MailContext,
            ) -> Result<SMTPReplyCode, std::io::Error> {
                assert_eq!(ctx.envelop.helo, "foobar");
                assert_eq!(ctx.envelop.mail_from.full(), "john@doe");
                assert_eq!(
                    ctx.envelop.rcpt,
                    std::collections::HashSet::from([Address::new("aa@bb").unwrap()])
                );
                assert_eq!(ctx.body, "");
                assert!(ctx.metadata.is_some());

                Ok(SMTPReplyCode::Code250)
            }
        }

        assert!(test_receiver::<T>(
            [
                "HELO foobar\r\n",
                "MAIL FROM:<john@doe>\r\n",
                "RCPT TO:<aa@bb>\r\n",
                "DATA\r\n",
                ".\r\n",
                "QUIT\r\n",
            ]
            .concat()
            .as_bytes(),
            [
                "220 test.server.com Service ready\r\n",
                "250 Ok\r\n",
                "250 Ok\r\n",
                "250 Ok\r\n",
                "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
                "250 Ok\r\n",
                "221 Service closing transmission channel\r\n",
            ]
            .concat()
            .as_bytes(),
            get_test_config(),
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn test_receiver_2() {
        assert!(test_receiver::<DefaultResolverTest>(
            ["foo\r\n"].concat().as_bytes(),
            [
                "220 test.server.com Service ready\r\n",
                "501 Syntax error in parameters or arguments\r\n",
            ]
            .concat()
            .as_bytes(),
            get_test_config()
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn test_receiver_3() {
        assert!(test_receiver::<DefaultResolverTest>(
            ["MAIL FROM:<john@doe>\r\n"].concat().as_bytes(),
            [
                "220 test.server.com Service ready\r\n",
                "503 Bad sequence of commands\r\n",
            ]
            .concat()
            .as_bytes(),
            get_test_config()
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn test_receiver_4() {
        assert!(test_receiver::<DefaultResolverTest>(
            ["RCPT TO:<john@doe>\r\n"].concat().as_bytes(),
            [
                "220 test.server.com Service ready\r\n",
                "503 Bad sequence of commands\r\n",
            ]
            .concat()
            .as_bytes(),
            get_test_config()
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn test_receiver_5() {
        assert!(test_receiver::<DefaultResolverTest>(
            ["HELO foo\r\n", "RCPT TO:<bar@foo>\r\n"]
                .concat()
                .as_bytes(),
            [
                "220 test.server.com Service ready\r\n",
                "250 Ok\r\n",
                "503 Bad sequence of commands\r\n",
            ]
            .concat()
            .as_bytes(),
            get_test_config()
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn test_receiver_6() {
        assert!(test_receiver::<DefaultResolverTest>(
            ["HELO foobar\r\n", "QUIT\r\n"].concat().as_bytes(),
            [
                "220 test.server.com Service ready\r\n",
                "250 Ok\r\n",
                "221 Service closing transmission channel\r\n",
            ]
            .concat()
            .as_bytes(),
            get_test_config()
        )
        .await
        .is_ok());
    }

    // FIXME: what if tls_config == None && TlsSecurityLevel != None
    /*
    #[tokio::test]
    async fn test_receiver_7() {
        assert!(test_receiver::<DefaultResolverTest>(
            ["EHLO foobar\r\n", "STARTTLS\r\n", "QUIT\r\n"]
                .concat()
                .as_bytes(),
            [
                "220 test.server.com Service ready\r\n",
                "250-test.server.com\r\n",
                "250-8BITMIME\r\n",
                "250-SMTPUTF8\r\n",
                "250 STARTTLS\r\n",
                "454 TLS not available due to temporary reason\r\n",
                "221 Service closing transmission channel\r\n",
            ]
            .concat()
            .as_bytes(),
            ServerConfig {
                tls: InnerTlsConfig {
                    security_level: TlsSecurityLevel::Encrypt,
                    ..get_test_config().tls
                },
                ..get_test_config()
            },
        )
        .await
        .is_ok());
    }
    */

    #[tokio::test]
    async fn test_receiver_8() {
        assert!(test_receiver::<DefaultResolverTest>(
            ["EHLO foobar\r\n", "MAIL FROM: <foo@bar>\r\n", "QUIT\r\n"]
                .concat()
                .as_bytes(),
            [
                "220 test.server.com Service ready\r\n",
                "250-test.server.com\r\n",
                "250-8BITMIME\r\n",
                "250-SMTPUTF8\r\n",
                "250 STARTTLS\r\n",
                "530 Must issue a STARTTLS command first\r\n",
                "221 Service closing transmission channel\r\n",
            ]
            .concat()
            .as_bytes(),
            ServerConfig {
                tls: InnerTlsConfig {
                    security_level: TlsSecurityLevel::Encrypt,
                    ..get_test_config().tls
                },
                ..get_test_config()
            },
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn test_receiver_9() {
        let before_test = std::time::Instant::now();
        let res = test_receiver::<DefaultResolverTest>(
            [
                "RCPT TO:<bar@foo>\r\n",
                "MAIL FROM: <foo@bar>\r\n",
                "EHLO\r\n",
                "NOOP\r\n",
                "azeai\r\n",
                "STARTTLS\r\n",
                "MAIL FROM:<john@doe>\r\n",
                "EHLO\r\n",
                "EHLO\r\n",
                "HELP\r\n",
                "aieari\r\n",
                "not a valid smtp command\r\n",
            ]
            .concat()
            .as_bytes(),
            [
                "220 test.server.com Service ready\r\n",
                "503 Bad sequence of commands\r\n",
                "503 Bad sequence of commands\r\n",
                "501 Syntax error in parameters or arguments\r\n",
                "250 Ok\r\n",
                "501 Syntax error in parameters or arguments\r\n",
                "503 Bad sequence of commands\r\n",
                "503 Bad sequence of commands\r\n",
            ]
            .concat()
            .as_bytes(),
            get_test_config(),
        )
        .await;

        assert!(res.is_err());

        // (hard_error - soft_error) * error_delay
        assert!(before_test.elapsed().as_millis() >= 5 * 100);
    }

    #[tokio::test]
    async fn test_receiver_10() {
        assert!(test_receiver::<DefaultResolverTest>(
            ["HELP\r\n"].concat().as_bytes(),
            [
                "220 test.server.com Service ready\r\n",
                "214 joining us https://viridit.com/support\r\n",
            ]
            .concat()
            .as_bytes(),
            ServerConfig {
                tls: InnerTlsConfig {
                    security_level: TlsSecurityLevel::Encrypt,
                    ..get_test_config().tls
                },
                ..get_test_config()
            },
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn test_receiver_11() {
        assert!(test_receiver::<DefaultResolverTest>(
            [
                "HELO postmaster\r\n",
                "MAIL FROM: <lala@foo>\r\n",
                "RCPT TO: <lala@foo>\r\n",
                "DATA\r\n",
                ".\r\n",
                "DATA\r\n",
                "MAIL FROM:<b@b>\r\n",
            ]
            .concat()
            .as_bytes(),
            [
                "220 test.server.com Service ready\r\n",
                "250 Ok\r\n",
                "250 Ok\r\n",
                "250 Ok\r\n",
                "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
                "250 Ok\r\n",
                "503 Bad sequence of commands\r\n",
                "250 Ok\r\n",
            ]
            .concat()
            .as_bytes(),
            get_test_config()
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn test_receiver_11_bis() {
        assert!(test_receiver::<DefaultResolverTest>(
            [
                "HELO postmaster\r\n",
                "MAIL FROM: <lala@foo>\r\n",
                "RCPT TO: <lala@foo>\r\n",
                "DATA\r\n",
                ".\r\n",
                "DATA\r\n",
                "RCPT TO:<b@b>\r\n",
            ]
            .concat()
            .as_bytes(),
            [
                "220 test.server.com Service ready\r\n",
                "250 Ok\r\n",
                "250 Ok\r\n",
                "250 Ok\r\n",
                "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
                "250 Ok\r\n",
                "503 Bad sequence of commands\r\n",
                "503 Bad sequence of commands\r\n",
            ]
            .concat()
            .as_bytes(),
            get_test_config()
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn test_receiver_12() {
        assert!(test_receiver::<DefaultResolverTest>(
            ["EHLO postmaster\r\n"].concat().as_bytes(),
            [
                "220 test.server.com Service ready\r\n",
                "502 Command not implemented\r\n",
            ]
            .concat()
            .as_bytes(),
            ServerConfig {
                smtp: InnerSMTPConfig {
                    disable_ehlo: true,
                    ..get_test_config().smtp
                },
                ..get_test_config()
            },
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn test_receiver_13() {
        struct T;

        static mut COUNT: u32 = 0;

        #[async_trait::async_trait]
        impl DataEndResolver for T {
            async fn on_data_end(
                _: &ServerConfig,
                ctx: &MailContext,
            ) -> Result<SMTPReplyCode, std::io::Error> {
                let count = unsafe { COUNT };

                match count {
                    0 => {
                        assert_eq!(ctx.envelop.helo, "foobar");
                        assert_eq!(ctx.envelop.mail_from.full(), "john@doe");
                        assert_eq!(
                            ctx.envelop.rcpt,
                            std::collections::HashSet::from([Address::new("aa@bb").unwrap()])
                        );
                        assert_eq!(ctx.body, "mail one\n");
                        assert!(ctx.metadata.is_some());
                    }
                    1 => {
                        assert_eq!(ctx.envelop.helo, "foobar");
                        assert_eq!(ctx.envelop.mail_from.full(), "john2@doe");
                        assert_eq!(
                            ctx.envelop.rcpt,
                            std::collections::HashSet::from([Address::new("aa2@bb").unwrap()])
                        );
                        assert_eq!(ctx.body, "mail two\n");
                    }
                    _ => panic!(),
                }

                unsafe { COUNT += 1 };

                Ok(SMTPReplyCode::Code250)
            }
        }

        assert!(test_receiver::<T>(
            [
                "HELO foobar\r\n",
                "MAIL FROM:<john@doe>\r\n",
                "RCPT TO:<aa@bb>\r\n",
                "DATA\r\n",
                "mail one\r\n",
                ".\r\n",
                "MAIL FROM:<john2@doe>\r\n",
                "RCPT TO:<aa2@bb>\r\n",
                "DATA\r\n",
                "mail two\r\n",
                ".\r\n",
                "QUIT\r\n",
            ]
            .concat()
            .as_bytes(),
            [
                "220 test.server.com Service ready\r\n",
                "250 Ok\r\n",
                "250 Ok\r\n",
                "250 Ok\r\n",
                "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
                "250 Ok\r\n",
                "250 Ok\r\n",
                "250 Ok\r\n",
                "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
                "250 Ok\r\n",
                "221 Service closing transmission channel\r\n",
            ]
            .concat()
            .as_bytes(),
            get_test_config(),
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn test_receiver_14() {
        struct T;

        static mut COUNT: u32 = 0;

        #[async_trait::async_trait]
        impl DataEndResolver for T {
            async fn on_data_end(
                _: &ServerConfig,
                ctx: &MailContext,
            ) -> Result<SMTPReplyCode, std::io::Error> {
                let count = unsafe { COUNT };

                match count {
                    0 => {
                        assert_eq!(ctx.envelop.helo, "foobar");
                        assert_eq!(ctx.envelop.mail_from.full(), "john@doe");
                        assert_eq!(
                            ctx.envelop.rcpt,
                            std::collections::HashSet::from([Address::new("aa@bb").unwrap()])
                        );
                        assert_eq!(ctx.body, "mail one\n");
                    }
                    1 => {
                        assert_eq!(ctx.envelop.helo, "foobar2");
                        assert_eq!(ctx.envelop.mail_from.full(), "john2@doe");
                        assert_eq!(
                            ctx.envelop.rcpt,
                            std::collections::HashSet::from([Address::new("aa2@bb").unwrap()])
                        );
                        assert_eq!(ctx.body, "mail two\n");
                        assert!(ctx.metadata.is_some());
                    }
                    _ => panic!(),
                }

                unsafe { COUNT += 1 };

                Ok(SMTPReplyCode::Code250)
            }
        }

        assert!(test_receiver::<T>(
            [
                "HELO foobar\r\n",
                "MAIL FROM:<john@doe>\r\n",
                "RCPT TO:<aa@bb>\r\n",
                "DATA\r\n",
                "mail one\r\n",
                ".\r\n",
                "HELO foobar2\r\n",
                "MAIL FROM:<john2@doe>\r\n",
                "RCPT TO:<aa2@bb>\r\n",
                "DATA\r\n",
                "mail two\r\n",
                ".\r\n",
                "QUIT\r\n",
            ]
            .concat()
            .as_bytes(),
            [
                "220 test.server.com Service ready\r\n",
                "250 Ok\r\n",
                "250 Ok\r\n",
                "250 Ok\r\n",
                "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
                "250 Ok\r\n",
                "250 Ok\r\n",
                "250 Ok\r\n",
                "250 Ok\r\n",
                "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
                "250 Ok\r\n",
                "221 Service closing transmission channel\r\n",
            ]
            .concat()
            .as_bytes(),
            get_test_config(),
        )
        .await
        .is_ok());
    }
}
