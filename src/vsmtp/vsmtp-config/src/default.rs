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

use crate::{
    config::field::{
        FieldApp, FieldAppLogs, FieldAppVSL, FieldQueueDelivery, FieldQueueWorking, FieldServer,
        FieldServerDNS, FieldServerInterfaces, FieldServerLogs, FieldServerQueues, FieldServerSMTP,
        FieldServerSMTPAuth, FieldServerSMTPError, FieldServerSMTPTimeoutClient, FieldServerSystem,
        FieldServerSystemThreadPool, FieldServerTls, FieldServerVirtual, ResolverOptsWrapper,
        SyslogSocket,
    },
    Config,
};
use vsmtp_common::{auth::Mechanism, collection, CodeID, Reply};

impl Default for Config {
    fn default() -> Self {
        let current_version =
            semver::Version::parse(env!("CARGO_PKG_VERSION")).expect("valid semver");
        Self {
            version_requirement: semver::VersionReq::from_iter([
                semver::Comparator {
                    op: semver::Op::GreaterEq,
                    major: current_version.major,
                    minor: Some(current_version.minor),
                    patch: Some(current_version.patch),
                    pre: current_version.pre,
                },
                semver::Comparator {
                    op: semver::Op::Less,
                    major: current_version.major + 1,
                    minor: Some(0),
                    patch: Some(0),
                    pre: semver::Prerelease::EMPTY,
                },
            ]),
            server: FieldServer::default(),
            app: FieldApp::default(),
            path: None,
        }
    }
}

impl Config {
    /// This function is primarily used to inject a config structure into vsl.
    ///
    /// Context: groups & users MUST be initialized when creating a default configuration.
    /// The configuration COULD be changed in a `vsmtp.vsl` or `config.vsl` script.
    /// But rust does not know that in advance, thus, even tough the user does not
    /// want to use the 'vsmtp' user by default, vsmtp will try to get that user
    /// when creating a default config. This leads to users that MUST create a 'vsmtp'
    /// user, even tough they want to change it in the configuration.
    ///
    /// We could also wrap the user & group configuration variable into an enum, but that will lead
    /// either to a lot of match patters to check if they are set or not, or simply more
    /// unwrap because we know that after the config has been loaded that it is correct.
    #[must_use]
    pub(crate) fn default_with_current_user_and_group() -> Self {
        let current_version =
            semver::Version::parse(env!("CARGO_PKG_VERSION")).expect("valid semver");
        Self {
            version_requirement: semver::VersionReq::from_iter([
                semver::Comparator {
                    op: semver::Op::GreaterEq,
                    major: current_version.major,
                    minor: Some(current_version.minor),
                    patch: Some(current_version.patch),
                    pre: current_version.pre,
                },
                semver::Comparator {
                    op: semver::Op::Less,
                    major: current_version.major + 1,
                    minor: Some(0),
                    patch: Some(0),
                    pre: semver::Prerelease::EMPTY,
                },
            ]),
            server: FieldServer {
                // NOTE: Dirty fix to prevent vsmtp 'default user not found' error message
                //       when injecting a default config instance in vsl config.
                system: FieldServerSystem {
                    user: {
                        let uid = users::get_current_uid();

                        users::get_user_by_uid(uid).expect("current uid must be valid")
                    },
                    group: {
                        let gid = users::get_current_gid();

                        users::get_group_by_gid(gid).expect("current gid must be valid")
                    },
                    group_local: None,
                    thread_pool: FieldServerSystemThreadPool::default(),
                },
                // All of this is necessary since `FieldServer` implements a custom
                // default function instead of using the derivative macro.
                name: FieldServer::hostname(),
                client_count_max: FieldServer::default_client_count_max(),
                message_size_limit: FieldServer::default_message_size_limit(),
                interfaces: FieldServerInterfaces::default(),
                logs: FieldServerLogs::default(),
                queues: FieldServerQueues::default(),
                tls: None,
                smtp: FieldServerSMTP::default(),
                dns: FieldServerDNS::default(),
                r#virtual: std::collections::BTreeMap::default(),
            },
            app: FieldApp::default(),
            path: None,
        }
    }
}

impl Default for FieldServer {
    fn default() -> Self {
        Self {
            name: Self::hostname(),
            client_count_max: Self::default_client_count_max(),
            message_size_limit: Self::default_message_size_limit(),
            system: FieldServerSystem::default(),
            interfaces: FieldServerInterfaces::default(),
            logs: FieldServerLogs::default(),
            queues: FieldServerQueues::default(),
            tls: None,
            smtp: FieldServerSMTP::default(),
            dns: FieldServerDNS::default(),
            r#virtual: std::collections::BTreeMap::default(),
        }
    }
}

impl FieldServer {
    pub(crate) fn hostname() -> String {
        hostname::get().unwrap().to_str().unwrap().to_string()
    }

    pub(crate) const fn default_client_count_max() -> i64 {
        16
    }

    pub(crate) const fn default_message_size_limit() -> usize {
        10_000_000
    }
}

impl Default for FieldServerSystem {
    fn default() -> Self {
        Self {
            user: Self::default_user(),
            group: Self::default_group(),
            group_local: None,
            thread_pool: FieldServerSystemThreadPool::default(),
        }
    }
}

impl FieldServerSystem {
    pub(crate) fn default_user() -> users::User {
        users::get_user_by_name(match option_env!("CI") {
            Some(_) => "root",
            None => "vsmtp",
        })
        .expect("default user 'vsmtp' not found.")
    }

    pub(crate) fn default_group() -> users::Group {
        users::get_group_by_name(match option_env!("CI") {
            Some(_) => "root",
            None => "vsmtp",
        })
        .expect("default group 'vsmtp' not found.")
    }
}

impl Default for FieldServerSystemThreadPool {
    fn default() -> Self {
        Self {
            receiver: Self::default_receiver(),
            processing: Self::default_processing(),
            delivery: Self::default_delivery(),
        }
    }
}

impl FieldServerSystemThreadPool {
    pub(crate) const fn default_receiver() -> usize {
        6
    }

    pub(crate) const fn default_processing() -> usize {
        6
    }

    pub(crate) const fn default_delivery() -> usize {
        6
    }
}

impl Default for FieldServerInterfaces {
    fn default() -> Self {
        Self::ipv4_localhost()
    }
}

impl FieldServerInterfaces {
    pub(crate) fn ipv4_localhost() -> Self {
        Self {
            addr: vec!["127.0.0.1:25".parse().expect("valid")],
            addr_submission: vec!["127.0.0.1:587".parse().expect("valid")],
            addr_submissions: vec!["127.0.0.1:465".parse().expect("valid")],
        }
    }
}

impl Default for FieldServerLogs {
    fn default() -> Self {
        Self {
            filename: Self::default_filename(),
            level: Self::default_level(),
            system: None,
        }
    }
}

impl FieldServerLogs {
    pub(crate) fn default_filename() -> std::path::PathBuf {
        "/var/log/vsmtp/vsmtp.log".into()
    }

    pub(crate) fn default_level() -> Vec<tracing_subscriber::filter::Directive> {
        vec!["warn".parse().expect("hardcoded value is valid")]
    }
}

impl SyslogSocket {
    pub(crate) fn default_udp_local() -> std::net::SocketAddr {
        "127.0.0.1:0".parse().expect("valid")
    }

    pub(crate) fn default_udp_server() -> std::net::SocketAddr {
        "127.0.0.1:514".parse().expect("valid")
    }

    pub(crate) fn default_tcp_server() -> std::net::SocketAddr {
        "127.0.0.1:601".parse().expect("valid")
    }
}

impl Default for SyslogSocket {
    fn default() -> Self {
        Self::Unix { path: None }
    }
}

impl FieldServerTls {
    pub(crate) fn default_cipher_suite() -> Vec<vsmtp_common::CipherSuite> {
        [
            // TLS1.3 suites
            rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
            rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            // TLS1.2 suites
            rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ]
        .into_iter()
        .map(vsmtp_common::CipherSuite)
        .collect::<Vec<_>>()
    }

    pub(crate) const fn default_handshake_timeout() -> std::time::Duration {
        std::time::Duration::from_secs(1)
    }
}

impl Default for FieldServerQueues {
    fn default() -> Self {
        Self {
            dirpath: Self::default_dirpath(),
            working: FieldQueueWorking::default(),
            delivery: FieldQueueDelivery::default(),
        }
    }
}

impl FieldServerQueues {
    pub(crate) fn default_dirpath() -> std::path::PathBuf {
        "/var/spool/vsmtp".into()
    }
}

impl Default for FieldQueueWorking {
    fn default() -> Self {
        Self {
            channel_size: Self::default_channel_size(),
        }
    }
}

impl FieldQueueWorking {
    pub(crate) const fn default_channel_size() -> usize {
        32
    }
}

impl Default for FieldQueueDelivery {
    fn default() -> Self {
        Self {
            channel_size: Self::default_channel_size(),
            deferred_retry_max: Self::default_deferred_retry_max(),
            deferred_retry_period: Self::default_deferred_retry_period(),
        }
    }
}

impl FieldQueueDelivery {
    pub(crate) const fn default_channel_size() -> usize {
        32
    }

    pub(crate) const fn default_deferred_retry_max() -> usize {
        100
    }

    pub(crate) const fn default_deferred_retry_period() -> std::time::Duration {
        std::time::Duration::from_secs(300)
    }
}

impl FieldServerVirtual {
    pub(crate) fn default_json() -> anyhow::Result<rhai::Map> {
        Ok(rhai::Engine::new().parse_json(serde_json::to_string(&Self::default())?, true)?)
    }
}

impl Default for FieldServerSMTPAuth {
    fn default() -> Self {
        Self {
            enable_dangerous_mechanism_in_clair: Self::default_enable_dangerous_mechanism_in_clair(
            ),
            mechanisms: Self::default_mechanisms(),
            attempt_count_max: Self::default_attempt_count_max(),
        }
    }
}

impl FieldServerSMTPAuth {
    pub(crate) const fn default_enable_dangerous_mechanism_in_clair() -> bool {
        false
    }

    /// Return all the supported SASL mechanisms
    #[must_use]
    pub fn default_mechanisms() -> Vec<Mechanism> {
        vec![Mechanism::Plain, Mechanism::Login, Mechanism::CramMd5]
    }

    pub(crate) const fn default_attempt_count_max() -> i64 {
        -1
    }
}

impl Default for FieldServerSMTP {
    fn default() -> Self {
        Self {
            rcpt_count_max: Self::default_rcpt_count_max(),
            error: FieldServerSMTPError::default(),
            timeout_client: FieldServerSMTPTimeoutClient::default(),
            codes: Self::default_smtp_codes(),
            auth: None,
        }
    }
}

impl FieldServerSMTP {
    pub(crate) const fn default_rcpt_count_max() -> usize {
        1000
    }

    // TODO: should be const and compile time checked
    pub(crate) fn default_smtp_codes() -> std::collections::BTreeMap<CodeID, Reply> {
        let codes: std::collections::BTreeMap<CodeID, Reply> = collection! {
            CodeID::Greetings => "220 {name} Service ready\r\n".parse::<Reply>().unwrap(),
            CodeID::Help => "214 joining us https://viridit.com/support\r\n".parse::<Reply>().unwrap(),
            CodeID::Closing => "221 Service closing transmission channel\r\n".parse::<Reply>().unwrap(),
            CodeID::Helo => "250 Ok\r\n".parse::<Reply>().unwrap(),
            CodeID::DataStart => "354 Start mail input; end with <CRLF>.<CRLF>\r\n".parse::<Reply>().unwrap(),
            CodeID::Ok => "250 Ok\r\n".parse::<Reply>().unwrap(),
            CodeID::Failure => "451 Requested action aborted: local error in processing\r\n".parse::<Reply>().unwrap(),
            CodeID::Denied => "554 permanent problems with the remote server\r\n".parse::<Reply>().unwrap(),
            CodeID::UnrecognizedCommand => "500 Syntax error command unrecognized\r\n".parse::<Reply>().unwrap(),
            CodeID::SyntaxErrorParams => "501 Syntax error in parameters or arguments\r\n".parse::<Reply>().unwrap(),
            CodeID::ParameterUnimplemented => "504 Command parameter not implemented\r\n".parse::<Reply>().unwrap(),
            CodeID::Unimplemented => "502 Command not implemented\r\n".parse::<Reply>().unwrap(),
            CodeID::BadSequence => "503 Bad sequence of commands\r\n".parse::<Reply>().unwrap(),
            CodeID::MessageSizeExceeded => "552 4.3.1 Message size exceeds fixed maximum message size\r\n".parse::<Reply>().unwrap(),
            CodeID::TlsGoAhead => "220 TLS go ahead\r\n".parse::<Reply>().unwrap(),
            CodeID::TlsNotAvailable => "454 TLS not available due to temporary reason\r\n".parse::<Reply>().unwrap(),
            CodeID::AlreadyUnderTLS => "554 5.5.1 Error: TLS already active\r\n".parse::<Reply>().unwrap(),
            CodeID::AuthSucceeded => "235 2.7.0 Authentication succeeded\r\n".parse::<Reply>().unwrap(),
            CodeID::AuthMechNotSupported => "504 5.5.4 Mechanism is not supported\r\n".parse::<Reply>().unwrap(),
            CodeID::AuthClientMustNotStart => "501 5.7.0 Client must not start with this mechanism\r\n".parse::<Reply>().unwrap(),
            CodeID::AuthMechanismMustBeEncrypted => "538 5.7.11 Encryption required for requested authentication mechanism\r\n".parse::<Reply>().unwrap(),
            CodeID::AuthInvalidCredentials => "535 5.7.8 Authentication credentials invalid\r\n".parse::<Reply>().unwrap(),
            CodeID::AuthClientCanceled => "501 Authentication canceled by client\r\n".parse::<Reply>().unwrap(),
            CodeID::AuthErrorDecode64 => "501 5.5.2 Invalid, not base64\r\n".parse::<Reply>().unwrap(),
            CodeID::AuthTempError => "454 4.7.0 Temporary authentication failure\r\n".parse::<Reply>().unwrap(),
            CodeID::ConnectionMaxReached => "554 Cannot process connection, closing\r\n".parse::<Reply>().unwrap(),
            CodeID::TooManyError => "451 Too many errors from the client\r\n".parse::<Reply>().unwrap(),
            CodeID::Timeout => "451 Timeout - closing connection\r\n".parse::<Reply>().unwrap(),
            CodeID::TooManyRecipients => "452 Requested action not taken: too many recipients\r\n".parse::<Reply>().unwrap(),
        };

        assert!(
            <CodeID as strum::IntoEnumIterator>::iter()
                // exclude these codes because they are generated by the [Config::ensure] and vsl.
                .filter(|i| ![CodeID::EhloPain, CodeID::EhloSecured,].contains(i))
                .all(|i| codes.contains_key(&i)),
            "default SMTPReplyCode are ill-formed "
        );

        codes
    }
}

impl Default for FieldServerDNS {
    fn default() -> Self {
        Self::System
    }
}

impl Default for ResolverOptsWrapper {
    fn default() -> Self {
        Self {
            timeout: Self::default_timeout(),
            attempts: Self::default_attempts(),
            rotate: Self::default_rotate(),
            dnssec: Self::default_dnssec(),
            ip_strategy: Self::default_ip_strategy(),
            cache_size: Self::default_cache_size(),
            use_hosts_file: Self::default_use_hosts_file(),
            num_concurrent_reqs: Self::default_num_concurrent_reqs(),
        }
    }
}

impl ResolverOptsWrapper {
    pub(crate) const fn default_timeout() -> std::time::Duration {
        std::time::Duration::from_secs(5)
    }

    pub(crate) const fn default_attempts() -> usize {
        2
    }
    pub(crate) const fn default_rotate() -> bool {
        false
    }

    pub(crate) const fn default_dnssec() -> bool {
        false
    }

    pub(crate) fn default_ip_strategy() -> trust_dns_resolver::config::LookupIpStrategy {
        trust_dns_resolver::config::LookupIpStrategy::default()
    }

    pub(crate) const fn default_cache_size() -> usize {
        32
    }

    pub(crate) const fn default_use_hosts_file() -> bool {
        true
    }

    pub(crate) const fn default_num_concurrent_reqs() -> usize {
        2
    }
}

impl Default for FieldServerSMTPError {
    fn default() -> Self {
        Self {
            soft_count: 10,
            hard_count: 20,
            delay: std::time::Duration::from_millis(5000),
        }
    }
}

impl Default for FieldServerSMTPTimeoutClient {
    fn default() -> Self {
        Self {
            connect: std::time::Duration::from_secs(5 * 60),
            helo: std::time::Duration::from_secs(5 * 60),
            mail_from: std::time::Duration::from_secs(5 * 60),
            rcpt_to: std::time::Duration::from_secs(5 * 60),
            data: std::time::Duration::from_secs(5 * 60),
        }
    }
}

impl Default for FieldApp {
    fn default() -> Self {
        Self {
            dirpath: Self::default_dirpath(),
            vsl: FieldAppVSL::default(),
            logs: FieldAppLogs::default(),
        }
    }
}

impl FieldApp {
    pub(crate) fn default_dirpath() -> std::path::PathBuf {
        "/var/spool/vsmtp/app".into()
    }
}

impl Default for FieldAppLogs {
    fn default() -> Self {
        Self {
            filename: Self::default_filename(),
        }
    }
}

impl FieldAppLogs {
    pub(crate) fn default_filename() -> std::path::PathBuf {
        "/var/log/vsmtp/app.log".into()
    }
}
