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
use crate::Config;
use vsmtp_common::{collection, CodeID, Reply};

#[test]
fn parse() {
    let path_to_config = std::path::PathBuf::from_iter([
        env!("CARGO_MANIFEST_DIR"),
        "../../../examples/config/logging.vsl",
    ]);
    pretty_assertions::assert_eq!(
        Config::from_vsl_file(&path_to_config).unwrap(),
        Config::builder()
        .with_version_str(&format!(">={}, <3.0.0", env!("CARGO_PKG_VERSION")))
        .unwrap()
            .with_path(path_to_config)
            .with_hostname()
            .with_default_system()
            .with_ipv4_localhost()
            .with_logs_settings(
                "/var/log/vsmtp/vsmtp.log",
                &[
                    "default=warn".parse().unwrap(),
                    "receiver=info".parse().unwrap(),
                    "rule_engine=warn".parse().unwrap(),
                    "delivery=error".parse().unwrap(),
                    "parser=trace".parse().unwrap(),
                ],
            )
            .with_default_delivery()
            .without_tls_support()
            .with_default_smtp_options()
            .with_default_smtp_error_handler()
            .with_smtp_codes(collection! {
                CodeID::Help =>
                    "214 This server supports the following commands\n\
                    HELO EHLO STARTTLS RCPT DATA RSET MAIL QUIT HELP AUTH".parse::<Reply>().unwrap(),
                CodeID::Greetings => "220 {name} ESMTP Service ready".parse().unwrap(),
            })
            .without_auth()
            .with_default_app()
            .with_default_vsl_settings()
            .with_app_logs_at("/var/log/vsmtp/app.log")
            .with_system_dns()
            .without_virtual_entries()
            .validate()
            .unwrap()
    );
}
