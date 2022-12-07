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
    builder::VirtualEntry,
    field::{FieldServerDNS, ResolverOptsWrapper},
    Config,
};

#[test]
fn parse() {
    let path_to_config = std::path::PathBuf::from_iter([
        env!("CARGO_MANIFEST_DIR"),
        "../../../examples/config/tls.vsl",
    ]);

    pretty_assertions::assert_eq!(
        Config::from_vsl_file(&path_to_config).unwrap(),
        Config::builder()
            .with_version_str(&format!(">={}, <2.0.0", env!("CARGO_PKG_VERSION")))
            .unwrap()
            .with_path(path_to_config)
            .with_server_name("testserver.com")
            .with_default_system()
            .with_ipv4_localhost()
            .with_default_logs_settings()
            .with_default_delivery()
            .with_safe_and_path(
                "../../../examples/config/tls/certificate.crt",
                "../../../examples/config/tls/private_key.key"
            )
            .unwrap()
            .with_default_smtp_options()
            .with_default_smtp_error_handler()
            .with_default_smtp_codes()
            .without_auth()
            .with_default_app()
            .with_default_vsl_settings()
            .with_default_app_logs()
            .with_system_dns()
            .with_virtual_entries(
                [
                    VirtualEntry {
                        domain: "testserver1.com".to_string(),
                        tls: None,
                        dns: None,
                    },
                    VirtualEntry {
                        domain: "testserver2.com".to_string(),
                        tls: None,
                        dns: Some(FieldServerDNS::System),
                    },
                    VirtualEntry {
                        domain: "testserver3.com".to_string(),
                        tls: Some((
                            "../../../examples/config/tls/certificate.crt".to_string(),
                            "../../../examples/config/tls/private_key.key".to_string()
                        )),
                        dns: None,
                    },
                    VirtualEntry {
                        domain: "testserver4.com".to_string(),
                        tls: Some((
                            "../../../examples/config/tls/certificate.crt".to_string(),
                            "../../../examples/config/tls/private_key.key".to_string()
                        )),
                        dns: Some(FieldServerDNS::Google {
                            options: ResolverOptsWrapper::default()
                        }),
                    },
                ]
                .into_iter()
            )
            .unwrap()
            .validate()
            .unwrap()
    );
}
