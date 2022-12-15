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
use rustls::ALL_CIPHER_SUITES;

use crate::field::{FieldServerTls, FieldServerVirtual, FieldServerVirtualTls};

struct TlsLogger;
impl rustls::KeyLog for TlsLogger {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        tracing::trace!(label, ?client_random, ?secret);
    }
}

static JUST_TLS1_2: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];
static JUST_TLS1_3: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

static ALL_VERSIONS: &[&rustls::SupportedProtocolVersion] =
    &[&rustls::version::TLS13, &rustls::version::TLS12];

fn to_supported_cipher_suite(
    cipher_suite: &[vsmtp_common::CipherSuite],
) -> Vec<rustls::SupportedCipherSuite> {
    ALL_CIPHER_SUITES
        .iter()
        .filter(|i| cipher_suite.iter().any(|x| x.0 == i.suite()))
        .copied()
        .collect::<Vec<_>>()
}

#[doc(hidden)]
pub fn get_rustls_config(
    config: &FieldServerTls,
    virtual_entries: &std::collections::BTreeMap<String, FieldServerVirtual>,
) -> anyhow::Result<rustls::ServerConfig> {
    let protocol_version = match (
        config
            .protocol_version
            .iter()
            .any(|i| i.0 == rustls::ProtocolVersion::TLSv1_2),
        config
            .protocol_version
            .iter()
            .any(|i| i.0 == rustls::ProtocolVersion::TLSv1_3),
    ) {
        (true, true) => ALL_VERSIONS,
        (true, false) => JUST_TLS1_2,
        (false, true) => JUST_TLS1_3,
        (false, false) => anyhow::bail!("requested version is not supported"),
    };

    let mut cert_resolver = rustls::server::ResolvesServerCertUsingSni::new();
    let virtual_server_with_tls = virtual_entries
        .iter()
        .filter_map(|(virtual_name, params)| params.tls.as_ref().map(|tls| (virtual_name, tls)));
    for (
        virtual_name,
        FieldServerVirtualTls {
            certificate,
            private_key,
            ..
        },
    ) in virtual_server_with_tls
    {
        cert_resolver
            .add(
                virtual_name,
                rustls::sign::CertifiedKey {
                    cert: certificate.inner.clone(),
                    key: rustls::sign::any_supported_type(&private_key.inner)?,
                    // TODO: support OCSP and SCT
                    ocsp: None,
                    sct_list: None,
                },
            )
            .map_err(|e| anyhow::anyhow!("cannot add sni to resolver '{virtual_name}': {e}"))?;
    }

    let mut tls_config = rustls::ServerConfig::builder()
        .with_cipher_suites(&to_supported_cipher_suite(&config.cipher_suite))
        .with_kx_groups(&rustls::ALL_KX_GROUPS)
        .with_protocol_versions(protocol_version)
        .map_err(|e| anyhow::anyhow!("cannot initialize tls config: '{e}'"))?
        // TODO: allow configurable ClientAuth (DANE)
        .with_client_cert_verifier(rustls::server::NoClientAuth::new())
        .with_cert_resolver(std::sync::Arc::new(cert_resolver));

    tls_config.ignore_client_order = config.preempt_cipherlist;
    tls_config.key_log = std::sync::Arc::new(TlsLogger {});

    // TODO: override other `tls_config` params ?

    Ok(tls_config)
}
