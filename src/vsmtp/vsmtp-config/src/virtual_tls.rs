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
    field::{FieldServerVirtualTls, SecretFile},
    parser::{tls_certificate, tls_private_key},
};
use vsmtp_auth::dkim;

impl<'de> serde::Deserialize<'de> for SecretFile<rustls::PrivateKey> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        Ok(Self {
            inner: tls_private_key::from_string(&s).map_err(serde::de::Error::custom)?,
            path: s.into(),
        })
    }
}

impl<'de> serde::Deserialize<'de> for SecretFile<rustls::Certificate> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        Ok(Self {
            inner: tls_certificate::from_string(&s).map_err(serde::de::Error::custom)?,
            path: s.into(),
        })
    }
}

impl<'de> serde::Deserialize<'de> for SecretFile<rsa::RsaPrivateKey> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        Ok(Self {
            inner: <rsa::RsaPrivateKey as rsa::pkcs8::DecodePrivateKey>::read_pkcs8_pem_file(&s)
                .or_else(|_| {
                    <rsa::RsaPrivateKey as rsa::pkcs1::DecodeRsaPrivateKey>::read_pkcs1_pem_file(&s)
                })
                .map_err(serde::de::Error::custom)?,
            path: s.into(),
        })
    }
}

impl<'de> serde::Deserialize<'de> for SecretFile<std::sync::Arc<dkim::PrivateKey>> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let filepath = <String as serde::Deserialize>::deserialize(deserializer)?;

        let rsa =
            <rsa::RsaPrivateKey as rsa::pkcs8::DecodePrivateKey>::read_pkcs8_pem_file(&filepath)
                .or_else(|_| {
                    <rsa::RsaPrivateKey as rsa::pkcs1::DecodeRsaPrivateKey>::read_pkcs1_pem_file(
                        &filepath,
                    )
                });

        if let Ok(rsa) = rsa {
            return Ok(Self {
                inner: std::sync::Arc::new(dkim::PrivateKey::Rsa(Box::new(rsa))),
                path: filepath.into(),
            });
        }

        let content = std::fs::read_to_string(&filepath)
            .map_err(|e| serde::de::Error::custom(format!("Read '{filepath}' produced: '{e}'")))?;

        let content_pem = pem::parse(content).map_err(|e| {
            serde::de::Error::custom(format!("Parsing '{filepath}' produced: '{e}'"))
        })?;

        let ed25519 = ring_compat::ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(
            &content_pem.contents,
        )
        .map_err(|e| {
            serde::de::Error::custom(format!("Failed to parse '{filepath}' as ed25519: '{e}'"))
        })?;

        Ok(Self {
            inner: std::sync::Arc::new(dkim::PrivateKey::Ed25519(Box::new(ed25519))),
            path: filepath.into(),
        })
    }
}

impl FieldServerVirtualTls {
    /// create a virtual tls configuration from the certificate & private key paths.
    ///
    /// # Errors
    ///
    /// * certificate file not found.
    /// * private key file not found.
    pub fn from_path(certificate: &str, private_key: &str) -> anyhow::Result<Self> {
        Ok(Self {
            protocol_version: vec![rustls::ProtocolVersion::TLSv1_3],
            certificate: SecretFile::<rustls::Certificate> {
                inner: tls_certificate::from_string(certificate)?,
                path: certificate.into(),
            },
            private_key: SecretFile::<rustls::PrivateKey> {
                inner: tls_private_key::from_string(private_key)?,
                path: private_key.into(),
            },
            sender_security_level: Self::default_sender_security_level(),
        })
    }
}
