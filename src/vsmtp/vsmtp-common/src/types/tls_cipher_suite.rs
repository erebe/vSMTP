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

/*
const ALL_CIPHER_SUITE: [rustls::CipherSuite; 9] = [
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
];
*/

/// Wrapper around [`rustls::CipherSuite`] to implement [`serde::Deserialize`] and [`serde::Serialize`]
#[derive(
    Debug, Clone, PartialEq, Eq, serde_with::DeserializeFromStr, serde_with::SerializeDisplay,
)]
pub struct CipherSuite(pub rustls::CipherSuite);

impl std::str::FromStr for CipherSuite {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "TLS_AES_256_GCM_SHA384" => Ok(Self(rustls::CipherSuite::TLS13_AES_256_GCM_SHA384)),
            "TLS_AES_128_GCM_SHA256" => Ok(Self(rustls::CipherSuite::TLS13_AES_128_GCM_SHA256)),
            "TLS_CHACHA20_POLY1305_SHA256" => {
                Ok(Self(rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256))
            }
            "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => Ok(Self(
                rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            )),
            "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => Ok(Self(
                rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            )),
            "ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => Ok(Self(
                rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            )),
            "ECDHE_RSA_WITH_AES_256_GCM_SHA384" => Ok(Self(
                rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            )),
            "ECDHE_RSA_WITH_AES_128_GCM_SHA256" => Ok(Self(
                rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            )),
            "ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => Ok(Self(
                rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            )),
            _ => Err(anyhow::anyhow!("not a valid cipher suite: '{}'", s)),
        }
    }
}

impl std::fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.0 {
            rustls::CipherSuite::TLS13_AES_256_GCM_SHA384 => "TLS_AES_256_GCM_SHA384",
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256",
            rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => "TLS_CHACHA20_POLY1305_SHA256",
            rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => {
                "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
            }
            rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => {
                "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
            }
            rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => {
                "ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
            }
            rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => {
                "ECDHE_RSA_WITH_AES_256_GCM_SHA384"
            }
            rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => {
                "ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            }
            rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => {
                "ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
            }
            _ => "unsupported",
        })
    }
}

/*
#[cfg(test)]
mod tests {
    #[derive(serde::Serialize, serde::Deserialize)]
    struct S {
        #[serde(
            serialize_with = "super::serialize",
            deserialize_with = "super::deserialize"
        )]
        v: Vec<rustls::CipherSuite>,
    }

    #[test]
    fn error() {
        assert!(serde_json::from_str::<S>(r#"{ "v": ["SRP_SHA_WITH_AES_128_CBC_SHA"] }"#).is_err());
        assert!(serde_json::from_str::<S>(r#"{ "v": "foobar" }"#).is_err());
        assert!(serde_json::from_str::<S>(r#"{ "v": 100 }"#).is_err());
    }

    #[test]
    fn tls1_3() {
        assert_eq!(
            serde_json::from_str::<S>(
                r#"{ "v": [
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256"
] }"#
            )
            .unwrap()
            .v,
            vec![
                rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
                rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
                rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            ]
        );
    }

    #[test]
    fn tls1_2() {
        assert_eq!(
            serde_json::from_str::<S>(
                r#"{ "v": [
    "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
] }"#
            )
            .unwrap()
            .v,
            vec![
                rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ]
        );
    }

    const ALL_CIPHER_SUITE: [rustls::CipherSuite; 9] = [
        rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
        rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ];

    #[test]
    fn serialize() {
        for i in ALL_CIPHER_SUITE {
            assert_eq!(
                serde_json::to_string(&S { v: vec![i] }).unwrap(),
                format!("{{\"v\":[\"{}\"]}}", super::CipherSuite(i))
            );
        }
    }
}
*/
