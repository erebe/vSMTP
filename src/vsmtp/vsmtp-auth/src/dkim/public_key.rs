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

use super::{HashAlgorithm, MINIMUM_ACCEPTABLE_KEY_SIZE};
use crate::ParseError;

#[derive(Debug, Clone, PartialEq, Eq, strum::EnumString, strum::Display)]
#[strum(serialize_all = "UPPERCASE")]
pub enum Version {
    Dkim1,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, strum::EnumString, strum::Display)]
#[strum(serialize_all = "lowercase")]
pub enum Type {
    Rsa,
}

impl Default for Type {
    fn default() -> Self {
        Self::Rsa
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, strum::EnumString, strum::Display)]
#[strum(serialize_all = "lowercase")]
pub enum ServiceType {
    #[strum(serialize = "*")]
    Wildcard,
    Email,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, strum::EnumString, strum::Display)]
pub enum Flags {
    /// Verifiers MUST treat messages from Signers as unsigned email
    #[strum(serialize = "y")]
    Testing,
    /// the "i=" domain MUST NOT be a subdomain of "d="
    #[strum(serialize = "s")]
    SameDomain,
}

/// The public key exposed by the Signing Domain Identifier, claiming the
/// responsibility for a [`crate::dkim::Signature`]
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// tag "v="
    /// MUST be "DKIM1"
    version: Version,
    /// tag "h="
    pub acceptable_hash_algorithms: Vec<HashAlgorithm>,
    /// tag "k="
    pub r#type: Type,
    /// tag "n="
    /// a message to the administrator
    pub notes: Option<String>,
    /// tag "p="
    pub public_key: Vec<u8>,
    /// tag "s="
    /// default: "*"
    pub service_type: Vec<ServiceType>,
    /// tag "t="
    pub flags: Vec<Flags>,
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicKey")
            .field("version", &self.version)
            .field(
                "acceptable_hash_algorithms",
                &self.acceptable_hash_algorithms,
            )
            .field("type", &self.r#type)
            .field("notes", &self.notes)
            .field("public_key", &base64::encode(&self.public_key))
            .field("service_type", &self.service_type)
            .field("flags", &self.flags)
            .finish()
    }
}

///
#[must_use]
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    ///
    #[error(
        "invalid key size: {0} bits, was expecting at least {} bits",
        MINIMUM_ACCEPTABLE_KEY_SIZE
    )]
    KeySizeInvalid,
}

impl PublicKey {
    /// Does the signature contains the tag: `t=y`
    #[must_use]
    pub fn has_debug_flag(&self) -> bool {
        self.flags.iter().any(|f| *f == Flags::Testing)
    }

    ///
    /// # Errors
    ///
    /// * see [`KeyError`]
    pub fn new(
        r#type: Type,
        public_key: Vec<u8>,
        public_key_len_bit: usize,
        flags: Vec<Flags>,
    ) -> Result<Self, KeyError> {
        if public_key_len_bit * 8 < MINIMUM_ACCEPTABLE_KEY_SIZE {
            return Err(KeyError::KeySizeInvalid);
        }
        Ok(Self {
            version: Version::Dkim1,
            acceptable_hash_algorithms: match r#type {
                Type::Rsa => vec![
                    #[cfg(feature = "historic")]
                    HashAlgorithm::Sha1,
                    HashAlgorithm::Sha256,
                ],
            },
            r#type: Type::Rsa,
            notes: None,
            public_key,
            service_type: vec![ServiceType::Wildcard],
            flags,
        })
    }
}

impl std::str::FromStr for PublicKey {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut version = Version::Dkim1;
        let mut acceptable_hash_algorithms = vec![
            #[cfg(feature = "historic")]
            HashAlgorithm::Sha1,
            HashAlgorithm::Sha256,
        ];

        let mut r#type = Type::default();
        let mut notes = None;
        let mut public_key = None;
        let mut service_type = vec![ServiceType::Wildcard];
        let mut flags = vec![];

        for i in s
            .split(';')
            .map(|tag| tag.split_whitespace().collect::<Vec<_>>().concat())
            // ?
            .take_while(|s| !s.is_empty())
        {
            match i.split_once('=').ok_or(ParseError::SyntaxError {
                reason: "tag syntax is `{tag}={value}`".to_string(),
            })? {
                ("v", p_version) => {
                    version =
                        Version::from_str(p_version).map_err(|e| ParseError::SyntaxError {
                            reason: format!("when parsing `version`, got: `{e}`"),
                        })?;
                }
                ("h", p_acceptable_hash_algorithms) => {
                    acceptable_hash_algorithms = p_acceptable_hash_algorithms
                        .split(':')
                        // ignore unrecognized algorithms
                        .filter_map(|h| HashAlgorithm::from_str(h).ok())
                        .collect();
                }
                ("k", p_type) => {
                    r#type = Type::from_str(p_type).unwrap_or_default();
                }
                ("n", p_notes) => notes = Some(p_notes.to_string()),
                ("p", p_public_key) => {
                    public_key = Some(base64::decode(p_public_key).map_err(|e| {
                        ParseError::SyntaxError {
                            reason: format!("failed to pase `public_key`: got `{e}`"),
                        }
                    })?);
                }
                ("s", p_service_type) => {
                    service_type = p_service_type
                        .split(':')
                        // ignore unrecognized service type
                        .filter_map(|s| ServiceType::from_str(s).ok())
                        .collect();
                }
                ("t", p_flags) => {
                    flags = p_flags
                        .split(':')
                        // ignore unrecognized flags
                        .filter_map(|t| Flags::from_str(t).ok())
                        .collect();
                }
                // ignore unknown tag
                _ => continue,
            }
        }

        Ok(Self {
            version,
            acceptable_hash_algorithms,
            r#type,
            notes,
            public_key: public_key.ok_or(ParseError::MissingRequiredField {
                field: "public_key".to_string(),
            })?,
            service_type,
            flags,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::dkim::{
        public_key::{Flags, ServiceType, Type, Version},
        HashAlgorithm, PublicKey,
    };

    const TXT: &str = "v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvxxZDZBe61KUSY/nQ09l9P9n4rmeb2Ol/Z2j7g33viWEfTCro0+Nyicz/vjTQZv+cq5Wla+ADyXkdSGJ0OFp9SrUu9tGeDhil2UEPsHHdnf3AaarX3hyY8Ne5X5EOnJ5WY3QSpTL+eVUtSTt5DbsDqfShzxbc/BsKb5sfHuGJxcKuCyFVqCyhpSKT4kdpzZ5FLLrEiyvJGYUfq7qvqPB+A/wx1TIO5YONWWH2mqy3zviLx70u06wnxwyvGve2HMKeMvDm1HGibZShJnOIRzJuZ9BFYffm8iGisYFocxp7daiJgbpMtqYY/TB8ZvGajv/ZqITrbRp+qpfK9Bpdk8qXwIDAQAB";

    #[test]
    fn parse() {
        let key = <PublicKey as std::str::FromStr>::from_str(TXT).unwrap();
        assert_eq!(
            key,
            PublicKey {
                version: Version::Dkim1,
                acceptable_hash_algorithms: vec![HashAlgorithm::Sha256],
                r#type: Type::Rsa,
                notes: None,
                public_key: base64::decode(concat!(
                    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvxxZDZBe61KUSY/nQ09l9P9n4rmeb2Ol/Z2",
                    "j7g33viWEfTCro0+Nyicz/vjTQZv+cq5Wla+ADyXkdSGJ0OFp9SrUu9tGeDhil2UEPsHHdnf3AaarX3",
                    "hyY8Ne5X5EOnJ5WY3QSpTL+eVUtSTt5DbsDqfShzxbc/BsKb5sfHuGJxcKuCyFVqCyhpSKT4kdpzZ5F",
                    "LLrEiyvJGYUfq7qvqPB+A/wx1TIO5YONWWH2mqy3zviLx70u06wnxwyvGve2HMKeMvDm1HGibZShJnO",
                    "IRzJuZ9BFYffm8iGisYFocxp7daiJgbpMtqYY/TB8ZvGajv/ZqITrbRp+qpfK9Bpdk8qXwIDAQAB"
                )).unwrap(),
                service_type: vec![ServiceType::Wildcard],
                flags: vec![]
            }
        );

        println!("{key:?}");
        assert!(!key.has_debug_flag());

        let debug_key = PublicKey {
            flags: vec![Flags::Testing],
            ..key
        };

        assert!(debug_key.has_debug_flag());
    }

    #[test]
    fn parse_service_email() {
        let key = <PublicKey as std::str::FromStr>::from_str(&format!("{TXT}; s=email")).unwrap();
        assert_eq!(
            key,
            PublicKey {
                version: Version::Dkim1,
                acceptable_hash_algorithms: vec![HashAlgorithm::Sha256],
                r#type: Type::Rsa,
                notes: None,
                public_key: base64::decode(concat!(
                    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvxxZDZBe61KUSY/nQ09l9P9n4rmeb2Ol/Z2",
                    "j7g33viWEfTCro0+Nyicz/vjTQZv+cq5Wla+ADyXkdSGJ0OFp9SrUu9tGeDhil2UEPsHHdnf3AaarX3",
                    "hyY8Ne5X5EOnJ5WY3QSpTL+eVUtSTt5DbsDqfShzxbc/BsKb5sfHuGJxcKuCyFVqCyhpSKT4kdpzZ5F",
                    "LLrEiyvJGYUfq7qvqPB+A/wx1TIO5YONWWH2mqy3zviLx70u06wnxwyvGve2HMKeMvDm1HGibZShJnO",
                    "IRzJuZ9BFYffm8iGisYFocxp7daiJgbpMtqYY/TB8ZvGajv/ZqITrbRp+qpfK9Bpdk8qXwIDAQAB"
                )).unwrap(),
                service_type: vec![ServiceType::Email],
                flags: vec![]
            }
        );
    }

    #[test]
    fn parse2() {
        let public_key = "v=DKIM1;h=sha256;k=rsa;p=MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAy/Xyk/Kvboflr/9jgiF/9cgxPk7JluoGRFZd4+UGDRcVn6qp8HzdBS1CTfgzznE9DBD3SosJOo/XawEbZvBw1xCwe/DCnhoxznqOmXeHBgmVIpR2BBGdr5QT7ByfkSJUwlzHiRCjjx2++y+EAEsk5Wo6xRtrJLm19SCc2q4CCBTMx6rSSP9PGTZdtgOxIAdW/58pJrEH3OtBEEXO/e42JR81bwKGJYjL+5oCLjnEJjz/nyMwJRiQQLsCQqUnpoZqoLs5J43N+6mJZhG+8DoitXU7zW4a7GGOzYqF45zkuQbCv6h3eaA+s1+SjcaUzCq45zCgOjONSlWec2kA6ciuDaRx0QvipCIou3fovP0x/Md/L3YbVJUk7cpxjCTrY63CzTLZycbz1DX3rqY5Dq0g1CmpUPDRZjCm7Q8KD1B9t4w5md7vXlKWCR6ojoujiRbR6kxxverOZWdTtMOiH2G4eB8AAWP6sTgBhgNgiLjWjakkQvGGbfNnRdeCV7ygZwBnYhS43k7tPNtbGB0LTE9FaNzYKW7NfjCDiS7z3JJZzsi3vhf5lkjYFwKbWpa4NeKmtu/6mWclSTeLL7GlmywPMOUYOPLmGFCAiDfuG1Qcjm7ocsQsGs9Rd3/kDo5rREL5USpNzW8bd7DBsUzMk6iY4VMVZG4up1rZ6dZ0Qpt1m9MCAwEAAQ==;t=s;";

        assert_eq!(
            <PublicKey as std::str::FromStr>::from_str(public_key).unwrap(),
            PublicKey {
                version: Version::Dkim1,
                acceptable_hash_algorithms: vec![HashAlgorithm::Sha256],
                r#type: Type::Rsa,
                notes: None,
                public_key: base64::decode(concat!(
                    "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAy/Xyk/Kvboflr/9jgiF/9cgxPk7JluoGRFZd4+UGDRcVn6qp8HzdBS1CTfgzznE9DBD3SosJOo/XawEbZvBw1xCwe/DCnhoxznqOmXeHBgmVIpR2BBGdr5QT7ByfkSJUwlzHiRCjjx2++y+EAEsk5Wo6xRtrJLm19SCc2q4CCBTMx6rSSP9PGTZdtgOxIAdW/58pJrEH3OtBEEXO/e42JR81bwKGJYjL+5oCLjnEJjz/nyMwJRiQQLsCQqUnpoZqoLs5J43N+6mJZhG+8DoitXU7zW4a7GGOzYqF45zkuQbCv6h3eaA+s1+SjcaUzCq45zCgOjONSlWec2kA6ciuDaRx0QvipCIou3fovP0x/Md/L3YbVJUk7cpxjCTrY63CzTLZycbz1DX3rqY5Dq0g1CmpUPDRZjCm7Q8KD1B9t4w5md7vXlKWCR6ojoujiRbR6kxxverOZWdTtMOiH2G4eB8AAWP6sTgBhgNgiLjWjakkQvGGbfNnRdeCV7ygZwBnYhS43k7tPNtbGB0LTE9FaNzYKW7NfjCDiS7z3JJZzsi3vhf5lkjYFwKbWpa4NeKmtu/6mWclSTeLL7GlmywPMOUYOPLmGFCAiDfuG1Qcjm7ocsQsGs9Rd3/kDo5rREL5USpNzW8bd7DBsUzMk6iY4VMVZG4up1rZ6dZ0Qpt1m9MCAwEAAQ=="
                )).unwrap(),
                service_type: vec![ServiceType::Wildcard],
                flags: vec![Flags::SameDomain]
            }
        );
    }

    mod error {
        use super::*;

        #[test]
        fn not_tag_based_syntax() {
            let _err = <PublicKey as std::str::FromStr>::from_str("foobar").unwrap_err();
        }

        #[test]
        fn not_right_version() {
            let _err = <PublicKey as std::str::FromStr>::from_str("v=DKIM2").unwrap_err();
        }

        #[test]
        fn invalid_key() {
            let _err = <PublicKey as std::str::FromStr>::from_str("p=foobar").unwrap_err();
        }

        #[test]
        fn missing_key() {
            let _err = <PublicKey as std::str::FromStr>::from_str("s=*").unwrap_err();
        }
    }
}
