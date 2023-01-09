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
use super::HashAlgorithm;
use crate::ParseError;
use base64::{engine::general_purpose::STANDARD, Engine};

#[derive(Debug, Default, Clone, PartialEq, Eq, strum::EnumString, strum::Display)]
#[strum(serialize_all = "UPPERCASE")]
pub enum Version {
    #[default]
    Dkim1,
}

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, strum::EnumString, strum::Display)]
#[strum(serialize_all = "lowercase")]
pub enum Type {
    #[default]
    Rsa,
    Ed25519,
}

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, strum::EnumString, strum::Display)]
#[strum(serialize_all = "lowercase")]
pub enum ServiceType {
    #[default]
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

#[derive(Clone, PartialEq, Eq)]
pub struct Record {
    /// tag "v="
    /// MUST be "DKIM1"
    pub(super) version: Version,
    /// tag "h="
    pub(super) acceptable_hash_algorithms: Vec<HashAlgorithm>,
    /// tag "k="
    pub(super) r#type: Type,
    /// tag "n="
    /// a message to the administrator
    pub(super) notes: Option<String>,
    /// tag "p="
    pub(super) public_key: Vec<u8>,
    /// tag "s="
    /// default: "*"
    pub(super) service_type: Vec<ServiceType>,
    /// tag "t="
    pub(super) flags: Vec<Flags>,
}

impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Record")
            .field("version", &self.version)
            .field(
                "acceptable_hash_algorithms",
                &self.acceptable_hash_algorithms,
            )
            .field("type", &self.r#type)
            .field("notes", &self.notes)
            .field("public_key", &STANDARD.encode(&self.public_key))
            .field("service_type", &self.service_type)
            .field("flags", &self.flags)
            .finish()
    }
}

impl std::str::FromStr for Record {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut version = Version::default();
        let mut acceptable_hash_algorithms = vec![];

        let mut r#type = Type::default();
        let mut notes = None;
        let mut public_key = None;
        let mut service_type = vec![ServiceType::default()];
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
                    public_key = Some(STANDARD.decode(p_public_key).map_err(|e| {
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
            acceptable_hash_algorithms: match r#type {
                _ if !acceptable_hash_algorithms.is_empty() => acceptable_hash_algorithms,
                #[cfg(feature = "historic")]
                Type::Rsa => vec![HashAlgorithm::Sha1, HashAlgorithm::Sha256],
                _ => vec![HashAlgorithm::Sha256],
            },
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
mod try_from {
    use super::{HashAlgorithm, Record, ServiceType, Type, Version};
    use crate::dkim::{public_key::InnerPublicKey, RSA_MINIMUM_ACCEPTABLE_KEY_SIZE};

    impl TryFrom<&InnerPublicKey> for Record {
        type Error = ();

        fn try_from(inner: &InnerPublicKey) -> Result<Self, Self::Error> {
            match inner {
                InnerPublicKey::Rsa(rsa) => {
                    if rsa::PublicKeyParts::size(rsa) * 8 < RSA_MINIMUM_ACCEPTABLE_KEY_SIZE {
                        return Err(());
                    }
                    Ok(Self {
                        version: Version::Dkim1,
                        acceptable_hash_algorithms: vec![
                            #[cfg(feature = "historic")]
                            HashAlgorithm::Sha1,
                            HashAlgorithm::Sha256,
                        ],
                        r#type: Type::Rsa,
                        notes: None,
                        public_key: rsa::pkcs8::EncodePublicKey::to_public_key_der(rsa)
                            .unwrap()
                            .as_ref()
                            .to_vec(),
                        service_type: vec![ServiceType::Wildcard],
                        flags: vec![],
                    })
                }
                InnerPublicKey::Ed25519(ed25519) => Ok(Self {
                    version: Version::Dkim1,
                    acceptable_hash_algorithms: vec![HashAlgorithm::Sha256],
                    r#type: Type::Ed25519,
                    notes: None,
                    public_key: ed25519.as_ref().to_vec(),
                    service_type: vec![ServiceType::Wildcard],
                    flags: vec![],
                }),
            }
        }
    }
}
