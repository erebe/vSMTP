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

use super::{
    record::{Flags, Record, Type},
    verify::InnerError,
    BackendError, SigningAlgorithm,
};
use crate::ParseError;

#[derive(Clone, PartialEq, Eq)]
pub(super) enum InnerPublicKey {
    Rsa(rsa::RsaPublicKey),
    Ed25519(ring_compat::signature::ed25519::VerifyingKey),
}

impl std::fmt::Debug for InnerPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rsa(_) => f.debug_struct("Rsa").finish_non_exhaustive(),
            Self::Ed25519(_) => f.debug_struct("Ed25519").finish_non_exhaustive(),
        }
    }
}

impl TryFrom<&Record> for InnerPublicKey {
    type Error = ParseError;

    fn try_from(record: &Record) -> Result<Self, Self::Error> {
        match record.r#type {
            Type::Rsa => Ok(Self::Rsa(
                <rsa::RsaPublicKey as rsa::pkcs8::DecodePublicKey>::from_public_key_der(
                    &record.public_key,
                )
                .map_err(|e| ParseError::InvalidArgument {
                    reason: format!("invalid RSA public key: {}", e),
                })?,
            )),
            Type::Ed25519 => Ok(Self::Ed25519(
                ring_compat::signature::ed25519::VerifyingKey::new(&record.public_key).map_err(
                    |e| ParseError::InvalidArgument {
                        reason: format!("invalid Ed25519 public key: {}", e),
                    },
                )?,
            )),
        }
    }
}

impl InnerPublicKey {
    pub(super) fn verify(
        &self,
        hashed: &[u8],
        signature: &[u8],
        signing_algorithm: SigningAlgorithm,
    ) -> Result<(), InnerError> {
        match (self, signing_algorithm) {
            #[cfg(feature = "historic")]
            (InnerPublicKey::Rsa(rsa), SigningAlgorithm::RsaSha1) => rsa::PublicKey::verify(
                rsa,
                rsa::PaddingScheme::PKCS1v15Sign {
                    hash: Some(rsa::hash::Hash::SHA1),
                },
                hashed,
                signature,
            )
            .map_err(BackendError::Rsa),
            (InnerPublicKey::Rsa(rsa), SigningAlgorithm::RsaSha256) => rsa::PublicKey::verify(
                rsa,
                rsa::PaddingScheme::PKCS1v15Sign {
                    hash: Some(rsa::hash::Hash::SHA2_256),
                },
                hashed,
                signature,
            )
            .map_err(BackendError::Rsa),
            (InnerPublicKey::Ed25519(ed25519), SigningAlgorithm::Ed25519Sha256) => {
                match ring_compat::signature::ed25519::Signature::from_bytes(signature).map(
                    |signature| {
                        ring_compat::signature::Verifier::verify(ed25519, hashed, &signature)
                    },
                ) {
                    Ok(Ok(())) => Ok(()),
                    Err(e) | Ok(Err(e)) => Err(BackendError::Ed25519(e)),
                }
            }
            _ => return Err(InnerError::HashAlgorithmUnsupported { signing_algorithm }),
        }
        .map_err(InnerError::BackendError)
    }
}

/// The public key exposed by the Signing Domain Identifier, claiming the
/// responsibility for a [`crate::dkim::Signature`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub(super) record: Record,
    pub(super) inner: InnerPublicKey,
}

impl PublicKey {
    /// Does the signature contains the tag: `t=y`
    #[must_use]
    pub fn has_debug_flag(&self) -> bool {
        self.record.flags.iter().any(|f| *f == Flags::Testing)
    }
}

impl std::str::FromStr for PublicKey {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let record = s.parse::<Record>()?;

        Ok(Self {
            inner: InnerPublicKey::try_from(&record)?,
            record,
        })
    }
}

#[cfg(test)]
impl TryFrom<rsa::RsaPublicKey> for PublicKey {
    type Error = ();

    fn try_from(key: rsa::RsaPublicKey) -> Result<Self, Self::Error> {
        let inner = InnerPublicKey::Rsa(key);
        Ok(Self {
            record: Record::try_from(&inner)?,
            inner,
        })
    }
}

#[cfg(test)]
impl TryFrom<&ring_compat::ring::signature::Ed25519KeyPair> for PublicKey {
    type Error = ();

    fn try_from(key: &ring_compat::ring::signature::Ed25519KeyPair) -> Result<Self, Self::Error> {
        let key=  <ring_compat::ring::signature::Ed25519KeyPair as ring_compat::ring::signature::KeyPair>::public_key(key).as_ref();

        let key = ring_compat::signature::ed25519::VerifyingKey::new(key).map_err(|_| ())?;

        let inner = InnerPublicKey::Ed25519(key);
        Ok(Self {
            record: Record::try_from(&inner)?,
            inner,
        })
    }
}
