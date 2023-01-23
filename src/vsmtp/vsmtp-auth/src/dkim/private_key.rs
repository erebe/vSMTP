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

use super::{sign::InnerError, BackendError, SigningAlgorithm, RSA_MINIMUM_ACCEPTABLE_KEY_SIZE};

///
pub enum PrivateKey {
    ///
    Rsa(Box<rsa::RsaPrivateKey>),
    ///
    Ed25519(Box<ring_compat::ring::signature::Ed25519KeyPair>),
}

impl PrivateKey {
    pub(super) const fn get_preferred_signing_algo(&self) -> SigningAlgorithm {
        match self {
            PrivateKey::Rsa(_) => SigningAlgorithm::RsaSha256,
            PrivateKey::Ed25519(_) => SigningAlgorithm::Ed25519Sha256,
        }
    }

    pub(super) fn sign(
        &self,
        signing_algorithm: SigningAlgorithm,
        digest_in: &[u8],
    ) -> Result<Vec<u8>, InnerError> {
        match self {
            PrivateKey::Rsa(rsa) => {
                let size = rsa::PublicKeyParts::size(rsa.as_ref()) * 8;
                if size < RSA_MINIMUM_ACCEPTABLE_KEY_SIZE {
                    return Err(InnerError::InvalidSize(size));
                }
                match signing_algorithm {
                    SigningAlgorithm::Ed25519Sha256 => {
                        Err(InnerError::HashAlgorithmUnsupported { signing_algorithm })
                    }
                    #[cfg(feature = "historic")]
                    SigningAlgorithm::RsaSha1 => rsa
                        .sign(rsa::Pkcs1v15Sign::new::<sha1::Sha1>(), digest_in)
                        .map_err(|e| InnerError::BackendError(BackendError::Rsa(e))),
                    SigningAlgorithm::RsaSha256 => rsa
                        .sign(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), digest_in)
                        .map_err(|e| InnerError::BackendError(BackendError::Rsa(e))),
                }
            }
            PrivateKey::Ed25519(ed25519) => match signing_algorithm {
                #[cfg(feature = "historic")]
                SigningAlgorithm::RsaSha1 => {
                    Err(InnerError::HashAlgorithmUnsupported { signing_algorithm })
                }
                SigningAlgorithm::RsaSha256 => {
                    Err(InnerError::HashAlgorithmUnsupported { signing_algorithm })
                }
                SigningAlgorithm::Ed25519Sha256 => Ok(ed25519.sign(digest_in).as_ref().to_vec()),
            },
        }
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rsa(_) => f.debug_struct("Rsa").finish_non_exhaustive(),
            Self::Ed25519(_) => f.debug_struct("Ed25519").finish_non_exhaustive(),
        }
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (PrivateKey::Rsa(a), PrivateKey::Rsa(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for PrivateKey {}
