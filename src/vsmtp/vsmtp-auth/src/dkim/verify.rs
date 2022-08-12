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

use super::{HashAlgorithm, PublicKey, Signature, SigningAlgorithm};
use vsmtp_common::{re::log, RawBody};

/// Possible error produced by [`Signature::verify`]
#[derive(Debug, thiserror::Error)]
pub enum VerifierError {
    /// The algorithm used in the signature is not supported by the public key
    #[error(
        "the `signing_algorithm` ({singing_algorithm}) is not suitable for the `acceptable_hash_algorithms` ({})",
        acceptable
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )]
    AlgorithmMismatch {
        /// The algorithm of the `DKIM-Signature` header
        singing_algorithm: SigningAlgorithm,
        /// The algorithms of the public key
        acceptable: Vec<HashAlgorithm>,
    },
    /// The key is empty
    #[error("the key has been revoked, or is empty")]
    KeyMissingOrRevoked,
    /// The public key is invalid
    #[error("the key format could not be recognized: `{e_pkcs1}` and `{e_pkcs8}`")]
    KeyFormatInvalid {
        /// Error produced when trying to convert to format `PKCS1`
        e_pkcs1: rsa::pkcs1::Error,
        /// Error produced when trying to convert to format `PKCS8`
        e_pkcs8: rsa::pkcs8::spki::Error,
    },
    /// The hash produced of the body does not match the hash in the signature
    #[error("body hash does not match")]
    BodyHashMismatch,
    /// The hash produced of the headers does not match the hash in the signature
    #[error("headers hash does not match, got `{error}`")]
    HeaderHashMismatch {
        /// The error produced by the hash function
        error: rsa::errors::Error,
    },
    /// Not a valid base64 format in the `DKIM-Signature` header
    #[error("base64 error: {error}")]
    Base64Error {
        /// Error produced by `base64::`
        error: base64::DecodeError,
    },
}

impl Default for VerifierError {
    fn default() -> Self {
        VerifierError::KeyMissingOrRevoked
    }
}

impl Signature {
    /// Verify a signature
    ///
    /// # Errors
    ///
    /// * see [`VerifierError`]
    pub fn verify(&self, message: &RawBody, key: &PublicKey) -> Result<(), VerifierError> {
        if !self
            .signing_algorithm
            .is_supported(&key.acceptable_hash_algorithms)
        {
            return Err(VerifierError::AlgorithmMismatch {
                singing_algorithm: self.signing_algorithm,
                acceptable: key.acceptable_hash_algorithms.clone(),
            });
        }

        if key.public_key.is_empty() {
            return Err(VerifierError::KeyMissingOrRevoked);
        }

        let body = self.canonicalization.body.canonicalize_body(
            &message
                .body()
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
        );

        let body_hash = self.signing_algorithm.hash(match self.body_length {
            // TODO: handle policy
            Some(len) => &body[..std::cmp::min(body.len(), len)],
            None => &body,
        });

        if self.body_hash != base64::encode(body_hash) {
            return Err(VerifierError::BodyHashMismatch);
        }

        let headers_hash = self.get_header_hash(message);
        log::debug!("headers_hash={}", base64::encode(&headers_hash));

        // the type of public_key is not precised in the DNS record,
        // so we try each format..

        let key = match <rsa::RsaPublicKey as rsa::pkcs1::DecodeRsaPublicKey>::from_pkcs1_der(
            &key.public_key,
        )
        .map(Box::new)
        {
            Ok(key) => key,
            Err(e_pkcs1) => {
                match <rsa::RsaPublicKey as rsa::pkcs8::DecodePublicKey>::from_public_key_der(
                    &key.public_key,
                )
                .map(Box::new)
                {
                    Ok(key) => key,
                    Err(e_pkcs8) => {
                        return Err(VerifierError::KeyFormatInvalid { e_pkcs1, e_pkcs8 });
                    }
                }
            }
        };
        rsa::PublicKey::verify(
            key.as_ref(),
            rsa::PaddingScheme::PKCS1v15Sign {
                hash: Some(match self.signing_algorithm {
                    SigningAlgorithm::RsaSha1 => rsa::hash::Hash::SHA1,
                    SigningAlgorithm::RsaSha256 => rsa::hash::Hash::SHA2_256,
                }),
            },
            &headers_hash,
            &base64::decode(&self.signature)
                .map_err(|e| VerifierError::Base64Error { error: e })?,
        )
        .map_err(|e| VerifierError::HeaderHashMismatch { error: e })
    }
}
