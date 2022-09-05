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
use vsmtp_mail_parser::RawBody;

/// Possible error produced by [`crate::dkim::Signature::verify`]
#[must_use]
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
        VerifierError::BodyHashMismatch
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
        tracing::debug!("headers_hash={}", base64::encode(&headers_hash));

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
                    #[cfg(feature = "historic")]
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

#[cfg(test)]
mod tests {

    use crate::dkim::{
        public_key::Type, Canonicalization, CanonicalizationAlgorithm, PublicKey, Signature,
        SigningAlgorithm,
    };
    use vsmtp_mail_parser::MessageBody;

    #[test]
    fn sign_and_verify() {
        let mut rng = rand::thread_rng();

        let private_key = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let public_key = rsa::RsaPublicKey::from(&private_key);

        let mut message = MessageBody::try_from(concat!(
            "From: toto@com\r\n",
            "To: tata@com\r\n",
            "Subject: test\r\n",
            "Date: Mon, 1 Jan 2020 00:00:00 +0000\r\n",
            "\r\n",
            "test\r\n",
        ))
        .unwrap();

        let signature = Signature::new(
            message.inner(),
            &private_key,
            SigningAlgorithm::RsaSha256,
            "localhost".to_string(),
            "foobar".to_string(),
            Canonicalization {
                header: CanonicalizationAlgorithm::Relaxed,
                body: CanonicalizationAlgorithm::Relaxed,
            },
            vec![
                "From".to_string(),
                "To".to_string(),
                "Subject".to_string(),
                "Date".to_string(),
                "From".to_string(),
            ],
        )
        .unwrap();

        message.prepend_header("DKIM-Signature", &signature.raw["DKIM-Signature: ".len()..]);

        let key = PublicKey::new(
            Type::Rsa,
            rsa::pkcs8::EncodePublicKey::to_public_key_der(&public_key)
                .unwrap()
                .as_ref()
                .to_vec(),
            rsa::PublicKeyParts::size(&public_key),
            vec![],
        )
        .unwrap();

        signature.verify(message.inner(), &key).unwrap();
    }

    mod error {
        use super::*;

        #[test]
        #[cfg(feature = "historic")]
        fn incompatible_key() {
            use crate::dkim::HashAlgorithm;

            let mut rng = rand::thread_rng();

            let private_key = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();
            let public_key = rsa::RsaPublicKey::from(&private_key);

            let mut message = MessageBody::try_from(concat!(
                "From: toto@com\r\n",
                "To: tata@com\r\n",
                "Subject: test\r\n",
                "Date: Mon, 1 Jan 2020 00:00:00 +0000\r\n",
                "\r\n",
                "test\r\n",
            ))
            .unwrap();

            let signature = Signature::new(
                message.inner(),
                &private_key,
                SigningAlgorithm::RsaSha256,
                "localhost".to_string(),
                "foobar".to_string(),
                Canonicalization {
                    header: CanonicalizationAlgorithm::Relaxed,
                    body: CanonicalizationAlgorithm::Relaxed,
                },
                vec![
                    "From".to_string(),
                    "To".to_string(),
                    "Subject".to_string(),
                    "Date".to_string(),
                    "From".to_string(),
                ],
            )
            .unwrap();

            message.prepend_header("DKIM-Signature", &signature.raw["DKIM-Signature: ".len()..]);

            let mut key = PublicKey::new(
                Type::Rsa,
                rsa::pkcs8::EncodePublicKey::to_public_key_der(&public_key)
                    .unwrap()
                    .as_ref()
                    .to_vec(),
                rsa::PublicKeyParts::size(&public_key),
                vec![],
            )
            .unwrap();
            key.acceptable_hash_algorithms = vec![HashAlgorithm::Sha1];

            let err = signature.verify(message.inner(), &key).unwrap_err();
            println!("{err}");
        }

        #[test]
        fn empty_key() {
            let mut rng = rand::thread_rng();

            let private_key = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();

            let mut message = MessageBody::try_from(concat!(
                "From: toto@com\r\n",
                "To: tata@com\r\n",
                "Subject: test\r\n",
                "Date: Mon, 1 Jan 2020 00:00:00 +0000\r\n",
                "\r\n",
                "test\r\n",
            ))
            .unwrap();

            let signature = Signature::new(
                message.inner(),
                &private_key,
                SigningAlgorithm::RsaSha256,
                "localhost".to_string(),
                "foobar".to_string(),
                Canonicalization {
                    header: CanonicalizationAlgorithm::Relaxed,
                    body: CanonicalizationAlgorithm::Relaxed,
                },
                vec![
                    "From".to_string(),
                    "To".to_string(),
                    "Subject".to_string(),
                    "Date".to_string(),
                    "From".to_string(),
                ],
            )
            .unwrap();

            message.prepend_header("DKIM-Signature", &signature.raw["DKIM-Signature: ".len()..]);

            let _key = PublicKey::new(Type::Rsa, vec![], 0, vec![]).unwrap_err();
        }

        #[test]
        fn body_mismatch() {
            let mut rng = rand::thread_rng();

            let private_key = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();
            let public_key = rsa::RsaPublicKey::from(&private_key);

            let mut message = MessageBody::try_from(concat!(
                "From: toto@com\r\n",
                "To: tata@com\r\n",
                "Subject: test\r\n",
                "Date: Mon, 1 Jan 2020 00:00:00 +0000\r\n",
                "\r\n",
                "test\r\n",
            ))
            .unwrap();

            let mut signature = Signature::new(
                message.inner(),
                &private_key,
                SigningAlgorithm::RsaSha256,
                "localhost".to_string(),
                "foobar".to_string(),
                Canonicalization {
                    header: CanonicalizationAlgorithm::Relaxed,
                    body: CanonicalizationAlgorithm::Relaxed,
                },
                vec![
                    "From".to_string(),
                    "To".to_string(),
                    "Subject".to_string(),
                    "Date".to_string(),
                    "From".to_string(),
                ],
            )
            .unwrap();

            signature.body_hash = base64::encode("foobar");

            message.prepend_header("DKIM-Signature", &signature.raw["DKIM-Signature: ".len()..]);

            let key = PublicKey::new(
                Type::Rsa,
                rsa::pkcs8::EncodePublicKey::to_public_key_der(&public_key)
                    .unwrap()
                    .as_ref()
                    .to_vec(),
                rsa::PublicKeyParts::size(&public_key),
                vec![],
            )
            .unwrap();

            let err = signature.verify(message.inner(), &key).unwrap_err();
            println!("{err}");
        }

        #[test]
        fn signature_mismatch() {
            let mut rng = rand::thread_rng();

            let private_key = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();
            let public_key = rsa::RsaPublicKey::from(&private_key);

            let mut message = MessageBody::try_from(concat!(
                "From: toto@com\r\n",
                "To: tata@com\r\n",
                "Subject: test\r\n",
                "Date: Mon, 1 Jan 2020 00:00:00 +0000\r\n",
                "\r\n",
                "test\r\n",
            ))
            .unwrap();

            let signature = Signature::new(
                message.inner(),
                &private_key,
                SigningAlgorithm::RsaSha256,
                "localhost".to_string(),
                "foobar".to_string(),
                Canonicalization {
                    header: CanonicalizationAlgorithm::Relaxed,
                    body: CanonicalizationAlgorithm::Relaxed,
                },
                vec![
                    "From".to_string(),
                    "To".to_string(),
                    "Subject".to_string(),
                    "Date".to_string(),
                    "From".to_string(),
                ],
            )
            .unwrap();

            message.prepend_header("DKIM-Signature", &signature.raw["DKIM-Signature: ".len()..]);

            message.set_header(
                "From",
                "this header changed, so the dkim signature is invalid",
            );

            let key = PublicKey::new(
                Type::Rsa,
                rsa::pkcs8::EncodePublicKey::to_public_key_der(&public_key)
                    .unwrap()
                    .as_ref()
                    .to_vec(),
                rsa::PublicKeyParts::size(&public_key),
                vec![],
            )
            .unwrap();

            let err = signature.verify(message.inner(), &key).unwrap_err();
            println!("{err}");
        }
    }
}
