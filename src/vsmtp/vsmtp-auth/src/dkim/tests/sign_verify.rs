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
use crate::dkim::{
    canonicalization::CanonicalizationAlgorithm, private_key::PrivateKey, sign, verify,
    Canonicalization, PublicKey,
};
use vsmtp_test::config::local_msg;

#[test]
fn rsa_sha256() {
    let mut rng = rand::thread_rng();

    let private_key = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();
    let public_key = rsa::RsaPublicKey::from(&private_key);
    let public_key = PublicKey::try_from(public_key).unwrap();

    let mut message = local_msg();

    let signature = sign(
        message.inner(),
        &PrivateKey::Rsa(Box::new(private_key)),
        "localhost".to_string(),
        "foobar".to_string(),
        Canonicalization::new(
            CanonicalizationAlgorithm::Relaxed,
            CanonicalizationAlgorithm::Relaxed,
        ),
        vec![
            "From".to_string(),
            "To".to_string(),
            "Subject".to_string(),
            "Date".to_string(),
            "From".to_string(),
        ],
        None,
    )
    .unwrap();

    message.prepend_header("DKIM-Signature", &signature.raw["DKIM-Signature: ".len()..]);

    verify(&signature, message.inner(), &public_key).unwrap();
}

#[test]
#[cfg(feature = "historic")]
fn rsa_sha1() {
    use crate::dkim::HashAlgorithm;

    let mut rng = rand::thread_rng();

    let private_key = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();
    let public_key = rsa::RsaPublicKey::from(&private_key);

    let mut message = local_msg();

    let signature = sign(
        message.inner(),
        &PrivateKey::Rsa(Box::new(private_key)),
        "localhost".to_string(),
        "foobar".to_string(),
        Canonicalization::new(
            CanonicalizationAlgorithm::Relaxed,
            CanonicalizationAlgorithm::Relaxed,
        ),
        vec![
            "From".to_string(),
            "To".to_string(),
            "Subject".to_string(),
            "Date".to_string(),
            "From".to_string(),
        ],
        Some(crate::dkim::SigningAlgorithm::RsaSha1),
    )
    .unwrap();

    message.prepend_header("DKIM-Signature", &signature.raw["DKIM-Signature: ".len()..]);

    let mut public_key = PublicKey::try_from(public_key).unwrap();
    public_key.record.acceptable_hash_algorithms = vec![HashAlgorithm::Sha1];

    verify(&signature, message.inner(), &public_key).unwrap()
}

#[test]
fn ed25519_sha256() {
    let mut ed25519_seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut ed25519_seed);

    let signing_key =
        ring_compat::ring::signature::Ed25519KeyPair::from_seed_unchecked(&ed25519_seed).unwrap();

    let public_key = PublicKey::try_from(&signing_key).unwrap();

    let mut message = local_msg();

    let signature = sign(
        message.inner(),
        &PrivateKey::Ed25519(Box::new(signing_key)),
        "localhost".to_string(),
        "foobar".to_string(),
        Canonicalization::new(
            CanonicalizationAlgorithm::Relaxed,
            CanonicalizationAlgorithm::Relaxed,
        ),
        vec![
            "From".to_string(),
            "To".to_string(),
            "Subject".to_string(),
            "Date".to_string(),
            "From".to_string(),
        ],
        None,
    )
    .unwrap();

    message.prepend_header("DKIM-Signature", &signature.raw["DKIM-Signature: ".len()..]);

    verify(&signature, message.inner(), &public_key).unwrap();
}

mod error {
    use super::*;

    #[test]
    fn forbidden_header() {
        let mut rng = rand::thread_rng();

        let private_key = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let public_key = rsa::RsaPublicKey::from(&private_key);
        let public_key = PublicKey::try_from(public_key).unwrap();

        let mut message = local_msg();

        let signature = sign(
            message.inner(),
            &PrivateKey::Rsa(Box::new(private_key)),
            "localhost".to_string(),
            "foobar".to_string(),
            Canonicalization::new(
                CanonicalizationAlgorithm::Relaxed,
                CanonicalizationAlgorithm::Relaxed,
            ),
            vec![
                "DKIM-Signature".to_string(),
                "From".to_string(),
                "To".to_string(),
                "Subject".to_string(),
                "Date".to_string(),
                "From".to_string(),
            ],
            None,
        )
        .unwrap();

        message.prepend_header("DKIM-Signature", &signature.raw["DKIM-Signature: ".len()..]);

        let _err = verify(&signature, message.inner(), &public_key).unwrap_err();
    }

    #[test]
    #[cfg(feature = "historic")]
    fn incompatible_algo() {
        use crate::dkim::HashAlgorithm;

        let mut rng = rand::thread_rng();

        let private_key = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let public_key = rsa::RsaPublicKey::from(&private_key);

        let mut message = local_msg();

        let signature = sign(
            message.inner(),
            &PrivateKey::Rsa(Box::new(private_key)),
            "localhost".to_string(),
            "foobar".to_string(),
            Canonicalization::new(
                CanonicalizationAlgorithm::Relaxed,
                CanonicalizationAlgorithm::Relaxed,
            ),
            vec![
                "From".to_string(),
                "To".to_string(),
                "Subject".to_string(),
                "Date".to_string(),
                "From".to_string(),
            ],
            Some(crate::dkim::SigningAlgorithm::RsaSha1),
        )
        .unwrap();

        message.prepend_header("DKIM-Signature", &signature.raw["DKIM-Signature: ".len()..]);

        let mut public_key = PublicKey::try_from(public_key).unwrap();
        public_key.record.acceptable_hash_algorithms = vec![HashAlgorithm::Sha256];

        let _err = verify(&signature, message.inner(), &public_key).unwrap_err();
    }

    #[test]
    fn too_small() {
        let mut rng = rand::thread_rng();

        let private_key = rsa::RsaPrivateKey::new(&mut rng, 512).unwrap();

        let message = local_msg();

        let _err = sign(
            message.inner(),
            &PrivateKey::Rsa(Box::new(private_key)),
            "localhost".to_string(),
            "foobar".to_string(),
            Canonicalization::new(
                CanonicalizationAlgorithm::Relaxed,
                CanonicalizationAlgorithm::Relaxed,
            ),
            vec![
                "From".to_string(),
                "To".to_string(),
                "Subject".to_string(),
                "Date".to_string(),
                "From".to_string(),
            ],
            None,
        )
        .unwrap_err();
    }

    #[test]
    fn too_small_2() {
        let mut rng = rand::thread_rng();

        let private_key = rsa::RsaPrivateKey::new(&mut rng, 512).unwrap();
        let public_key = rsa::RsaPublicKey::from(&private_key);
        PublicKey::try_from(public_key).unwrap_err();
    }

    #[test]
    fn body_mismatch() {
        let mut rng = rand::thread_rng();

        let private_key = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let public_key = rsa::RsaPublicKey::from(&private_key);

        let mut message = local_msg();

        let mut signature = sign(
            message.inner(),
            &PrivateKey::Rsa(Box::new(private_key)),
            "localhost".to_string(),
            "foobar".to_string(),
            Canonicalization::new(
                CanonicalizationAlgorithm::Relaxed,
                CanonicalizationAlgorithm::Relaxed,
            ),
            vec![
                "From".to_string(),
                "To".to_string(),
                "Subject".to_string(),
                "Date".to_string(),
                "From".to_string(),
            ],
            None,
        )
        .unwrap();

        signature.body_hash = base64::encode("foobar");

        message.prepend_header("DKIM-Signature", &signature.raw["DKIM-Signature: ".len()..]);

        let public_key = PublicKey::try_from(public_key).unwrap();

        let err = verify(&signature, message.inner(), &public_key).unwrap_err();
        println!("{err}");
    }

    #[test]
    fn signature_mismatch() {
        let mut rng = rand::thread_rng();

        let private_key = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let public_key = rsa::RsaPublicKey::from(&private_key);

        let mut message = local_msg();

        let signature = sign(
            message.inner(),
            &PrivateKey::Rsa(Box::new(private_key)),
            "localhost".to_string(),
            "foobar".to_string(),
            Canonicalization::new(
                CanonicalizationAlgorithm::Relaxed,
                CanonicalizationAlgorithm::Relaxed,
            ),
            vec![
                "From".to_string(),
                "To".to_string(),
                "Subject".to_string(),
                "Date".to_string(),
                "From".to_string(),
            ],
            None,
        )
        .unwrap();

        message.prepend_header("DKIM-Signature", &signature.raw["DKIM-Signature: ".len()..]);

        message.set_header(
            "From",
            "this header changed, so the dkim signature is invalid",
        );

        let public_key = PublicKey::try_from(public_key).unwrap();

        let err = verify(&signature, message.inner(), &public_key).unwrap_err();
        println!("{err}");
    }
}
