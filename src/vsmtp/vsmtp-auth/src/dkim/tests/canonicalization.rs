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
use crate::dkim::{canonicalization::CanonicalizationAlgorithm, HashAlgorithm};
use vsmtp_mail_parser::RawBody;

macro_rules! canonicalization_empty_body {
    ($name:ident, $canon:expr, $algo:expr, $expected:expr) => {
        #[test]
        fn $name() {
            assert_eq!(
                base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    $algo.hash($canon.canonicalize_body(""))
                ),
                $expected
            );
        }
    };
}

#[cfg(feature = "historic")]
canonicalization_empty_body!(
    simple_empty_body_rsa_sha1,
    CanonicalizationAlgorithm::Simple,
    HashAlgorithm::Sha1,
    "uoq1oCgLlTqpdDX/iUbLy7J1Wic="
);

canonicalization_empty_body!(
    simple_empty_body_rsa_sha256,
    CanonicalizationAlgorithm::Simple,
    HashAlgorithm::Sha256,
    "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY="
);

#[cfg(feature = "historic")]
canonicalization_empty_body!(
    relaxed_empty_body_rsa_sha1,
    CanonicalizationAlgorithm::Relaxed,
    HashAlgorithm::Sha1,
    "2jmj7l5rSw0yVb/vlWAYkK/YBwk="
);

canonicalization_empty_body!(
    relaxed_empty_body_rsa_sha256,
    CanonicalizationAlgorithm::Relaxed,
    HashAlgorithm::Sha256,
    "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
);

#[test]
fn canonicalize_ex1() {
    let msg = RawBody::new(
        vec![
            "A: X\r\n".to_string(),
            "B : Y\t\r\n".to_string(),
            "\tZ  \r\n".to_string(),
        ],
        concat!(" C \r\n", "D \t E\r\n", "\r\n", "\r\n").to_string(),
    );

    assert_eq!(
        msg.headers()
            .into_iter()
            .map(|(key, value)| CanonicalizationAlgorithm::Relaxed
                .canonicalize_header(&format!("{key}:{value}")))
            .fold(String::new(), |mut acc, s| {
                acc.push_str(&s);
                acc.push_str("\r\n");
                acc
            }),
        concat!("a:X\r\n", "b:Y Z\r\n")
    );

    assert_eq!(
        CanonicalizationAlgorithm::Relaxed.canonicalize_headers(
            &msg.headers()
                .iter()
                .map(|(key, value)| format!("{key}:{value}"))
                .collect::<Vec<_>>()
        ),
        concat!("a:X\r\n", "b:Y Z\r\n")
    );

    assert_eq!(
        CanonicalizationAlgorithm::Relaxed.canonicalize_body(msg.body().as_ref().unwrap()),
        concat!(" C\r\n", "D E\r\n")
    );
}

#[test]
fn canonicalize_ex2() {
    let msg = RawBody::new(
        vec![
            "A: X\r\n".to_string(),
            "B : Y\t\r\n".to_string(),
            "\tZ  \r\n".to_string(),
        ],
        concat!(" C \r\n", "D \t E\r\n", "\r\n", "\r\n").to_string(),
    );

    assert_eq!(
        msg.headers()
            .into_iter()
            .map(|(key, value)| CanonicalizationAlgorithm::Simple
                .canonicalize_header(&format!("{key}:{value}")))
            .fold(String::new(), |mut acc, s| {
                acc.push_str(&s);
                acc
            }),
        concat!("A: X\r\n", "B : Y\t\r\n", "\tZ  \r\n")
    );

    assert_eq!(
        CanonicalizationAlgorithm::Simple.canonicalize_headers(
            &msg.headers()
                .iter()
                .map(|(key, value)| format!("{key}:{value}"))
                .collect::<Vec<_>>()
        ),
        concat!("A: X\r\n", "B : Y\t\r\n", "\tZ  \r\n")
    );

    assert_eq!(
        CanonicalizationAlgorithm::Simple.canonicalize_body(msg.body().as_ref().unwrap()),
        concat!(" C \r\n", "D \t E\r\n").to_string()
    );
}

#[test]
fn canonicalize_trailing_newline() {
    let msg = RawBody::new(
        vec![
            "A: X\r\n".to_string(),
            "B : Y\t\r\n".to_string(),
            "\tZ  \r\n".to_string(),
        ],
        concat!(" C \r\n", "D \t E\r\n", "\r\n", "\r\nok").to_string(),
    );

    assert_eq!(
        CanonicalizationAlgorithm::Relaxed.canonicalize_body(msg.body().as_ref().unwrap()),
        concat!(" C\r\n", "D E\r\n\r\n\r\nok\r\n")
    );
}
