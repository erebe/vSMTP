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
    canonicalization::CanonicalizationAlgorithm, signature::QueryMethod, Canonicalization,
    Signature, SigningAlgorithm,
};

#[test]
fn from_str_wikipedia() {
    let signature = [
        "DKIM-Signature: v=1; a=rsa-sha256; d=example.net; s=brisbane;",
        "    c=relaxed/simple; q=dns/txt; i=foo@eng.example.net;",
        "    t=1117574938; x=1118006938; l=200;",
        "    h=from:to:subject:date:keywords:keywords;",
        "    z=From:foo@eng.example.net|To:joe@example.com|",
        "      Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700;",
        "    bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;",
        "    b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZ",
        "             VoG4ZHRNiYzR",
    ]
    .concat();

    let sign = <Signature as std::str::FromStr>::from_str(&signature).unwrap();
    pretty_assertions::assert_eq!(
        sign,
        Signature {
            version: 1,
            signing_algorithm: SigningAlgorithm::RsaSha256,
            sdid: "example.net".to_string(),
            selector: "brisbane".to_string(),
            canonicalization: Canonicalization::new(
                CanonicalizationAlgorithm::Relaxed,
                CanonicalizationAlgorithm::Simple,
            ),
            query_method: vec![QueryMethod::default()],
            auid: "foo@eng.example.net".to_string(),
            signature_timestamp: Some(std::time::Duration::from_secs(1_117_574_938)),
            expire_time: Some(std::time::Duration::from_secs(1_118_006_938)),
            body_length: Some(200),
            headers_field: ["from", "to", "subject", "date", "keywords", "keywords"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            copy_header_fields: Some(
                [
                    ("From", "foo@eng.example.net"),
                    ("To", "joe@example.com"),
                    ("Subject", "demo=20run"),
                    ("Date", "July=205,=202005=203:44:08=20PM=20-0700"),
                ]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
            ),
            body_hash: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=".to_string(),
            signature: "dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR"
                .to_string(),
            raw: signature.clone()
        }
    );

    pretty_assertions::assert_eq!(
        sign.get_signature_value(),
        signature["DKIM-Signature:".len()..]
    );

    assert!(sign.has_expired(100));
    assert!(!sign.has_expired(1_000_000_000));

    assert_eq!(sign.get_dns_query(), "brisbane._domainkey.example.net");
}

#[test]
fn rfc8463() {
    let signature = concat![
        "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;",
        "  d=football.example.com; i=@football.example.com;",
        "  q=dns/txt; s=brisbane; t=1528637909; h=from : to :",
        "  subject : date : message-id : from : subject : date;",
        "  bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;",
        "  b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus",
        "  Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==",
    ];

    let sign = <Signature as std::str::FromStr>::from_str(signature).unwrap();
    pretty_assertions::assert_eq!(
        sign,
        Signature {
            version: 1,
            signing_algorithm: SigningAlgorithm::Ed25519Sha256,
            sdid: "football.example.com".to_string(),
            selector: "brisbane".to_string(),
            canonicalization: Canonicalization::new(
                CanonicalizationAlgorithm::Relaxed,
                CanonicalizationAlgorithm::Relaxed,
            ),
            query_method: vec![QueryMethod::default()],
            auid: "@football.example.com".to_string(),
            signature_timestamp: Some(std::time::Duration::from_secs(1_528_637_909)),
            expire_time: None,
            body_length: None,
            headers_field: [
                "from",
                "to",
                "subject",
                "date",
                "message-id",
                "from",
                "subject",
                "date"
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            copy_header_fields: None,
            body_hash: "2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=".to_string(),
            signature: "/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11BusFa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw=="
                .to_string(),
            raw: signature.to_string()
        }
    );
}

mod error {
    use super::*;

    #[test]
    fn not_right_header() {
        let _err = <Signature as std::str::FromStr>::from_str("From: yes").unwrap_err();
    }

    #[test]
    fn not_tag_based_syntax() {
        let _err = <Signature as std::str::FromStr>::from_str("DKIM-Signature: yes").unwrap_err();
    }

    #[test]
    fn not_right_version() {
        let _err =
            <Signature as std::str::FromStr>::from_str("DKIM-Signature: v=foobar").unwrap_err();
    }

    #[test]
    fn not_right_sign_algo() {
        let _err =
            <Signature as std::str::FromStr>::from_str("DKIM-Signature: a=foobar").unwrap_err();
    }

    #[test]
    fn not_right_canonicalization() {
        let _err =
            <Signature as std::str::FromStr>::from_str("DKIM-Signature: c=foobar").unwrap_err();
    }

    #[test]
    fn not_right_query_method() {
        let _err =
            <Signature as std::str::FromStr>::from_str("DKIM-Signature: q=foobar").unwrap_err();
    }

    #[test]
    fn not_right_sign_timestamp() {
        let _err =
            <Signature as std::str::FromStr>::from_str("DKIM-Signature: t=foobar").unwrap_err();
    }

    #[test]
    fn not_right_expire_timestamp() {
        let _err =
            <Signature as std::str::FromStr>::from_str("DKIM-Signature: x=foobar").unwrap_err();
    }

    #[test]
    fn not_right_body_len() {
        let _err =
            <Signature as std::str::FromStr>::from_str("DKIM-Signature: l=foobar").unwrap_err();
    }

    #[test]
    fn not_right_header_copy() {
        let _err =
            <Signature as std::str::FromStr>::from_str("DKIM-Signature: z=From\\x").unwrap_err();
    }

    #[test]
    fn not_right_body_hash() {
        let _err =
            <Signature as std::str::FromStr>::from_str("DKIM-Signature: bh=foobar").unwrap_err();
    }

    #[test]
    fn not_right_signature_hash() {
        let _err =
            <Signature as std::str::FromStr>::from_str("DKIM-Signature: b=foobar").unwrap_err();
    }

    #[test]
    fn missing_version() {
        let _err = <Signature as std::str::FromStr>::from_str(
            "DKIM-Signature: d=example.net; a=rsa-sha256; s=toto; h=From; bh=b2theQ==; b=b2theQ==",
        )
        .unwrap_err();
    }

    #[test]
    fn missing_sdid() {
        let _err = <Signature as std::str::FromStr>::from_str(
            "DKIM-Signature: v=1; a=rsa-sha256; s=toto; h=From; bh=b2theQ==; b=b2theQ==",
        )
        .unwrap_err();
    }

    #[test]
    fn missing_sign_algo() {
        let _err = <Signature as std::str::FromStr>::from_str(
            "DKIM-Signature: v=1; d=example.net; s=toto; h=From; bh=b2theQ==; b=b2theQ==",
        )
        .unwrap_err();
    }

    #[test]
    fn missing_selector() {
        let _err = <Signature as std::str::FromStr>::from_str(
            "DKIM-Signature: v=1; d=example.net; a=rsa-sha256; h=From; bh=b2theQ==; b=b2theQ==",
        )
        .unwrap_err();
    }

    #[test]
    fn missing_headers() {
        let _err = <Signature as std::str::FromStr>::from_str(
            "DKIM-Signature: v=1; d=example.net; a=rsa-sha256; s=toto; bh=b2theQ==; b=b2theQ==",
        )
        .unwrap_err();
    }

    #[test]
    fn missing_body_hash() {
        let _err = <Signature as std::str::FromStr>::from_str(
            "DKIM-Signature: v=1; d=example.net; a=rsa-sha256; s=toto;  h=From; b=b2theQ==",
        )
        .unwrap_err();
    }

    #[test]
    fn missing_signature() {
        let _err = <Signature as std::str::FromStr>::from_str(
            "DKIM-Signature: v=1; d=example.net; a=rsa-sha256; s=toto;  h=From; bh=b2theQ==",
        )
        .unwrap_err();
    }

    #[test]
    fn invalid_auid() {
        let _err = <Signature as std::str::FromStr>::from_str(
            "DKIM-Signature: v=1; i=user@example.com; d=example.net; a=rsa-sha256; s=toto; h=From; bh=b2theQ==; b=b2theQ==").unwrap_err();
    }

    #[test]
    fn invalid_header_empty() {
        let _err = <Signature as std::str::FromStr>::from_str(
            "DKIM-Signature: v=1; d=example.net; a=rsa-sha256; s=toto; h=; bh=b2theQ==; b=b2theQ==",
        )
        .unwrap_err();
    }

    #[test]
    fn forbidden_header() {
        let _err = <Signature as std::str::FromStr>::from_str(
            "DKIM-Signature: v=1; d=example.net; a=rsa-sha256; s=toto; h=; h=From:Dkim-Signature; bh=b2theQ==; b=b2theQ==",
        )
        .unwrap_err();
    }
}

// FIXME: okay ?
#[test]
fn not_right_version_v2() {
    let _sign = <Signature as std::str::FromStr>::from_str(
        "DKIM-Signature: v=2; d=example.net; a=rsa-sha256; s=toto; h=From; bh=b2theQ==; b=b2theQ==",
    )
    .unwrap();
}
