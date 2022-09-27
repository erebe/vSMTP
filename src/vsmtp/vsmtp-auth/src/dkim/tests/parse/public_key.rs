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
    record::{Flags, Record, ServiceType, Type, Version},
    HashAlgorithm, PublicKey,
};

const TXT: &str = "v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvxxZDZBe61KUSY/nQ09l9P9n4rmeb2Ol/Z2j7g33viWEfTCro0+Nyicz/vjTQZv+cq5Wla+ADyXkdSGJ0OFp9SrUu9tGeDhil2UEPsHHdnf3AaarX3hyY8Ne5X5EOnJ5WY3QSpTL+eVUtSTt5DbsDqfShzxbc/BsKb5sfHuGJxcKuCyFVqCyhpSKT4kdpzZ5FLLrEiyvJGYUfq7qvqPB+A/wx1TIO5YONWWH2mqy3zviLx70u06wnxwyvGve2HMKeMvDm1HGibZShJnOIRzJuZ9BFYffm8iGisYFocxp7daiJgbpMtqYY/TB8ZvGajv/ZqITrbRp+qpfK9Bpdk8qXwIDAQAB";

const RAW: &str = concat!(
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvxxZDZBe61KUSY/nQ09l9P9n4rmeb2Ol/Z2",
    "j7g33viWEfTCro0+Nyicz/vjTQZv+cq5Wla+ADyXkdSGJ0OFp9SrUu9tGeDhil2UEPsHHdnf3AaarX3",
    "hyY8Ne5X5EOnJ5WY3QSpTL+eVUtSTt5DbsDqfShzxbc/BsKb5sfHuGJxcKuCyFVqCyhpSKT4kdpzZ5F",
    "LLrEiyvJGYUfq7qvqPB+A/wx1TIO5YONWWH2mqy3zviLx70u06wnxwyvGve2HMKeMvDm1HGibZShJnO",
    "IRzJuZ9BFYffm8iGisYFocxp7daiJgbpMtqYY/TB8ZvGajv/ZqITrbRp+qpfK9Bpdk8qXwIDAQAB"
);

#[test]
fn rsa_record() {
    let key = <PublicKey as std::str::FromStr>::from_str(TXT).unwrap();
    assert_eq!(
        key.record,
        Record {
            version: Version::Dkim1,
            acceptable_hash_algorithms: vec![HashAlgorithm::Sha256],
            r#type: Type::Rsa,
            notes: None,
            public_key: base64::decode(RAW).unwrap(),
            service_type: vec![ServiceType::Wildcard],
            flags: vec![],
        }
    );
    pretty_assertions::assert_eq!(
        format!("{key:#?}"),
        concat!(
            "PublicKey {\n",
            "    record: Record {\n",
            "        version: Dkim1,\n",
            "        acceptable_hash_algorithms: [\n",
            "            Sha256,\n",
            "        ],\n",
            "        type: Rsa,\n",
            "        notes: None,\n",
            "        public_key: \"",
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvxxZDZBe61KUSY/nQ09l9P9n4rmeb2Ol/Z2",
            "j7g33viWEfTCro0+Nyicz/vjTQZv+cq5Wla+ADyXkdSGJ0OFp9SrUu9tGeDhil2UEPsHHdnf3AaarX3",
            "hyY8Ne5X5EOnJ5WY3QSpTL+eVUtSTt5DbsDqfShzxbc/BsKb5sfHuGJxcKuCyFVqCyhpSKT4kdpzZ5F",
            "LLrEiyvJGYUfq7qvqPB+A/wx1TIO5YONWWH2mqy3zviLx70u06wnxwyvGve2HMKeMvDm1HGibZShJnO",
            "IRzJuZ9BFYffm8iGisYFocxp7daiJgbpMtqYY/TB8ZvGajv/ZqITrbRp+qpfK9Bpdk8qXwIDAQAB",
            "\",\n",
            "        service_type: [\n",
            "            Wildcard,\n",
            "        ],\n",
            "        flags: [],\n",
            "    },\n",
            "    inner: Rsa { .. },\n",
            "}",
        )
    );
}

#[test]
fn rsa_record_service_email() {
    assert_eq!(
        <PublicKey as std::str::FromStr>::from_str(&format!("{TXT}; s=email"))
            .unwrap()
            .record,
        Record {
            version: Version::Dkim1,
            acceptable_hash_algorithms: vec![HashAlgorithm::Sha256],
            r#type: Type::Rsa,
            notes: None,
            public_key: base64::decode(RAW).unwrap(),
            service_type: vec![ServiceType::Email],
            flags: vec![],
        }
    );
}

#[test]
fn rsa_record_flags_testing() {
    let key = <PublicKey as std::str::FromStr>::from_str(&format!("{TXT}; t=y")).unwrap();
    assert_eq!(
        key.record,
        Record {
            version: Version::Dkim1,
            acceptable_hash_algorithms: vec![HashAlgorithm::Sha256],
            r#type: Type::Rsa,
            notes: None,
            public_key: base64::decode(RAW).unwrap(),
            service_type: vec![ServiceType::Wildcard],
            flags: vec![Flags::Testing],
        }
    );
    assert!(key.has_debug_flag());
}

#[test]
fn rsa_record_2() {
    const TXT_2: &str = "v=DKIM1;h=sha256;k=rsa;p=MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAy/Xyk/Kvboflr/9jgiF/9cgxPk7JluoGRFZd4+UGDRcVn6qp8HzdBS1CTfgzznE9DBD3SosJOo/XawEbZvBw1xCwe/DCnhoxznqOmXeHBgmVIpR2BBGdr5QT7ByfkSJUwlzHiRCjjx2++y+EAEsk5Wo6xRtrJLm19SCc2q4CCBTMx6rSSP9PGTZdtgOxIAdW/58pJrEH3OtBEEXO/e42JR81bwKGJYjL+5oCLjnEJjz/nyMwJRiQQLsCQqUnpoZqoLs5J43N+6mJZhG+8DoitXU7zW4a7GGOzYqF45zkuQbCv6h3eaA+s1+SjcaUzCq45zCgOjONSlWec2kA6ciuDaRx0QvipCIou3fovP0x/Md/L3YbVJUk7cpxjCTrY63CzTLZycbz1DX3rqY5Dq0g1CmpUPDRZjCm7Q8KD1B9t4w5md7vXlKWCR6ojoujiRbR6kxxverOZWdTtMOiH2G4eB8AAWP6sTgBhgNgiLjWjakkQvGGbfNnRdeCV7ygZwBnYhS43k7tPNtbGB0LTE9FaNzYKW7NfjCDiS7z3JJZzsi3vhf5lkjYFwKbWpa4NeKmtu/6mWclSTeLL7GlmywPMOUYOPLmGFCAiDfuG1Qcjm7ocsQsGs9Rd3/kDo5rREL5USpNzW8bd7DBsUzMk6iY4VMVZG4up1rZ6dZ0Qpt1m9MCAwEAAQ==;t=s;";

    const RAW_2: &str = concat!(
        "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAy/Xyk/Kvboflr/9jgiF/9cgxPk7JluoGRFZ",
        "d4+UGDRcVn6qp8HzdBS1CTfgzznE9DBD3SosJOo/XawEbZvBw1xCwe/DCnhoxznqOmXeHBgmVIpR2BBG",
        "dr5QT7ByfkSJUwlzHiRCjjx2++y+EAEsk5Wo6xRtrJLm19SCc2q4CCBTMx6rSSP9PGTZdtgOxIAdW/58",
        "pJrEH3OtBEEXO/e42JR81bwKGJYjL+5oCLjnEJjz/nyMwJRiQQLsCQqUnpoZqoLs5J43N+6mJZhG+8Do",
        "itXU7zW4a7GGOzYqF45zkuQbCv6h3eaA+s1+SjcaUzCq45zCgOjONSlWec2kA6ciuDaRx0QvipCIou3f",
        "ovP0x/Md/L3YbVJUk7cpxjCTrY63CzTLZycbz1DX3rqY5Dq0g1CmpUPDRZjCm7Q8KD1B9t4w5md7vXlK",
        "WCR6ojoujiRbR6kxxverOZWdTtMOiH2G4eB8AAWP6sTgBhgNgiLjWjakkQvGGbfNnRdeCV7ygZwBnYhS",
        "43k7tPNtbGB0LTE9FaNzYKW7NfjCDiS7z3JJZzsi3vhf5lkjYFwKbWpa4NeKmtu/6mWclSTeLL7Glmyw",
        "PMOUYOPLmGFCAiDfuG1Qcjm7ocsQsGs9Rd3/kDo5rREL5USpNzW8bd7DBsUzMk6iY4VMVZG4up1rZ6dZ",
        "0Qpt1m9MCAwEAAQ=="
    );
    assert_eq!(
        <PublicKey as std::str::FromStr>::from_str(TXT_2)
            .unwrap()
            .record,
        Record {
            version: Version::Dkim1,
            acceptable_hash_algorithms: vec![HashAlgorithm::Sha256],
            r#type: Type::Rsa,
            notes: None,
            public_key: base64::decode(RAW_2).unwrap(),
            service_type: vec![ServiceType::Wildcard],
            flags: vec![Flags::SameDomain],
        }
    );
}

#[test]
fn ed25519_record() {
    const TXT_3: &str = "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
    assert_eq!(
        <PublicKey as std::str::FromStr>::from_str(TXT_3)
            .unwrap()
            .record,
        Record {
            version: Version::Dkim1,
            acceptable_hash_algorithms: vec![HashAlgorithm::Sha256],
            r#type: Type::Ed25519,
            notes: None,
            public_key: base64::decode(concat!("11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="))
                .unwrap(),
            service_type: vec![ServiceType::Wildcard],
            flags: vec![],
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

    #[test]
    fn invalid_rsa() {
        let _err = <PublicKey as std::str::FromStr>::from_str("v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvxxZDZBe61KUSY/nQ09l9P9n4rmeb2Ol/Z2j7g33viWEfTCro0+Nyicz/vjTQZv+cq5Wla+ADyXkdSGJ0OFp9SrUu9tGeDhil2UEPsHHdnf3AaarX3hyY8Ne5X5EOnJ5WY3QSpTL+eVUtSTt5DbsDqfShzxbc/BsKb5sfHuGJxcKuCyFVqCyhpSKT4kdpzZ5FLLrEiyvJGYUfq7qvqPB+A/wx1TIO5YONWWH2mqy3zviLx70u06wnxwyvGve2HMKeMvDm1HGibZShJnOIRzJuZ9BFYffm8iGisYFocxp7daiJgbpMtqYY/TB8ZvGajv/ZqITrbRp+qpfK9Bpdk8qXwIDAQ").unwrap_err();
    }

    #[test]
    fn invalid_ed25515() {
        let _err = <PublicKey as std::str::FromStr>::from_str(
            "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcH",
        )
        .unwrap_err();
    }
}
