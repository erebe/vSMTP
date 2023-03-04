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

use crate::dkim::{self, PublicKey, Signature};
use base64::Engine;
use vsmtp_mail_parser::MessageBody;

#[ignore = "used for debugging with FILE env var as input file"]
#[test_log::test]
fn verify_file() {
    let filepath = option_env!("FILE").unwrap();
    let file_content = std::fs::read_to_string(filepath).unwrap();
    let body = MessageBody::try_from(file_content.as_str()).unwrap();

    let signature = <Signature as std::str::FromStr>::from_str(
        &body.inner().get_header("DKIM-Signature", true).unwrap(),
    )
    .unwrap();

    let txt_record = trust_dns_resolver::Resolver::default()
        .unwrap()
        .txt_lookup(dbg!(signature.get_dns_query()))
        .unwrap();

    let keys = txt_record
        .into_iter()
        .map(|i| <PublicKey as std::str::FromStr>::from_str(&i.to_string()));

    let keys = keys
        .collect::<Result<Vec<_>, <PublicKey as std::str::FromStr>::Err>>()
        .unwrap();

    dkim::verify(&signature, body.inner(), keys.first().unwrap()).unwrap();
}

#[test]
fn mail_5() {
    let body = MessageBody::try_from(include_str!("mail_5.eml")).unwrap();

    let signature = <Signature as std::str::FromStr>::from_str(
        &body.inner().get_header("DKIM-Signature", true).unwrap(),
    )
    .unwrap();

    let header = signature.get_header_for_hash(body.inner());

    pretty_assertions::assert_eq!(
        header,
        concat!(
            "Date: Wed, 3 Aug 2022 17:48:03 +0200\r\n",
            "To: jdoe@negabit.com\r\nFrom: john <john.doe@example.com>\r\n",
            "Subject: after dns update\r\nDKIM-Signature: v=1; a=rsa-sha256; c=simple/simple; d=example.com; s=mail;\r\n",
            "\tt=1659541683; bh=Touenr7dUe0Mxv9r3OfnQ+GHpFRIdDa3Wa3TWnDOQKs=;\r\n",
            "\th=Date:To:From:Subject:From;\r\n",
            "\tb=\r\n"
        )
    );

    println!(
        "{}",
        base64::engine::general_purpose::STANDARD.encode(signature.get_header_hash(body.inner()))
    );
}
