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

use crate::dkim::{PublicKey, Signature};
use trust_dns_resolver::config::ResolverOpts;
use vsmtp_mail_parser::MessageBody;

async fn verify(mail: &str) {
    let body = MessageBody::try_from(mail).unwrap();

    let resolver = trust_dns_resolver::TokioAsyncResolver::tokio(
        trust_dns_resolver::config::ResolverConfig::cloudflare(),
        ResolverOpts::default(),
    )
    .unwrap();

    let signature = <Signature as std::str::FromStr>::from_str(
        &body
            .inner()
            .get_header("DKIM-Signature", true, true)
            .unwrap(),
    )
    .unwrap();
    let public_key = resolver
        .txt_lookup(signature.get_dns_query())
        .await
        .unwrap();
    let field = public_key.iter().next().unwrap();

    let public_key = <PublicKey as std::str::FromStr>::from_str(&field.to_string()).unwrap();

    signature.verify(body.inner(), &public_key).unwrap();
}

fn verify_3rd_party(filepath: &str) {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("dkimverify -v < {filepath}"))
        .output()
        .expect("failed to execute process");

    assert_eq!(
        output,
        std::process::Output {
            status: <std::process::ExitStatus as std::os::unix::prelude::ExitStatusExt>::from_raw(
                0
            ),
            stdout: b"signature ok\n".to_vec(),
            stderr: vec![],
        }
    );
}

#[tokio::test]
#[ignore = "need to regenerate the email because the signature is not valid anymore"]
async fn mail_1() {
    verify(include_str!("mail_1.eml")).await;
}

#[tokio::test]
#[ignore = "need to regenerate the email because the signature is not valid anymore"]
async fn mail_2() {
    verify(include_str!("mail_2.eml")).await;
}

#[test]
#[ignore = "need `sudo apt install python3-dkim`"]
fn mail_1_3rd_party() {
    verify_3rd_party("./src/dkim/tests/mail_1.eml");
}

#[test]
#[ignore = "need `sudo apt install python3-dkim`"]
fn mail_2_3rd_party() {
    verify_3rd_party("./src/dkim/tests/mail_2.eml");
}
