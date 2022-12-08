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

#![allow(clippy::too_many_arguments)]

const DUMMY_DOMAIN: &str = "this-domain-has-no-mx-record-so-mail-will-go-in-deferred-queue.com";
const DUMMY_CREDENTIALS: (&str, &str) = ("dummy", "dummy");
const DUMMY_MAILBOX: &str =
    "dummy@this-domain-has-no-mx-record-so-mail-will-go-in-deferred-queue.com";

// NOTE: using option_env! to silent the linter in IDE
lazy_static::lazy_static! {
    // common name (CN) of the server certificate
    static ref STAGING_DOMAIN: &'static str = option_env!("STAGING_DOMAIN").unwrap();

    // a virtual domain hosted of the staging server, accessed using SNI with TLS
    static ref STAGING_SNI_DOMAIN: &'static str = option_env!("STAGING_SNI_DOMAIN").unwrap();

    // TCP/IP address of the staging server
    static ref STAGING_SERVER_MX: &'static str = option_env!("STAGING_SERVER_MX").unwrap();

    // valid credentials of a mailbox used to authenticate the connection
    static ref STAGING_CREDENTIALS: (&'static str, &'static str) = (
        option_env!("STAGING_AUTHID").unwrap(),
        option_env!("STAGING_PASS").unwrap()
    );

    // a mailbox hosted on the staging server
    static ref STAGING_MAILBOX: &'static str = option_env!("STAGING_MAILBOX").unwrap();

    // a mailbox hosted on the second staging server
    static ref STAGING_2_MAILBOX: &'static str = option_env!("STAGING_2_MAILBOX").unwrap();
}

use lettre::{
    transport::smtp::{
        authentication::Mechanism,
        client::{Tls, TlsParametersBuilder, TlsVersion},
    },
    SmtpTransport, Transport,
};
use rstest::{fixture, rstest};

#[fixture]
fn tls_disabled() -> Tls {
    Tls::None
}

#[fixture]
fn tls_wrapper(#[default("")] domain: impl Into<String>) -> Tls {
    Tls::Wrapper(
        TlsParametersBuilder::new(domain.into())
            // FIXME ?
            .dangerous_accept_invalid_certs(true)
            .set_min_tls_version(TlsVersion::Tlsv12)
            .build()
            .unwrap(),
    )
}

#[fixture]
fn tls_opportunistic(#[default("")] domain: impl Into<String>) -> Tls {
    Tls::Opportunistic(
        TlsParametersBuilder::new(domain.into())
            // FIXME ?
            .dangerous_accept_invalid_certs(true)
            .set_min_tls_version(TlsVersion::Tlsv12)
            .build()
            .unwrap(),
    )
}

#[fixture]
fn tls_required(#[default("")] domain: impl Into<String>) -> Tls {
    Tls::Required(
        TlsParametersBuilder::new(domain.into())
            // FIXME ?
            .dangerous_accept_invalid_certs(true)
            .set_min_tls_version(TlsVersion::Tlsv12)
            .build()
            .unwrap(),
    )
}

#[function_name::named]
#[rstest]
#[trace]
#[ignore]
fn staging(
    #[values(25, 587, 465)] port: u16,
    #[values(*crate::STAGING_DOMAIN, crate::DUMMY_DOMAIN /* *crate::STAGING_SNI_DOMAIN */)]
    tls_domain: &str,
    // version <TLSv1.2 is not supported by the client (lettre+rustls)
    // #[values(TlsVersion::Tlsv12/*, TlsVersion::Tlsv13*/)] _min_tls_version: TlsVersion,
    #[values(
        tls_disabled(),
        tls_opportunistic(tls_domain),
        tls_required(tls_domain),
        tls_wrapper(tls_domain)
    )]
    tls: Tls,
    // all the SASL mechanism supported by both client (lettre) and server (vSMTP)
    // FIXME: LOGIN: Unrecognized challenge
    #[values(None, /*Some(Mechanism::Login),*/ Some(Mechanism::Plain))] mechanism: Option<
        Mechanism,
    >,
    // the credentials parameters are unused if the mechanism is None
    #[values(DUMMY_CREDENTIALS, *STAGING_CREDENTIALS)] credentials: (&str, &str),
    #[values(DUMMY_MAILBOX, *STAGING_MAILBOX)] reverse_path: &str,
    // TODO: test with multiple recipients
    #[values(DUMMY_MAILBOX, *STAGING_MAILBOX, *STAGING_2_MAILBOX)] forward_path: &str,
) {
    // TLS tunnel is required on port 465
    // we could uncomment the following line to test the TLS handshake timeout
    if (port == 465 && !matches!(tls, Tls::Wrapper(_)))
        || (matches!(tls, Tls::Wrapper(_)) && port != 465)
    {
        return;
    }

    let sender = SmtpTransport::builder_dangerous(*STAGING_SERVER_MX)
        .port(port)
        .tls(tls.clone())
        .timeout(Some(std::time::Duration::from_secs(5)))
        .hello_name(lettre::transport::smtp::extension::ClientId::Domain(
            "staging.test.com".to_string(),
        ));

    let sender = match mechanism {
        Some(mechanism) => sender
            .authentication(vec![mechanism])
            .credentials(credentials.into()),
        None => sender,
    };

    let email = lettre::Message::builder()
        .from(reverse_path.parse().unwrap())
        .to(forward_path.parse().unwrap())
        .subject(function_name!())
        // TODO: set virus in matrix & small/medium/large attachments
        .body(String::from("Be happy!"))
        .unwrap();

    match sender.build().send(&email) {
        Ok(res) => assert_eq!(res, "250 Ok\r\n".parse().unwrap()),
        // case unsecured TLS
        Err(e) if matches!(tls, Tls::None) &&
            e.to_string() == "transient error (451): 5.7.3 Must issue a STARTTLS command first" => {}
        // case certificate name not matching
        Err(e) if tls_domain == crate::DUMMY_DOMAIN &&
            e.to_string() ==
            "network error: invalid peer certificate contents: invalid peer certificate: CertExpired" => {}
        // case auth bad credentials
        Err(e) if (reverse_path == crate::DUMMY_MAILBOX
            || credentials == crate::DUMMY_CREDENTIALS) && e.to_string() ==
            "permanent error (535): 5.7.8 Authentication credentials invalid" => {}
        // case unencrypted auth
        Err(e) if mechanism.is_some() && matches!(tls, Tls::None) &&
            e.to_string() == "internal client error: No compatible authentication mechanism was found" => {}
        // case unauthenticated
        Err(e) if mechanism.is_none() &&
            e.to_string() == "permanent error (530): 5.7.0 Authentication required" => {}
        Err(e) => todo!("{e}"),
    }
}
