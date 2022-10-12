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

const DUMMY_DOMAIN: &str = "dummy.com";
const DUMMY_CREDENTIALS: (&str, &str) = ("dummy", "dummy");

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
fn tls_wrapper(
    #[default("")] domain: impl Into<String>,
    #[default(TlsVersion::Tlsv12)] min_tls_version: TlsVersion,
) -> Tls {
    Tls::Wrapper(
        TlsParametersBuilder::new(domain.into())
            .dangerous_accept_invalid_certs(false)
            .set_min_tls_version(min_tls_version)
            .build()
            .unwrap(),
    )
}

#[fixture]
fn tls_opportunistic(
    #[default("")] domain: impl Into<String>,
    #[default(TlsVersion::Tlsv12)] min_tls_version: TlsVersion,
) -> Tls {
    Tls::Opportunistic(
        TlsParametersBuilder::new(domain.into())
            .dangerous_accept_invalid_certs(false)
            .set_min_tls_version(min_tls_version)
            .build()
            .unwrap(),
    )
}

#[fixture]
fn tls_required(
    #[default("")] domain: impl Into<String>,
    #[default(TlsVersion::Tlsv12)] min_tls_version: TlsVersion,
) -> Tls {
    Tls::Required(
        TlsParametersBuilder::new(domain.into())
            .dangerous_accept_invalid_certs(false)
            .set_min_tls_version(min_tls_version)
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
    #[values(TlsVersion::Tlsv12/*, TlsVersion::Tlsv13*/)] _min_tls_version: TlsVersion,
    #[values(
        tls_disabled(),
        tls_opportunistic(tls_domain, _min_tls_version),
        tls_required(tls_domain, _min_tls_version),
        tls_wrapper(tls_domain, _min_tls_version)
    )]
    tls: Tls,
    // all the SASL mechanism supported by both client (lettre) and server (vSMTP)
    // FIXME: LOGIN: Unrecognized challenge
    #[values(None, /*Some(Mechanism::Login),*/ Some(Mechanism::Plain))] mechanism: Option<
        Mechanism,
    >,
    // the credentials parameters are unused if the mechanism is None
    #[values(DUMMY_CREDENTIALS, *STAGING_CREDENTIALS)] credentials: (&str, &str),
) {
    // TLS tunnel is required on port 465
    if (port == 465 && !matches!(tls, Tls::Wrapper(_)))
        || (matches!(tls, Tls::Wrapper(_)) && port != 465)
    {
        return;
    }

    let sender = SmtpTransport::builder_dangerous(*STAGING_SERVER_MX)
        .port(port)
        .tls(tls.clone())
        .timeout(Some(std::time::Duration::from_secs(5)));

    let sender = match mechanism {
        Some(mechanism) => sender
            .authentication(vec![mechanism])
            .credentials(credentials.into()),
        None => sender,
    };

    let email = lettre::Message::builder()
        // TODO: set FROM in matrix
        // FIXME: if the connection is authenticated, the FROM is accepted
        .from("NoBody <nobody@domain.tld>".parse().unwrap())
        // TODO: set TO in matrix
        .to("Hei <hei@domain.tld>".parse().unwrap())
        .subject(function_name!())
        // TODO: set virus in matrix
        .body(String::from("Be happy!"))
        .unwrap();

    match sender.build().send(&email) {
        Ok(res) => {
            assert_eq!(res, "250 Ok\r\n".parse().unwrap());
        }
        // FIXME ?
        Err(e) if e.to_string() ==
            "network error: invalid peer certificate contents: invalid peer certificate: UnknownIssuer" => {}
        Err(e) if tls_domain == crate::DUMMY_DOMAIN &&
            e.to_string() ==
            "network error: invalid peer certificate contents: invalid peer certificate: CertExpired" => {
        }
        Err(e) if credentials == crate::DUMMY_CREDENTIALS && e.to_string() ==
            "permanent error (535): 5.7.8 Authentication credentials invalid" => {
        }
        Err(e) if mechanism.is_some() && matches!(tls, Tls::None) &&
            e.to_string() == "internal client error: No compatible authentication mechanism was found" => {
        }
        Err(e)
            if e.to_string() == "permanent error (554): 5.7.1 Relay access denied"
                && (mechanism.is_none() || credentials == crate::DUMMY_CREDENTIALS) =>
        {
            // case (no auth)
        }
        Err(e) => todo!("{e}"),
    }
}
