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

/// List of supported SASL Mechanism
/// See <https://www.iana.org/assignments/sasl-mechanisms/sasl-mechanisms.xhtml>
#[derive(
    Debug,
    PartialEq,
    Eq,
    Copy,
    Clone,
    Hash,
    PartialOrd,
    Ord,
    strum::Display,
    strum::AsRefStr,
    strum::EnumString,
    serde_with::SerializeDisplay,
    serde_with::DeserializeFromStr,
)]
#[strum(serialize_all = "SCREAMING-KEBAB-CASE")]
pub enum Mechanism {
    /// Common, but for interoperability
    Plain,
    /// Obsolete
    Login,
    /// Limited
    CramMd5,
    /// Common
    /// See <https://datatracker.ietf.org/doc/html/rfc4505>
    Anonymous,
    /*
    - EXTERNAL
    - SECURID
    - DIGEST-MD5
    - SCRAM-SHA-1
    - SCRAM-SHA-1-PLUS
    - SCRAM-SHA-256
    - SCRAM-SHA-256-PLUS
    - SAML20
    - OPENID20
    - GSSAPI
    - GS2-KRB5
    - XOAUTH-2
    */
}

impl Mechanism {
    /// Does the client must send data first with initial response
    #[must_use]
    pub const fn client_first(self) -> bool {
        match self {
            Self::Plain | Self::Anonymous => true,
            Self::Login | Self::CramMd5 => false,
        }
    }

    /// Does this mechanism must be under TLS (STARTTLS or Tunnel)
    #[must_use]
    pub const fn must_be_under_tls(self) -> bool {
        match self {
            Self::Plain | Self::Login | Self::CramMd5 | Self::Anonymous => true,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn to_str() {
        assert_eq!(Mechanism::Plain.to_string(), "PLAIN");
        assert_eq!(Mechanism::Login.to_string(), "LOGIN");
        assert_eq!(Mechanism::CramMd5.to_string(), "CRAM-MD5");
        assert_eq!(Mechanism::Anonymous.to_string(), "ANONYMOUS");
    }

    #[test]
    fn error() {
        assert!(<Mechanism as std::str::FromStr>::from_str("foobar").is_err());
    }
}
