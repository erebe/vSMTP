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

use crate::ConnectionKind;
use vsmtp_common::{auth::Mechanism, ClientName};
extern crate alloc;

/// Buffer received from the client.
#[non_exhaustive]
pub struct UnparsedArgs(pub Vec<u8>);

pub type Command<Verb, Args> = (Verb, Args);

/// Information received from the client at the connection TCP/IP.
#[non_exhaustive]
pub struct AcceptArgs {
    /// Address of the server which accepted the connection.
    pub client_addr: std::net::SocketAddr,
    /// Peer address of the connection.
    pub server_addr: std::net::SocketAddr,
    /// Instant when the connection was accepted.
    pub timestamp: time::OffsetDateTime,
    /// Universal unique identifier of the connection.
    pub uuid: uuid::Uuid,
    /// Kind of connection.
    pub kind: ConnectionKind,
}

impl AcceptArgs {
    /// Create a new instance.
    #[inline]
    #[must_use]
    pub const fn new(
        client_addr: std::net::SocketAddr,
        server_addr: std::net::SocketAddr,
        timestamp: time::OffsetDateTime,
        uuid: uuid::Uuid,
        kind: ConnectionKind,
    ) -> Self {
        Self {
            client_addr,
            server_addr,
            timestamp,
            uuid,
            kind,
        }
    }
}

/// Information received from the client at the HELO command.
#[non_exhaustive]
pub struct HeloArgs {
    /// Name of the client.
    // TODO: wrap in a domain
    pub client_name: String,
}

/// Information received from the client at the EHLO command.
#[non_exhaustive]
pub struct EhloArgs {
    /// Name of the client.
    pub client_name: ClientName,
}

/// See "SMTP Service Extension for 8-bit MIME Transport"
/// <https://datatracker.ietf.org/doc/html/rfc6152>
#[derive(strum::EnumVariantNames, strum::EnumString)]
pub enum MimeBodyType {
    ///
    #[strum(serialize = "7BIT")]
    SevenBit,
    ///
    #[strum(serialize = "8BITMIME")]
    EightBitMime,
    // TODO: https://datatracker.ietf.org/doc/html/rfc3030
    // Binary,
}

/// Information received from the client at the MAIL FROM command.
#[non_exhaustive]
pub struct MailFromArgs {
    /// Sender address.
    // TODO: wrap in a type mailbox
    pub reverse_path: Option<String>,
    /// (8BITMIME)
    pub mime_body_type: Option<MimeBodyType>,
    // TODO:
    // Option<String>       (AUTH)
    // Option<usize>        (SIZE)
    // use_smtputf8: bool,
}

/// Information received from the client at the RCPT TO command.
#[non_exhaustive]
pub struct RcptToArgs {
    /// Recipient address.
    // TODO: wrap in a type mailbox
    pub forward_path: String,
}

/// Information received from the client at the AUTH command.
#[non_exhaustive]
pub struct AuthArgs {
    /// Authentication mechanism.
    pub mechanism: Mechanism,
    /// First buffer of the challenge, optionally issued by the server.
    /// [`base64`] encoded buffer.
    pub initial_response: Option<Vec<u8>>,
}

/// Error while parsing the arguments of a command.
#[non_exhaustive]
pub enum ParseArgsError {
    /// Non-UTF8 buffer.
    InvalidUtf8(alloc::string::FromUtf8Error),
    /// Invalid IP address.
    BadTypeAddr(std::net::AddrParseError),
    /// The buffer is too big (between each "\r\n").
    BufferTooLong {
        /// buffer size limit
        expected: usize,
        /// actual size of the buffer we got
        got: usize,
    },
    /// Other
    // FIXME: improve that
    InvalidArgs,
}

impl TryFrom<UnparsedArgs> for HeloArgs {
    type Error = ParseArgsError;

    #[inline]
    fn try_from(value: UnparsedArgs) -> Result<Self, Self::Error> {
        let value = value
            .0
            .strip_suffix(b"\r\n")
            .ok_or(ParseArgsError::InvalidArgs)?
            .to_vec();

        Ok(Self {
            client_name: addr::parse_domain_name(
                &String::from_utf8(value).map_err(ParseArgsError::InvalidUtf8)?,
            )
            .map_err(|_err| ParseArgsError::InvalidArgs)?
            .to_string(),
        })
    }
}

impl TryFrom<UnparsedArgs> for EhloArgs {
    type Error = ParseArgsError;

    #[inline]
    fn try_from(value: UnparsedArgs) -> Result<Self, Self::Error> {
        let value = String::from_utf8(
            value
                .0
                .strip_suffix(b"\r\n")
                .ok_or(ParseArgsError::InvalidArgs)?
                .to_vec(),
        )
        .map_err(ParseArgsError::InvalidUtf8)?;

        let client_name = match &value {
            ipv6 if ipv6.to_lowercase().starts_with("[ipv6:") && ipv6.ends_with(']') => {
                match ipv6.get("[IPv6:".len()..ipv6.len() - 1) {
                    Some(ipv6) => ClientName::Ip6(
                        ipv6.parse::<std::net::Ipv6Addr>()
                            .map_err(ParseArgsError::BadTypeAddr)?,
                    ),
                    None => return Err(ParseArgsError::InvalidArgs),
                }
            }
            ipv4 if ipv4.starts_with('[') && ipv4.ends_with(']') => {
                match ipv4.get(1..ipv4.len() - 1) {
                    Some(ipv4) => ClientName::Ip4(
                        ipv4.parse::<std::net::Ipv4Addr>()
                            .map_err(ParseArgsError::BadTypeAddr)?,
                    ),
                    None => return Err(ParseArgsError::InvalidArgs),
                }
            }
            domain => ClientName::Domain(
                addr::parse_domain_name(domain)
                    .map_err(|_err| ParseArgsError::InvalidArgs)?
                    .to_string(),
            ),
        };

        Ok(Self { client_name })
    }
}

impl TryFrom<UnparsedArgs> for AuthArgs {
    type Error = ParseArgsError;

    #[inline]
    fn try_from(value: UnparsedArgs) -> Result<Self, Self::Error> {
        let value = value
            .0
            .strip_suffix(b"\r\n")
            .ok_or(ParseArgsError::InvalidArgs)?;

        let (mechanism, initial_response) = if let Some((idx, _)) = value
            .iter()
            .copied()
            .enumerate()
            .find(|&(_, c)| c.is_ascii_whitespace())
        {
            let (mechanism, initial_response) = value.split_at(idx);
            (
                mechanism.to_vec(),
                Some(
                    initial_response
                        .get(1..)
                        .ok_or(ParseArgsError::InvalidArgs)?
                        .to_vec(),
                ),
            )
        } else {
            (value.to_vec(), None)
        };

        let mechanism = String::from_utf8(mechanism)
            .map_err(ParseArgsError::InvalidUtf8)?
            .parse()
            .map_err(|_err| ParseArgsError::InvalidArgs)?;

        Ok(Self {
            mechanism,
            initial_response,
        })
    }
}

impl TryFrom<UnparsedArgs> for MailFromArgs {
    type Error = ParseArgsError;

    #[inline]
    fn try_from(value: UnparsedArgs) -> Result<Self, Self::Error> {
        let value = value
            .0
            .strip_suffix(b"\r\n")
            .ok_or(ParseArgsError::InvalidArgs)?;

        let mut words = value
            .split(u8::is_ascii_whitespace)
            .filter(|s| !s.is_empty());

        let mailbox = if let Some(s) = words.next() {
            let mailbox = s
                .strip_prefix(b"<")
                .ok_or(ParseArgsError::InvalidArgs)?
                .strip_suffix(b">")
                .ok_or(ParseArgsError::InvalidArgs)?;
            if mailbox.is_empty() {
                None
            } else {
                Some(String::from_utf8(mailbox.to_vec()).map_err(ParseArgsError::InvalidUtf8)?)
            }
        } else {
            return Err(ParseArgsError::InvalidArgs);
        };

        let mut mime_body_type = None;

        #[allow(clippy::expect_used)]
        for args in words {
            match args.strip_prefix(b"BODY=") {
                Some(args_mime_body_type) if mime_body_type.is_none() => {
                    mime_body_type = <MimeBodyType as strum::VariantNames>::VARIANTS
                        .iter()
                        .find(|i| {
                            args_mime_body_type.len() >= i.len()
                                && args_mime_body_type
                                    .get(..i.len())
                                    .expect("range checked above")
                                    .eq_ignore_ascii_case(i.as_bytes())
                        })
                        .map(|body| body.parse().expect("body found above"));
                }
                _ => return Err(ParseArgsError::InvalidArgs),
            }
        }

        Ok(Self {
            reverse_path: mailbox,
            mime_body_type,
        })
    }
}

impl TryFrom<UnparsedArgs> for RcptToArgs {
    type Error = ParseArgsError;

    #[inline]
    fn try_from(value: UnparsedArgs) -> Result<Self, Self::Error> {
        let value = value
            .0
            .strip_suffix(b"\r\n")
            .ok_or(ParseArgsError::InvalidArgs)?;

        let mut word = value
            .split(u8::is_ascii_whitespace)
            .filter(|s| !s.is_empty());

        let mailbox = if let Some(s) = word.next() {
            String::from_utf8(
                s.strip_prefix(b"<")
                    .ok_or(ParseArgsError::InvalidArgs)?
                    .strip_suffix(b">")
                    .ok_or(ParseArgsError::InvalidArgs)?
                    .to_vec(),
            )
            .map_err(ParseArgsError::InvalidUtf8)?
        } else {
            return Err(ParseArgsError::InvalidArgs);
        };

        Ok(Self {
            forward_path: mailbox,
        })
    }
}

/// SMTP Command.
#[derive(Debug, strum::AsRefStr, strum::EnumString, strum::EnumVariantNames)]
#[non_exhaustive]
pub enum Verb {
    /// Used to identify the SMTP client to the SMTP server. (historical)
    #[strum(serialize = "HELO ")]
    Helo,
    /// Used to identify the SMTP client to the SMTP server and request smtp extensions.
    #[strum(serialize = "EHLO ")]
    Ehlo,
    /// This command is used to initiate a mail transaction in which the mail
    /// data is delivered to an SMTP server that may, in turn, deliver it to
    /// one or more mailboxes or pass it on to another system (possibly using
    /// SMTP).
    #[strum(serialize = "MAIL FROM:")]
    MailFrom,
    /// This command is used to identify an individual recipient of the mail
    /// data; multiple recipients are specified by multiple uses of this
    /// command.
    #[strum(serialize = "RCPT TO:")]
    RcptTo,
    #[strum(serialize = "DATA\r\n")]
    /// This command causes the mail data to be appended to the mail data
    /// buffer.
    Data,
    /// This command specifies that the receiver MUST send a "221 OK" reply,
    /// and then close the transmission channel.
    #[strum(serialize = "QUIT\r\n")]
    Quit,
    /// This command specifies that the current mail transaction will be
    /// aborted. Any stored sender, recipients, and mail data MUST be
    /// discarded, and all buffers and state tables cleared.
    #[strum(serialize = "RSET\r\n")]
    Rset,
    /// This command causes the server to send helpful information to the
    /// client. The command MAY take an argument (e.g., any command name)
    /// and return more specific information as a response.
    #[strum(serialize = "HELP")]
    Help,
    /// This command does not affect any parameters or previously entered
    /// commands.
    #[strum(serialize = "NOOP\r\n")]
    Noop,
    /// See "Transport Layer Security"
    /// <https://datatracker.ietf.org/doc/html/rfc3207>
    #[strum(serialize = "STARTTLS\r\n")]
    StartTls,
    /// Authentication with SASL protocol
    /// <https://datatracker.ietf.org/doc/html/rfc4954>
    #[strum(serialize = "AUTH ")]
    Auth,
    /// Any other buffer received while expecting a command is considered an
    /// unknown.
    Unknown,
}
