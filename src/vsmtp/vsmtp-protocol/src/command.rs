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

/// Buffer received from the client.
pub struct UnparsedArgs(pub Vec<u8>);
pub type Command<Verb, Args> = (Verb, Args);

/// Information received from the client at the connection TCP/IP.
pub struct AcceptArgs {
    /// Address of the server which accepted the connection.
    pub client_addr: std::net::SocketAddr,
    /// Peer address of the connection.
    pub server_addr: std::net::SocketAddr,
    /// Kind of connection.
    pub kind: ConnectionKind,
}

/// Information received from the client at the HELO command.
pub struct HeloArgs {
    /// Name of the client.
    // TODO: wrap in a domain
    pub client_name: String,
}

/// Information received from the client at the EHLO command.
pub struct EhloArgs {
    /// Name of the client.
    pub client_name: ClientName,
}

/// Information received from the client at the MAIL FROM command.
pub struct MailFromArgs {
    /// Sender address.
    // TODO: wrap in a type mailbox
    pub reverse_path: Option<String>,
    // TODO:
    // Option<MimeBodyType> (8BITMIME)
    // Option<String>       (AUTH)
    // Option<usize>        (SIZE)
}

/// Information received from the client at the RCPT TO command.
pub struct RcptToArgs {
    /// Recipient address.
    // TODO: wrap in a type mailbox
    pub forward_path: String,
}

/// Information received from the client at the AUTH command.
pub struct AuthArgs {
    /// Authentication mechanism.
    pub mechanism: Mechanism,
    /// First buffer of the challenge, optionally issued by the server.
    /// [`base64`] encoded buffer.
    pub initial_response: Option<Vec<u8>>,
}

/// Error while parsing the arguments of a command.
pub enum ParseArgsError {
    /// Non-UTF8 buffer.
    InvalidUtf8(std::string::FromUtf8Error),
    /// Invalid IP address.
    BadTypeAddr(std::net::AddrParseError),
    /// Other
    // FIXME: improve that
    InvalidArgs,
}

impl TryFrom<UnparsedArgs> for HeloArgs {
    type Error = ParseArgsError;

    fn try_from(value: UnparsedArgs) -> Result<Self, Self::Error> {
        Ok(Self {
            client_name: String::from_utf8(
                value
                    .0
                    .strip_suffix(b"\r\n")
                    .ok_or(ParseArgsError::InvalidArgs)?
                    .to_vec(),
            )
            .map_err(ParseArgsError::InvalidUtf8)?,
        })
    }
}

impl TryFrom<UnparsedArgs> for EhloArgs {
    type Error = ParseArgsError;

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
                ClientName::Ip6(
                    ipv6["[IPv6:".len()..ipv6.len() - 1]
                        .parse::<std::net::Ipv6Addr>()
                        .map_err(ParseArgsError::BadTypeAddr)?,
                )
            }
            ipv4 if ipv4.starts_with('[') && ipv4.ends_with(']') => ClientName::Ip4(
                ipv4[1..ipv4.len() - 1]
                    .parse::<std::net::Ipv4Addr>()
                    .map_err(ParseArgsError::BadTypeAddr)?,
            ),
            domain => ClientName::Domain(
                addr::parse_domain_name(domain)
                    .map_err(|_| ParseArgsError::InvalidArgs)?
                    .to_string(),
            ),
        };

        Ok(Self { client_name })
    }
}

impl TryFrom<UnparsedArgs> for AuthArgs {
    type Error = ParseArgsError;

    fn try_from(value: UnparsedArgs) -> Result<Self, Self::Error> {
        let value = value
            .0
            .strip_suffix(b"\r\n")
            .ok_or(ParseArgsError::InvalidArgs)?;

        let (mechanism, initial_response) = if let Some((idx, _)) = value
            .iter()
            .copied()
            .enumerate()
            .find(|(_, c)| c.is_ascii_whitespace())
        {
            let (mechanism, initial_response) = value.split_at(idx);
            (mechanism.to_vec(), Some(initial_response[1..].to_vec()))
        } else {
            (value.to_vec(), None)
        };

        let mechanism = String::from_utf8(mechanism)
            .map_err(ParseArgsError::InvalidUtf8)?
            .parse()
            .map_err(|_| ParseArgsError::InvalidArgs)?;

        Ok(Self {
            mechanism,
            initial_response,
        })
    }
}

// NOTE: from [`[u8]::trim_ascii_start`]
const fn trim_ascii_start(slice: &[u8]) -> &[u8] {
    let mut bytes = slice;
    while let [first, rest @ ..] = bytes {
        if first.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

impl TryFrom<UnparsedArgs> for MailFromArgs {
    type Error = ParseArgsError;

    fn try_from(value: UnparsedArgs) -> Result<Self, Self::Error> {
        let value = value
            .0
            .strip_suffix(b"\r\n")
            .ok_or(ParseArgsError::InvalidArgs)?;
        let mut buffer = trim_ascii_start(value).to_vec();

        if buffer.remove(0) != b'<' {
            return Err(ParseArgsError::InvalidArgs);
        }
        if buffer.remove(buffer.len() - 1) != b'>' {
            return Err(ParseArgsError::InvalidArgs);
        }

        Ok(Self {
            reverse_path: Some(String::from_utf8(buffer).map_err(ParseArgsError::InvalidUtf8)?),
        })
    }
}

impl TryFrom<UnparsedArgs> for RcptToArgs {
    type Error = ParseArgsError;

    fn try_from(value: UnparsedArgs) -> Result<Self, Self::Error> {
        let value = value
            .0
            .strip_suffix(b"\r\n")
            .ok_or(ParseArgsError::InvalidArgs)?;
        let mut buffer = trim_ascii_start(value).to_vec();

        if buffer.remove(0) != b'<' {
            return Err(ParseArgsError::InvalidArgs);
        }
        if buffer.remove(buffer.len() - 1) != b'>' {
            return Err(ParseArgsError::InvalidArgs);
        }

        Ok(Self {
            forward_path: String::from_utf8(buffer).map_err(ParseArgsError::InvalidUtf8)?,
        })
    }
}

/// SMTP Command.
#[derive(Debug, strum::AsRefStr, strum::EnumString, strum::EnumVariantNames)]
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
