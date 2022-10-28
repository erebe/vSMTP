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

use std::str::FromStr;

use vsmtp_plugins::{anyhow, rhai};

/// Objects are rust's representation of rule engine variables.
/// multiple types are supported.
///
/// NOTE: Objects are represented as an enum because it is easier to create containers
/// for them.
#[derive(Debug, Clone, strum::AsRefStr)]
#[strum(serialize_all = "lowercase")]
pub enum Object {
    /// ip v4 address. (a.b.c.d)
    Ip4(std::net::Ipv4Addr),
    /// ip v6 address. (x:x:x:x:x:x:x:x)
    Ip6(std::net::Ipv6Addr),
    /// an ip v4 range. (a.b.c.d/range)
    Rg4(iprange::IpRange<ipnet::Ipv4Net>),
    /// an ip v6 range. (x:x:x:x:x:x:x:x/range)
    Rg6(iprange::IpRange<ipnet::Ipv6Net>),
    /// an email address (jones@foo.com)
    Address(vsmtp_common::Address),
    /// a valid fully qualified domain name (foo.com)
    Fqdn(String),
    /// a regex (^[a-z0-9.]+@foo.com$)
    Regex(regex::Regex),
    /// a user identifier.
    Identifier(String),
    /// a custom smtp reply code.
    Code(vsmtp_common::Reply),
}

/// A ``vSL`` object that is shared or not, depending of the context of the rule engine.
pub type SharedObject = rhai::Shared<Object>;

/// Create a new object using the [`FromStr`] trait.
macro_rules! new_object_from_str {
    ($value:expr, $type:ty, $object_type:expr) => {
        <$type as std::str::FromStr>::from_str($value)
            .map(|value| $object_type(value))
            .map_err(|err| anyhow::anyhow!("{err}"))
    };
}

impl Object {
    fn from_str(s: &str, value: &str) -> anyhow::Result<Self> {
        match s {
            "ip4" => Self::new_ip4(value),
            "ip6" => Self::new_ip6(value),
            "rg4" => Self::new_rg4(value),
            "rg6" => Self::new_rg6(value),
            "address" => Self::new_address(value),
            "fqdn" => Self::new_fqdn(value),
            "regex" => Self::new_regex(value),
            "identifier" => Ok(Self::new_identifier(value)),

            // "file" => Ok(Self::new_file(value)),
            // "code" => Ok(()),
            _ => Err(anyhow::anyhow!("invalid object type: {}", s)),
        }
    }

    /// Create a new ip v4 object.
    ///
    /// # Errors
    /// * The value could not be converted.
    pub fn new_ip4(ip: impl AsRef<str>) -> anyhow::Result<Object> {
        new_object_from_str!(ip.as_ref(), std::net::Ipv4Addr, Object::Ip4)
    }

    /// Create a new ip v6 object.
    ///
    /// # Errors
    /// * The value could not be converted.
    pub fn new_ip6(ip: impl AsRef<str>) -> anyhow::Result<Object> {
        new_object_from_str!(ip.as_ref(), std::net::Ipv6Addr, Object::Ip6)
    }

    /// Create a new ip v4 range object.
    ///
    /// # Errors
    /// * The value could not be converted.
    pub fn new_rg4(range: impl AsRef<str>) -> anyhow::Result<Object> {
        range
            .as_ref()
            .parse::<ipnet::Ipv4Net>()
            .map(|range| Object::Rg4(std::iter::once(range).collect()))
            .map_err(|error| anyhow::anyhow!("{error}"))
    }

    /// Create a new ip v6 range object.
    ///
    /// # Errors
    /// * The value could not be converted.
    pub fn new_rg6(range: impl AsRef<str>) -> anyhow::Result<Object> {
        range
            .as_ref()
            .parse::<ipnet::Ipv6Net>()
            .map(|range| Object::Rg6(std::iter::once(range).collect()))
            .map_err(|error| anyhow::anyhow!("{error}"))
    }

    /// Create a new address object.
    ///
    /// # Errors
    /// * The value could not be converted.
    pub fn new_address(address: impl AsRef<str>) -> anyhow::Result<Object> {
        new_object_from_str!(address.as_ref(), vsmtp_common::Address, Object::Address)
    }

    /// Create a new full qualified domain name object.
    ///
    /// # Errors
    /// * The value could not be converted.

    pub fn new_fqdn(domain: impl AsRef<str>) -> anyhow::Result<Object> {
        addr::parse_domain_name(domain.as_ref())
            .map(|domain| Object::Fqdn(domain.to_string()))
            .map_err(|error| anyhow::anyhow!("{error}"))
    }

    /// Create a new regex object.
    ///
    /// # Errors
    /// * The value could not be converted.
    pub fn new_regex(regex: impl AsRef<str>) -> anyhow::Result<Object> {
        new_object_from_str!(regex.as_ref(), regex::Regex, Object::Regex)
    }

    /// Create a new file object.
    ///
    /// # Errors
    /// * The value could not be converted.
    pub fn new_file(
        path: impl AsRef<std::path::Path>,
        content_type: impl AsRef<str>,
    ) -> anyhow::Result<rhai::Array> {
        std::fs::read_to_string(path.as_ref())?
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(|line| Self::from_str(content_type.as_ref(), line).map(rhai::Dynamic::from))
            .collect::<anyhow::Result<rhai::Array>>()
    }

    /// Create a new identifier object.
    pub fn new_identifier(identifier: impl Into<String>) -> Object {
        Object::Identifier(identifier.into())
    }

    /// Create a new code object.
    pub fn new_code(code: u16, text: impl Into<String>) -> Object {
        Object::Code(vsmtp_common::Reply::new(
            vsmtp_common::ReplyCode::Code { code },
            text.into(),
        ))
    }

    /// Create a new code object with an enhanced code.
    pub fn new_code_enhanced<T>(code: u16, enhanced: T, text: T) -> Object
    where
        T: Into<String>,
    {
        Object::Code(vsmtp_common::Reply::new(
            vsmtp_common::ReplyCode::Enhanced {
                code,
                enhanced: enhanced.into(),
            },
            text.into(),
        ))
    }
}

impl Object {
    /// check if the `other` object is contained in this object,
    /// return false automatically if the item cannot be contained in this object.
    #[must_use]
    pub fn contains(&self, other: &Self) -> bool {
        match (self, other) {
            (Object::Rg4(rg4), Object::Ip4(ip4)) => rg4.contains(ip4),
            (Object::Rg6(rg6), Object::Ip6(ip6)) => rg6.contains(ip6),
            (Object::Regex(regex), other) => regex.find(other.as_ref()).is_some(),
            (Object::Address(addr), Object::Identifier(identifier)) => {
                addr.local_part() == identifier.as_str()
            }
            (Object::Address(addr), Object::Fqdn(fqdn)) => addr.domain() == fqdn.as_str(),
            _ => false,
        }
    }

    /// check if the `other` string is contained in this object,
    /// return false automatically if the item cannot be contained in this object.
    #[must_use]
    pub fn contains_str(&self, other: &str) -> bool {
        match self {
            Object::Rg4(rg4) => ipnet::Ipv4Net::from_str(other)
                .map(|ip4| rg4.contains(&ip4))
                .unwrap_or(false),
            Object::Rg6(rg6) => ipnet::Ipv6Net::from_str(other)
                .map(|ip6| rg6.contains(&ip6))
                .unwrap_or(false),
            Object::Regex(regex) => regex.find(other).is_some(),
            Object::Address(addr) => addr.local_part() == other || addr.domain() == other,
            _ => false,
        }
    }
}

impl PartialEq for Object {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Ip4(l0), Self::Ip4(r0)) => l0 == r0,
            (Self::Ip6(l0), Self::Ip6(r0)) => l0 == r0,
            (Self::Rg4(l0), Self::Rg4(r0)) => l0 == r0,
            (Self::Rg6(l0), Self::Rg6(r0)) => l0 == r0,
            (Self::Address(l0), Self::Address(r0)) => l0 == r0,
            (Self::Fqdn(l0), Self::Fqdn(r0)) | (Self::Identifier(l0), Self::Identifier(r0)) => {
                l0 == r0
            }
            (Self::Regex(r0), Self::Regex(l0)) => r0.as_str() == l0.as_str(),
            (Self::Code(r0), Self::Code(l0)) => r0 == l0,

            // NOTE: do we want those two to be comparable ?
            // (Self::File(l0), Self::File(r0)) => l0 == r0,
            _ => false,
        }
    }
}

// Added to easily enable the user to print data of an object.
impl std::fmt::Display for Object {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Object::Ip4(ip) => write!(f, "{ip}"),
            Object::Ip6(ip) => write!(f, "{ip}"),
            Object::Rg4(range) => write!(f, "{range:?}"),
            Object::Rg6(range) => write!(f, "{range:?}"),
            Object::Address(addr) => write!(f, "{addr}"),
            Object::Fqdn(fqdn) => write!(f, "{fqdn}"),
            Object::Regex(regex) => write!(f, "{regex}"),
            Object::Identifier(ident) => write!(f, "{ident}"),
            Object::Code(reply) => write!(f, "{} {}", reply.code(), reply.text()),
        }
    }
}
