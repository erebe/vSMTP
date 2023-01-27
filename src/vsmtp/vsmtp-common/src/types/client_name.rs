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

/// Identity of the client.
#[derive(
    Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(untagged)]
pub enum ClientName {
    // TODO: wrap in a type domain & ensure fqdn
    /// FQDN of the client.
    Domain(String),
    /// IP address of the client.
    Ip4(std::net::Ipv4Addr),
    /// IP address of the client.
    Ip6(std::net::Ipv6Addr),
}

impl std::fmt::Display for ClientName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Domain(domain) => write!(f, "{domain}"),
            Self::Ip4(ip) => write!(f, "{ip}"),
            Self::Ip6(ip) => write!(f, "{ip}"),
        }
    }
}
