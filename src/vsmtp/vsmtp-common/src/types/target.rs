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

use crate::{utils::ipv6_with_scope_id, Domain};

/// Possible format of the forward target.
#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, serde::Serialize, serde::Deserialize,
)]
pub enum Target {
    /// the target is a domain name.
    Domain(Domain),
    /// the target is an ip address, a domain resolution needs to be made.
    Ip(std::net::IpAddr),
    /// the target is an ip address with an associated port.
    Socket(std::net::SocketAddr),
}

impl std::str::FromStr for Target {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.find('%').map_or_else(
            || {
                s.parse::<std::net::SocketAddr>().map_or_else(
                    |_| {
                        s.parse::<std::net::IpAddr>().map_or_else(
                            |_| {
                                Domain::from_utf8(s).map(Self::Domain).map_err(|err| {
                                    anyhow::anyhow!("{err} could not be used as a forward target.",)
                                })
                            },
                            |ip| Ok(Self::Ip(ip)),
                        )
                    },
                    |socket| Ok(Self::Socket(socket)),
                )
            },
            |_| ipv6_with_scope_id(s).map(Self::Socket),
        )
    }
}
