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

/// A domain name.
pub type Domain = trust_dns_resolver::Name;

/// An iterator over the domain name.
///
/// # Example
///
/// ```
/// let domain = "www.john.doe.example.com".parse::<vsmtp_common::Domain>().unwrap();
///
/// let domain_str = domain.to_string();
/// let mut domain_part = vsmtp_common::iter_to_root(&domain_str);
/// // assert_eq!(domain_part.next().unwrap(), "www.john.doe.example.com");
/// assert_eq!(domain_part.next().unwrap(), "john.doe.example.com");
/// assert_eq!(domain_part.next().unwrap(), "doe.example.com");
/// assert_eq!(domain_part.next().unwrap(), "example.com");
/// assert_eq!(domain_part.next().unwrap(), "com");
/// assert_eq!(domain_part.next(), None);
/// ```
#[must_use]
pub fn iter_to_root(domain: &str) -> IterDomain<'_> {
    IterDomain::iter(domain)
}

#[allow(clippy::module_name_repetitions)]
pub struct IterDomain<'a>(&'a str);

impl<'a> IterDomain<'a> {
    /// Create an iterator over the given domain.
    #[must_use]
    pub const fn iter(domain: &'a str) -> Self {
        Self(domain)
    }
}

impl<'a> Iterator for IterDomain<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.split_once('.').map(|(_, rest)| {
            self.0 = rest;
            self.0
        })
    }
}
