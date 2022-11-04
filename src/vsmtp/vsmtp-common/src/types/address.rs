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
/// Address Email
#[derive(Clone, Debug, Eq, serde_with::SerializeDisplay, serde_with::DeserializeFromStr)]
pub struct Address {
    at_sign: usize,
    full: String,
}

/// Creates an iterator over a domain that remove the prefix every call to `next`.
pub struct Domain<'a>(&'a str);

impl<'a> Domain<'a> {
    /// Create an iterator over the given domain.
    #[must_use]
    pub const fn iter(domain: &'a str) -> Self {
        Self(domain)
    }
}

impl<'a> Iterator for Domain<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.split_once('.').map(|(_, rest)| {
            self.0 = rest;
            self.0
        })
    }
}

/// Syntax sugar Address object from dyn `ToString`
///
/// # Panics
///
/// if the argument failed to be converted
#[macro_export]
macro_rules! addr {
    ($e:expr) => {
        <$crate::Address as core::str::FromStr>::from_str($e).unwrap()
    };
}

impl std::str::FromStr for Address {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Err(error) = addr::parse_email_address(s) {
            anyhow::bail!("'{s}' is not a valid address: {error}")
        }
        Ok(Self {
            at_sign: s.find('@').expect("no '@' in address"),
            full: s.to_string(),
        })
    }
}

impl From<Address> for String {
    fn from(value: Address) -> Self {
        value.full().to_string()
    }
}

impl PartialEq for Address {
    fn eq(&self, other: &Self) -> bool {
        self.full == other.full
    }
}

impl std::hash::Hash for Address {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.full.hash(state);
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.full)
    }
}

impl Address {
    /// get the full email address.
    #[must_use]
    pub fn full(&self) -> &str {
        &self.full
    }

    /// get the user of the address.
    #[must_use]
    pub fn local_part(&self) -> &str {
        &self.full[..self.at_sign]
    }

    /// get the fqdn of the address.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.full[self.at_sign + 1..]
    }

    /// create a new address without verifying the syntax.
    ///
    /// # Panics
    ///
    /// * there is no '@' characters in the string
    #[must_use]
    pub fn new_unchecked(addr: String) -> Self {
        Self {
            at_sign: addr.find('@').unwrap(),
            full: addr,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn deserialize() {
        let parsed = serde_json::from_str::<Address>(r#""hello@domain.com""#).unwrap();
        assert_eq!(
            parsed,
            Address {
                full: "hello@domain.com".to_string(),
                at_sign: 6
            }
        );
        assert_eq!(parsed.local_part(), "hello");
        assert_eq!(parsed.domain(), "domain.com");
    }

    #[test]
    fn serialize() {
        assert_eq!(
            serde_json::to_string(&Address {
                full: "hello@domain.com".to_string(),
                at_sign: 6
            })
            .unwrap(),
            r#""hello@domain.com""#
        );
    }

    #[test]
    fn domain() {
        let mut domain = Domain("www.john.doe.example.com");

        assert_eq!(domain.next(), Some("john.doe.example.com"));
        assert_eq!(domain.next(), Some("doe.example.com"));
        assert_eq!(domain.next(), Some("example.com"));
        assert_eq!(domain.next(), Some("com"));
        assert_eq!(domain.next(), None);
    }
}
