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

/// Some mail systems modify email in transit, potentially invalidating a
/// signature.
///
/// To satisfy all requirements, two canonicalization algorithms are
/// defined for each of the header and the body
#[derive(Debug, Default, PartialEq, Eq, Copy, Clone, strum::EnumString, strum::Display)]
#[strum(serialize_all = "lowercase")]
#[allow(clippy::module_name_repetitions)]
pub(super) enum CanonicalizationAlgorithm {
    /// a "simple" algorithm that tolerates almost no modification
    #[default]
    Simple,
    /// a "relaxed" algorithm that tolerates common modifications
    /// such as whitespace replacement and header field line rewrapping.
    Relaxed,
}

impl CanonicalizationAlgorithm {
    fn dedup_whitespaces(s: &str) -> String {
        let mut new_str = s.to_owned();
        let mut prev = None;
        new_str.retain(|ch| {
            let result = ch != ' ' || prev != Some(' ');
            prev = Some(ch);
            result
        });
        new_str
    }

    pub(super) fn canonicalize_body(self, body: &str) -> String {
        match self {
            Self::Relaxed => {
                let mut s = Self::dedup_whitespaces(&body.replace('\t', " "));

                while let Some(idx) = s.find(" \r\n") {
                    s.remove(idx);
                }

                while s.ends_with("\r\n\r\n") {
                    s.remove(s.len() - 1);
                    s.remove(s.len() - 1);
                }

                if !s.is_empty() && !s.ends_with("\r\n") {
                    s.push('\r');
                    s.push('\n');
                }

                s
            }
            Self::Simple => {
                if body.is_empty() {
                    return "\r\n".to_string();
                }

                let mut i = body;
                while i.ends_with("\r\n\r\n") {
                    i = &i[..i.len() - 2];
                }

                i.to_string()
            }
        }
    }

    pub(super) fn canonicalize_headers(self, headers: &[String]) -> String {
        match self {
            Self::Relaxed => headers.iter().map(|s| self.canonicalize_header(s)).fold(
                String::new(),
                |mut acc, s| {
                    acc.push_str(&s);
                    acc.push_str("\r\n");
                    acc
                },
            ),
            Self::Simple => headers.iter().map(|s| self.canonicalize_header(s)).fold(
                String::new(),
                |mut acc, s| {
                    acc.push_str(&s);
                    acc
                },
            ),
        }
    }

    pub(super) fn canonicalize_header(self, header: &str) -> String {
        match self {
            Self::Relaxed => {
                let mut words = header.splitn(2, ':');
                match (words.next(), words.next()) {
                    (Some(key), Some(value)) => {
                        format!(
                            "{}:{}",
                            key.to_lowercase().trim_end(),
                            Self::dedup_whitespaces(&value.replace('\t', " ").replace("\r\n", " "))
                                .trim()
                        )
                    }
                    _ => todo!("handle this case: (not containing `:`) `{header}`"),
                }
            }
            Self::Simple => header.to_string(),
        }
    }
}

/// The algorithm used to canonicalize the message.
#[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
pub struct Canonicalization {
    /// The algorithm used to canonicalize the header.
    header: CanonicalizationAlgorithm,
    /// The algorithm used to canonicalize the body.
    body: CanonicalizationAlgorithm,
}

impl std::fmt::Display for Canonicalization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.header, self.body)
    }
}

impl std::str::FromStr for Canonicalization {
    type Err = strum::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (header, body) = s
            .split_once('/')
            .map_or_else(|| (s, None), |(k, v)| (k, Some(v)));

        Ok(Self {
            header: CanonicalizationAlgorithm::from_str(header)?,
            body: body.map_or(
                Ok(CanonicalizationAlgorithm::Simple),
                CanonicalizationAlgorithm::from_str,
            )?,
        })
    }
}

impl Canonicalization {
    #[cfg(test)]
    pub(super) const fn new(
        header: CanonicalizationAlgorithm,
        body: CanonicalizationAlgorithm,
    ) -> Self {
        Self { header, body }
    }

    pub(super) fn canonicalize_body(self, body: &str) -> String {
        self.body.canonicalize_body(body)
    }

    pub(super) fn canonicalize_headers(self, headers: &[String]) -> String {
        self.header.canonicalize_headers(headers)
    }

    pub(super) fn canonicalize_header(self, header: &str) -> String {
        self.header.canonicalize_header(header)
    }
}
