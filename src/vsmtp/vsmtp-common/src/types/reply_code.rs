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

/// Codes as the start of each lines of a reply
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(untagged)]
pub enum ReplyCode {
    /// simple Reply Code as defined in RFC5321
    Code {
        // https://datatracker.ietf.org/doc/html/rfc5321#section-4.2
        // NOTE: could be a struct with 3 digits
        /// code base
        code: u16,
    },
    /// enhanced codes
    Enhanced {
        // https://datatracker.ietf.org/doc/html/rfc5321#section-4.2
        // NOTE: could be a struct with 3 digits
        /// code base
        code: u16,
        ///
        // NOTE: could be a struct with 3 digits
        enhanced: String,
    },
}

const ENHANCED: i32 = 0;
const SIMPLE: i32 = 1;

impl ReplyCode {
    ///
    #[must_use]
    pub fn is_error(&self) -> bool {
        match self {
            Self::Code { code, .. } | Self::Enhanced { code, .. } => code / 100 >= 4,
        }
    }

    /// Return the underlying value of the reply code
    #[must_use]
    pub fn value(&self) -> u16 {
        match self {
            Self::Code { code, .. } | Self::Enhanced { code, .. } => *code,
        }
    }

    /// Return the enhanced value of the reply code
    #[must_use]
    pub fn details(&self) -> Option<&str> {
        match self {
            Self::Enhanced { enhanced, .. } => Some(enhanced),
            Self::Code { .. } => None,
        }
    }

    fn try_parse(which: i32, words: &[&str]) -> Option<Self> {
        match (which, words) {
            (ENHANCED, [_, "", ..]) => None,
            (ENHANCED, [code, enhanced, ..]) => {
                let mut enhanced = enhanced.splitn(3, '.').map(str::parse::<u16>);

                let (a, b, c) = (
                    enhanced.next()?.ok()?,
                    enhanced.next()?.ok()?,
                    enhanced.next()?.ok()?,
                );

                Some(Self::Enhanced {
                    code: match Self::try_parse(SIMPLE, &[code])? {
                        Self::Code { code, .. } => code,
                        Self::Enhanced { .. } => unreachable!(),
                    },
                    enhanced: format!("{a}.{b}.{c}"),
                })
            }
            (SIMPLE, [code, ..]) => Some(Self::Code {
                code: code.parse::<u16>().ok()?,
            }),
            _ => None,
        }
    }

    pub(super) fn from_str(s: &str) -> anyhow::Result<(Self, String)> {
        for i in ENHANCED..=SIMPLE {
            let words = s.split([' ', '-']).collect::<Vec<&str>>();
            if let Some(code) = Self::try_parse(i, words.as_slice()) {
                // FIXME: do not need to_string().len(), make a get_length() method
                let code_len = code.to_string().len();

                return Ok((code, s[code_len..].to_string()));
            }
        }

        anyhow::bail!("cannot parse {s:?}")
    }
}

impl std::fmt::Display for ReplyCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Code { code } => f.write_fmt(format_args!("{code}")),
            Self::Enhanced { code, enhanced } => f.write_fmt(format_args!("{code} {enhanced}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ReplyCode;

    // NOTE: if the separator is `-`, it will not be included in the output of `ReplyCode::to_string()`
    // but is handled correctly in `Reply::to_string()`
    #[rstest::rstest]
    #[case(
        "250",
        (&ReplyCode::Code { code: 250 }, ""),
        "250"
    )]
    #[case(
        "504 5.5.4",
        (&ReplyCode::Enhanced {
            code: 504,
            enhanced: "5.5.4".to_string(),
        },
        ""),
        "504 5.5.4",
    )]
    #[case(
        "250-2.0.0",
        (&ReplyCode::Enhanced {
            code: 250,
            enhanced: "2.0.0".to_string(),
        },
        ""),
        "250 2.0.0",
    )]
    #[case(
        "250 ",
        (&ReplyCode::Code { code: 250 }, " "),
        "250"
    )]
    #[case(
        "504 5.5.4 ",
        (&ReplyCode::Enhanced {
            code: 504,
            enhanced: "5.5.4".to_string(),
        },
        " "),
        "504 5.5.4",
    )]
    #[case(
        "250-2.0.0 ",
        (&ReplyCode::Enhanced {
            code: 250,
            enhanced: "2.0.0".to_string(),
        },
        " "),
        "250 2.0.0",
    )]
    fn parse_reply(
        #[case] input: &str,
        #[case] expected: (&ReplyCode, &str),
        #[case] to_string: &str,
    ) {
        let (code, message) = ReplyCode::from_str(input).unwrap();
        pretty_assertions::assert_eq!(code, *expected.0);
        pretty_assertions::assert_eq!(code.to_string(), to_string);
        pretty_assertions::assert_eq!(message, expected.1);
    }
}
