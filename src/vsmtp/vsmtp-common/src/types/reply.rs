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

use crate::ReplyCode;

/// SMTP message send by the server to the client as defined in RFC5321#4.2
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    code: ReplyCode,
    text: Vec<String>,
    folded: String,
}

impl serde::Serialize for Reply {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.fold())
    }
}

impl<'de> serde::Deserialize<'de> for Reply {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ReplyVisitor;

        impl<'de> serde::de::Visitor<'de> for ReplyVisitor {
            type Value = Reply;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("[...]")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                <Reply as std::str::FromStr>::from_str(v).map_err(serde::de::Error::custom)
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                #[derive(serde::Deserialize)]
                #[serde(field_identifier, rename_all = "lowercase")]
                enum Field {
                    Code,
                    Enhanced,
                    Text,
                }

                let mut text: Option<String> = None;
                let mut code = None;
                let mut enhanced = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Code => {
                            if code.is_some() {
                                return Err(serde::de::Error::duplicate_field("code"));
                            }
                            code = Some(map.next_value()?);
                        }
                        Field::Text => {
                            if text.is_some() {
                                return Err(serde::de::Error::duplicate_field("text"));
                            }
                            text = Some(map.next_value()?);
                        }
                        Field::Enhanced => {
                            if enhanced.is_some() {
                                return Err(serde::de::Error::duplicate_field("enhanced"));
                            }
                            enhanced = Some(map.next_value()?);
                        }
                    }
                }
                let code = code.ok_or_else(|| serde::de::Error::missing_field("code"))?;

                let reply = Reply {
                    code: enhanced.map_or(ReplyCode::Code { code }, |enhanced| {
                        ReplyCode::Enhanced { code, enhanced }
                    }),
                    text: vec![text.ok_or_else(|| serde::de::Error::missing_field("text"))?],
                    folded: String::new(),
                };

                Ok(Reply {
                    folded: reply.fold(),
                    ..reply
                })
            }
        }

        deserializer.deserialize_any(ReplyVisitor)
    }
}

impl Reply {
    ///
    #[must_use]
    pub const fn code(&self) -> &ReplyCode {
        &self.code
    }

    fn fold(&self) -> String {
        let prefix = self.code.to_string();

        let mut output = self
            .text
            .iter()
            .map(|line| format!("{prefix} {line}"))
            .collect::<Vec<_>>();

        let len = output.len();
        for i in output.iter_mut().take(len - 1) {
            i.replace_range(3..4, "-");
        }
        if let Some(s) = output.get_mut(len - 1) {
            s.replace_range(3..4, " ");
        }

        output
            .into_iter()
            .flat_map(|mut l| {
                l.push_str("\r\n");
                l.chars().collect::<Vec<_>>()
            })
            .collect::<String>()
    }

    /// Create a new reply with:
    /// * `text` = `self.text` + `other.text`
    /// * `code` = `other.code`
    /// ```
    /// # use vsmtp_common::Reply;
    /// let first = "454 TLS not available due to temporary reason".parse::<Reply>().unwrap();
    /// let second = "451 Too many errors from the client".parse::<Reply>().unwrap();
    ///
    /// assert_eq!(
    ///   first.extended(&second).to_string(),
    ///   [
    ///     "451-TLS not available due to temporary reason\r\n",
    ///     "451 Too many errors from the client\r\n"
    ///   ].concat()
    /// );
    /// ```
    pub fn extended(mut self, other: &Self) -> Self {
        self.text.extend(other.text.iter().cloned());
        let reply = Self {
            code: match &other.code {
                ReplyCode::Code { code } => ReplyCode::Code { code: *code },
                ReplyCode::Enhanced { code, enhanced } => ReplyCode::Enhanced {
                    code: *code,
                    enhanced: enhanced.to_string(),
                },
            },
            text: self.text,
            folded: String::new(),
        };
        Self {
            folded: reply.fold(),
            ..reply
        }
    }
}

impl std::str::FromStr for Reply {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let x = s
            .split("\r\n")
            .filter(|s| !s.is_empty())
            .map(ReplyCode::from_str);

        let mut first_code = None;
        let mut text = vec![];

        for x in x {
            let (new_code, mut line) = x?;

            match (&first_code, new_code) {
                (Some(ReplyCode::Code { code: first }), ReplyCode::Code { code: new })
                    if *first == new => {}
                (
                    Some(ReplyCode::Enhanced {
                        code: first,
                        enhanced: first_enhanced,
                    }),
                    ReplyCode::Enhanced {
                        code: new,
                        enhanced: new_enhanced,
                    },
                ) if *first == new && *first_enhanced == new_enhanced => (),
                (Some(_), _) => anyhow::bail!("Reply codes are not consistent"),
                (None, anything) => first_code = Some(anything),
            }

            if !line.is_empty() {
                let c = line.remove(0);
                assert!(" -".contains(c));
            }
            text.push(line);
        }

        let reply = Self {
            code: first_code.unwrap(),
            text,
            folded: String::new(),
        };
        Ok(Self {
            folded: reply.fold(),
            ..reply
        })
    }
}

impl std::fmt::Display for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.folded)
    }
}

impl AsRef<str> for Reply {
    fn as_ref(&self) -> &str {
        &self.folded
    }
}

#[cfg(test)]
mod tests {
    use crate::{Reply, ReplyCode};

    #[rstest::rstest]
    #[case(
        &Reply {
            code: ReplyCode::Code { code: 501 },
            text: vec![String::new()],
            folded:  "501 \r\n".to_string(),
        }
    )]
    #[case(
        &Reply {
            code: ReplyCode::Code { code: 220,},
            text: vec!["this is a custom code.".to_string()],
            folded: "220 this is a custom code.\r\n".to_string(),
        }
    )]
    #[case(
        &Reply {
            code: ReplyCode::Enhanced { code: 504, enhanced: "5.5.4".to_string() },
            text: vec![String::new()],
            folded: "504 5.5.4 \r\n".to_string(),
        }
    )]
    #[case(
        &Reply {
            code: ReplyCode::Enhanced { code: 451, enhanced: "5.7.3".to_string() },
            text: vec!["STARTTLS is required to send mail".to_string()],
            folded: "451 5.7.3 STARTTLS is required to send mail\r\n".to_string(),
        }
    )]
    #[case(
        &Reply {
            code: ReplyCode::Code { code: 250, },
            text: vec![
                "mydomain.tld".to_string(),
                "PIPELINING".to_string(),
                "8BITMIME".to_string(),
                "AUTH PLAIN LOGIN".to_string(),
                "XCLIENT NAME HELO".to_string(),
                "XFORWARD NAME ADDR PROTO HELO".to_string(),
                "ENHANCEDSTATUSCODES".to_string(),
                "DSN".to_string(),
                String::new(),
            ],
            folded:  concat!(
                "250-mydomain.tld\r\n",
                "250-PIPELINING\r\n",
                "250-8BITMIME\r\n",
                "250-AUTH PLAIN LOGIN\r\n",
                "250-XCLIENT NAME HELO\r\n",
                "250-XFORWARD NAME ADDR PROTO HELO\r\n",
                "250-ENHANCEDSTATUSCODES\r\n",
                "250-DSN\r\n",
                "250 \r\n",
            ).to_string(),
        }
    )]
    #[case(
        &Reply {
            code: ReplyCode::Enhanced {
                code: 220,
                enhanced: "2.0.0".to_string(),
            },
            text: vec![
                "this is a long message, a very very long message ...".to_string(),
                " carriage return will be properly added automatically.".to_string(),
            ],
            folded: concat!(
                "220-2.0.0 this is a long message, a very very long message ...\r\n",
                "220 2.0.0  carriage return will be properly added automatically.\r\n",
            ).to_string(),
        }
    )]
    #[case(
        &Reply {
            code: ReplyCode::Enhanced {
                code: 220,
                enhanced: "2.0.0".to_string(),
            },
            text: vec![
                "this is a long message, a very very long message ... carriage return".to_string(),
                " will be properly added automatically. Made by vSMTP mail transfer a".to_string(),
                "gent\nCopyright (C) 2022 viridIT SAS".to_string(),
            ],
            folded: concat!(
                "220-2.0.0 this is a long message, a very very long message ... carriage return\r\n",
                "220-2.0.0  will be properly added automatically. Made by vSMTP mail transfer a\r\n",
                "220 2.0.0 gent\nCopyright (C) 2022 viridIT SAS\r\n",
            ).to_string(),
        }
    )]
    fn parse_reply(#[case] expected: &Reply) {
        let input: &str = expected.as_ref();
        for i in input.split("\r\n") {
            assert!(i.len() <= 78);
        }

        let output = input.parse::<Reply>().unwrap();
        pretty_assertions::assert_eq!(output, *expected);

        let fold = output.fold();
        pretty_assertions::assert_eq!(input, fold);
    }
}
