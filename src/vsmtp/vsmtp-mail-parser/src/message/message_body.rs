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

use crate::{implementation::basic_parser::BasicParser, Mail, MailParser, RawBody};

// NOTE: should it be a tristate enum?
// enum {
//   Raw(Vec<u8>),
//   Fast { raw: Vec<u8>, headers: Vec<String>, body: Vec<u8> },
//   Parsed { raw: Vec<u8>, mail: Mail },
// }
/// Message body issued by a SMTP transaction
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct MessageBody {
    raw: RawBody,
    parsed: Option<Mail>,
}

impl From<either::Either<RawBody, Mail>> for MessageBody {
    fn from(this: either::Either<RawBody, Mail>) -> Self {
        match this {
            either::Left(raw) => Self { raw, parsed: None },
            either::Right(_parsed) => todo!(),
        }
    }
}

impl TryFrom<&str> for MessageBody {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut bytes = vec![];
        let splitted = value.split("\r\n").collect::<Vec<_>>();
        for (idx, mut line) in splitted.iter().map(|l| l.as_bytes().to_vec()).enumerate() {
            bytes.push({
                if idx != splitted.len() - 1 {
                    line.extend_from_slice(b"\r\n");
                }
                line
            });
        }

        Ok(Self {
            raw: BasicParser::default().parse_sync(bytes)?.unwrap_left(),
            parsed: None,
        })
    }
}

impl MessageBody {
    ///
    #[must_use]
    pub fn new(headers: Vec<String>, body: String) -> Self {
        Self {
            raw: RawBody::new(headers, body),
            parsed: None,
        }
    }

    ///
    #[must_use]
    pub const fn inner(&self) -> &RawBody {
        &self.raw
    }

    /// Get the parsed part
    #[must_use]
    pub const fn get_parsed(&self) -> &Option<Mail> {
        &self.parsed
    }

    /// get the value of an header, return None if it does not exists or when the body is empty.
    #[must_use]
    pub fn get_header(&self, name: &str) -> Option<String> {
        let header = self.parsed.as_ref().map_or_else(
            || self.raw.get_header(name, false),
            |p| p.get_header(name).map(str::to_string),
        );
        header
            .as_ref()
            .map(|header| header.strip_suffix("\r\n").unwrap_or(header))
            .map(str::to_string)
    }

    /// Count the number of headers with the given name.
    #[must_use]
    pub fn count_header(&self, name: &str) -> usize {
        self.parsed
            .as_ref()
            .map_or_else(|| self.raw.count_header(name), |p| p.count_header(name))
    }

    /// rewrite a header with a new value or add it to the header section.
    pub fn set_header(&mut self, name: &str, value: &str) {
        if let Some(parsed) = &mut self.parsed {
            parsed.set_header(name, &format!("{value}\r\n"));
        }

        self.raw.set_header(name, &format!("{value}\r\n"));
    }

    /// Rename a header.
    pub fn rename_header(&mut self, old: &str, new: &str) {
        if let Some(parsed) = &mut self.parsed {
            parsed.rename_header(old, new);
        }

        self.raw.rename_header(old, new);
    }

    /// push a header to the header section.
    ///
    /// push back
    pub fn append_header(&mut self, name: &str, value: &str) {
        if let Some(parsed) = &mut self.parsed {
            parsed.push_headers([(name.to_string(), value.to_string())]);
        }

        self.raw.add_header(name, &format!("{value}\r\n"));
    }

    /// prepend a header to the header section.
    ///
    /// push front
    // FIXME: fold this header.
    pub fn prepend_header(&mut self, name: &str, value: &str) {
        if let Some(parsed) = &mut self.parsed {
            parsed.prepend_headers([(name.to_string(), value.to_string())]);
        }

        self.raw.prepend_header([format!("{name}: {value}\r\n")]);
    }

    /// Remove a header from the list.
    pub fn remove_header(&mut self, name: &str) -> bool {
        if let Some(parsed) = &mut self.parsed {
            // NOTE: the result for a parsed email is ignored.
            parsed.remove_header(name);
        }

        self.raw.remove_header(name)
    }

    /// # Errors
    ///
    /// * the value produced by the [`MailParser`] was not a parsed [`Mail`]
    /// * Fail to parse using the provided [`MailParser`]
    pub fn parse<P: MailParser>(&mut self) -> anyhow::Result<()> {
        self.parsed = Some(
            P::default()
                .convert(&self.raw)?
                .ok_or_else(|| anyhow::anyhow!("the parser did not produced a `Mail` part."))?,
        );
        Ok(())
    }

    /// # Errors
    ///
    /// * error from [`Self::parse`]
    pub fn parsed<P: MailParser>(&mut self) -> anyhow::Result<&mut Mail> {
        if self.parsed.is_some() {
            return Ok(self.parsed.as_mut().expect(""));
        }
        self.parse::<P>()?;
        self.parsed::<P>()
    }
}
