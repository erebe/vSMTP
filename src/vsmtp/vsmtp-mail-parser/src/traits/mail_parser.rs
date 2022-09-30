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

use crate::{
    message::{mail::Mail, raw_body::RawBody},
    ParserResult,
};

/// An abstract mail parser
#[async_trait::async_trait]
pub trait MailParser: Default {
    /// From a buffer of strings, return either:
    ///
    /// * a RFC valid [`Mail`] object
    /// * a [`RawBody`] instance
    ///
    /// # Errors
    ///
    /// * the input is not compliant
    fn parse_sync(&mut self, raw: Vec<String>) -> ParserResult<either::Either<RawBody, Mail>>;

    ///
    /// # Errors
    ///
    /// * the input is not compliant
    async fn parse<'a>(
        &'a mut self,
        mut stream: impl tokio_stream::Stream<Item = String> + Unpin + Send + 'a,
    ) -> ParserResult<either::Either<RawBody, Mail>> {
        let mut buffer = vec![];

        while let Some(i) = tokio_stream::StreamExt::next(&mut stream).await {
            buffer.push(i);
        }

        self.parse_sync(buffer)
    }

    ///
    fn convert(mut self, input: &RawBody) -> ParserResult<Option<Mail>> {
        // TODO(perf):
        let raw = input.to_string();

        self.parse_sync(raw.lines().map(String::from).collect())
            .map(|either| match either {
                either::Left(_) => None,
                either::Right(mail) => Some(mail),
            })
    }
}
