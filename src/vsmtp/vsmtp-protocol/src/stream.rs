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

use crate::{command::Command, UnparsedArgs, Verb};
use tokio::io::AsyncReadExt;

fn find(bytes: &[u8], search: &[u8]) -> Option<usize> {
    bytes
        .windows(search.len())
        .position(|window| window == search)
}

pub struct Stream<R: tokio::io::AsyncRead + Unpin + Send> {
    pub(super) inner: R,
    initial_capacity: usize,
    additional_reserve: usize,
}

// TODO: handle PIPELINING
// TODO: handle line length max
impl<R: tokio::io::AsyncRead + Unpin + Send> Stream<R> {
    #[must_use]
    pub const fn new(tcp_stream: R) -> Self {
        Self {
            inner: tcp_stream,
            initial_capacity: 80,
            additional_reserve: 100,
        }
    }

    pub fn as_line_stream(
        &mut self,
    ) -> impl tokio_stream::Stream<Item = std::io::Result<Vec<u8>>> + '_ {
        async_stream::try_stream! {
            let mut buffer = bytes::BytesMut::with_capacity(self.initial_capacity);
            let mut n = 0;

            loop {
                if let Some(pos) = find(&buffer[..n], b"\r\n") {
                    let out = buffer.split_to(pos + 2);
                    n -= out.len();

                    // PIPELINING: handle buffer here
                    // TODO: should we return the extra bytes read?

                    yield Vec::<u8>::from(out);
                } else {
                    buffer.reserve(self.additional_reserve);
                    let read_size = self.inner.read_buf(&mut buffer).await?;
                    if read_size == 0 {
                        if !buffer.is_empty() {
                            todo!("what about the remaining buffer? {:?}", buffer);
                        }
                        return;
                    }
                    n += read_size;
                }
            }
        }
    }

    pub fn as_message_stream(
        &mut self,
        size_limit: usize,
    ) -> impl tokio_stream::Stream<Item = std::io::Result<Vec<u8>>> + '_ {
        async_stream::stream! {
            let mut size = 0;

            for await line in self.as_line_stream() {
                let mut line = match line {
                    Ok(line) => line,
                    Err(err) => {
                        yield Err(err);
                        return;
                    }
                };

                if line == b".\r\n" {
                    return;
                } else {
                    if line.first() == Some(&b'.') {
                        line = line[1..].to_vec();
                    }

                    size += line.len();
                    if size >= size_limit {
                        yield Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "message size limit reached"
                        ));
                        return;
                    }

                    yield Ok(line);
                }
            }
        }
    }

    // TODO: handle line len max
    pub fn as_command_stream(
        &mut self,
    ) -> impl tokio_stream::Stream<Item = std::io::Result<Command<Verb, UnparsedArgs>>> + '_ {
        async_stream::try_stream! {
            for await line in self.as_line_stream() {
                let line = line?;

                let verb_parsed = <Verb as strum::VariantNames>::VARIANTS.iter().find(|i| {
                    if line.len() < i.len() {
                        return false;
                    }
                    line[..i.len()].eq_ignore_ascii_case(i.as_bytes())
                });

                yield verb_parsed.map_or_else(
                    || (Verb::Unknown, UnparsedArgs(line.clone())),
                    |verb_parsed| { (
                        verb_parsed.parse().expect("verb found above"),
                        UnparsedArgs(line[verb_parsed.len()..].to_vec()),
                    ) },
                );
            }
        }
    }
}
