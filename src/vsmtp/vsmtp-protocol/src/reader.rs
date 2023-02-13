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

use crate::{command::Command, Error, UnparsedArgs, Verb};
use tokio::io::AsyncReadExt;
use vsmtp_common::Reply;

fn find(bytes: &[u8], search: &[u8]) -> Option<usize> {
    bytes
        .windows(search.len())
        .position(|window| window == search)
}

/// Stream for reading commands from the client.
pub struct Reader<R: tokio::io::AsyncRead + Unpin + Send> {
    pub(super) inner: R,
    initial_capacity: usize,
    additional_reserve: usize,
}

// TODO: handle PIPELINING
impl<R: tokio::io::AsyncRead + Unpin + Send> Reader<R> {
    /// Create a new stream.
    #[must_use]
    #[inline]
    pub const fn new(tcp_stream: R) -> Self {
        Self {
            inner: tcp_stream,
            initial_capacity: 80,
            additional_reserve: 100,
        }
    }

    /// Produce a stream of "\r\n" terminated lines.
    #[inline]
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

    /// Produce a stream of lines to generate IMF compliant messages.
    #[inline]
    pub fn as_message_stream(
        &mut self,
        size_limit: usize,
    ) -> impl tokio_stream::Stream<Item = Result<Vec<u8>, Error>> + '_ {
        async_stream::stream! {
            let mut size = 0;

            for await line in self.as_line_stream() {
                let mut line = line?;
                tracing::trace!("<< {:?}", std::str::from_utf8(&line));

                if line == b".\r\n" {
                    return;
                } else {
                    if line.first() == Some(&b'.') {
                        line = line[1..].to_vec();
                    }

                    // TODO: handle line length max ?

                    size += line.len();
                    if size >= size_limit {
                        yield Err(Error::BufferTooLong { expected: size_limit, got: size });
                        return;
                    }

                    yield Ok(line);
                }
            }
        }
    }

    /// Produce a stream of ESMTP commands.
    #[inline]
    pub fn as_command_stream(
        &mut self,
    ) -> impl tokio_stream::Stream<Item = Result<Command<Verb, UnparsedArgs>, Error>> + '_ {
        async_stream::stream! {
            for await line in self.as_line_stream() {
                let line = line?;

                // TODO: put value as a parameter
                if line.len() >= 512 {
                    yield Err(Error::BufferTooLong { expected: 512, got: line.len() });
                    return;
                }

                yield Ok(<Verb as strum::VariantNames>::VARIANTS.iter().find(|i| {
                    line.len() >= i.len() && line[..i.len()].eq_ignore_ascii_case(i.as_bytes())
                }).map_or_else(
                    || (Verb::Unknown, UnparsedArgs(line.clone())),
                    |verb| { (
                        verb.parse().expect("verb found above"),
                        UnparsedArgs(line[verb.len()..].to_vec()),
                    ) },
                ));
            }
        }
    }

    /// Produce a stream of SMTP replies.
    #[inline]
    pub fn as_reply_stream(
        &mut self,
    ) -> impl tokio_stream::Stream<Item = Result<Reply, Error>> + '_ {
        use tokio_stream::StreamExt;

        async_stream::stream! {
            let line_stream = self.as_line_stream();
            tokio::pin!(line_stream);

            loop {
                let mut next_reply = Vec::with_capacity(512);

                loop {
                    let new_line = line_stream.next().await;
                    let new_line = match new_line {
                        Some(new_line) => new_line?,
                        None => return,
                    };

                    next_reply.extend_from_slice(&new_line);
                    if new_line.get(3) == Some(&b' ') {
                        break;
                    }
                }

                let next_reply = std::str::from_utf8(&next_reply);
                tracing::trace!("<< {:?}", next_reply);
                yield <Reply as std::str::FromStr>::from_str(next_reply?).map_err(|_| todo!());
            }
        }
    }
}
