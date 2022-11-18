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
use crate::{receiver::ErrorCounter, ReceiverContext, ReceiverHandler};
use tokio::io::AsyncWriteExt;
use vsmtp_common::Reply;

pub struct Sink<W: tokio::io::AsyncWrite + Unpin + Send> {
    pub inner: W,
}

impl<W: tokio::io::AsyncWrite + Unpin + Send> Sink<W> {
    pub const fn new(tcp_sink: W) -> Self {
        Self { inner: tcp_sink }
    }

    async fn write_all(&mut self, buffer: &str) -> std::io::Result<()> {
        tracing::trace!(">> {:?}", buffer);
        self.inner.write_all(buffer.as_bytes()).await
    }

    pub async fn send_reply<T: ReceiverHandler + Send>(
        &mut self,
        ctx: &mut ReceiverContext,
        error_counter: &mut ErrorCounter,
        handler: &mut T,
        reply: Reply,
    ) -> std::io::Result<()> {
        if !reply.code().is_error() {
            return self.write_all(&reply.fold()).await;
        }
        error_counter.error_count += 1;

        let hard_error = error_counter.threshold_hard_error;
        let soft_error = error_counter.threshold_soft_error;

        if hard_error != -1 && error_counter.error_count >= hard_error {
            let reply = handler.on_hard_error(ctx, reply).await;
            return self.write_all(&reply.fold()).await;
        }

        if soft_error != -1 && error_counter.error_count >= soft_error {
            let reply = handler.on_soft_error(ctx, reply).await;
            return self.write_all(&reply.fold()).await;
        }

        self.write_all(&reply.fold()).await
    }
}
