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
use super::AbstractIO;
use vsmtp_common::{mail_context::ConnectionContext, CodeID, ConnectionKind, Reply, ReplyOrCodeID};
use vsmtp_config::Config;

/// Instance containing connection to the server's information
pub struct Connection<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
{
    /// Kind of connection
    pub kind: ConnectionKind,
    /// Data related to this connection
    pub context: ConnectionContext,
    /// server's configuration
    pub config: std::sync::Arc<Config>,
    /// inner stream
    pub inner: AbstractIO<S>,
}

impl<S> std::fmt::Debug for Connection<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("context", &self.context)
            .field("kind", &self.kind)
            .finish()
    }
}

impl<S> Connection<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
{
    ///
    pub fn new(
        kind: ConnectionKind,
        client_addr: std::net::SocketAddr,
        server_addr: std::net::SocketAddr,
        config: std::sync::Arc<Config>,
        inner: S,
    ) -> Self {
        Self {
            context: ConnectionContext {
                timestamp: std::time::SystemTime::now(),
                client_addr,
                credentials: None,
                server_name: config.server.domain.clone(),
                server_addr,
                is_authenticated: false,
                is_secured: false,
                error_count: 0,
                authentication_attempt: 0,
            },
            config,
            inner: AbstractIO::new(inner),
            kind,
        }
    }
}

impl<S> Connection<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + std::fmt::Debug,
{
    ///
    /// # Errors
    ///
    /// * see [`Connection::send_code`] and [`Connection::send_reply`]
    pub async fn send_reply_or_code(&mut self, reply_or_code: ReplyOrCodeID) -> anyhow::Result<()> {
        match reply_or_code {
            ReplyOrCodeID::Left(code) => self.send_code(code).await,
            ReplyOrCodeID::Right(reply) => self.send_reply(reply).await,
        }
    }

    ///
    /// # Errors
    pub async fn send_code(&mut self, code_id: CodeID) -> anyhow::Result<()> {
        self.send_reply(
            self.config
                .server
                .smtp
                .codes
                .get(&code_id)
                .expect("config is ill-formed")
                .clone(),
        )
        .await
    }

    /// send a reply code to the client
    ///
    /// # Errors
    pub async fn send_reply(&mut self, reply: Reply) -> anyhow::Result<()> {
        if !reply.code().is_error() {
            self.send(&reply.fold()).await?;
            return Ok(());
        }
        self.context.error_count += 1;

        let hard_error = self.config.server.smtp.error.hard_count;
        let soft_error = self.config.server.smtp.error.soft_count;

        if hard_error != -1 && self.context.error_count >= hard_error {
            tracing::warn!(
                max = hard_error,
                "Hard error count max reached, closing connection."
            );
            self.send(
                &Reply::combine(
                    &reply,
                    self.config
                        .server
                        .smtp
                        .codes
                        .get(&CodeID::TooManyError)
                        .expect("config is ill-formed"),
                )
                .fold(),
            )
            .await?;
            tokio::io::AsyncWriteExt::flush(&mut self.inner.inner).await?;

            anyhow::bail!("{:?}", CodeID::TooManyError)
        }

        self.send(&reply.fold()).await?;

        if soft_error != -1 && self.context.error_count >= soft_error {
            tracing::warn!(
                max = soft_error,
                "Soft error max count reached, delaying connection."
            );
            tokio::time::sleep(self.config.server.smtp.error.delay).await;
        }
        Ok(())
    }

    /// Send a buffer
    ///
    /// # Errors
    ///
    /// * internal connection writer error
    pub async fn send(&mut self, reply: &str) -> anyhow::Result<()> {
        tracing::trace!(%reply);
        tokio::io::AsyncWriteExt::write_all(&mut self.inner.inner, reply.as_bytes()).await?;
        Ok(())
    }

    /// Read a line from the client
    ///
    /// # Errors
    ///
    /// * timed-out
    /// * internal connection reader error
    pub async fn read(
        &mut self,
        timeout: std::time::Duration,
    ) -> std::io::Result<Option<std::string::String>> {
        self.inner.next_line(Some(timeout)).await
    }
}
