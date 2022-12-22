//! vSMTP server

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

#![doc(html_no_source)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
//
#![warn(rust_2018_idioms)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(clippy::cargo)]
//
#![allow(clippy::use_self)]

mod channel_message;
mod delivery;
mod on_mail;
mod processing;
mod runtime;
mod server;

mod receiver {
    pub mod handler;
    mod post_transaction;
    pub mod pre_transaction;
}

pub use channel_message::ProcessMessage;
pub use on_mail::{MailHandler, OnMail};
pub use receiver::handler::Handler;
pub use receiver::pre_transaction::ValidationVSL;
pub use runtime::start_runtime;
pub use server::{socket_bind_anyhow, Server};

use anyhow::Context;
use vsmtp_common::transfer::SmtpConnection;
use vsmtp_common::ContextFinished;
use vsmtp_mail_parser::MessageBody;

/// tag for a specific email process.
#[derive(Debug, strum::Display)]
pub enum Process {
    /// The server handle clients, parse commands & store emails at this stage.
    Receiver,
    /// The server handle emails "offline", the client is no longer communicating.
    Processing,
    /// The server is going to deliver the email locally or to another server.
    Delivery,
}

/// delegate a message to another service.
pub(crate) fn delegate(
    delegator: &SmtpConnection,
    context: &ContextFinished,
    message: &MessageBody,
) -> anyhow::Result<lettre::transport::smtp::response::Response> {
    use lettre::Transport;

    let envelope = lettre::address::Envelope::new(
        match context.mail_from.reverse_path {
            Some(ref reverse_path) => Some(
                reverse_path
                    .full()
                    .parse::<lettre::Address>()
                    .context("cannot parse address")?,
            ),
            None => None,
        },
        context
            .rcpt_to
            .forward_paths
            .iter()
            .map(|rcpt| {
                rcpt.address
                    .full()
                    .parse::<lettre::Address>()
                    .with_context(|| format!("failed to parse address {}", rcpt.address.full()))
            })
            .collect::<anyhow::Result<Vec<_>>>()?,
    )?;

    delegator
        .0
        .lock()
        .unwrap()
        .send_raw(&envelope, message.inner().to_string().as_bytes())
        .context("failed to delegate email")
}
