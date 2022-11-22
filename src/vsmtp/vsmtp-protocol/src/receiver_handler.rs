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
    receiver::ReceiverContext, stream::Error, AcceptArgs, AuthArgs, AuthError, EhloArgs, HeloArgs,
    MailFromArgs, ParseArgsError, RcptToArgs, UnparsedArgs, Verb,
};
// TODO: should we move these type in this crate
use vsmtp_common::{Reply, Stage};

// NOTE: could have 3 trait to make the implementation easier
// PreTransactionHandler + TransactionHandler + PostTransactionHandler

/// Trait to implement to handle the SMTP commands in pair with the [`Receiver`](crate::Receiver).
#[async_trait::async_trait]
pub trait ReceiverHandler {
    /// The [`Receiver`](crate::Receiver) does not store the context.
    /// This function is called after each command to get the context stage.
    fn get_stage(&self) -> Stage;

    /// Create an instance capable to handle the SASL handshake.
    fn generate_sasl_callback(&self) -> Box<dyn rsasl::callback::SessionCallback>;

    /// Called when the client connects to the server.
    async fn on_accept(&mut self, ctx: &mut ReceiverContext, args: AcceptArgs) -> Reply;

    /// Called after receiving a [`Verb::StartTls`] command.
    async fn on_starttls(&mut self, ctx: &mut ReceiverContext) -> Reply;

    /// Called after a successful TLS handshake.
    // TODO: take the tls config as argument
    async fn on_post_tls_handshake(&mut self, sni: Option<String>) -> Reply;

    /// Called after receiving a [`Verb::Auth`] command.
    async fn on_auth(&mut self, ctx: &mut ReceiverContext, args: AuthArgs) -> Option<Reply>;

    /// Called after a successful SASL handshake.
    async fn on_post_auth(
        &mut self,
        ctx: &mut ReceiverContext,
        result: Result<(), AuthError>,
    ) -> Reply;

    /// Called after receiving a [`Verb::Helo`] command.
    async fn on_helo(&mut self, ctx: &mut ReceiverContext, args: HeloArgs) -> Reply;

    /// Called after receiving a [`Verb::Ehlo`] command.
    async fn on_ehlo(&mut self, ctx: &mut ReceiverContext, args: EhloArgs) -> Reply;

    /// Called after receiving a [`Verb::MailFrom`] command.
    async fn on_mail_from(&mut self, ctx: &mut ReceiverContext, args: MailFromArgs) -> Reply;

    /// Called after receiving a [`Verb::RcptTo`] command.
    async fn on_rcpt_to(&mut self, ctx: &mut ReceiverContext, args: RcptToArgs) -> Reply;

    /// Called after receiving a [`Verb::Data`] command.
    /// The stream is the body of the message, with dot-stuffing handled.
    /// The stream return `None` when the message is finished (`.<CRLF>`).
    async fn on_message(
        &mut self,
        ctx: &mut ReceiverContext,
        stream: impl tokio_stream::Stream<Item = Result<Vec<u8>, Error>> + Send + Unpin,
    ) -> Reply;

    /// Called when the number of reply considered as error reached a threshold (hard).
    async fn on_hard_error(&mut self, ctx: &mut ReceiverContext, reply: Reply) -> Reply;

    /// Called when the number of reply considered as error reached a threshold (soft).
    async fn on_soft_error(&mut self, ctx: &mut ReceiverContext, reply: Reply) -> Reply;

    /// Called after receiving a [`Verb::Rset`] command.
    async fn on_rset(&mut self) -> Reply;

    /// Called after receiving a [`Verb::Data`] command.
    async fn on_data(&mut self) -> Reply {
        "354 Start mail input; end with <CRLF>.<CRLF>\r\n"
            .parse()
            .unwrap()
    }

    /// Called after receiving a [`Verb::Quit`] command.
    async fn on_quit(&mut self) -> Reply {
        "221 Service closing transmission channel".parse().unwrap()
    }

    /// Called after receiving a [`Verb::Noop`] command.
    async fn on_noop(&mut self) -> Reply {
        "250 Ok\r\n".parse().unwrap()
    }

    /// Called after receiving a [`Verb::Help`] command.
    async fn on_help(&mut self, _: UnparsedArgs) -> Reply {
        "214 joining us https://viridit.com/support"
            .parse()
            .unwrap()
    }

    /// Called after receiving an unknown command (unrecognized or unimplemented).
    async fn on_unknown(&mut self, buffer: Vec<u8>) -> Reply {
        let unimplemented_command = [b"VRFY" as &[u8], b"EXPN" as &[u8], b"TURN" as &[u8]];

        if unimplemented_command
            .iter()
            .any(|c| buffer.len() >= c.len() && buffer[..c.len()].eq_ignore_ascii_case(c))
        {
            "502 Command not implemented\r\n".parse().unwrap()
        } else {
            "500 Syntax error command unrecognized\r\n".parse().unwrap()
        }
    }

    /// Called when the stage of the transaction (obtained with [`get_stage`](Self::get_stage))
    /// and the command are not compatible.
    async fn on_bad_sequence(&mut self, _: (Verb, Stage)) -> Reply {
        "503 Bad sequence of commands\r\n".parse().unwrap()
    }

    /// Called when an argument of a command is invalid.
    async fn on_args_error(&mut self, _: ParseArgsError) -> Reply {
        "501 Syntax error in parameters or arguments\r\n"
            .parse()
            .unwrap()
    }
}
