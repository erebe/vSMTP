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
use crate::{auth::Credentials, rcpt::Rcpt, status::Status, Address};
use vsmtp_auth::{dkim, spf};

///
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct TlsProperties {}

///
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct AuthProperties {
    ///
    pub credentials: Credentials,
}

macro_rules! state_smtp_impl {
    ($state:tt) => {
        impl StateSMTP for $state {
            fn as_str() -> &'static str {
                stringify!($state)
            }
        }
    };
}

///
pub trait StateSMTP: std::fmt::Debug + Clone {
    /// return the string version of the state.
    fn as_str() -> &'static str;
}

///
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct MailContext<State: StateSMTP> {
    #[serde(flatten)]
    state: State,
}

impl<State: StateSMTP> MailContext<State> {
    ///
    #[must_use]
    pub const fn empty() -> MailContext<Empty> {
        MailContext { state: Empty {} }
    }

    ///
    #[must_use]
    pub fn connect(
        client_addr: std::net::SocketAddr,
        server_addr: std::net::SocketAddr,
        server_name: String,
    ) -> MailContext<Connect> {
        MailContext::<Connect> {
            state: Connect {
                connect_timestamp: time::OffsetDateTime::now_utc(),
                client_addr,
                server_addr,
                server_name,
                skipped: None,
                tls: None,
                auth: None,
            },
        }
    }
}

impl MailContext<Connect> {
    ///
    #[allow(clippy::missing_const_for_fn)]
    #[must_use]
    pub fn helo(self, client_name: String) -> MailContext<Helo> {
        MailContext::<Helo> {
            state: Helo {
                connect: self.state,
                client_name,
            },
        }
    }

    ///
    #[allow(clippy::missing_const_for_fn)]
    #[must_use]
    pub fn take_connect(self) -> Connect {
        self.state
    }

    ///
    #[must_use]
    pub const fn connection_timestamp(&self) -> &time::OffsetDateTime {
        &self.state.connect_timestamp
    }

    ///
    pub fn set_skipped(&mut self, skipped: Option<Status>) {
        self.state.skipped = skipped;
    }

    ///
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.state.server_name
    }

    const fn server_addr(&self) -> &std::net::SocketAddr {
        &self.state.server_addr
    }

    const fn client_addr(&self) -> &std::net::SocketAddr {
        &self.state.client_addr
    }
}

impl MailContext<Helo> {
    ///
    #[allow(clippy::missing_const_for_fn)]
    #[must_use]
    pub fn mail_from(self, reverse_path: Address, outgoing: bool) -> MailContext<MailFrom> {
        let now = time::OffsetDateTime::now_utc();
        let message_id = new_message_id(self.state.connect.connect_timestamp);

        MailContext::<MailFrom> {
            state: MailFrom {
                helo: self.state,
                reverse_path,
                mail_timestamp: now,
                message_id,
                outgoing,
            },
        }
    }

    ///
    #[allow(clippy::missing_const_for_fn)]
    #[must_use]
    pub fn take_connect(self) -> Connect {
        self.state.connect
    }

    ///
    #[must_use]
    pub const fn connection_timestamp(&self) -> &time::OffsetDateTime {
        &self.state.connect.connect_timestamp
    }

    /// Get the name of the client emitting this mail (HELO/EHLO).
    #[must_use]
    pub fn client_name(&self) -> &str {
        &self.state.client_name
    }

    ///
    pub fn set_skipped(&mut self, skipped: Option<Status>) {
        self.state.connect.skipped = skipped;
    }

    ///
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.state.connect.server_name
    }

    const fn server_addr(&self) -> &std::net::SocketAddr {
        &self.state.connect.server_addr
    }

    const fn client_addr(&self) -> &std::net::SocketAddr {
        &self.state.connect.client_addr
    }
}

impl MailContext<MailFrom> {
    ///
    #[allow(clippy::missing_const_for_fn)]
    #[must_use]
    pub fn rcpt_to(self, forward_path: Vec<Rcpt>) -> MailContext<RcptTo> {
        MailContext::<RcptTo> {
            state: RcptTo {
                mail_from: self.state,
                forward_path,
            },
        }
    }

    ///
    #[allow(clippy::missing_const_for_fn)]
    #[must_use]
    pub fn take_connect(self) -> Connect {
        self.state.helo.connect
    }

    ///
    #[must_use]
    pub const fn connection_timestamp(&self) -> &time::OffsetDateTime {
        &self.state.helo.connect.connect_timestamp
    }

    /// Get the unique message ID associated with this mail.
    #[must_use]
    pub fn message_id(&self) -> &str {
        &self.state.message_id
    }

    /// Re-generate the message id.
    pub fn generate_message_id(&mut self) {
        self.state.message_id = new_message_id(self.state.helo.connect.connect_timestamp);
    }

    ///
    #[must_use]
    pub const fn mail_timestamp(&self) -> &time::OffsetDateTime {
        &self.state.mail_timestamp
    }

    /// Get the name of the client emitting this mail (HELO/EHLO).
    #[must_use]
    pub fn client_name(&self) -> &str {
        &self.state.helo.client_name
    }

    ///
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.state.helo.connect.server_name
    }

    const fn server_addr(&self) -> &std::net::SocketAddr {
        &self.state.helo.connect.server_addr
    }

    const fn client_addr(&self) -> &std::net::SocketAddr {
        &self.state.helo.connect.client_addr
    }

    /// Is the current transaction is outgoing from one of our domain or incoming from an unknown domain ?
    #[must_use]
    pub const fn is_outgoing(&self) -> bool {
        self.state.outgoing
    }

    ///
    pub fn set_skipped(&mut self, skipped: Option<Status>) {
        self.state.helo.connect.skipped = skipped;
    }

    ///
    pub fn set_outgoing(&mut self, is_outgoing: bool) {
        self.state.outgoing = is_outgoing;
    }

    ///
    #[must_use]
    pub const fn reverse_path(&self) -> &Address {
        &self.state.reverse_path
    }
}

impl MailContext<RcptTo> {
    ///
    #[allow(clippy::missing_const_for_fn)]
    #[must_use]
    pub fn finish(self) -> MailContext<Finished> {
        MailContext::<Finished> {
            state: Finished {
                rcpt_to: self.state,
                dkim: None,
                spf: None,
            },
        }
    }

    ///
    #[allow(clippy::missing_const_for_fn)]
    #[must_use]
    pub fn take_connect(self) -> Connect {
        self.state.mail_from.helo.connect
    }

    ///
    #[must_use]
    pub const fn connection_timestamp(&self) -> &time::OffsetDateTime {
        &self.state.mail_from.helo.connect.connect_timestamp
    }

    /// Get the unique message ID associated with this mail.
    #[must_use]
    pub fn message_id(&self) -> &str {
        &self.state.mail_from.message_id
    }

    /// Re-generate the message id.
    pub fn generate_message_id(&mut self) {
        self.state.mail_from.message_id =
            new_message_id(self.state.mail_from.helo.connect.connect_timestamp);
    }

    ///
    #[must_use]
    pub const fn mail_timestamp(&self) -> &time::OffsetDateTime {
        &self.state.mail_from.mail_timestamp
    }

    /// Get the name of the client emitting this mail (HELO/EHLO).
    #[must_use]
    pub fn client_name(&self) -> &str {
        &self.state.mail_from.helo.client_name
    }

    ///
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.state.mail_from.helo.connect.server_name
    }

    const fn server_addr(&self) -> &std::net::SocketAddr {
        &self.state.mail_from.helo.connect.server_addr
    }

    const fn client_addr(&self) -> &std::net::SocketAddr {
        &self.state.mail_from.helo.connect.client_addr
    }

    ///
    #[must_use]
    pub const fn is_outgoing(&self) -> bool {
        self.state.mail_from.outgoing
    }

    ///
    pub fn set_skipped(&mut self, skipped: Option<Status>) {
        self.state.mail_from.helo.connect.skipped = skipped;
    }

    ///
    #[must_use]
    pub const fn reverse_path(&self) -> &Address {
        &self.state.mail_from.reverse_path
    }

    ///
    #[must_use]
    pub const fn forward_paths(&self) -> &Vec<Rcpt> {
        &self.state.forward_path
    }
}

impl MailContext<Finished> {
    ///
    #[allow(clippy::missing_const_for_fn)]
    #[must_use]
    pub fn take_connect(self) -> Connect {
        self.state.rcpt_to.mail_from.helo.connect
    }

    ///
    #[must_use]
    pub const fn connection_timestamp(&self) -> &time::OffsetDateTime {
        &self.state.rcpt_to.mail_from.helo.connect.connect_timestamp
    }

    /// Get the unique message ID associated with this mail.
    #[must_use]
    pub fn message_id(&self) -> &str {
        &self.state.rcpt_to.mail_from.message_id
    }

    ///
    pub fn set_message_id(&mut self, message_id: String) {
        self.state.rcpt_to.mail_from.message_id = message_id;
    }

    ///
    #[must_use]
    pub const fn mail_timestamp(&self) -> &time::OffsetDateTime {
        &self.state.rcpt_to.mail_from.mail_timestamp
    }

    /// Get the name of the client emitting this mail (HELO/EHLO).
    #[must_use]
    pub fn client_name(&self) -> &str {
        &self.state.rcpt_to.mail_from.helo.client_name
    }

    ///
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.state.rcpt_to.mail_from.helo.connect.server_name
    }

    const fn server_addr(&self) -> &std::net::SocketAddr {
        &self.state.rcpt_to.mail_from.helo.connect.server_addr
    }

    const fn client_addr(&self) -> &std::net::SocketAddr {
        &self.state.rcpt_to.mail_from.helo.connect.client_addr
    }

    ///
    #[must_use]
    pub const fn is_outgoing(&self) -> bool {
        self.state.rcpt_to.mail_from.outgoing
    }

    ///
    #[must_use]
    pub const fn reverse_path(&self) -> &Address {
        &self.state.rcpt_to.mail_from.reverse_path
    }

    ///
    #[must_use]
    pub const fn forward_paths(&self) -> &Vec<Rcpt> {
        &self.state.rcpt_to.forward_path
    }

    ///
    #[must_use]
    pub fn forward_paths_mut(&mut self) -> &mut Vec<Rcpt> {
        &mut self.state.rcpt_to.forward_path
    }

    ///
    pub fn set_skipped(&mut self, skipped: Option<Status>) {
        self.state.rcpt_to.mail_from.helo.connect.skipped = skipped;
    }

    ///
    #[must_use]
    pub const fn skipped(&self) -> Option<&Status> {
        self.state.rcpt_to.mail_from.helo.connect.skipped.as_ref()
    }

    ///
    pub fn set_forward_paths(&mut self, rcpt: Vec<Rcpt>) {
        self.state.rcpt_to.forward_path = rcpt;
    }
}

///
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Empty {}

///
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Connect {
    /// timestamp of the connection TCP/IP
    #[serde(with = "time::serde::iso8601")]
    pub connect_timestamp: time::OffsetDateTime,
    /// TCP/IP address of the client
    pub client_addr: std::net::SocketAddr,
    /// TCP/IP address of the server
    pub server_addr: std::net::SocketAddr,
    /// Name serving the connection
    pub server_name: String,
    /// whether further rule analysis has been skipped.
    pub skipped: Option<Status>,
    /// if tunnel TLS
    pub tls: Option<TlsProperties>,
    /// if authentication
    pub auth: Option<AuthProperties>,
}

///
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Helo {
    #[serde(flatten)]
    connect: Connect,
    // Name
    // send by the client with HELO/EHLO command (domain / ip4|6)
    client_name: String,
}

///
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct MailFrom {
    #[serde(flatten)]
    helo: Helo,
    /// Mailbox of the sender
    /// send by the client with MAIL FROM command (email address)
    reverse_path: Address,
    //
    #[serde(with = "time::serde::iso8601")]
    mail_timestamp: time::OffsetDateTime,

    /// unique id generated when the "MAIL FROM" has been received.
    /// format: {mail timestamp}{connection timestamp}{process id}
    // TODO: use uuid format
    message_id: String,

    /// true if outgoing, otherwise incoming.
    outgoing: bool,
}

///
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct RcptTo {
    #[serde(flatten)]
    mail_from: MailFrom,
    // Mailbox of the recipients
    // send by the client with RCPT TO command (email address)
    forward_path: Vec<Rcpt>,
}

///
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Finished {
    #[serde(flatten)]
    rcpt_to: RcptTo,
    // Result of the DKIM verification
    dkim: Option<dkim::VerificationResult>,
    // Result of the SPF verification
    spf: Option<spf::Result>,
}

state_smtp_impl!(Empty);
state_smtp_impl!(Connect);
state_smtp_impl!(Helo);
state_smtp_impl!(MailFrom);
state_smtp_impl!(RcptTo);
state_smtp_impl!(Finished);

///
// using an enum instead of MailContext<Box<dyn StateSMTP>>
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub enum MailContextAPI {
    ///
    Empty(MailContext<Empty>),
    ///
    Connect(MailContext<Connect>),
    ///
    Helo(MailContext<Helo>),
    ///
    MailFrom(MailContext<MailFrom>),
    ///
    RcptTo(MailContext<RcptTo>),
    ///
    Finished(MailContext<Finished>),
}

///
#[derive(Debug, Default, thiserror::Error)]
pub enum Error {
    ///
    #[default]
    #[error("todo")]
    TODO,

    ///
    #[error("method can be executed since the '{0}' smtp state, but was run during the '{1}' smtp state")]
    WrongState(&'static str, &'static str),
}

impl MailContextAPI {
    ///
    #[must_use]
    pub fn state(&self) -> &'static str {
        match self {
            MailContextAPI::Empty(_) => Empty::as_str(),
            MailContextAPI::Connect(_) => Connect::as_str(),
            MailContextAPI::Helo(_) => Helo::as_str(),
            MailContextAPI::MailFrom(_) => MailFrom::as_str(),
            MailContextAPI::RcptTo(_) => RcptTo::as_str(),
            MailContextAPI::Finished(_) => Finished::as_str(),
        }
    }

    ///
    #[must_use]
    pub fn get_connect(&self) -> &Connect {
        match self {
            MailContextAPI::Empty(_) => unimplemented!(),
            MailContextAPI::Connect(ctx) => &ctx.state,
            MailContextAPI::Helo(ctx) => &ctx.state.connect,
            MailContextAPI::MailFrom(ctx) => &ctx.state.helo.connect,
            MailContextAPI::RcptTo(ctx) => &ctx.state.mail_from.helo.connect,
            MailContextAPI::Finished(ctx) => &ctx.state.rcpt_to.mail_from.helo.connect,
        }
    }

    ///
    #[must_use]
    pub const fn skipped(&self) -> Option<&Status> {
        match self {
            MailContextAPI::Empty(_) => None,
            MailContextAPI::Connect(ctx) => ctx.state.skipped.as_ref(),
            MailContextAPI::Helo(ctx) => ctx.state.connect.skipped.as_ref(),
            MailContextAPI::MailFrom(ctx) => ctx.state.helo.connect.skipped.as_ref(),
            MailContextAPI::RcptTo(ctx) => ctx.state.mail_from.helo.connect.skipped.as_ref(),
            MailContextAPI::Finished(ctx) => ctx.skipped(),
        }
    }

    ///
    pub fn set_skipped(&mut self, skipped: Option<Status>) {
        match self {
            MailContextAPI::Empty(_) => unimplemented!(),
            MailContextAPI::Connect(ctx) => ctx.set_skipped(skipped),
            MailContextAPI::Helo(ctx) => ctx.set_skipped(skipped),
            MailContextAPI::MailFrom(ctx) => ctx.set_skipped(skipped),
            MailContextAPI::RcptTo(ctx) => ctx.set_skipped(skipped),
            MailContextAPI::Finished(ctx) => ctx.set_skipped(skipped),
        }
    }

    ///
    #[must_use]
    pub fn server_name(&self) -> &str {
        match self {
            MailContextAPI::Empty(_) => unimplemented!(),
            MailContextAPI::Connect(ctx) => ctx.server_name(),
            MailContextAPI::Helo(ctx) => ctx.server_name(),
            MailContextAPI::MailFrom(ctx) => ctx.server_name(),
            MailContextAPI::RcptTo(ctx) => ctx.server_name(),
            MailContextAPI::Finished(ctx) => ctx.server_name(),
        }
    }

    ///
    #[must_use]
    pub fn client_name(&self) -> Option<&str> {
        match self {
            MailContextAPI::Empty(_) | MailContextAPI::Connect(_) => None,
            MailContextAPI::Helo(ctx) => Some(ctx.client_name()),
            MailContextAPI::MailFrom(ctx) => Some(ctx.client_name()),
            MailContextAPI::RcptTo(ctx) => Some(ctx.client_name()),
            MailContextAPI::Finished(ctx) => Some(ctx.client_name()),
        }
    }

    ///
    #[must_use]
    pub const fn connection_timestamp(&self) -> &time::OffsetDateTime {
        match self {
            MailContextAPI::Empty(_) => unimplemented!(),
            MailContextAPI::Connect(ctx) => ctx.connection_timestamp(),
            MailContextAPI::Helo(ctx) => ctx.connection_timestamp(),
            MailContextAPI::MailFrom(ctx) => ctx.connection_timestamp(),
            MailContextAPI::RcptTo(ctx) => ctx.connection_timestamp(),
            MailContextAPI::Finished(ctx) => ctx.connection_timestamp(),
        }
    }

    ///
    #[must_use]
    pub fn client_addr(&self) -> &std::net::SocketAddr {
        match self {
            MailContextAPI::Empty(_) => unimplemented!(),
            MailContextAPI::Connect(ctx) => ctx.client_addr(),
            MailContextAPI::Helo(ctx) => ctx.client_addr(),
            MailContextAPI::MailFrom(ctx) => ctx.client_addr(),
            MailContextAPI::RcptTo(ctx) => ctx.client_addr(),
            MailContextAPI::Finished(ctx) => ctx.client_addr(),
        }
    }

    ///
    #[must_use]
    pub const fn is_outgoing(&self) -> bool {
        match self {
            MailContextAPI::Empty(_) | MailContextAPI::Connect(_) | MailContextAPI::Helo(_) => {
                false
            }
            MailContextAPI::MailFrom(ctx) => ctx.is_outgoing(),
            MailContextAPI::RcptTo(ctx) => ctx.is_outgoing(),
            MailContextAPI::Finished(ctx) => ctx.is_outgoing(),
        }
    }

    ///
    #[must_use]
    pub fn server_addr(&self) -> &std::net::SocketAddr {
        match self {
            MailContextAPI::Empty(_) => unimplemented!(),
            MailContextAPI::Connect(ctx) => ctx.server_addr(),
            MailContextAPI::Helo(ctx) => ctx.server_addr(),
            MailContextAPI::MailFrom(ctx) => ctx.server_addr(),
            MailContextAPI::RcptTo(ctx) => ctx.server_addr(),
            MailContextAPI::Finished(ctx) => ctx.server_addr(),
        }
    }

    ///
    #[must_use]
    pub const fn tls(&self) -> Option<&TlsProperties> {
        match self {
            MailContextAPI::Empty(_) => None,
            MailContextAPI::Connect(ctx) => ctx.state.tls.as_ref(),
            MailContextAPI::Helo(ctx) => ctx.state.connect.tls.as_ref(),
            MailContextAPI::MailFrom(ctx) => ctx.state.helo.connect.tls.as_ref(),
            MailContextAPI::RcptTo(ctx) => ctx.state.mail_from.helo.connect.tls.as_ref(),
            MailContextAPI::Finished(ctx) => ctx.state.rcpt_to.mail_from.helo.connect.tls.as_ref(),
        }
    }

    ///
    #[must_use]
    pub const fn auth(&self) -> Option<&AuthProperties> {
        match self {
            MailContextAPI::Empty(_) => None,
            MailContextAPI::Connect(ctx) => ctx.state.auth.as_ref(),
            MailContextAPI::Helo(ctx) => ctx.state.connect.auth.as_ref(),
            MailContextAPI::MailFrom(ctx) => ctx.state.helo.connect.auth.as_ref(),
            MailContextAPI::RcptTo(ctx) => ctx.state.mail_from.helo.connect.auth.as_ref(),
            MailContextAPI::Finished(ctx) => ctx.state.rcpt_to.mail_from.helo.connect.auth.as_ref(),
        }
    }

    ///
    #[must_use]
    pub fn message_id(&self) -> Option<&str> {
        match self {
            MailContextAPI::Empty(_) | MailContextAPI::Connect(_) | MailContextAPI::Helo(_) => None,
            MailContextAPI::MailFrom(ctx) => Some(ctx.message_id()),
            MailContextAPI::RcptTo(ctx) => Some(ctx.message_id()),
            MailContextAPI::Finished(ctx) => Some(ctx.message_id()),
        }
    }

    /// Re-generate the message id.
    ///
    /// # Errors
    /// * The smtp state is pre-mail or post-preq.
    pub fn generate_message_id(&mut self) -> Result<(), Error> {
        match self {
            MailContextAPI::Empty(_)
            | MailContextAPI::Connect(_)
            | MailContextAPI::Helo(_)
            | MailContextAPI::Finished(_) => {
                Err(Error::WrongState(MailFrom::as_str(), self.state()))
            }
            MailContextAPI::MailFrom(ctx) => {
                ctx.generate_message_id();

                Ok(())
            }
            MailContextAPI::RcptTo(ctx) => {
                ctx.generate_message_id();

                Ok(())
            }
        }
    }

    ///
    #[must_use]
    pub const fn mail_timestamp(&self) -> Option<&time::OffsetDateTime> {
        match self {
            MailContextAPI::Empty(_) | MailContextAPI::Connect(_) | MailContextAPI::Helo(_) => None,
            MailContextAPI::MailFrom(ctx) => Some(ctx.mail_timestamp()),
            MailContextAPI::RcptTo(ctx) => Some(ctx.mail_timestamp()),
            MailContextAPI::Finished(ctx) => Some(ctx.mail_timestamp()),
        }
    }

    ///
    #[must_use]
    pub const fn reverse_path(&self) -> Option<&Address> {
        match self {
            MailContextAPI::Empty(_) | MailContextAPI::Connect(_) | MailContextAPI::Helo(_) => None,
            MailContextAPI::MailFrom(ctx) => Some(ctx.reverse_path()),
            MailContextAPI::RcptTo(ctx) => Some(ctx.reverse_path()),
            MailContextAPI::Finished(ctx) => Some(ctx.reverse_path()),
        }
    }

    /// # Errors
    ///
    /// * the state of the context is before `MailFrom`
    pub fn set_reverse_path(&mut self, reverse_path: Address) -> Result<(), Error> {
        match self {
            MailContextAPI::Empty(_) | MailContextAPI::Connect(_) | MailContextAPI::Helo(_) => {
                Err(Error::WrongState(MailFrom::as_str(), self.state()))
            }
            MailContextAPI::MailFrom(ctx) => {
                ctx.state.reverse_path = reverse_path;
                Ok(())
            }
            MailContextAPI::RcptTo(ctx) => {
                ctx.state.mail_from.reverse_path = reverse_path;
                Ok(())
            }
            MailContextAPI::Finished(ctx) => {
                ctx.state.rcpt_to.mail_from.reverse_path = reverse_path;
                Ok(())
            }
        }
    }

    ///
    #[must_use]
    pub const fn forward_paths(&self) -> Option<&Vec<Rcpt>> {
        match self {
            MailContextAPI::Empty(_)
            | MailContextAPI::Connect(_)
            | MailContextAPI::Helo(_)
            | MailContextAPI::MailFrom(_) => None,
            MailContextAPI::RcptTo(ctx) => Some(ctx.forward_paths()),
            MailContextAPI::Finished(ctx) => Some(ctx.forward_paths()),
        }
    }

    ///
    #[must_use]
    pub fn forward_paths_mut(&mut self) -> Option<&mut Vec<Rcpt>> {
        match self {
            MailContextAPI::Empty(_)
            | MailContextAPI::Connect(_)
            | MailContextAPI::Helo(_)
            | MailContextAPI::MailFrom(_) => None,
            MailContextAPI::RcptTo(ctx) => Some(&mut ctx.state.forward_path),
            MailContextAPI::Finished(ctx) => Some(ctx.forward_paths_mut()),
        }
    }

    /// # Errors
    /// * function called before the `RcptTo` smtp state.
    pub fn add_forward_path(&mut self, forward_path: Address) -> Result<(), Error> {
        match self {
            MailContextAPI::Empty(_)
            | MailContextAPI::Connect(_)
            | MailContextAPI::Helo(_)
            | MailContextAPI::MailFrom(_) => Err(Error::WrongState(RcptTo::as_str(), self.state())),
            MailContextAPI::RcptTo(ctx) => {
                ctx.state.forward_path.push(Rcpt::new(forward_path));
                Ok(())
            }
            MailContextAPI::Finished(ctx) => {
                ctx.state.rcpt_to.forward_path.push(Rcpt::new(forward_path));
                Ok(())
            }
        }
    }

    /// Clears all recipients.
    ///
    /// # Errors
    /// * function called before the `RcptTo` smtp state.
    pub fn clear_forward_paths(&mut self) {
        match self {
            MailContextAPI::RcptTo(ctx) => ctx.state.forward_path.clear(),
            MailContextAPI::Finished(ctx) => ctx.state.rcpt_to.forward_path.clear(),
            _ => {}
        }
    }

    /// # Errors
    /// * function called before the `RcptTo` smtp state.
    pub fn remove_forward_path(&mut self, forward_path: &Address) -> Result<(), Error> {
        match self {
            MailContextAPI::Empty(_)
            | MailContextAPI::Connect(_)
            | MailContextAPI::Helo(_)
            | MailContextAPI::MailFrom(_) => Err(Error::TODO),
            MailContextAPI::RcptTo(ctx) => {
                if let Some(index) = ctx
                    .state
                    .forward_path
                    .iter()
                    .position(|rcpt| rcpt.address == *forward_path)
                {
                    ctx.state.forward_path.swap_remove(index);
                }
                Ok(())
            }
            MailContextAPI::Finished(ctx) => {
                if let Some(index) = ctx
                    .state
                    .rcpt_to
                    .forward_path
                    .iter()
                    .position(|rcpt| rcpt.address == *forward_path)
                {
                    ctx.state.rcpt_to.forward_path.swap_remove(index);
                }
                Ok(())
            }
        }
    }

    ///
    #[must_use]
    pub fn dkim(&self) -> Option<&dkim::VerificationResult> {
        TryInto::<&MailContext<Finished>>::try_into(self)
            .ok()
            .and_then(|this| this.state.dkim.as_ref())
    }

    /// # Errors
    ///
    /// * the state of the context is not `Finished`
    pub fn set_dkim(&mut self, dkim: dkim::VerificationResult) -> Result<(), Error> {
        TryInto::<&mut MailContext<Finished>>::try_into(self)?
            .state
            .dkim = Some(dkim);

        Ok(())
    }

    ///
    #[must_use]
    pub fn spf(&self) -> Option<&spf::Result> {
        TryInto::<&MailContext<Finished>>::try_into(self)
            .ok()
            .and_then(|this| this.state.spf.as_ref())
    }

    /// # Errors
    ///
    /// * the state of the context is not `Finished`
    pub fn set_spf(&mut self, spf: spf::Result) -> Result<(), Error> {
        TryInto::<&mut MailContext<Finished>>::try_into(self)?
            .state
            .spf = Some(spf);

        Ok(())
    }

    ///
    pub fn set_state_connect(&mut self, connect: Connect) {
        *self = MailContext::<Connect> { state: connect }.into();
    }

    /// # Errors
    pub fn set_state_helo(&mut self, client_name: String) -> Result<(), Error> {
        let connect = match self {
            MailContextAPI::Empty(_) => unimplemented!(),
            MailContextAPI::Connect(ctx) => &ctx.state,
            MailContextAPI::Helo(ctx) => &ctx.state.connect,
            MailContextAPI::MailFrom(ctx) => &ctx.state.helo.connect,
            MailContextAPI::RcptTo(ctx) => &ctx.state.mail_from.helo.connect,
            MailContextAPI::Finished(_) => return Err(Error::TODO),
        };
        *self = MailContext::<Connect> {
            state: connect.clone(),
        }
        .helo(client_name)
        .into();
        Ok(())
    }

    /// # Errors
    pub fn set_state_mail_from(
        &mut self,
        reverse_path: Address,
        is_outgoing: bool,
    ) -> Result<(), Error> {
        let helo = match self {
            MailContextAPI::Empty(_) => unimplemented!(),
            MailContextAPI::Helo(ctx) => Ok(&ctx.state),
            MailContextAPI::MailFrom(ctx) => Ok(&ctx.state.helo),
            MailContextAPI::Connect(_)
            | MailContextAPI::RcptTo(_)
            | MailContextAPI::Finished(_) => Err(Error::TODO),
        }?;
        *self = MailContext::<Helo> {
            state: helo.clone(),
        }
        .mail_from(reverse_path, is_outgoing)
        .into();
        Ok(())
    }

    /// Set the state to `RcptTo`.
    ///
    /// # Args
    ///
    /// * `forward_path` - an optional recipient to push to the forward path.
    ///
    /// # Errors
    pub fn set_state_rcpt_to(&mut self, forward_path: Option<Rcpt>) -> Result<(), Error> {
        match self {
            MailContextAPI::Empty(_) => unimplemented!(),
            MailContextAPI::Connect(_) | MailContextAPI::Helo(_) | MailContextAPI::Finished(_) => {
                Err(Error::WrongState(MailFrom::as_str(), self.state()))
            }
            MailContextAPI::MailFrom(ctx) => {
                let rcpt =
                    forward_path.map_or_else(std::vec::Vec::new, |forward_path| vec![forward_path]);

                *self = ctx.clone().rcpt_to(rcpt).into();
                Ok(())
            }
            MailContextAPI::RcptTo(ctx) => {
                if let Some(forward_path) = forward_path {
                    ctx.state.forward_path.push(forward_path);
                }

                Ok(())
            }
        }
    }

    /// # Errors
    pub fn set_state_finished(&mut self) -> Result<(), Error> {
        match self {
            MailContextAPI::Empty(_) => unimplemented!(),
            MailContextAPI::Connect(_)
            | MailContextAPI::Helo(_)
            | MailContextAPI::MailFrom(_)
            | MailContextAPI::Finished(_) => Err(Error::WrongState(RcptTo::as_str(), self.state())),
            MailContextAPI::RcptTo(ctx) => {
                *self = ctx.clone().finish().into();
                Ok(())
            }
        }
    }

    /// # Errors
    pub fn reset_state(&mut self) -> Result<(), Error> {
        let helo = match self {
            MailContextAPI::Empty(_) => unimplemented!(),
            MailContextAPI::Connect(_) | MailContextAPI::Helo(_) => return Ok(()),
            MailContextAPI::MailFrom(ctx) => &ctx.state.helo,
            MailContextAPI::RcptTo(ctx) => &ctx.state.mail_from.helo,
            MailContextAPI::Finished(ctx) => &ctx.state.rcpt_to.mail_from.helo,
        }
        .clone();
        self.set_state_helo(helo.client_name)
    }
}

// TODO: use uuid.
/// Create a new message id.
#[must_use]
pub fn new_message_id(connect_timestamp: time::OffsetDateTime) -> String {
    let now = time::OffsetDateTime::now_utc();

    format!(
        "{}{}{}{}",
        now.unix_timestamp_nanos(),
        connect_timestamp.unix_timestamp_nanos(),
        std::iter::repeat_with(fastrand::alphanumeric)
            .take(36)
            .collect::<String>(),
        std::process::id()
    )
}

macro_rules! try_from_ref {
    ($state:tt) => {
        impl<'a> TryFrom<&'a MailContextAPI> for &'a MailContext<$state> {
            type Error = Error;

            fn try_from(value: &'a MailContextAPI) -> Result<Self, Self::Error> {
                match value {
                    MailContextAPI::$state(inner) => Ok(inner),
                    _ => Err(Error::TODO),
                }
            }
        }

        impl<'a> TryFrom<&'a mut MailContextAPI> for &'a mut MailContext<$state> {
            type Error = Error;

            fn try_from(value: &'a mut MailContextAPI) -> Result<Self, Self::Error> {
                match value {
                    MailContextAPI::$state(inner) => Ok(inner),
                    _ => Err(Error::TODO),
                }
            }
        }

        impl TryFrom<MailContextAPI> for MailContext<$state> {
            type Error = Error;

            fn try_from(value: MailContextAPI) -> Result<Self, Self::Error> {
                match value {
                    MailContextAPI::$state(inner) => Ok(inner),
                    _ => Err(Error::TODO),
                }
            }
        }

        impl From<MailContext<$state>> for MailContextAPI {
            fn from(value: MailContext<$state>) -> Self {
                MailContextAPI::$state(value)
            }
        }
    };
}

try_from_ref!(Empty);
try_from_ref!(Helo);
try_from_ref!(Connect);
try_from_ref!(MailFrom);
try_from_ref!(RcptTo);
try_from_ref!(Finished);
