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
use crate::{auth::Credentials, rcpt::Rcpt, status::Status, Address, ClientName};
use vsmtp_auth::{dkim, spf};

/// What rules should be executed regarding the domains of the sender and recipients.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionType {
    /// The sender's domain is unknown, contained domain is only one of the recipients.
    /// If none, it means all recipients are unknown, or that the rcpt stage has not
    /// yet been executed.
    Incoming(Option<String>),
    /// The sender's domain is known, and the recipient domain is not : going out.
    Outgoing {
        /// Domain of the reverse path.
        domain: String,
    },
    /// The sender's domain is known, and recipients domains are the same.
    /// Use the sender's domain to execute your rules.
    Internal,
}

/// Stage of the step-by-step SMTP transaction
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    /// The client has just connected to the server
    Connect,
    /// The client has sent the HELO/EHLO command
    Helo,
    /// The client has sent the MAIL FROM command
    MailFrom,
    /// The client has sent the RCPT TO command
    RcptTo,
    /// The client has sent the complete message
    Finished,
}

// FIXME: remove clone ?
// and serde::Serialize (= only used for vsl::dump function)
// (and serde::Serialize for other sub-context)
/// A step-by-step SMTP envelop produced by the transaction
#[derive(Debug, Default, Clone, serde::Serialize)]
pub enum Context {
    // FIXME: remove `Empty` ?
    /// Just initialized
    #[default]
    Empty,
    /// See [`Stage::Connect`]
    Connect(ContextConnect),
    /// See [`Stage::Helo`]
    Helo(ContextHelo),
    /// See [`Stage::MailFrom`]
    MailFrom(ContextMailFrom),
    /// See [`Stage::RcptTo`]
    RcptTo(ContextRcptTo),
    /// See [`Stage::Finished`]
    Finished(ContextFinished),
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("state is not in correct state")]
    BadState,
    #[error("bad argument: {0}")]
    BadArgument(String), // TODO: do not use string here
}

impl Context {
    /// Get the current SMTP stage of the transaction
    #[must_use]
    pub fn stage(&self) -> Stage {
        match self {
            Context::Empty => unreachable!(),
            Context::Connect { .. } => Stage::Connect,
            Context::Helo { .. } => Stage::Helo,
            Context::MailFrom { .. } => Stage::MailFrom,
            Context::RcptTo { .. } => Stage::RcptTo,
            Context::Finished { .. } => Stage::Finished,
        }
    }

    /// Called when a "RSET" is issued
    pub fn reset(&mut self) {
        match self {
            Context::Empty => unreachable!(),
            Context::Connect(_) => (),
            Context::Helo(ContextHelo { connect, helo })
            | Context::MailFrom(ContextMailFrom { connect, helo, .. })
            | Context::RcptTo(ContextRcptTo { connect, helo, .. })
            | Context::Finished(ContextFinished { connect, helo, .. }) => {
                *self = Context::Helo(ContextHelo {
                    connect: connect.clone(),
                    helo: helo.clone(),
                });
            }
        }
    }

    /// Convert the context to a [`ContextConnect`]
    ///
    /// # Errors
    ///
    /// * state if not [`Context::Empty`]
    pub fn to_connect(
        &mut self,
        client_addr: std::net::SocketAddr,
        server_addr: std::net::SocketAddr,
        server_name: String,
        timestamp: time::OffsetDateTime,
        uuid: uuid::Uuid,
    ) -> Result<&mut Self, Error> {
        match self {
            Context::Empty => {
                *self = Self::Connect(ContextConnect {
                    connect: ConnectProperties {
                        connect_timestamp: timestamp,
                        connect_uuid: uuid,
                        client_addr,
                        server_addr,
                        server_name,
                        skipped: None,
                        tls: None,
                        auth: None,
                    },
                });
                Ok(self)
            }
            _ => Err(Error::BadState),
        }
    }

    /// Convert the context to a [`ContextHelo`] or overwrite the existing one
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::Helo`] or [`Stage::MailFrom`]
    pub fn to_helo(
        &mut self,
        client_name: ClientName,
        using_deprecated: bool,
    ) -> Result<&mut Self, Error> {
        match self {
            Context::Connect(ContextConnect { connect }) => {
                *self = Self::Helo(ContextHelo {
                    connect: connect.clone(),
                    helo: HeloProperties {
                        client_name,
                        using_deprecated,
                    },
                });
                Ok(self)
            }
            Context::Helo(ContextHelo { helo, .. }) => {
                helo.client_name = client_name;
                helo.using_deprecated = using_deprecated;
                Ok(self)
            }
            _ => Err(Error::BadState),
        }
    }

    /// Set the credentials used by the client during the SASL handshake
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::Helo`] or [`Stage::MailFrom`]
    pub fn with_credentials(&mut self, credentials: Credentials) -> Result<(), Error> {
        match self {
            Context::Connect(ContextConnect { connect })
            | Context::Helo(ContextHelo { connect, .. }) => {
                connect.auth = Some(AuthProperties {
                    credentials: Some(credentials),
                    cancel_count: 0,
                    authenticated: false,
                });
                Ok(())
            }
            Context::Empty | Context::MailFrom(_) | Context::RcptTo(_) | Context::Finished(_) => {
                Err(Error::BadState)
            }
        }
    }

    /// Convert the context to a [`ContextMailFrom`] or overwrite the existing one
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::Helo`] or [`Stage::MailFrom`]
    pub fn to_mail_from(&mut self, reverse_path: Address, outgoing: bool) -> Result<(), Error> {
        match self {
            Context::Helo(ContextHelo { connect, helo }) => {
                let now = time::OffsetDateTime::now_utc();
                *self = Self::MailFrom(ContextMailFrom {
                    connect: connect.clone(),
                    helo: helo.clone(),
                    mail_from: MailFromProperties {
                        reverse_path,
                        mail_timestamp: now,
                        message_uuid: uuid::Uuid::new_v4(),
                        outgoing,
                    },
                });
                Ok(())
            }
            Context::MailFrom(ContextMailFrom { mail_from, .. }) => {
                mail_from.reverse_path = reverse_path;
                mail_from.outgoing = outgoing;
                Ok(())
            }
            _ => Err(Error::BadState),
        }
    }

    /// Convert the context to a [`ContextFinished`]
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::RcptTo`]
    pub fn to_finished(&mut self) -> Result<(), Error> {
        match self {
            Context::RcptTo(ContextRcptTo {
                connect,
                helo,
                mail_from,
                rcpt_to,
            }) => {
                *self = Self::Finished(ContextFinished {
                    connect: connect.clone(),
                    helo: helo.clone(),
                    mail_from: mail_from.clone(),
                    rcpt_to: rcpt_to.clone(),
                    finished: FinishedProperties {
                        dkim: None,
                        spf: None,
                    },
                });
                Ok(())
            }
            _ => Err(Error::BadState),
        }
    }

    ///
    #[must_use]
    pub fn skipped(&self) -> &Option<Status> {
        match self {
            Context::Empty => unreachable!(),
            Context::Connect(ContextConnect { connect })
            | Context::Helo(ContextHelo { connect, .. })
            | Context::MailFrom(ContextMailFrom { connect, .. })
            | Context::RcptTo(ContextRcptTo { connect, .. })
            | Context::Finished(ContextFinished { connect, .. }) => &connect.skipped,
        }
    }

    ///
    pub fn set_skipped(&mut self, status: Status) {
        match self {
            Context::Empty => unreachable!(),
            Context::Connect(ContextConnect { connect })
            | Context::Helo(ContextHelo { connect, .. })
            | Context::MailFrom(ContextMailFrom { connect, .. })
            | Context::RcptTo(ContextRcptTo { connect, .. })
            | Context::Finished(ContextFinished { connect, .. }) => connect.skipped = Some(status),
        }
    }

    /// Get the timestamp of the TCP/IP connection
    #[must_use]
    pub fn connection_timestamp(&self) -> &time::OffsetDateTime {
        match self {
            Context::Empty => unreachable!(),
            Context::Connect(ContextConnect { connect })
            | Context::Helo(ContextHelo { connect, .. })
            | Context::MailFrom(ContextMailFrom { connect, .. })
            | Context::RcptTo(ContextRcptTo { connect, .. })
            | Context::Finished(ContextFinished { connect, .. }) => &connect.connect_timestamp,
        }
    }

    /// Get the address of the socket client
    #[must_use]
    pub fn client_addr(&self) -> &std::net::SocketAddr {
        match self {
            Context::Empty => unreachable!(),
            Context::Connect(ContextConnect { connect })
            | Context::Helo(ContextHelo { connect, .. })
            | Context::MailFrom(ContextMailFrom { connect, .. })
            | Context::RcptTo(ContextRcptTo { connect, .. })
            | Context::Finished(ContextFinished { connect, .. }) => &connect.client_addr,
        }
    }

    /// Get the address of the socket server which accepted the connection
    #[must_use]
    pub fn server_addr(&self) -> &std::net::SocketAddr {
        match self {
            Context::Empty => unreachable!(),
            Context::Connect(ContextConnect { connect })
            | Context::Helo(ContextHelo { connect, .. })
            | Context::MailFrom(ContextMailFrom { connect, .. })
            | Context::RcptTo(ContextRcptTo { connect, .. })
            | Context::Finished(ContextFinished { connect, .. }) => &connect.server_addr,
        }
    }

    /// Get the name of the server which the client connected to.
    #[must_use]
    pub fn server_name(&self) -> &String {
        match self {
            Context::Empty => unreachable!(),
            Context::Connect(ContextConnect { connect })
            | Context::Helo(ContextHelo { connect, .. })
            | Context::MailFrom(ContextMailFrom { connect, .. })
            | Context::RcptTo(ContextRcptTo { connect, .. })
            | Context::Finished(ContextFinished { connect, .. }) => &connect.server_name,
        }
    }

    /// Is the connection been encrypted using the SMTP+TLS protocol?
    #[must_use]
    pub fn is_secured(&self) -> bool {
        match self {
            Context::Empty => unreachable!(),
            Context::Connect(ContextConnect { connect })
            | Context::Helo(ContextHelo { connect, .. })
            | Context::MailFrom(ContextMailFrom { connect, .. })
            | Context::RcptTo(ContextRcptTo { connect, .. })
            | Context::Finished(ContextFinished { connect, .. }) => connect.tls.is_some(),
        }
    }

    /// Is the connection been authenticated using the SMTP+SASL protocol?
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        match self {
            Context::Empty => unreachable!(),
            Context::Connect(ContextConnect { connect })
            | Context::Helo(ContextHelo { connect, .. })
            | Context::MailFrom(ContextMailFrom { connect, .. })
            | Context::RcptTo(ContextRcptTo { connect, .. })
            | Context::Finished(ContextFinished { connect, .. }) => connect
                .auth
                .as_ref()
                .map_or(false, |auth| auth.authenticated),
        }
    }

    /// Set the [`TlsProperties`] of the connection.
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::Connect`] or [`Stage::Helo`]
    pub fn to_secured(&mut self, sni: Option<String>) -> Result<(), Error> {
        match self {
            Context::Empty => unreachable!(),
            Context::Connect(ContextConnect { connect })
            | Context::Helo(ContextHelo { connect, .. }) => {
                connect.tls = Some(TlsProperties {});
                if let Some(sni) = sni {
                    connect.server_name = sni;
                }
                Ok(())
            }
            Context::MailFrom(ContextMailFrom { .. })
            | Context::RcptTo(ContextRcptTo { .. })
            | Context::Finished(ContextFinished { .. }) => Err(Error::BadState),
        }
    }

    /// Get the name of the client.
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::Helo`] or after
    pub fn client_name(&self) -> Result<&ClientName, Error> {
        match self {
            Context::Empty => unreachable!(),
            Context::Connect(ContextConnect { .. }) => Err(Error::BadState),
            Context::Helo(ContextHelo { helo, .. })
            | Context::MailFrom(ContextMailFrom { helo, .. })
            | Context::RcptTo(ContextRcptTo { helo, .. })
            | Context::Finished(ContextFinished { helo, .. }) => Ok(&helo.client_name),
        }
    }

    /// Get the [`TlsProperties`] of the connection.
    #[must_use]
    pub fn tls(&self) -> &Option<TlsProperties> {
        match self {
            Context::Empty => unreachable!(),
            Context::Connect(ContextConnect { connect })
            | Context::Helo(ContextHelo { connect, .. })
            | Context::MailFrom(ContextMailFrom { connect, .. })
            | Context::RcptTo(ContextRcptTo { connect, .. })
            | Context::Finished(ContextFinished { connect, .. }) => &connect.tls,
        }
    }

    /// Get the [`AuthProperties`] of the connection.
    #[must_use]
    pub fn auth(&self) -> &Option<AuthProperties> {
        match self {
            Context::Empty => unreachable!(),
            Context::Connect(ContextConnect { connect })
            | Context::Helo(ContextHelo { connect, .. })
            | Context::MailFrom(ContextMailFrom { connect, .. })
            | Context::RcptTo(ContextRcptTo { connect, .. })
            | Context::Finished(ContextFinished { connect, .. }) => &connect.auth,
        }
    }

    /// Get the mutable reference [`AuthProperties`] of the connection.
    #[must_use]
    pub fn auth_mut(&mut self) -> Option<&mut AuthProperties> {
        match self {
            Context::Empty => unreachable!(),
            Context::Connect(ContextConnect { connect })
            | Context::Helo(ContextHelo { connect, .. })
            | Context::MailFrom(ContextMailFrom { connect, .. })
            | Context::RcptTo(ContextRcptTo { connect, .. })
            | Context::Finished(ContextFinished { connect, .. }) => connect.auth.as_mut(),
        }
    }

    /// Set the [`AuthProperties`] of the connection.
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::Connect`] or [`Stage::Helo`]
    pub fn to_auth(&mut self) -> Result<&mut AuthProperties, Error> {
        match self {
            Context::Empty => unreachable!(),
            Context::Connect(ContextConnect { connect })
            | Context::Helo(ContextHelo { connect, .. }) => {
                connect.auth = Some(AuthProperties {
                    authenticated: false,
                    cancel_count: 0,
                    credentials: None,
                });
                Ok(connect.auth.as_mut().expect("has been set just above"))
            }
            Context::MailFrom(ContextMailFrom { .. })
            | Context::RcptTo(ContextRcptTo { .. })
            | Context::Finished(ContextFinished { .. }) => Err(Error::BadState),
        }
    }

    /// Get the reverse path.
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::MailFrom`] or after
    pub const fn reverse_path(&self) -> Result<&Address, Error> {
        match self {
            Context::Empty | Context::Connect { .. } | Context::Helo { .. } => Err(Error::BadState),
            Context::MailFrom(ContextMailFrom { mail_from, .. })
            | Context::RcptTo(ContextRcptTo { mail_from, .. })
            | Context::Finished(ContextFinished { mail_from, .. }) => Ok(&mail_from.reverse_path),
        }
    }

    /// Set the reverse path.
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::MailFrom`] or after
    pub fn set_reverse_path(&mut self, reverse_path: Address) -> Result<(), Error> {
        match self {
            Context::Empty | Context::Connect { .. } | Context::Helo { .. } => Err(Error::BadState),
            Context::MailFrom(ContextMailFrom { mail_from, .. })
            | Context::RcptTo(ContextRcptTo { mail_from, .. })
            | Context::Finished(ContextFinished { mail_from, .. }) => {
                mail_from.reverse_path = reverse_path;
                Ok(())
            }
        }
    }

    /// Get the [`time::OffsetDateTime`] when the `MAIL FROM` has been received.
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::MailFrom`] or after
    pub const fn mail_timestamp(&self) -> Result<&time::OffsetDateTime, Error> {
        match self {
            Context::Empty | Context::Connect { .. } | Context::Helo { .. } => Err(Error::BadState),
            Context::MailFrom(ContextMailFrom { mail_from, .. })
            | Context::RcptTo(ContextRcptTo { mail_from, .. })
            | Context::Finished(ContextFinished { mail_from, .. }) => Ok(&mail_from.mail_timestamp),
        }
    }

    /// Get the message id
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::MailFrom`] or after
    pub const fn message_uuid(&self) -> Result<&uuid::Uuid, Error> {
        match self {
            Context::Empty | Context::Connect { .. } | Context::Helo { .. } => Err(Error::BadState),
            Context::MailFrom(ContextMailFrom { mail_from, .. })
            | Context::RcptTo(ContextRcptTo { mail_from, .. })
            | Context::Finished(ContextFinished { mail_from, .. }) => Ok(&mail_from.message_uuid),
        }
    }

    /// Generate a new message id in the context
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::MailFrom`] or after
    pub fn generate_message_id(&mut self) -> Result<(), Error> {
        match self {
            Context::Empty | Context::Connect(_) | Context::Helo(_) => Err(Error::BadState),
            Context::MailFrom(ContextMailFrom { mail_from, .. })
            | Context::RcptTo(ContextRcptTo { mail_from, .. })
            | Context::Finished(ContextFinished { mail_from, .. }) => {
                mail_from.message_uuid = uuid::Uuid::new_v4();
                Ok(())
            }
        }
    }

    /// Is the domain of the reverse path in the list of handled domains?
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::MailFrom`] or after
    pub const fn is_outgoing(&self) -> Result<bool, Error> {
        match self {
            Context::Empty | Context::Connect { .. } | Context::Helo { .. } => Err(Error::BadState),
            Context::MailFrom(ContextMailFrom { mail_from, .. })
            | Context::RcptTo(ContextRcptTo { mail_from, .. })
            | Context::Finished(ContextFinished { mail_from, .. }) => Ok(mail_from.outgoing),
        }
    }

    /// Add a recipient at the end of the list of forward paths.
    /// If the state was [`Stage::MailFrom`], the state is changed to [`Stage::RcptTo`].
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::MailFrom`] or after
    pub fn add_forward_path(&mut self, forward_path: Address) -> Result<(), Error> {
        match self {
            Context::Empty | Context::Connect(_) | Context::Helo(_) => Err(Error::BadState),
            Context::MailFrom(ContextMailFrom {
                connect,
                helo,
                mail_from,
            }) => {
                *self = Context::RcptTo(ContextRcptTo {
                    connect: connect.clone(),
                    helo: helo.clone(),
                    mail_from: mail_from.clone(),
                    rcpt_to: RcptToProperties {
                        forward_paths: vec![Rcpt::new(forward_path)],
                        transaction_type: TransactionType::Internal, // FIXME: should not have default value
                    },
                });
                Ok(())
            }
            Context::RcptTo(ContextRcptTo { rcpt_to, .. })
            | Context::Finished(ContextFinished { rcpt_to, .. }) => {
                rcpt_to.forward_paths.push(Rcpt::new(forward_path));
                Ok(())
            }
        }
    }

    /// Remove the first recipient with the address `forward_path`.
    /// Return `false` if no such recipient exist
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::RcptTo`] or after
    pub fn remove_forward_path(&mut self, forward_path: &Address) -> Result<bool, Error> {
        match self {
            Context::Empty | Context::Connect(_) | Context::Helo(_) | Context::MailFrom(_) => {
                Err(Error::BadState)
            }
            Context::RcptTo(ContextRcptTo { rcpt_to, .. })
            | Context::Finished(ContextFinished { rcpt_to, .. }) => {
                if let Some(index) = rcpt_to
                    .forward_paths
                    .iter()
                    .position(|rcpt| rcpt.address == *forward_path)
                {
                    rcpt_to.forward_paths.swap_remove(index);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }

    /// Get a reference of the forwards path.
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::RcptTo`] or after
    pub const fn forward_paths(&self) -> Result<&Vec<Rcpt>, Error> {
        match self {
            Context::Empty
            | Context::Connect { .. }
            | Context::Helo { .. }
            | Context::MailFrom { .. } => Err(Error::BadState),
            Context::RcptTo(ContextRcptTo { rcpt_to, .. })
            | Context::Finished(ContextFinished { rcpt_to, .. }) => Ok(&rcpt_to.forward_paths),
        }
    }

    /// Get a mutable reference of the forwards path.
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::RcptTo`] or after
    pub fn forward_paths_mut(&mut self) -> Result<&mut Vec<Rcpt>, Error> {
        match self {
            Context::Empty
            | Context::Connect { .. }
            | Context::Helo { .. }
            | Context::MailFrom { .. } => Err(Error::BadState),
            Context::RcptTo(ContextRcptTo { rcpt_to, .. })
            | Context::Finished(ContextFinished { rcpt_to, .. }) => Ok(&mut rcpt_to.forward_paths),
        }
    }

    /// Get the [`TransactionType`].
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::RcptTo`] or after
    pub const fn transaction_type(&self) -> Result<&TransactionType, Error> {
        match self {
            Context::Empty
            | Context::Connect { .. }
            | Context::Helo { .. }
            | Context::MailFrom { .. } => Err(Error::BadState),
            Context::RcptTo(ContextRcptTo { rcpt_to, .. })
            | Context::Finished(ContextFinished { rcpt_to, .. }) => Ok(&rcpt_to.transaction_type),
        }
    }

    /// Set the [`TransactionType`].
    /// If the state was [`Stage::MailFrom`], the state is changed to [`Stage::RcptTo`].
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::MailFrom`] or after
    pub fn set_transaction_type(&mut self, transaction_type: TransactionType) -> Result<(), Error> {
        match self {
            Context::Empty | Context::Connect(_) | Context::Helo(_) => Err(Error::BadState),
            Context::MailFrom(ContextMailFrom {
                connect,
                helo,
                mail_from,
            }) => {
                *self = Context::RcptTo(ContextRcptTo {
                    connect: connect.clone(),
                    helo: helo.clone(),
                    mail_from: mail_from.clone(),
                    rcpt_to: RcptToProperties {
                        transaction_type,
                        forward_paths: Vec::new(),
                    },
                });
                Ok(())
            }
            Context::RcptTo(ContextRcptTo { rcpt_to, .. })
            | Context::Finished(ContextFinished { rcpt_to, .. }) => {
                rcpt_to.transaction_type = transaction_type;
                Ok(())
            }
        }
    }

    /// Get the [`spf::Result`].
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::Finished`]
    pub const fn spf(&self) -> Result<Option<&spf::Result>, Error> {
        match self {
            Context::Empty
            | Context::Connect(_)
            | Context::Helo(_)
            | Context::MailFrom(_)
            | Context::RcptTo(_) => Err(Error::BadState),
            Context::Finished(ContextFinished { finished, .. }) => Ok(finished.spf.as_ref()),
        }
    }

    /// Set the [`spf::Result`].
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::Finished`]
    pub fn set_spf(&mut self, spf: spf::Result) -> Result<(), Error> {
        match self {
            Context::Empty
            | Context::Connect(_)
            | Context::Helo(_)
            | Context::MailFrom(_)
            | Context::RcptTo(_) => Err(Error::BadState),
            Context::Finished(ContextFinished { finished, .. }) => {
                finished.spf = Some(spf);
                Ok(())
            }
        }
    }

    /// Get the [`dkim::VerificationResult`] if it exists.
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::Finished`]
    pub const fn dkim(&self) -> Result<Option<&dkim::VerificationResult>, Error> {
        match self {
            Context::Empty
            | Context::Connect(_)
            | Context::Helo(_)
            | Context::MailFrom(_)
            | Context::RcptTo(_) => Err(Error::BadState),
            Context::Finished(ContextFinished { finished, .. }) => Ok(finished.dkim.as_ref()),
        }
    }

    /// Set the [`dkim::VerificationResult`].
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::Finished`]
    pub fn set_dkim(&mut self, result: dkim::VerificationResult) -> Result<(), Error> {
        match self {
            Context::Empty
            | Context::Connect(_)
            | Context::Helo(_)
            | Context::MailFrom(_)
            | Context::RcptTo(_) => Err(Error::BadState),
            Context::Finished(ContextFinished { finished, .. }) => {
                finished.dkim = Some(result);
                Ok(())
            }
        }
    }

    /// Convert the instance into a [`ContextFinished`].
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::Finished`]
    #[allow(clippy::missing_const_for_fn)]
    pub fn unwrap_finished(self) -> Result<ContextFinished, Error> {
        match self {
            Context::Finished(finished) => Ok(finished),
            _ => Err(Error::BadState),
        }
    }
}

/// Properties of the TLS connection
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct TlsProperties {
    // TODO: store protocol version / cipher suite / ...
}

/// Properties of the authentication SASL
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct AuthProperties {
    /// Has the SASL authentication been successful?
    pub authenticated: bool,
    /// Number of times the SASL authentication has been canceled by the client
    pub cancel_count: usize,
    /// The credentials used for authentication
    pub credentials: Option<Credentials>,
}

///
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConnectProperties {
    ///
    #[serde(with = "time::serde::iso8601")]
    pub connect_timestamp: time::OffsetDateTime,
    ///
    pub connect_uuid: uuid::Uuid,
    ///
    pub client_addr: std::net::SocketAddr,
    ///
    pub server_addr: std::net::SocketAddr,
    ///
    pub server_name: String,
    ///
    pub skipped: Option<Status>,
    ///
    pub tls: Option<TlsProperties>,
    ///
    pub auth: Option<AuthProperties>,
}

///
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HeloProperties {
    ///
    pub client_name: ClientName,
    ///
    pub using_deprecated: bool,
}

///
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MailFromProperties {
    ///
    // TODO: support null reverse_path
    pub reverse_path: Address,
    ///
    #[serde(with = "time::serde::iso8601")]
    pub mail_timestamp: time::OffsetDateTime,
    ///
    pub message_uuid: uuid::Uuid,
    ///
    pub outgoing: bool,
}

///
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RcptToProperties {
    ///
    pub forward_paths: Vec<Rcpt>,
    ///
    pub transaction_type: TransactionType,
}

///
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FinishedProperties {
    ///
    pub dkim: Option<dkim::VerificationResult>,
    ///
    // FIXME: spf result could be in the MailFromProperties
    pub spf: Option<spf::Result>,
}

#[doc(hidden)]
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, serde::Serialize)]
pub struct ContextConnect {
    pub connect: ConnectProperties,
}

#[doc(hidden)]
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, serde::Serialize)]
pub struct ContextHelo {
    pub connect: ConnectProperties,
    pub helo: HeloProperties,
}

#[doc(hidden)]
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, serde::Serialize)]
pub struct ContextMailFrom {
    pub connect: ConnectProperties,
    pub helo: HeloProperties,
    pub mail_from: MailFromProperties,
}

#[doc(hidden)]
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, serde::Serialize)]
pub struct ContextRcptTo {
    pub connect: ConnectProperties,
    pub helo: HeloProperties,
    pub mail_from: MailFromProperties,
    pub rcpt_to: RcptToProperties,
}

#[doc(hidden)]
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ContextFinished {
    #[serde(flatten)]
    pub connect: ConnectProperties,
    #[serde(flatten)]
    pub helo: HeloProperties,
    #[serde(flatten)]
    pub mail_from: MailFromProperties,
    #[serde(flatten)]
    pub rcpt_to: RcptToProperties,
    #[serde(flatten)]
    pub finished: FinishedProperties,
}
