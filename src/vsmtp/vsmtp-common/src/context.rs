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
    auth::Credentials,
    status, transfer,
    transport::{AbstractTransport, DeliverTo, WrapperSerde},
    Address, CipherSuite, ClientName, Domain, ProtocolVersion,
};
use vsmtp_auth::{dkim, spf};

/// What rules should be executed regarding the domains of the sender and recipients.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[cfg_attr(feature = "testing", derive(PartialEq, Eq))]
#[serde(rename_all = "snake_case")]
pub enum TransactionType {
    /// The sender's domain is unknown, contained domain is only one of the recipients.
    /// If none, it means all recipients are unknown, or that the rcpt stage has not
    /// yet been executed.
    Incoming(Option<Domain>),
    /// The sender's domain is known, and the recipient domain is not : going out.
    Outgoing {
        /// Domain of the reverse path.
        domain: Domain,
    },
    /// The sender's domain is known, and recipients domains are the same.
    /// Use the sender's domain to execute your rules.
    Internal,
}

/// Stage of the step-by-step SMTP transaction
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, strum::Display)]
#[strum(serialize_all = "lowercase")]
pub enum Stage {
    /// The client has just connected to the server
    Connect,
    /// The client has sent the HELO/EHLO command
    Helo,
    /// The client has sent the MAIL FROM command
    #[strum(serialize = "mail")]
    MailFrom,
    /// The client has sent the RCPT TO command
    #[strum(serialize = "rcpt")]
    RcptTo,
    /// The client has sent the complete message
    #[strum(serialize = "preq")]
    Finished,
}

// FIXME: remove clone ? used to create a copy of the context for internal state
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

///
#[derive(Debug, thiserror::Error)]
pub enum Error {
    ///
    #[error("state is not in correct state")]
    BadState,
    ///
    #[error("bad argument: {0}")]
    BadArgument(String), // TODO: do not use string here
}

impl Context {
    /// Get the current SMTP stage of the transaction
    #[must_use]
    pub fn stage(&self) -> Stage {
        match self {
            Self::Empty => unreachable!(),
            Self::Connect { .. } => Stage::Connect,
            Self::Helo { .. } => Stage::Helo,
            Self::MailFrom { .. } => Stage::MailFrom,
            Self::RcptTo { .. } => Stage::RcptTo,
            Self::Finished { .. } => Stage::Finished,
        }
    }

    /// Called when a "RSET" is issued
    pub fn reset(&mut self) {
        match self {
            Self::Empty => unreachable!(),
            Self::Connect(_) => (),
            Self::Helo(ContextHelo { connect, helo })
            | Self::MailFrom(ContextMailFrom { connect, helo, .. })
            | Self::RcptTo(ContextRcptTo { connect, helo, .. })
            | Self::Finished(ContextFinished { connect, helo, .. }) => {
                *self = Self::Helo(ContextHelo {
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
        server_name: Domain,
        timestamp: time::OffsetDateTime,
        uuid: uuid::Uuid,
    ) -> Result<&mut Self, Error> {
        match self {
            Self::Empty => {
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
            Self::Connect(ContextConnect { connect }) => {
                *self = Self::Helo(ContextHelo {
                    connect: connect.clone(),
                    helo: HeloProperties {
                        client_name,
                        using_deprecated,
                    },
                });
                Ok(self)
            }
            Self::Helo(ContextHelo { helo, .. }) => {
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
            Self::Connect(ContextConnect { connect }) | Self::Helo(ContextHelo { connect, .. }) => {
                connect.auth = Some(AuthProperties {
                    credentials: Some(credentials),
                    cancel_count: 0,
                    authenticated: false,
                });
                Ok(())
            }
            Self::Empty | Self::MailFrom(_) | Self::RcptTo(_) | Self::Finished(_) => {
                Err(Error::BadState)
            }
        }
    }

    /// Convert the context to a [`ContextMailFrom`] or overwrite the existing one
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::Helo`] or [`Stage::MailFrom`]
    pub fn to_mail_from(&mut self, reverse_path: Option<Address>) -> Result<(), Error> {
        match self {
            Self::Helo(ContextHelo { connect, helo }) => {
                let now = time::OffsetDateTime::now_utc();
                *self = Self::MailFrom(ContextMailFrom {
                    connect: connect.clone(),
                    helo: helo.clone(),
                    mail_from: MailFromProperties {
                        reverse_path,
                        mail_timestamp: now,
                        message_uuid: uuid::Uuid::new_v4(),
                        spf: None,
                    },
                });
                Ok(())
            }
            Self::MailFrom(ContextMailFrom { mail_from, .. }) => {
                mail_from.reverse_path = reverse_path;
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
            Self::RcptTo(ContextRcptTo {
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
                    finished: FinishedProperties { dkim: None },
                });
                Ok(())
            }
            _ => Err(Error::BadState),
        }
    }

    ///
    pub fn set_skipped(&mut self, status: status::Status) {
        match self {
            Self::Empty => unreachable!(),
            Self::Connect(ContextConnect { connect })
            | Self::Helo(ContextHelo { connect, .. })
            | Self::MailFrom(ContextMailFrom { connect, .. })
            | Self::RcptTo(ContextRcptTo { connect, .. })
            | Self::Finished(ContextFinished { connect, .. }) => connect.skipped = Some(status),
        }
    }

    /// Get the timestamp of the TCP/IP connection
    #[must_use]
    pub fn connection_timestamp(&self) -> &time::OffsetDateTime {
        match self {
            Self::Empty => unreachable!(),
            Self::Connect(ContextConnect { connect })
            | Self::Helo(ContextHelo { connect, .. })
            | Self::MailFrom(ContextMailFrom { connect, .. })
            | Self::RcptTo(ContextRcptTo { connect, .. })
            | Self::Finished(ContextFinished { connect, .. }) => &connect.connect_timestamp,
        }
    }

    /// Get the address of the socket client
    #[must_use]
    pub fn client_addr(&self) -> &std::net::SocketAddr {
        match self {
            Self::Empty => unreachable!(),
            Self::Connect(ContextConnect { connect })
            | Self::Helo(ContextHelo { connect, .. })
            | Self::MailFrom(ContextMailFrom { connect, .. })
            | Self::RcptTo(ContextRcptTo { connect, .. })
            | Self::Finished(ContextFinished { connect, .. }) => &connect.client_addr,
        }
    }

    /// Get the address of the socket server which accepted the connection
    #[must_use]
    pub fn server_addr(&self) -> &std::net::SocketAddr {
        match self {
            Self::Empty => unreachable!(),
            Self::Connect(ContextConnect { connect })
            | Self::Helo(ContextHelo { connect, .. })
            | Self::MailFrom(ContextMailFrom { connect, .. })
            | Self::RcptTo(ContextRcptTo { connect, .. })
            | Self::Finished(ContextFinished { connect, .. }) => &connect.server_addr,
        }
    }

    /// Get the name of the server which the client connected to.
    #[must_use]
    pub fn server_name(&self) -> &Domain {
        match self {
            Self::Empty => unreachable!(),
            Self::Connect(ContextConnect { connect })
            | Self::Helo(ContextHelo { connect, .. })
            | Self::MailFrom(ContextMailFrom { connect, .. })
            | Self::RcptTo(ContextRcptTo { connect, .. })
            | Self::Finished(ContextFinished { connect, .. }) => &connect.server_name,
        }
    }

    /// Is the connection been encrypted using the SMTP+TLS protocol?
    #[must_use]
    pub fn is_secured(&self) -> bool {
        match self {
            Self::Empty => unreachable!(),
            Self::Connect(ContextConnect { connect })
            | Self::Helo(ContextHelo { connect, .. })
            | Self::MailFrom(ContextMailFrom { connect, .. })
            | Self::RcptTo(ContextRcptTo { connect, .. })
            | Self::Finished(ContextFinished { connect, .. }) => connect.tls.is_some(),
        }
    }

    /// Is the connection been authenticated using the SMTP+SASL protocol?
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        match self {
            Self::Empty => unreachable!(),
            Self::Connect(ContextConnect { connect })
            | Self::Helo(ContextHelo { connect, .. })
            | Self::MailFrom(ContextMailFrom { connect, .. })
            | Self::RcptTo(ContextRcptTo { connect, .. })
            | Self::Finished(ContextFinished { connect, .. }) => connect
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
    pub fn to_secured(
        &mut self,
        sni: Option<Domain>,
        protocol_version: rustls::ProtocolVersion,
        cipher_suite: rustls::CipherSuite,
        peer_certificates: Option<Vec<rustls::Certificate>>,
        alpn_protocol: Option<Vec<u8>>,
    ) -> Result<(), Error> {
        match self {
            Self::Empty => unreachable!(),
            Self::Connect(ContextConnect { connect }) | Self::Helo(ContextHelo { connect, .. }) => {
                connect.tls = Some(TlsProperties {
                    protocol_version: ProtocolVersion(protocol_version),
                    cipher_suite: CipherSuite(cipher_suite),
                    peer_certificates,
                    alpn_protocol,
                });
                if let Some(sni) = sni {
                    connect.server_name = sni;
                }
                Ok(())
            }
            Self::MailFrom(ContextMailFrom { .. })
            | Self::RcptTo(ContextRcptTo { .. })
            | Self::Finished(ContextFinished { .. }) => Err(Error::BadState),
        }
    }

    /// Get the name of the client.
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::Helo`] or after
    pub fn client_name(&self) -> Result<&ClientName, Error> {
        match self {
            Self::Empty => unreachable!(),
            Self::Connect(ContextConnect { .. }) => Err(Error::BadState),
            Self::Helo(ContextHelo { helo, .. })
            | Self::MailFrom(ContextMailFrom { helo, .. })
            | Self::RcptTo(ContextRcptTo { helo, .. })
            | Self::Finished(ContextFinished { helo, .. }) => Ok(&helo.client_name),
        }
    }

    /// Get the [`TlsProperties`] of the connection.
    #[must_use]
    pub fn tls(&self) -> &Option<TlsProperties> {
        match self {
            Self::Empty => unreachable!(),
            Self::Connect(ContextConnect { connect })
            | Self::Helo(ContextHelo { connect, .. })
            | Self::MailFrom(ContextMailFrom { connect, .. })
            | Self::RcptTo(ContextRcptTo { connect, .. })
            | Self::Finished(ContextFinished { connect, .. }) => &connect.tls,
        }
    }

    /// Get the [`AuthProperties`] of the connection.
    #[must_use]
    pub fn auth(&self) -> &Option<AuthProperties> {
        match self {
            Self::Empty => unreachable!(),
            Self::Connect(ContextConnect { connect })
            | Self::Helo(ContextHelo { connect, .. })
            | Self::MailFrom(ContextMailFrom { connect, .. })
            | Self::RcptTo(ContextRcptTo { connect, .. })
            | Self::Finished(ContextFinished { connect, .. }) => &connect.auth,
        }
    }

    /// Get the mutable reference [`AuthProperties`] of the connection.
    #[must_use]
    pub fn auth_mut(&mut self) -> Option<&mut AuthProperties> {
        match self {
            Self::Empty => unreachable!(),
            Self::Connect(ContextConnect { connect })
            | Self::Helo(ContextHelo { connect, .. })
            | Self::MailFrom(ContextMailFrom { connect, .. })
            | Self::RcptTo(ContextRcptTo { connect, .. })
            | Self::Finished(ContextFinished { connect, .. }) => connect.auth.as_mut(),
        }
    }

    /// Set the [`AuthProperties`] of the connection.
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::Connect`] or [`Stage::Helo`]
    pub fn to_auth(&mut self) -> Result<&mut AuthProperties, Error> {
        match self {
            Self::Empty => unreachable!(),
            Self::Connect(ContextConnect { connect }) | Self::Helo(ContextHelo { connect, .. }) => {
                connect.auth = Some(AuthProperties {
                    authenticated: false,
                    cancel_count: 0,
                    credentials: None,
                });
                Ok(connect.auth.as_mut().expect("has been set just above"))
            }
            Self::MailFrom(ContextMailFrom { .. })
            | Self::RcptTo(ContextRcptTo { .. })
            | Self::Finished(ContextFinished { .. }) => Err(Error::BadState),
        }
    }

    /// Get the reverse path.
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::MailFrom`] or after
    pub const fn reverse_path(&self) -> Result<&Option<Address>, Error> {
        match self {
            Self::Empty | Self::Connect { .. } | Self::Helo { .. } => Err(Error::BadState),
            Self::MailFrom(ContextMailFrom { mail_from, .. })
            | Self::RcptTo(ContextRcptTo { mail_from, .. })
            | Self::Finished(ContextFinished { mail_from, .. }) => Ok(&mail_from.reverse_path),
        }
    }

    /// Set the reverse path.
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::MailFrom`] or after
    pub fn set_reverse_path(&mut self, reverse_path: Option<Address>) -> Result<(), Error> {
        match self {
            Self::Empty | Self::Connect { .. } | Self::Helo { .. } => Err(Error::BadState),
            Self::MailFrom(ContextMailFrom { mail_from, .. })
            | Self::RcptTo(ContextRcptTo { mail_from, .. })
            | Self::Finished(ContextFinished { mail_from, .. }) => {
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
            Self::Empty | Self::Connect { .. } | Self::Helo { .. } => Err(Error::BadState),
            Self::MailFrom(ContextMailFrom { mail_from, .. })
            | Self::RcptTo(ContextRcptTo { mail_from, .. })
            | Self::Finished(ContextFinished { mail_from, .. }) => Ok(&mail_from.mail_timestamp),
        }
    }

    /// Get the message id
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::MailFrom`] or after
    pub const fn message_uuid(&self) -> Result<&uuid::Uuid, Error> {
        match self {
            Self::Empty | Self::Connect { .. } | Self::Helo { .. } => Err(Error::BadState),
            Self::MailFrom(ContextMailFrom { mail_from, .. })
            | Self::RcptTo(ContextRcptTo { mail_from, .. })
            | Self::Finished(ContextFinished { mail_from, .. }) => Ok(&mail_from.message_uuid),
        }
    }

    /// Generate a new message id in the context
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::MailFrom`] or after
    pub fn generate_message_id(&mut self) -> Result<(), Error> {
        match self {
            Self::Empty | Self::Connect(_) | Self::Helo(_) => Err(Error::BadState),
            Self::MailFrom(ContextMailFrom { mail_from, .. })
            | Self::RcptTo(ContextRcptTo { mail_from, .. })
            | Self::Finished(ContextFinished { mail_from, .. }) => {
                mail_from.message_uuid = uuid::Uuid::new_v4();
                Ok(())
            }
        }
    }

    /// Add a recipient at the end of the list of forward paths.
    /// If the state was [`Stage::MailFrom`], the state is changed to [`Stage::RcptTo`].
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::MailFrom`] or after
    pub fn add_forward_path(
        &mut self,
        forward_path: Address,
        transport: std::sync::Arc<dyn AbstractTransport>,
    ) -> Result<(), Error> {
        match self {
            Self::Empty | Self::Connect(_) | Self::Helo(_) => Err(Error::BadState),
            Self::MailFrom(ContextMailFrom {
                connect,
                helo,
                mail_from,
            }) => {
                *self = Self::RcptTo(ContextRcptTo {
                    connect: connect.clone(),
                    helo: helo.clone(),
                    mail_from: mail_from.clone(),
                    rcpt_to: RcptToProperties {
                        // FIXME: should not have default value
                        transaction_type: TransactionType::Internal,
                        delivery: std::iter::once((
                            WrapperSerde::Ready(transport),
                            vec![(forward_path.clone(), transfer::Status::default())],
                        ))
                        .collect::<_>(),
                        forward_paths: vec![forward_path],
                    },
                });
                Ok(())
            }
            Self::RcptTo(ContextRcptTo { rcpt_to, .. })
            | Self::Finished(ContextFinished { rcpt_to, .. }) => {
                rcpt_to.forward_paths.push(forward_path.clone());
                let new_rcpt = (forward_path, transfer::Status::default());

                rcpt_to
                    .delivery
                    .entry(WrapperSerde::Ready(transport))
                    .and_modify(|t| {
                        t.push(new_rcpt.clone());
                    })
                    .or_insert_with(|| vec![new_rcpt]);
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
            Self::Empty | Self::Connect(_) | Self::Helo(_) | Self::MailFrom(_) => {
                Err(Error::BadState)
            }
            Self::RcptTo(ContextRcptTo { rcpt_to, .. })
            | Self::Finished(ContextFinished { rcpt_to, .. }) => {
                rcpt_to.forward_paths.retain(|rcpt| rcpt != forward_path);

                for rcpts in &mut rcpt_to.delivery.values_mut() {
                    if let Some(index) = rcpts.iter().position(|(rcpt, _)| *rcpt == *forward_path) {
                        rcpts.swap_remove(index);
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }

    /// Get a reference of the forwards path.
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::RcptTo`] or after
    pub const fn forward_paths(&self) -> Result<&Vec<Address>, Error> {
        match self {
            Self::Empty | Self::Connect { .. } | Self::Helo { .. } | Self::MailFrom { .. } => {
                Err(Error::BadState)
            }
            Self::RcptTo(ContextRcptTo { rcpt_to, .. })
            | Self::Finished(ContextFinished { rcpt_to, .. }) => Ok(&rcpt_to.forward_paths),
        }
    }

    /// Get a mutable reference of the forwards path.
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::RcptTo`] or after
    pub fn forward_paths_mut(&mut self) -> Result<&mut Vec<Address>, Error> {
        match self {
            Self::Empty | Self::Connect { .. } | Self::Helo { .. } | Self::MailFrom { .. } => {
                Err(Error::BadState)
            }
            Self::RcptTo(ContextRcptTo { rcpt_to, .. })
            | Self::Finished(ContextFinished { rcpt_to, .. }) => Ok(&mut rcpt_to.forward_paths),
        }
    }

    /// Set a delivery transport for a recipients.
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::RcptTo`] or after
    pub fn set_transport_for_one(
        &mut self,
        search: &Address,
        transport: std::sync::Arc<dyn AbstractTransport>,
    ) -> Result<(), Error> {
        let deliver = self.delivery_mut()?;

        for (_, v) in deliver.iter_mut() {
            if let Some((idx, _)) = v
                .iter()
                .map(|(rcpt, _)| rcpt)
                .enumerate()
                .find(|(_, rcpt)| *rcpt == search)
            {
                v.swap_remove(idx);
            }
        }

        deliver
            .entry(WrapperSerde::Ready(transport))
            .and_modify(|rcpt| rcpt.push((search.clone(), transfer::Status::default())))
            .or_insert_with(|| vec![(search.clone(), transfer::Status::default())]);

        Ok(())
    }

    /// Set a delivery transport for all recipients.
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::RcptTo`] or after
    pub fn set_transport_foreach(
        &mut self,
        transport: std::sync::Arc<dyn AbstractTransport>,
    ) -> Result<(), Error> {
        let forward_paths = self.forward_paths()?.clone();
        let deliver = self.delivery_mut()?;

        deliver.clear();
        deliver.insert(
            WrapperSerde::Ready(transport),
            forward_paths
                .into_iter()
                .map(|i| (i, transfer::Status::default()))
                .collect(),
        );

        Ok(())
    }

    /// # Errors
    ///
    /// * state if not [`Stage::RcptTo`] or after
    pub fn delivery(&self) -> Result<&std::collections::HashMap<WrapperSerde, DeliverTo>, Error> {
        match self {
            Self::Empty | Self::Connect { .. } | Self::Helo { .. } | Self::MailFrom { .. } => {
                Err(Error::BadState)
            }
            Self::RcptTo(ContextRcptTo { rcpt_to, .. })
            | Self::Finished(ContextFinished { rcpt_to, .. }) => Ok(&rcpt_to.delivery),
        }
    }

    /// # Errors
    ///
    /// * state if not [`Stage::RcptTo`] or after
    pub fn delivery_mut(
        &mut self,
    ) -> Result<&mut std::collections::HashMap<WrapperSerde, DeliverTo>, Error> {
        match self {
            Self::Empty | Self::Connect { .. } | Self::Helo { .. } | Self::MailFrom { .. } => {
                Err(Error::BadState)
            }
            Self::RcptTo(ContextRcptTo { rcpt_to, .. })
            | Self::Finished(ContextFinished { rcpt_to, .. }) => Ok(&mut rcpt_to.delivery),
        }
    }

    /// Get the [`TransactionType`].
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::RcptTo`] or after
    pub const fn transaction_type(&self) -> Result<&TransactionType, Error> {
        match self {
            Self::Empty | Self::Connect { .. } | Self::Helo { .. } | Self::MailFrom { .. } => {
                Err(Error::BadState)
            }
            Self::RcptTo(ContextRcptTo { rcpt_to, .. })
            | Self::Finished(ContextFinished { rcpt_to, .. }) => Ok(&rcpt_to.transaction_type),
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
            Self::Empty | Self::Connect(_) | Self::Helo(_) => Err(Error::BadState),
            Self::MailFrom(ContextMailFrom {
                connect,
                helo,
                mail_from,
            }) => {
                *self = Self::RcptTo(ContextRcptTo {
                    connect: connect.clone(),
                    helo: helo.clone(),
                    mail_from: mail_from.clone(),
                    rcpt_to: RcptToProperties {
                        transaction_type,
                        delivery: std::collections::HashMap::new(),
                        forward_paths: vec![],
                    },
                });
                Ok(())
            }
            Self::RcptTo(ContextRcptTo { rcpt_to, .. })
            | Self::Finished(ContextFinished { rcpt_to, .. }) => {
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
            Self::Empty | Self::Connect(_) | Self::Helo(_) => Err(Error::BadState),
            Self::MailFrom(ContextMailFrom { mail_from, .. })
            | Self::RcptTo(ContextRcptTo { mail_from, .. })
            | Self::Finished(ContextFinished { mail_from, .. }) => Ok(mail_from.spf.as_ref()),
        }
    }

    /// Set the [`spf::Result`].
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::Finished`]
    pub fn set_spf(&mut self, spf: spf::Result) -> Result<(), Error> {
        match self {
            Self::Empty | Self::Connect(_) | Self::Helo(_) => Err(Error::BadState),
            Self::MailFrom(ContextMailFrom { mail_from, .. })
            | Self::RcptTo(ContextRcptTo { mail_from, .. })
            | Self::Finished(ContextFinished { mail_from, .. }) => {
                mail_from.spf = Some(spf);
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
            Self::Empty
            | Self::Connect(_)
            | Self::Helo(_)
            | Self::MailFrom(_)
            | Self::RcptTo(_) => Err(Error::BadState),
            Self::Finished(ContextFinished { finished, .. }) => Ok(finished.dkim.as_ref()),
        }
    }

    /// Set the [`dkim::VerificationResult`].
    ///
    /// # Errors
    ///
    /// * state if not [`Stage::Finished`]
    pub fn set_dkim(&mut self, result: dkim::VerificationResult) -> Result<(), Error> {
        match self {
            Self::Empty
            | Self::Connect(_)
            | Self::Helo(_)
            | Self::MailFrom(_)
            | Self::RcptTo(_) => Err(Error::BadState),
            Self::Finished(ContextFinished { finished, .. }) => {
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
    pub fn unwrap_finished(self) -> Result<ContextFinished, Error> {
        match self {
            Self::Finished(finished) => Ok(finished),
            _ => Err(Error::BadState),
        }
    }
}

/// Properties of the TLS connection
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "testing", derive(PartialEq, Eq))]
pub struct TlsProperties {
    ///
    pub protocol_version: crate::ProtocolVersion,
    ///
    pub cipher_suite: crate::CipherSuite,
    ///
    #[serde(
        serialize_with = "serde_with::As::<Option<Vec<serde_with::base64::Base64>>>::serialize",
        deserialize_with = "de_peer_certificates"
    )]
    pub peer_certificates: Option<Vec<rustls::Certificate>>,
    ///
    pub alpn_protocol: Option<Vec<u8>>,
}

fn de_peer_certificates<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<rustls::Certificate>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    <Option<Vec<String>> as serde::Deserialize>::deserialize(deserializer)?
        .map(|certs| {
            match certs
                .into_iter()
                .map(|i| rustls_pemfile::certs(&mut i.as_bytes()))
                .collect::<Result<Vec<Vec<Vec<u8>>>, _>>()
            {
                Ok(certs) => Ok(certs
                    .into_iter()
                    .flatten()
                    .map(rustls::Certificate)
                    .collect()),
                Err(e) => Err(serde::de::Error::custom(e)),
            }
        })
        .transpose()
}

/// Properties of the authentication SASL
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[cfg_attr(feature = "testing", derive(PartialEq, Eq))]
pub struct AuthProperties {
    /// Has the SASL authentication been successful?
    pub authenticated: bool,
    /// Number of times the SASL authentication has been canceled by the client
    pub cancel_count: usize,
    /// The credentials used for authentication
    pub credentials: Option<Credentials>,
}

/// Properties accessible right after the TCP connection
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "testing", derive(PartialEq, Eq))]
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
    pub server_name: Domain,
    ///
    pub skipped: Option<status::Status>,
    ///
    pub tls: Option<TlsProperties>,
    ///
    pub auth: Option<AuthProperties>,
}

/// Properties accessible after the HELO/EHLO command
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "testing", derive(PartialEq, Eq))]
pub struct HeloProperties {
    ///
    pub client_name: ClientName,
    ///
    pub using_deprecated: bool,
}

/// Properties accessible after the MAIL FROM command
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "testing", derive(PartialEq, Eq))]
pub struct MailFromProperties {
    ///
    pub reverse_path: Option<Address>,
    ///
    #[serde(with = "time::serde::iso8601")]
    pub mail_timestamp: time::OffsetDateTime,
    ///
    pub message_uuid: uuid::Uuid,
    ///
    pub spf: Option<spf::Result>,
}

/// Properties accessible after the RCPT TO command
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "testing", derive(PartialEq, Eq))]
pub struct RcptToProperties {
    ///
    pub forward_paths: Vec<Address>,
    ///
    pub delivery: std::collections::HashMap<WrapperSerde, DeliverTo>,
    ///
    pub transaction_type: TransactionType,
}

/// Properties accessible once the message has been fully received
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "testing", derive(PartialEq, Eq))]
pub struct FinishedProperties {
    ///
    pub dkim: Option<dkim::VerificationResult>,
}
#[doc(hidden)]
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, serde::Serialize)]
pub struct ContextConnect {
    connect: ConnectProperties,
}

#[doc(hidden)]
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, serde::Serialize)]
pub struct ContextHelo {
    connect: ConnectProperties,
    helo: HeloProperties,
}

#[doc(hidden)]
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, serde::Serialize)]
pub struct ContextMailFrom {
    connect: ConnectProperties,
    helo: HeloProperties,
    mail_from: MailFromProperties,
}

#[doc(hidden)]
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, serde::Serialize)]
pub struct ContextRcptTo {
    connect: ConnectProperties,
    helo: HeloProperties,
    mail_from: MailFromProperties,
    rcpt_to: RcptToProperties,
}

#[doc(hidden)]
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "testing", derive(PartialEq, Eq))]
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
