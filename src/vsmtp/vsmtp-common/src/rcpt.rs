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
    transfer::{EmailTransferStatus, Transfer},
    Address,
};

/// representation of a recipient with it's delivery method.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Rcpt {
    /// Email address of the recipient.
    pub address: Address,
    /// Protocol used by vsmtp to deliver / transfer the email bound by this recipient.
    pub transfer_method: Transfer,
    /// Delivery status of the email bound to this recipient.
    pub email_status: EmailTransferStatus,
    /// Type of the transaction for this recipient.
    /// Is used to process rules for the current recipient, even when
    /// re-injecting the recipient in the processing loop.
    pub transaction_type: TransactionType,
}

// TODO: find a better name.
/// What rules should be executed regarding the domains of the sender and recipients.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum TransactionType {
    /// The sender's domain is unknown, contained domain is only one of the recipients.
    /// If none, it means all recipients are unknown, or that the rcpt stage has not
    /// yet been executed.
    Incoming(Option<String>),
    /// The sender's domain is known, the domain is stored.
    Outgoing(String),
    /// The sender's domain is known, and recipients domains are the same.
    /// Use the sender's domain to execute your rules.
    Internal,
}

impl Default for TransactionType {
    fn default() -> Self {
        Self::Incoming(None)
    }
}

impl Rcpt {
    /// create a new recipient from it's address.
    /// there is no transfer method by default.
    #[must_use]
    pub fn new(address: Address) -> Self {
        Self {
            address,
            transfer_method: Transfer::default(),
            email_status: EmailTransferStatus::default(),
            transaction_type: TransactionType::default(),
        }
    }

    /// create a new recipient from it's address with it's transaction type.
    #[must_use]
    pub fn with_transaction_type(address: Address, transaction_type: TransactionType) -> Self {
        Self {
            address,
            transfer_method: Transfer::default(),
            email_status: EmailTransferStatus::default(),
            transaction_type,
        }
    }
}

impl From<Address> for Rcpt {
    fn from(this: Address) -> Self {
        Self::new(this)
    }
}

impl std::fmt::Display for Rcpt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.address)
    }
}

impl PartialEq<Rcpt> for Address {
    fn eq(&self, other: &Rcpt) -> bool {
        *self == other.address
    }
}
