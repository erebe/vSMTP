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

use super::error::Variant;

/// the delivery status of the email of the current rcpt.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
#[cfg_attr(feature = "testing", derive(Eq))]
pub enum Status {
    /// the email has not been sent yet.
    /// the email is in the deliver / working queue at this point.
    Waiting {
        /// timestamp when the status has been set
        #[serde(with = "time::serde::iso8601")]
        timestamp: time::OffsetDateTime,
    },
    /// email for this recipient has been successfully sent.
    /// When all recipient are [`Status::Sent`], the files are removed from disk.
    Sent {
        /// timestamp when the status has been set
        #[serde(with = "time::serde::iso8601")]
        timestamp: time::OffsetDateTime,
        // TODO: keep the response ? and previous error ?
    },
    /// the delivery failed, the system is trying to re-send the email.
    /// the email is located in the deferred queue at this point.
    HeldBack {
        /// timestamp when the status has been set
        errors: Vec<Error>,
    },
    /// the email failed too many times. the argument is the reason of the failure.
    /// the email is probably written in the dead or quarantine queues at this point.
    Failed {
        // TODO: should be a `Vec<TransferError>` ?
        // history: Vec<TransferError>
        ///
        error: Error,
    },
}

// NOTE: ignore the timestamp
#[cfg(feature = "testing")]
impl PartialEq for Status {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Sent { .. }, Self::Sent { .. })
            | (Self::Waiting { .. }, Self::Waiting { .. }) => true,
            (Self::HeldBack { errors: l_errors }, Self::HeldBack { errors: r_errors }) => {
                l_errors == r_errors
            }
            (Self::Failed { error: l_error, .. }, Self::Failed { error: r_error, .. }) => {
                l_error == r_error
            }
            _ => false,
        }
    }
}

impl Default for Status {
    fn default() -> Self {
        Self::Waiting {
            timestamp: time::OffsetDateTime::now_utc(),
        }
    }
}

impl Status {
    /// Should the recipient be delivered, or it has been done already ?
    #[must_use]
    pub const fn is_sendable(&self) -> bool {
        match self {
            Self::Waiting { .. } | Self::HeldBack { .. } => true,
            Self::Sent { .. } | Self::Failed { .. } => false,
        }
    }

    /// Set the status to [`Status::HeldBack`] with an error, or increase the previous stack.
    pub fn held_back(&mut self, error: impl Into<Variant>) {
        let error = error.into();
        match self {
            Self::HeldBack { errors } => {
                errors.push(Error::new(error));
            }
            _ => {
                *self = Self::HeldBack {
                    errors: vec![(Error::new(error))],
                }
            }
        }
    }

    ///
    #[must_use]
    pub fn sent() -> Self {
        Self::Sent {
            timestamp: time::OffsetDateTime::now_utc(),
        }
    }

    ///
    #[must_use]
    pub fn failed(error: impl Into<Variant>) -> Self {
        Self::Failed {
            error: Error::new(error.into()),
        }
    }
}

///
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "testing", derive(Eq))]
pub struct Error {
    variant: Variant,
    #[serde(with = "time::serde::iso8601")]
    timestamp: time::OffsetDateTime,
}

#[cfg(feature = "testing")]
impl PartialEq for Error {
    // NOTE: ignore the timestamp
    fn eq(&self, other: &Self) -> bool {
        let Self {
            variant: self_variant,
            timestamp: _,
        } = self;

        let Self {
            variant: other_variant,
            timestamp: _,
        } = other;

        self_variant == other_variant
    }
}

impl Error {
    /// Create a new instance with the current timestamp
    #[must_use]
    pub fn new(variant: Variant) -> Self {
        Self {
            variant,
            timestamp: time::OffsetDateTime::now_utc(),
        }
    }

    /// Get the underlying error (only for testing)
    #[cfg(feature = "testing")]
    #[must_use]
    pub const fn variant(&self) -> &Variant {
        &self.variant
    }

    /// Get the underlying timestamp
    #[must_use]
    pub const fn timestamp(&self) -> &time::OffsetDateTime {
        &self.timestamp
    }
}
