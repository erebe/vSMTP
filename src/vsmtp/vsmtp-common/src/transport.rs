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

use crate::{transfer::Status, Address, ContextFinished};
extern crate alloc;

///
#[derive(Debug, thiserror::Error)]
pub enum DeserializerError {
    ///
    #[error("got error: {0}")]
    InvalidInput(String),
    ///
    #[error("the delivery assignation is already ready")]
    UnexpectedReady,
    ///
    #[error("the payload could not be deserialized with the provided deserializer")]
    CannotDeserialize,
}

/// Signature of the transport deserialize entry point in plugins
pub type DeserializerFn =
    unsafe extern "C" fn(
        input: *const std::os::raw::c_char,
    ) -> Result<std::sync::Arc<dyn AbstractTransport>, DeserializerError>;

/// Name of the transport deserialize entry point in plugins
pub const DESERIALIZER_SYMBOL_NAME: &str = "deserialize_transport";

///
pub type DeliverTo = Vec<(Address, Status)>;

/// Generic implementation of a transport
#[allow(clippy::module_name_repetitions)]
#[async_trait::async_trait]
pub trait AbstractTransport: erased_serde::Serialize + GetID + Send + Sync {
    /// Take the data required to deliver the email and return the updated version of the recipient.
    async fn deliver(
        self: std::sync::Arc<Self>,
        context: &ContextFinished,
        rcpt_to: DeliverTo,
        message: &[u8],
    ) -> DeliverTo;

    /// Cast the [`AbstractTransport::deserialize()`] as a [`DeserializerFn`] (ffi compatible function).
    #[must_use]
    fn get_symbol() -> DeserializerFn
    where
        Self: Sized + serde::Deserialize<'static> + 'static,
    {
        <Self as AbstractTransport>::deserialize
    }

    /// Produce a instance from a C string.
    ///
    /// # Safety
    ///
    /// * same note as [`std::ffi::CStr::from_ptr()`] safety section.
    #[allow(unsafe_code, improper_ctypes_definitions)]
    unsafe extern "C" fn deserialize<'de>(
        input: *const std::os::raw::c_char,
    ) -> Result<alloc::sync::Arc<dyn AbstractTransport>, DeserializerError>
    where
        Self: Sized + serde::Deserialize<'de> + 'static,
    {
        let input = std::ffi::CStr::from_ptr(input);
        let input = match input.to_str() {
            Ok(input) => input,
            Err(e) => return Err(DeserializerError::InvalidInput(e.to_string())),
        };
        match serde_json::from_str::<Self>(input) {
            Ok(input) => Ok(alloc::sync::Arc::new(input)),
            Err(e) => Err(DeserializerError::InvalidInput(e.to_string())),
        }
    }
}

impl std::fmt::Debug for dyn AbstractTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AbstractTransport")
            .field(&self.get_id())
            .finish()
    }
}

erased_serde::serialize_trait_object!(AbstractTransport);

/// Trait to abstract the [`Hash`], [`PartialEq`] and [`Eq`] implementations
pub trait GetID
where
    Self: erased_serde::Serialize,
{
    /// Produce a unique identifier for the transport
    fn get_id(&self) -> String {
        let writer = Vec::with_capacity(128);
        let mut ser = serde_json::Serializer::new(writer);
        erased_serde::serialize(self, &mut ser).unwrap();
        String::from_utf8(ser.into_inner()).unwrap()
    }
}

impl std::hash::Hash for dyn AbstractTransport {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.get_id().hash(state);
    }
}

impl PartialEq for dyn AbstractTransport {
    fn eq(&self, other: &Self) -> bool {
        self.get_id() == other.get_id()
    }
}

impl Eq for dyn AbstractTransport {}

/// Wrapper to allow serialization of the transport
#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Debug, Clone, Eq, serde::Deserialize)]
#[serde(untagged)]
pub enum WrapperSerde {
    /// Raw string representation of the transport's payload
    Raw(String),
    /// Ready to use instance
    #[serde(skip_deserializing)]
    Ready(std::sync::Arc<dyn AbstractTransport>),
}

impl serde::Serialize for WrapperSerde {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Raw(s) => serializer.serialize_str(s),
            Self::Ready(value) => erased_serde::serialize(value.as_ref(), serializer),
        }
    }
}

impl PartialEq for WrapperSerde {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Raw(l0), Self::Raw(r0)) => l0 == r0,
            (Self::Ready(l0), Self::Ready(r0)) => l0 == r0,
            _ => false,
        }
    }
}

impl std::hash::Hash for WrapperSerde {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            Self::Raw(raw) => raw.hash(state),
            Self::Ready(ready) => ready.hash(state),
        }
    }
}

impl WrapperSerde {
    /// Convert the instance to a [`WrapperSerde::Ready`] variant
    ///
    /// # Errors
    ///
    /// * see [`DeserializerError`]
    #[inline]
    pub fn to_ready(&self, deserializer: &[DeserializerFn]) -> Result<Self, DeserializerError> {
        match self {
            Self::Ready(_) => Err(DeserializerError::UnexpectedReady),
            Self::Raw(raw) => {
                let i = std::ffi::CString::new(raw.as_bytes()).expect("CString::new failed");

                deserializer
                    .iter()
                    .enumerate()
                    .find_map(|(nbr, deserialize)| {
                        #[allow(unsafe_code)]
                        // SAFETY: pointer is valid because `i` is in the scope
                        match unsafe { deserialize(i.as_ptr()) } {
                            Ok(transport) => {
                                tracing::trace!("({nbr}) deserialize transport successfully");
                                Some(transport)
                            }
                            Err(err) => {
                                tracing::trace!("({nbr}) could not deserialize transport: {err}");
                                None
                            }
                        }
                    })
                    .ok_or(DeserializerError::CannotDeserialize)
                    .map(Self::Ready)
            }
        }
    }

    /// Extract the inner value of the [`WrapperSerde::Ready`] variant.
    /// Must been initialized with [`WrapperSerde::to_ready()`] before.
    ///
    /// # Panics
    ///
    /// * if the delivery assignation is not `Ready`
    #[must_use]
    pub fn unwrap_ready(self) -> std::sync::Arc<dyn AbstractTransport> {
        match self {
            Self::Ready(transport) => transport,
            Self::Raw(_) => panic!("cannot unwrap a raw delivery assignation"),
        }
    }
}
