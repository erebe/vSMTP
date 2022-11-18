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
use super::Mechanism;

/// The credentials send by the client, not necessarily the right one
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize, strum::Display)]
#[strum(serialize_all = "PascalCase")]
pub enum Credentials {
    /// the pair will be sent and verified by a third party
    Verify {
        ///
        authid: String,
        ///
        authpass: String,
    },
    /// verify the token send by anonymous mechanism
    AnonymousToken {
        /// [ email / 1*255TCHAR ]
        token: String,
    },
}

#[doc(hidden)]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("field is missing")]
    MissingField,
    #[error("cannot parse utf8")]
    Utf8(std::str::Utf8Error),
    #[error("mechanism not implemented")]
    Unimplemented,
}

impl TryFrom<(&rsasl::callback::SessionData, &rsasl::callback::Context<'_>)> for Credentials {
    type Error = Error;

    fn try_from(
        value: (&rsasl::callback::SessionData, &rsasl::callback::Context<'_>),
    ) -> Result<Self, Self::Error> {
        let (session_data, context) = value;

        match session_data.mechanism().mechanism {
            mech if mech == Mechanism::Plain.as_ref() || mech == Mechanism::Login.as_ref() => {
                Ok(Self::Verify {
                    authid: context
                        .get_ref::<rsasl::property::AuthId>()
                        .ok_or(Error::MissingField)?
                        .to_string(),
                    authpass: std::str::from_utf8(
                        context
                            .get_ref::<rsasl::property::Password>()
                            .ok_or(Error::MissingField)?,
                    )
                    .map_err(Error::Utf8)?
                    .to_string(),
                })
            }
            mech if mech == Mechanism::Anonymous.as_ref() => Ok(Credentials::AnonymousToken {
                token: context
                    .get_ref::<rsasl::mechanisms::anonymous::AnonymousToken>()
                    .ok_or(Error::MissingField)?
                    .to_string(),
            }),
            // mech if mech == Mechanism::CramMd5.as_ref() => todo!(),
            _ => Err(Error::Unimplemented),
        }
    }
}
