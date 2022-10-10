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

use vsmtp_plugins::rhai;

use crate::api::EngineResult;
use rhai::plugin::{
    mem, Dynamic, EvalAltResult, FnAccess, FnNamespace, Module, NativeCallContext, PluginFunction,
    RhaiResult, TypeId,
};
use vsmtp_common::status::Status;

pub use types_rhai::*;

#[rhai::plugin::export_module]
mod types_rhai {

    // Status

    /// Operator `==` for `Status`
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "==", pure)]
    pub fn eq_status_operator(in1: &mut Status, in2: Status) -> bool {
        *in1 == in2
    }

    /// Operator `!=` for `Status`
    #[allow(clippy::needless_pass_by_value)]
    #[rhai_fn(global, name = "!=", pure)]
    pub fn neq_status_operator(in1: &mut Status, in2: Status) -> bool {
        !(*in1 == in2)
    }

    /// Convert a `Status` to a `String`
    #[rhai_fn(global, pure)]
    pub fn to_string(status: &mut Status) -> String {
        status.as_ref().to_string()
    }

    /// Convert a `Status` to a debug string
    #[rhai_fn(global, pure)]
    pub fn to_debug(status: &mut Status) -> String {
        status.as_ref().to_string()
    }

    // std::time::SystemTime

    /// Convert a `std::time::SystemTime` to a `String`
    #[rhai_fn(global, name = "to_string", return_raw, pure)]
    pub fn time_to_string(this: &mut std::time::SystemTime) -> EngineResult<String> {
        Ok(format!(
            "{}",
            this.duration_since(std::time::SystemTime::UNIX_EPOCH)
                .map_err::<Box<EvalAltResult>, _>(|e| e.to_string().into())?
                .as_secs()
        ))
    }

    /// Convert a `std::time::SystemTime` to a `String`
    #[rhai_fn(global, name = "to_debug", return_raw, pure)]
    pub fn time_to_debug(this: &mut std::time::SystemTime) -> EngineResult<String> {
        Ok(format!(
            "{:?}",
            this.duration_since(std::time::SystemTime::UNIX_EPOCH)
                .map_err::<Box<EvalAltResult>, _>(|e| e.to_string().into())?
        ))
    }
}
