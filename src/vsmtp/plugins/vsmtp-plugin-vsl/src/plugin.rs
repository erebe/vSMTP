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

use vsmtp_plugins::{
    anyhow,
    plugins::{vsl::native::Native, Plugin},
    rhai,
};

pub struct Objects;

impl Plugin for Objects {
    fn name(&self) -> &'static str {
        "objects"
    }
}

impl Native for Objects {
    fn register(
        &self,
        mut builder: vsmtp_plugins::plugins::vsl::native::Builder<'_>,
    ) -> anyhow::Result<()> {
        builder.register_global_module(rhai::exported_module!(super::api::objects));
        builder.register_global_module(rhai::exported_module!(super::api::utils));
        builder.register_global_module(rhai::exported_module!(super::api::comparisons));

        Ok(())
    }
}
