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

use vsmtp_plugins::plugins::vsl;
use vsmtp_plugins::plugins::vsl::native::Native;
use vsmtp_plugins::plugins::Plugin;

pub struct Smtp;

impl Plugin for Smtp {
    fn name(&self) -> &'static str {
        "smtp"
    }
}

impl Native for Smtp {
    fn register(&self, mut builder: vsl::native::Builder<'_>) -> anyhow::Result<()> {
        builder.register_global_module(vsmtp_plugins::rhai::exported_module!(super::api::smtp));

        Ok(())
    }
}
