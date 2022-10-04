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

pub mod native;

const PLUGIN_ENTRYPOINT: &str = "plugin_constructor";

/// Implement different kinds of plugin managers.
pub trait PluginManager {
    /// Load a plugin.
    fn load(
        &mut self,
        name: impl AsRef<str>,
        path: impl AsRef<std::ffi::OsStr>,
    ) -> anyhow::Result<()>;

    /// Apply plugins to the rhai engine.
    fn apply(&self, engine: &mut rhai::Engine) -> anyhow::Result<()>;
}
