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
    managers::PLUGIN_ENTRYPOINT,
    plugins::vsl::native::{Builder, Native},
};

use super::PluginManager;

/// Load and manage plugins.
#[allow(clippy::module_name_repetitions)]
#[derive(Default)]
pub struct NativeVSL {
    plugins: std::collections::HashMap<String, Box<dyn Native>>,
    libraries: Vec<std::sync::Arc<libloading::Library>>,
}

impl std::fmt::Debug for NativeVSL {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeVSL").finish_non_exhaustive()
    }
}

impl NativeVSL {
    pub fn add_native_plugin(
        &mut self,
        name: impl Into<String>,
        plugin: Box<dyn Native>,
    ) -> &mut Self {
        self.plugins.insert(name.into(), plugin);

        self
    }
}

impl PluginManager for NativeVSL {
    /// Load a plugin in memory from a dynamic library.
    fn load(
        &mut self,
        name: impl AsRef<str>,
        path: impl AsRef<std::ffi::OsStr>,
    ) -> anyhow::Result<()> {
        type PluginConstructor = fn() -> Box<dyn Native>;

        let library = unsafe {
            // Workaround for a crash on library unloading on linux: https://github.com/nagisa/rust_libloading/issues/5#issuecomment-244195096
            // FIXME: it leekS libraries once the server shuts down.
            libloading::Library::from(libloading::os::unix::Library::open(
                Some(path),
                // Load library with `RTLD_NOW | RTLD_NODELETE` to fix SIGSEGV.
                0x2 | 0x1000,
            )?)
        };

        self.libraries.push(std::sync::Arc::new(library));
        let library = self.libraries.last().ok_or_else(|| {
            anyhow::anyhow!("library has just been pushed in memory but could not get fetched.")
        })?;

        let constructor =
            unsafe { library.get::<PluginConstructor>(PLUGIN_ENTRYPOINT.as_bytes()) }?;

        let plugin = constructor();

        // Checking for ABI mismatch.
        let rust_version = env!("CARGO_PKG_RUST_VERSION");

        if plugin.rust_version() != rust_version {
            anyhow::bail!(
                "plugin rust version mismatch. vsmtp => {}, {} => {}",
                rust_version,
                plugin.name(),
                plugin.rust_version()
            );
        }

        self.plugins.insert(name.as_ref().to_string(), plugin);

        Ok(())
    }

    fn apply(&self, engine: &mut rhai::Engine) -> anyhow::Result<()> {
        for plugin in self.plugins.values() {
            tracing::debug!(name = %plugin.name(), version = %plugin.version(), "Registering plugin.");
            plugin.register(Builder::new(engine))?;
        }

        Ok(())
    }
}
