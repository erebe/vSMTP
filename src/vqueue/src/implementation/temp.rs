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

use crate::{FilesystemQueueManagerExt, QueueID};
use anyhow::Context;
use vsmtp_common::transport::DeserializerFn;
use vsmtp_config::Config;

extern crate alloc;

///
pub struct QueueManager {
    config: alloc::sync::Arc<Config>,
    pub(crate) tempdir: tempfile::TempDir,
    transport_deserializer: Vec<DeserializerFn>,
}

impl core::fmt::Debug for QueueManager {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TempQueueManager").finish_non_exhaustive()
    }
}

#[allow(clippy::missing_trait_methods)]
#[async_trait::async_trait]
impl FilesystemQueueManagerExt for QueueManager {
    #[inline]
    fn init(
        config: alloc::sync::Arc<Config>,
        transport_deserializer: Vec<DeserializerFn>,
    ) -> anyhow::Result<alloc::sync::Arc<Self>> {
        let this = alloc::sync::Arc::new(Self {
            config,
            tempdir: tempfile::Builder::new().rand_bytes(20).tempdir()?,
            transport_deserializer,
        });

        for i in <QueueID as strum::IntoEnumIterator>::iter() {
            let (cpy, q) = (alloc::sync::Arc::clone(&this), i.clone());
            let dir = cpy.get_queue_path(&q);
            std::fs::create_dir_all(&dir).with_context(|| {
                format!("could not create `{i}` directory at `{}`", dir.display())
            })?;
        }

        Ok(this)
    }

    #[inline]
    fn get_config(&self) -> &Config {
        &self.config
    }

    #[inline]
    fn get_transport_deserializer(&self) -> &[DeserializerFn] {
        &self.transport_deserializer
    }

    #[inline]
    fn get_queue_path(&self, queue: &QueueID) -> std::path::PathBuf {
        self.tempdir
            .path()
            .join(Self::get_root_folder(&self.config, queue).join(queue.to_string()))
    }
}
