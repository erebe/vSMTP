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
use vsmtp_config::Config;

///
pub struct QueueManager {
    config: std::sync::Arc<Config>,
    pub(crate) tempdir: tempfile::TempDir,
}

impl std::fmt::Debug for QueueManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TempQueueManager").finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl FilesystemQueueManagerExt for QueueManager {
    fn init(config: std::sync::Arc<Config>) -> anyhow::Result<std::sync::Arc<Self>> {
        let this = std::sync::Arc::new(Self {
            config,
            tempdir: tempfile::Builder::new().rand_bytes(20).tempdir()?,
        });

        for i in <QueueID as strum::IntoEnumIterator>::iter() {
            let (cpy, q) = (this.clone(), i.clone());
            let dir = cpy.get_queue_path(&q);
            std::fs::create_dir_all(&dir).with_context(|| {
                format!("could not create `{i}` directory at `{}`", dir.display())
            })?;
        }

        Ok(this)
    }

    fn get_config(&self) -> &Config {
        &self.config
    }

    fn get_queue_path(&self, queue: &QueueID) -> std::path::PathBuf {
        self.tempdir
            .path()
            .join(Self::get_root_folder(&self.config, queue).join(queue.to_string()))
    }
}
