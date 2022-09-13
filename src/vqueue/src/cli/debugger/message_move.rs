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
use crate::{cli::args::Commands, GenericQueueManager, QueueID};

impl Commands {
    pub(crate) async fn message_move(
        msg_id: &str,
        queue: &QueueID,
        queue_manager: std::sync::Arc<impl GenericQueueManager + Send + Sync>,
    ) -> anyhow::Result<()> {
        let old_queue = <QueueID as strum::IntoEnumIterator>::iter()
            .find(|q| queue_manager.get_ctx(q, msg_id).is_ok());

        match (old_queue, queue_manager.get_msg(msg_id)) {
            (None, Ok(_)) => {
                anyhow::bail!("Message is orphan: exists but no context in the queue!")
            }
            (None, Err(_)) => {
                anyhow::bail!("Message does not exist in any queue!")
            }
            (Some(_), Err(_)) => {
                anyhow::bail!("Message  is orphan: context in the queue but no message!")
            }
            (Some(old_queue), Ok(_)) => {
                queue_manager
                    .move_to_from_id(&old_queue, queue, msg_id)
                    .await
            }
        }
    }
}
