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
extern crate alloc;

#[allow(clippy::multiple_inherent_impl)]
impl Commands {
    pub(crate) async fn message_move(
        msg_uuid: &uuid::Uuid,
        queue: &QueueID,
        queue_manager: alloc::sync::Arc<impl GenericQueueManager + Send + Sync>,
    ) -> anyhow::Result<()> {
        match (futures_util::future::join_all(
            <QueueID as strum::IntoEnumIterator>::iter()
                .map(|q| (q, alloc::sync::Arc::clone(&queue_manager)))
                .map(|(q, manager)| async move { (q.clone(), manager.get_ctx(&q, msg_uuid).await) }),
        )
        .await
        .into_iter()
        .find_map(|(q, ctx)| match ctx {
            Ok(_) => Some(q),
            Err(_) => None,
        }), queue_manager.get_msg(msg_uuid).await) {
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
                    .move_to_from_id(&old_queue, queue, msg_uuid)
                    .await
            }
        }
    }
}
