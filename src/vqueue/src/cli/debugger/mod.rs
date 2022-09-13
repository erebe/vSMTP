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
use super::args::{Commands, MessageCommand};
use crate::{GenericQueueManager, QueueID};

mod message_move;
mod message_remove;
mod message_show;
mod show;

impl Commands {
    /// Execute the vQueue command
    ///
    /// # Errors
    pub async fn execute(
        self,
        queue_manager: std::sync::Arc<impl GenericQueueManager + Send + Sync>,
    ) -> anyhow::Result<()> {
        match self {
            Commands::Show {
                queues,
                empty_token,
            } => {
                Self::show(
                    if queues.is_empty() {
                        <QueueID as strum::IntoEnumIterator>::iter().collect::<Vec<_>>()
                    } else {
                        queues
                    },
                    queue_manager,
                    empty_token,
                    &mut std::io::stdout(),
                )
                .await
            }

            Commands::Msg { msg, command } => match command {
                MessageCommand::Show { format } => {
                    Self::message_show(&msg, queue_manager, &format, &mut std::io::stdout()).await
                }
                MessageCommand::Move { queue } => {
                    Self::message_move(&msg, &queue, queue_manager).await
                }
                MessageCommand::Remove { yes } => {
                    Self::message_remove(
                        &msg,
                        yes,
                        queue_manager,
                        &mut std::io::stdout(),
                        tokio::io::stdin(),
                    )
                    .await
                }
                MessageCommand::ReRun {} => unimplemented!(),
            },
        }
    }
}
