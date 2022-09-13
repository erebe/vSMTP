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
    pub(crate) async fn message_remove<
        OUT: std::io::Write + Send + Sync,
        IN: tokio::io::AsyncRead + Send + Sync + std::marker::Unpin,
    >(
        msg_id: &str,
        confirmed: bool,
        queue_manager: std::sync::Arc<impl GenericQueueManager + Send + Sync>,
        output: &mut OUT,
        mut input: IN,
    ) -> anyhow::Result<()> {
        let queue = <QueueID as strum::IntoEnumIterator>::iter()
            .find(|q| queue_manager.get_ctx(q, msg_id).is_ok());

        match (queue, queue_manager.get_msg(msg_id)) {
            (None, Ok(_)) => {
                anyhow::bail!("Message is orphan: exists but no context in the queue!")
            }
            (None, Err(_)) => {
                anyhow::bail!("Message does not exist in any queue!")
            }
            (Some(_), Err(_)) => {
                anyhow::bail!("Message  is orphan: context in the queue but no message!")
            }
            (Some(queue), Ok(_)) => {
                output.write_fmt(format_args!(
                    "Removing message '{msg_id}' in queue: '{queue}'\n",
                ))?;

                if !confirmed {
                    output.write_all(b"Confirm ? [y|yes] ")?;
                    output.flush()?;

                    let buf = &mut [0u8; 1];
                    tokio::io::AsyncReadExt::read(&mut input, buf).await?;

                    if buf[0] != b'y' {
                        output.write_all(b"Canceled\n")?;
                        return Ok(());
                    }
                }

                queue_manager.remove_both(&queue, msg_id).await?;
                output.write_all(b"File removed\n")?;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use vsmtp_test::config::{local_ctx, local_msg, local_test};

    #[tokio::test]
    async fn confirmed() {
        let mut output = vec![];
        let input = std::io::Cursor::new(vec![]);

        let mut config = local_test();
        config.server.queues.dirpath = "./tmp/cmd_remove".into();
        let config = std::sync::Arc::new(config);

        let _rm = std::fs::remove_dir_all(&config.server.queues.dirpath);
        let queue_manager = crate::fs::QueueManager::init(config).unwrap();

        let msg_id = "titi";

        let mut ctx = local_ctx();
        ctx.metadata.message_id = Some(msg_id.to_string());

        queue_manager
            .write_both(&QueueID::Working, &ctx, &local_msg())
            .await
            .unwrap();

        Commands::message_remove(msg_id, true, queue_manager.clone(), &mut output, input)
            .await
            .unwrap();

        queue_manager
            .get_both(&QueueID::Working, msg_id)
            .unwrap_err();

        pretty_assertions::assert_eq!(
            std::str::from_utf8(&output).unwrap(),
            [
                "Removing message 'titi' in queue: 'working'\n",
                "File removed\n"
            ]
            .concat()
        );
    }

    #[tokio::test]
    async fn not_confirmed() {
        let mut output = vec![];
        let input = std::io::Cursor::new(b"yes\n" as &[u8]);

        let mut config = local_test();
        config.server.queues.dirpath = "./tmp/cmd_remove".into();
        let config = std::sync::Arc::new(config);

        let _rm = std::fs::remove_dir_all(&config.server.queues.dirpath);
        let queue_manager = crate::fs::QueueManager::init(config).unwrap();

        let msg_id = "tata";

        let mut ctx = local_ctx();
        ctx.metadata.message_id = Some(msg_id.to_string());

        queue_manager
            .write_both(&QueueID::Working, &ctx, &local_msg())
            .await
            .unwrap();

        Commands::message_remove(msg_id, false, queue_manager.clone(), &mut output, input)
            .await
            .unwrap();

        queue_manager
            .get_both(&QueueID::Working, msg_id)
            .unwrap_err();

        pretty_assertions::assert_eq!(
            std::str::from_utf8(&output).unwrap(),
            [
                "Removing message 'tata' in queue: 'working'\n",
                "Confirm ? [y|yes] ",
                "File removed\n"
            ]
            .concat()
        );
    }

    #[tokio::test]
    async fn canceled() {
        let mut output = vec![];
        let input = std::io::Cursor::new(b"no\n" as &[u8]);

        let mut config = local_test();
        config.server.queues.dirpath = "./tmp/cmd_remove".into();
        let config = std::sync::Arc::new(config);

        let _rm = std::fs::remove_dir_all(&config.server.queues.dirpath);
        let queue_manager = crate::fs::QueueManager::init(config).unwrap();

        let msg_id = "toto";

        let mut ctx = local_ctx();
        ctx.metadata.message_id = Some(msg_id.to_string());

        queue_manager
            .write_both(&QueueID::Working, &ctx, &local_msg())
            .await
            .unwrap();

        Commands::message_remove(msg_id, false, queue_manager.clone(), &mut output, input)
            .await
            .unwrap();

        queue_manager.get_both(&QueueID::Working, msg_id).unwrap();

        pretty_assertions::assert_eq!(
            std::str::from_utf8(&output).unwrap(),
            [
                "Removing message 'toto' in queue: 'working'\n",
                "Confirm ? [y|yes] ",
                "Canceled\n"
            ]
            .concat()
        );
    }
}
