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
    cli::args::{Commands, MessageShowFormat},
    GenericQueueManager, QueueID,
};

impl Commands {
    pub(crate) async fn message_show<OUT: std::io::Write + Send + Sync>(
        msg_id: &str,
        queue_manager: std::sync::Arc<impl GenericQueueManager + Send + Sync>,
        format: &MessageShowFormat,
        output: &mut OUT,
    ) -> anyhow::Result<()> {
        let ctx = <QueueID as strum::IntoEnumIterator>::iter()
            .find_map(|q| queue_manager.get_ctx(&q, msg_id).ok());

        match (ctx, queue_manager.get_msg(msg_id)) {
            (None, Ok(_)) => {
                anyhow::bail!("Message is orphan: exists but no context in the queue!")
            }
            (None, Err(_)) => {
                anyhow::bail!("Message does not exist in any queue!")
            }
            (Some(_), Err(_)) => {
                anyhow::bail!("Message  is orphan: context in the queue but no message!")
            }
            (Some(ctx), Ok(msg)) => {
                output.write_fmt(format_args!(
                    "Message context:\n{}\n",
                    serde_json::to_string_pretty(&ctx)?
                ))?;

                output.write_all(b"Message body:\n")?;

                output.write_all(
                    match format {
                        MessageShowFormat::Eml => msg.inner().to_string(),
                        MessageShowFormat::Json => serde_json::to_string_pretty(&msg)?,
                    }
                    .as_bytes(),
                )?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vsmtp_test::config::{local_ctx, local_msg, local_test};

    #[tokio::test]
    async fn show1_json() {
        let mut output = vec![];

        let mut config = local_test();
        config.server.queues.dirpath = "./tmp/show1_json".into();
        let config = std::sync::Arc::new(config);

        let _rm = std::fs::remove_dir_all(&config.server.queues.dirpath);
        let queue_manager = crate::fs::QueueManager::init(config).unwrap();

        let msg_id = "my_message";

        let mut ctx = local_ctx();
        ctx.metadata.message_id = Some(msg_id.to_string());

        let timestamp = ctx.connection.timestamp;

        queue_manager
            .write_both(&QueueID::Deferred, &ctx, &local_msg())
            .await
            .unwrap();

        Commands::message_show(msg_id, queue_manager, &MessageShowFormat::Json, &mut output)
            .await
            .unwrap();

        pretty_assertions::assert_eq!(
            std::str::from_utf8(&output).unwrap(),
            format!(
                r#"Message context:
{{
  "connection": {{
    "timestamp": {},
    "client_addr": "127.0.0.1:5977",
    "credentials": null,
    "server_name": "testserver.com",
    "server_addr": "127.0.0.1:25",
    "is_authenticated": false,
    "is_secured": false,
    "error_count": 0,
    "authentication_attempt": 0
  }},
  "envelop": {{
    "helo": "client.testserver.com",
    "mail_from": "client@client.testserver.com",
    "rcpt": []
  }},
  "metadata": {{
    "timestamp": null,
    "message_id": "my_message",
    "skipped": null,
    "spf": null,
    "dkim": null
  }}
}}
Message body:
{{
  "raw": {{
    "headers": [
      "From: NoBody <nobody@domain.tld>",
      "Reply-To: Yuin <yuin@domain.tld>",
      "To: Hei <hei@domain.tld>",
      "Subject: Happy new year"
    ],
    "body": "Be happy!\r\n"
  }},
  "parsed": null
}}"#,
                serde_json::to_string_pretty(&timestamp)
                    .unwrap()
                    .replace("  ", "      ")
                    .replace('}', "    }")
            )
        );
    }

    #[tokio::test]
    async fn show1_eml() {
        let mut output = vec![];

        let mut config = local_test();
        config.server.queues.dirpath = "./tmp/show1_eml".into();
        let config = std::sync::Arc::new(config);

        let _rm = std::fs::remove_dir_all(&config.server.queues.dirpath);
        let queue_manager = crate::fs::QueueManager::init(config).unwrap();

        let msg_id = "my_message";

        let mut ctx = local_ctx();
        ctx.metadata.message_id = Some(msg_id.to_string());

        let timestamp = ctx.connection.timestamp;

        queue_manager
            .write_both(&QueueID::Deferred, &ctx, &local_msg())
            .await
            .unwrap();

        Commands::message_show(msg_id, queue_manager, &MessageShowFormat::Eml, &mut output)
            .await
            .unwrap();

        pretty_assertions::assert_eq!(
            std::str::from_utf8(&output).unwrap(),
            format!(
                r#"Message context:
{{
  "connection": {{
    "timestamp": {},
    "client_addr": "127.0.0.1:5977",
    "credentials": null,
    "server_name": "testserver.com",
    "server_addr": "127.0.0.1:25",
    "is_authenticated": false,
    "is_secured": false,
    "error_count": 0,
    "authentication_attempt": 0
  }},
  "envelop": {{
    "helo": "client.testserver.com",
    "mail_from": "client@client.testserver.com",
    "rcpt": []
  }},
  "metadata": {{
    "timestamp": null,
    "message_id": "my_message",
    "skipped": null,
    "spf": null,
    "dkim": null
  }}
}}
Message body:
{}"#,
                serde_json::to_string_pretty(&timestamp)
                    .unwrap()
                    .replace("  ", "      ")
                    .replace('}', "    }"),
                [
                    "From: NoBody <nobody@domain.tld>\r\n",
                    "Reply-To: Yuin <yuin@domain.tld>\r\n",
                    "To: Hei <hei@domain.tld>\r\n",
                    "Subject: Happy new year\r\n",
                    "\r\n",
                    "Be happy!\r\n",
                ]
                .concat()
            )
        );
    }
}
