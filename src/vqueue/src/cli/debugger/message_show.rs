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
use anyhow::Context;
extern crate alloc;

#[allow(clippy::multiple_inherent_impl)]
impl Commands {
    pub(crate) async fn message_show<OUT: std::io::Write + Send + Sync>(
        msg_uuid: &uuid::Uuid,
        queue_manager: &alloc::sync::Arc<impl GenericQueueManager + Send + Sync>,
        format: &MessageShowFormat,
        output: &mut OUT,
    ) -> anyhow::Result<()> {
        let ctx = futures_util::future::join_all(
            <QueueID as strum::IntoEnumIterator>::iter()
                .map(|q| async move { queue_manager.get_ctx(&q, msg_uuid).await }),
        )
        .await;

        let ctx = ctx
            .into_iter()
            .find_map(Result::ok)
            .context("Mail context not found")?;

        let msg = queue_manager
            .get_msg(msg_uuid)
            .await
            .context("Message not found")?;

        output.write_fmt(format_args!(
            "Message context:\n{}\n",
            serde_json::to_string_pretty(&ctx)?
        ))?;

        output.write_all(b"Message body:\n")?;

        output.write_all(
            match *format {
                MessageShowFormat::Eml => msg.inner().to_string(),
                MessageShowFormat::Json => serde_json::to_string_pretty(&msg)?,
            }
            .as_bytes(),
        )?;

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

        let config = alloc::sync::Arc::new(local_test());
        let queue_manager = crate::temp::QueueManager::init(config).unwrap();

        let mut ctx = local_ctx();
        let msg_uuid = uuid::Uuid::new_v4();
        ctx.mail_from.message_uuid = msg_uuid;

        queue_manager
            .write_both(&QueueID::Deferred, &ctx, &local_msg())
            .await
            .unwrap();

        Commands::message_show(
            &msg_uuid,
            &queue_manager,
            &MessageShowFormat::Json,
            &mut output,
        )
        .await
        .unwrap();

        let connect_uuid = ctx.connect.connect_uuid;

        let connect_timestamp = ctx.connect.connect_timestamp;
        let connect_timestamp =
            time::serde::iso8601::serialize(&connect_timestamp, serde_json::value::Serializer)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned();
        let connect_timestamp = connect_timestamp.replace("  ", "    ").replace('}', "  }");

        let mail_timestamp = ctx.mail_from.mail_timestamp;
        let mail_timestamp =
            time::serde::iso8601::serialize(&mail_timestamp, serde_json::value::Serializer)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned();
        let mail_timestamp = mail_timestamp.replace("  ", "    ").replace('}', "  }");

        pretty_assertions::assert_eq!(
            core::str::from_utf8(&output).unwrap(),
            format!(
                r#"Message context:
{{
  "connect_timestamp": "{connect_timestamp}",
  "connect_uuid": "{connect_uuid}",
  "client_addr": "127.0.0.1:25",
  "server_addr": "127.0.0.1:5977",
  "server_name": "testserver.com",
  "skipped": null,
  "tls": null,
  "auth": null,
  "client_name": "client.testserver.com",
  "using_deprecated": false,
  "reverse_path": "client@client.testserver.com",
  "mail_timestamp": "{mail_timestamp}",
  "message_uuid": "{msg_uuid}",
  "outgoing": false,
  "forward_paths": [],
  "transaction_type": {{
    "incoming": null
  }},
  "dkim": null,
  "spf": null
}}
Message body:
{{
  "raw": {{
    "headers": [
      "From: NoBody <nobody@domain.tld>\r\n",
      "Reply-To: Yuin <yuin@domain.tld>\r\n",
      "To: Hei <hei@domain.tld>\r\n",
      "Subject: Happy new year\r\n"
    ],
    "body": "Be happy!\r\n"
  }},
  "parsed": null
}}"#,
            )
        );
    }

    #[tokio::test]
    async fn show1_eml() {
        let mut output = vec![];

        let config = alloc::sync::Arc::new(local_test());
        let queue_manager = crate::temp::QueueManager::init(config).unwrap();

        let mut ctx = local_ctx();
        let msg_uuid = uuid::Uuid::new_v4();
        ctx.mail_from.message_uuid = msg_uuid;

        queue_manager
            .write_both(&QueueID::Deferred, &ctx, &local_msg())
            .await
            .unwrap();

        Commands::message_show(
            &msg_uuid,
            &queue_manager,
            &MessageShowFormat::Eml,
            &mut output,
        )
        .await
        .unwrap();

        let connect_uuid = ctx.connect.connect_uuid;

        let connect_timestamp = ctx.connect.connect_timestamp;
        let connect_timestamp =
            time::serde::iso8601::serialize(&connect_timestamp, serde_json::value::Serializer)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned();
        let connect_timestamp = connect_timestamp.replace("  ", "    ").replace('}', "  }");

        let mail_timestamp = ctx.mail_from.mail_timestamp;
        let mail_timestamp =
            time::serde::iso8601::serialize(&mail_timestamp, serde_json::value::Serializer)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned();
        let mail_timestamp = mail_timestamp.replace("  ", "    ").replace('}', "  }");

        pretty_assertions::assert_eq!(
            core::str::from_utf8(&output).unwrap(),
            format!(
                r#"Message context:
{{
  "connect_timestamp": "{connect_timestamp}",
  "connect_uuid": "{connect_uuid}",
  "client_addr": "127.0.0.1:25",
  "server_addr": "127.0.0.1:5977",
  "server_name": "testserver.com",
  "skipped": null,
  "tls": null,
  "auth": null,
  "client_name": "client.testserver.com",
  "using_deprecated": false,
  "reverse_path": "client@client.testserver.com",
  "mail_timestamp": "{mail_timestamp}",
  "message_uuid": "{msg_uuid}",
  "outgoing": false,
  "forward_paths": [],
  "transaction_type": {{
    "incoming": null
  }},
  "dkim": null,
  "spf": null
}}
Message body:
{}"#,
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
