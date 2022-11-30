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

use crate::{Process, ProcessMessage};
use vqueue::{GenericQueueManager, QueueID};
use vsmtp_common::ContextFinished;
use vsmtp_common::{
    state::State,
    status::Status,
    transfer::{EmailTransferStatus, RuleEngineVariants, TransferErrorsVariant},
    CodeID,
};
use vsmtp_mail_parser::MessageBody;

/// will be executed once the email is received.
#[async_trait::async_trait]
pub trait OnMail {
    /// the server executes this function once the email as been received.
    async fn on_mail(
        &mut self,
        mail: Box<ContextFinished>,
        message: MessageBody,
        queue_manager: std::sync::Arc<dyn GenericQueueManager>,
    ) -> CodeID
    where
        Self: Sized;
}

/// Send the email to the queue.
#[derive(Clone)]
pub struct MailHandler {
    pub(crate) working_sender: tokio::sync::mpsc::Sender<ProcessMessage>,
    pub(crate) delivery_sender: tokio::sync::mpsc::Sender<ProcessMessage>,
}

#[must_use]
#[derive(Debug, thiserror::Error)]
pub enum MailHandlerError {
    #[error("could not write to `mails` folder: `{0}`")]
    WriteMessageBody(std::io::Error),
    #[error("could not write to queue `{0}` got: `{1}`")]
    WriteToQueue(QueueID, String),
    #[error("could not send message to next process `{0}` got: `{1}`")]
    SendToNextProcess(Process, tokio::sync::mpsc::error::SendError<ProcessMessage>),
    #[error("delegate directive cannot be used in preq stage")]
    InvalidDelegation,
}

impl MailHandler {
    /// create a new mail handler
    #[must_use]
    pub const fn new(
        working_sender: tokio::sync::mpsc::Sender<ProcessMessage>,
        delivery_sender: tokio::sync::mpsc::Sender<ProcessMessage>,
    ) -> Self {
        Self {
            working_sender,
            delivery_sender,
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn on_mail_priv(
        &self,
        mut mail_context: Box<ContextFinished>,
        mail_message: MessageBody,
        queue_manager: &std::sync::Arc<dyn GenericQueueManager>,
    ) -> Result<(), MailHandlerError> {
        let (mut message_uuid, skipped) = (
            mail_context.mail_from.message_uuid,
            mail_context.connect.skipped.clone(),
        );

        let mut write_to_queue = Option::<QueueID>::None;
        let mut send_to_next_process = Option::<Process>::None;
        let mut delegated = false;

        match &skipped {
            Some(status @ Status::Quarantine(path)) => {
                let quarantine = QueueID::Quarantine { name: path.into() };
                queue_manager
                    .write_ctx(&quarantine, &mail_context)
                    .await
                    .map_err(|err| MailHandlerError::WriteToQueue(quarantine, err.to_string()))?;

                tracing::warn!(status = status.as_ref(), "Rules skipped.");
            }
            Some(Status::Delegated(_)) => {
                return Err(MailHandlerError::InvalidDelegation);
            }
            Some(Status::DelegationResult) => {
                if let Some(old_message_id) = mail_message
                    .get_header("X-VSMTP-DELEGATION")
                    .and_then(|header| {
                        vsmtp_mail_parser::get_mime_header("X-VSMTP-DELEGATION", &header)
                            .args
                            .get("id")
                            .cloned()
                    })
                {
                    message_uuid =
                        match <uuid::Uuid as std::str::FromStr>::from_str(&old_message_id) {
                            Ok(id) => id,
                            Err(_err) => return Err(MailHandlerError::InvalidDelegation),
                        };
                }

                delegated = true;
                send_to_next_process = Some(Process::Processing);
            }
            Some(Status::Deny(code)) => {
                for rcpt in &mut mail_context.rcpt_to.forward_paths {
                    rcpt.email_status = EmailTransferStatus::failed(
                        TransferErrorsVariant::RuleEngine(RuleEngineVariants::Denied(code.clone())),
                    );
                }

                write_to_queue = Some(QueueID::Dead);
            }
            Some(reason) => {
                tracing::warn!(stage = %State::PreQ, status = ?reason.as_ref(), "Rules skipped.");

                write_to_queue = Some(QueueID::Deliver);
                send_to_next_process = Some(Process::Delivery);
            }
            None => {
                write_to_queue = Some(QueueID::Working);
                send_to_next_process = Some(Process::Processing);
            }
        };

        queue_manager
            .write_msg(&message_uuid, &mail_message)
            .await
            .map_err(|e| MailHandlerError::WriteMessageBody(e.downcast().unwrap()))?;

        if let Some(queue) = write_to_queue {
            queue_manager
                .write_ctx(&queue, &mail_context)
                .await
                .map_err(|error| {
                    MailHandlerError::WriteToQueue(queue.clone(), error.to_string())
                })?;
        }

        // TODO: even if it's a rare case, a result of None should remove the
        //       email from the queue.
        match &send_to_next_process {
            Some(Process::Processing) => &self.working_sender,
            Some(Process::Delivery) => &self.delivery_sender,
            Some(Process::Receiver) | None => return Ok(()),
        }
        .send(ProcessMessage {
            message_uuid,
            delegated,
        })
        .await
        .map_err(|error| MailHandlerError::SendToNextProcess(send_to_next_process.unwrap(), error))
    }
}

#[async_trait::async_trait]
impl OnMail for MailHandler {
    #[tracing::instrument(name = "preq", skip_all)]
    async fn on_mail(
        &mut self,
        mail: Box<ContextFinished>,
        message: MessageBody,
        queue_manager: std::sync::Arc<dyn GenericQueueManager>,
    ) -> CodeID {
        match self.on_mail_priv(mail, message, &queue_manager).await {
            Ok(_) => CodeID::Ok,
            Err(error) => {
                tracing::warn!(%error, "Mail processing failure");
                CodeID::Denied
            }
        }
    }
}
