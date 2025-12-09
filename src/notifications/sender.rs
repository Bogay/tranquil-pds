use async_trait::async_trait;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::types::{NotificationChannel, QueuedNotification};

#[async_trait]
pub trait NotificationSender: Send + Sync {
    fn channel(&self) -> NotificationChannel;
    async fn send(&self, notification: &QueuedNotification) -> Result<(), SendError>;
}

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("Failed to spawn sendmail process: {0}")]
    ProcessSpawn(#[from] std::io::Error),

    #[error("Sendmail exited with non-zero status: {0}")]
    SendmailFailed(String),

    #[error("Channel not configured: {0:?}")]
    NotConfigured(NotificationChannel),

    #[error("External service error: {0}")]
    ExternalService(String),
}

pub struct EmailSender {
    from_address: String,
    from_name: String,
    sendmail_path: String,
}

impl EmailSender {
    pub fn new(from_address: String, from_name: String) -> Self {
        Self {
            from_address,
            from_name,
            sendmail_path: std::env::var("SENDMAIL_PATH").unwrap_or_else(|_| "/usr/sbin/sendmail".to_string()),
        }
    }

    pub fn from_env() -> Option<Self> {
        let from_address = std::env::var("MAIL_FROM_ADDRESS").ok()?;
        let from_name = std::env::var("MAIL_FROM_NAME").unwrap_or_else(|_| "BSPDS".to_string());
        Some(Self::new(from_address, from_name))
    }

    fn format_email(&self, notification: &QueuedNotification) -> String {
        let subject = notification.subject.as_deref().unwrap_or("Notification");
        let from_header = if self.from_name.is_empty() {
            self.from_address.clone()
        } else {
            format!("{} <{}>", self.from_name, self.from_address)
        };

        format!(
            "From: {}\r\nTo: {}\r\nSubject: {}\r\nContent-Type: text/plain; charset=utf-8\r\nMIME-Version: 1.0\r\n\r\n{}",
            from_header,
            notification.recipient,
            subject,
            notification.body
        )
    }
}

#[async_trait]
impl NotificationSender for EmailSender {
    fn channel(&self) -> NotificationChannel {
        NotificationChannel::Email
    }

    async fn send(&self, notification: &QueuedNotification) -> Result<(), SendError> {
        let email_content = self.format_email(notification);

        let mut child = Command::new(&self.sendmail_path)
            .arg("-t")
            .arg("-oi")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(email_content.as_bytes()).await?;
        }

        let output = child.wait_with_output().await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SendError::SendmailFailed(stderr.to_string()));
        }

        Ok(())
    }
}
