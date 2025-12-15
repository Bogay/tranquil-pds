use async_trait::async_trait;
use reqwest::Client;
use serde_json::json;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::types::{NotificationChannel, QueuedNotification};

const HTTP_TIMEOUT_SECS: u64 = 30;
const MAX_RETRIES: u32 = 3;
const INITIAL_RETRY_DELAY_MS: u64 = 500;

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
    #[error("Invalid recipient format: {0}")]
    InvalidRecipient(String),
    #[error("Request timeout")]
    Timeout,
    #[error("Max retries exceeded: {0}")]
    MaxRetriesExceeded(String),
}

fn create_http_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| Client::new())
}

fn is_retryable_status(status: reqwest::StatusCode) -> bool {
    status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS
}

async fn retry_delay(attempt: u32) {
    let delay_ms = INITIAL_RETRY_DELAY_MS * 2u64.pow(attempt);
    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
}

pub fn sanitize_header_value(value: &str) -> String {
    value.replace(['\r', '\n'], " ").trim().to_string()
}

pub fn is_valid_phone_number(number: &str) -> bool {
    if number.len() < 2 || number.len() > 20 {
        return false;
    }
    let mut chars = number.chars();
    if chars.next() != Some('+') {
        return false;
    }
    let remaining: String = chars.collect();
    !remaining.is_empty() && remaining.chars().all(|c| c.is_ascii_digit())
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

    pub fn format_email(&self, notification: &QueuedNotification) -> String {
        let subject = sanitize_header_value(notification.subject.as_deref().unwrap_or("Notification"));
        let recipient = sanitize_header_value(&notification.recipient);
        let from_header = if self.from_name.is_empty() {
            self.from_address.clone()
        } else {
            format!("{} <{}>", sanitize_header_value(&self.from_name), self.from_address)
        };
        format!(
            "From: {}\r\nTo: {}\r\nSubject: {}\r\nContent-Type: text/plain; charset=utf-8\r\nMIME-Version: 1.0\r\n\r\n{}",
            from_header,
            recipient,
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

pub struct DiscordSender {
    webhook_url: String,
    http_client: Client,
}

impl DiscordSender {
    pub fn new(webhook_url: String) -> Self {
        Self {
            webhook_url,
            http_client: create_http_client(),
        }
    }

    pub fn from_env() -> Option<Self> {
        let webhook_url = std::env::var("DISCORD_WEBHOOK_URL").ok()?;
        Some(Self::new(webhook_url))
    }
}

#[async_trait]
impl NotificationSender for DiscordSender {
    fn channel(&self) -> NotificationChannel {
        NotificationChannel::Discord
    }

    async fn send(&self, notification: &QueuedNotification) -> Result<(), SendError> {
        let subject = notification.subject.as_deref().unwrap_or("Notification");
        let content = format!("**{}**\n\n{}", subject, notification.body);
        let payload = json!({
            "content": content,
            "username": "BSPDS"
        });
        let mut last_error = None;
        for attempt in 0..MAX_RETRIES {
            let result = self
                .http_client
                .post(&self.webhook_url)
                .json(&payload)
                .send()
                .await;
            match result {
                Ok(response) => {
                    if response.status().is_success() {
                        return Ok(());
                    }
                    let status = response.status();
                    if is_retryable_status(status) && attempt < MAX_RETRIES - 1 {
                        last_error = Some(format!("Discord webhook returned {}", status));
                        retry_delay(attempt).await;
                        continue;
                    }
                    let body = response.text().await.unwrap_or_default();
                    return Err(SendError::ExternalService(format!(
                        "Discord webhook returned {}: {}",
                        status, body
                    )));
                }
                Err(e) => {
                    if e.is_timeout() {
                        if attempt < MAX_RETRIES - 1 {
                            last_error = Some(format!("Discord request timed out"));
                            retry_delay(attempt).await;
                            continue;
                        }
                        return Err(SendError::Timeout);
                    }
                    return Err(SendError::ExternalService(format!(
                        "Discord request failed: {}",
                        e
                    )));
                }
            }
        }
        Err(SendError::MaxRetriesExceeded(
            last_error.unwrap_or_else(|| "Unknown error".to_string()),
        ))
    }
}

pub struct TelegramSender {
    bot_token: String,
    http_client: Client,
}

impl TelegramSender {
    pub fn new(bot_token: String) -> Self {
        Self {
            bot_token,
            http_client: create_http_client(),
        }
    }

    pub fn from_env() -> Option<Self> {
        let bot_token = std::env::var("TELEGRAM_BOT_TOKEN").ok()?;
        Some(Self::new(bot_token))
    }
}

#[async_trait]
impl NotificationSender for TelegramSender {
    fn channel(&self) -> NotificationChannel {
        NotificationChannel::Telegram
    }

    async fn send(&self, notification: &QueuedNotification) -> Result<(), SendError> {
        let chat_id = &notification.recipient;
        let subject = notification.subject.as_deref().unwrap_or("Notification");
        let text = format!("*{}*\n\n{}", subject, notification.body);
        let url = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            self.bot_token
        );
        let payload = json!({
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown"
        });
        let mut last_error = None;
        for attempt in 0..MAX_RETRIES {
            let result = self
                .http_client
                .post(&url)
                .json(&payload)
                .send()
                .await;
            match result {
                Ok(response) => {
                    if response.status().is_success() {
                        return Ok(());
                    }
                    let status = response.status();
                    if is_retryable_status(status) && attempt < MAX_RETRIES - 1 {
                        last_error = Some(format!("Telegram API returned {}", status));
                        retry_delay(attempt).await;
                        continue;
                    }
                    let body = response.text().await.unwrap_or_default();
                    return Err(SendError::ExternalService(format!(
                        "Telegram API returned {}: {}",
                        status, body
                    )));
                }
                Err(e) => {
                    if e.is_timeout() {
                        if attempt < MAX_RETRIES - 1 {
                            last_error = Some(format!("Telegram request timed out"));
                            retry_delay(attempt).await;
                            continue;
                        }
                        return Err(SendError::Timeout);
                    }
                    return Err(SendError::ExternalService(format!(
                        "Telegram request failed: {}",
                        e
                    )));
                }
            }
        }
        Err(SendError::MaxRetriesExceeded(
            last_error.unwrap_or_else(|| "Unknown error".to_string()),
        ))
    }
}

pub struct SignalSender {
    signal_cli_path: String,
    sender_number: String,
}

impl SignalSender {
    pub fn new(signal_cli_path: String, sender_number: String) -> Self {
        Self {
            signal_cli_path,
            sender_number,
        }
    }

    pub fn from_env() -> Option<Self> {
        let signal_cli_path = std::env::var("SIGNAL_CLI_PATH")
            .unwrap_or_else(|_| "/usr/local/bin/signal-cli".to_string());
        let sender_number = std::env::var("SIGNAL_SENDER_NUMBER").ok()?;
        Some(Self::new(signal_cli_path, sender_number))
    }
}

#[async_trait]
impl NotificationSender for SignalSender {
    fn channel(&self) -> NotificationChannel {
        NotificationChannel::Signal
    }

    async fn send(&self, notification: &QueuedNotification) -> Result<(), SendError> {
        let recipient = &notification.recipient;
        if !is_valid_phone_number(recipient) {
            return Err(SendError::InvalidRecipient(format!(
                "Invalid phone number format: {}",
                recipient
            )));
        }
        let subject = notification.subject.as_deref().unwrap_or("Notification");
        let message = format!("{}\n\n{}", subject, notification.body);
        let output = Command::new(&self.signal_cli_path)
            .arg("-u")
            .arg(&self.sender_number)
            .arg("send")
            .arg("-m")
            .arg(&message)
            .arg(recipient)
            .output()
            .await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SendError::ExternalService(format!(
                "signal-cli failed: {}",
                stderr
            )));
        }
        Ok(())
    }
}
