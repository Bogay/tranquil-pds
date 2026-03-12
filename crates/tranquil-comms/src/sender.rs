use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use reqwest::Client;
use serde_json::json;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::timeout;

use super::types::{CommsChannel, QueuedComms};

const HTTP_TIMEOUT_SECS: u64 = 30;
const MAX_RETRIES: u32 = 3;
const INITIAL_RETRY_DELAY_MS: u64 = 500;

#[async_trait]
pub trait CommsSender: Send + Sync {
    fn channel(&self) -> CommsChannel;
    async fn send(&self, notification: &QueuedComms) -> Result<(), SendError>;
}

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("Failed to spawn {command}: {source}")]
    ProcessSpawn {
        command: String,
        source: std::io::Error,
    },
    #[error("{command} exited with non-zero status: {detail}")]
    ProcessFailed { command: String, detail: String },
    #[error("Channel not configured: {0:?}")]
    NotConfigured(CommsChannel),
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

pub fn mime_encode_header(value: &str) -> String {
    if value.is_ascii() {
        sanitize_header_value(value)
    } else {
        let sanitized = sanitize_header_value(value);
        format!("=?UTF-8?B?{}?=", BASE64.encode(sanitized.as_bytes()))
    }
}

pub fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
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

pub fn is_valid_signal_username(username: &str) -> bool {
    if username.len() < 6 || username.len() > 35 {
        return false;
    }
    let Some((base, discriminator)) = username.rsplit_once('.') else {
        return false;
    };
    if base.len() < 3 || base.len() > 32 {
        return false;
    }
    if !base.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return false;
    }
    if !base.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    discriminator.len() == 2 && discriminator.chars().all(|c| c.is_ascii_digit())
}

pub struct EmailSender {
    from_address: String,
    from_name: String,
    sendmail_path: String,
}

impl EmailSender {
    pub fn new(from_address: String, from_name: String, sendmail_path: String) -> Self {
        Self {
            from_address,
            from_name,
            sendmail_path,
        }
    }

    pub fn from_config(cfg: &tranquil_config::TranquilConfig) -> Option<Self> {
        let from_address = cfg.email.from_address.clone()?;
        let from_name = cfg.email.from_name.clone();
        let sendmail_path = cfg.email.sendmail_path.clone();
        Some(Self::new(from_address, from_name, sendmail_path))
    }

    pub fn format_email(&self, notification: &QueuedComms) -> String {
        let subject = mime_encode_header(notification.subject.as_deref().unwrap_or("Notification"));
        let recipient = sanitize_header_value(&notification.recipient);
        let from_header = if self.from_name.is_empty() {
            self.from_address.clone()
        } else {
            format!(
                "{} <{}>",
                sanitize_header_value(&self.from_name),
                self.from_address
            )
        };
        format!(
            "From: {}\r\nTo: {}\r\nSubject: {}\r\nContent-Type: text/plain; charset=utf-8\r\nMIME-Version: 1.0\r\n\r\n{}",
            from_header, recipient, subject, notification.body
        )
    }
}

#[async_trait]
impl CommsSender for EmailSender {
    fn channel(&self) -> CommsChannel {
        CommsChannel::Email
    }

    async fn send(&self, notification: &QueuedComms) -> Result<(), SendError> {
        let email_content = self.format_email(notification);
        let mut child = Command::new(&self.sendmail_path)
            .arg("-t")
            .arg("-oi")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| SendError::ProcessSpawn {
                command: self.sendmail_path.clone(),
                source: e,
            })?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(email_content.as_bytes())
                .await
                .map_err(|e| SendError::ProcessSpawn {
                    command: self.sendmail_path.clone(),
                    source: e,
                })?;
        }
        let output = child
            .wait_with_output()
            .await
            .map_err(|e| SendError::ProcessSpawn {
                command: self.sendmail_path.clone(),
                source: e,
            })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SendError::ProcessFailed {
                command: self.sendmail_path.clone(),
                detail: stderr.to_string(),
            });
        }
        Ok(())
    }
}

const DISCORD_API_BASE: &str = "https://discord.com/api/v10";

#[derive(Clone)]
pub struct DiscordSender {
    bot_token: String,
    http_client: Client,
}

impl DiscordSender {
    pub fn new(bot_token: String) -> Self {
        Self {
            bot_token,
            http_client: create_http_client(),
        }
    }

    pub fn from_config(cfg: &tranquil_config::TranquilConfig) -> Option<Self> {
        let bot_token = cfg.discord.bot_token.clone()?;
        Some(Self::new(bot_token))
    }

    fn auth_header(&self) -> String {
        format!("Bot {}", self.bot_token)
    }

    pub async fn resolve_application_info(&self) -> Result<(String, String), SendError> {
        let url = format!("{}/applications/@me", DISCORD_API_BASE);
        let response = self
            .http_client
            .get(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| {
                SendError::ExternalService(format!(
                    "Discord application info request failed: {}",
                    e
                ))
            })?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(SendError::ExternalService(format!(
                "Discord application info returned error: {}",
                body
            )));
        }

        let data: serde_json::Value = response.json().await.map_err(|e| {
            SendError::ExternalService(format!("Failed to parse Discord application info: {}", e))
        })?;

        let app_id = data
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| SendError::ExternalService("Application info missing id".to_string()))?;

        let verify_key = data
            .get("verify_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                SendError::ExternalService("Application info missing verify_key".to_string())
            })?;

        Ok((app_id, verify_key))
    }

    pub async fn register_slash_command(&self, app_id: &str) -> Result<(), SendError> {
        let url = format!("{}/applications/{}/commands", DISCORD_API_BASE, app_id);
        let payload = serde_json::json!({
            "name": "start",
            "description": "Verify your PDS account",
            "type": 1,
            "options": [{
                "name": "handle",
                "description": "Your PDS handle (e.g. alice.example.com)",
                "type": 3,
                "required": false
            }]
        });
        let response = self
            .http_client
            .post(&url)
            .header("Authorization", self.auth_header())
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                SendError::ExternalService(format!("Register command request failed: {}", e))
            })?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(SendError::ExternalService(format!(
                "Register command returned error: {}",
                body
            )));
        }
        Ok(())
    }

    pub async fn set_interactions_endpoint(
        &self,
        app_id: &str,
        url: &str,
    ) -> Result<(), SendError> {
        let patch_url = format!("{}/applications/{}", DISCORD_API_BASE, app_id);
        let payload = serde_json::json!({
            "interactions_endpoint_url": url
        });
        let response = self
            .http_client
            .patch(&patch_url)
            .header("Authorization", self.auth_header())
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                SendError::ExternalService(format!("Set interactions endpoint failed: {}", e))
            })?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(SendError::ExternalService(format!(
                "Set interactions endpoint returned error: {}",
                body
            )));
        }
        Ok(())
    }

    pub async fn resolve_bot_username(&self) -> Result<String, SendError> {
        let url = format!("{}/users/@me", DISCORD_API_BASE);
        let response = self
            .http_client
            .get(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| {
                SendError::ExternalService(format!("Discord getMe request failed: {}", e))
            })?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(SendError::ExternalService(format!(
                "Discord getMe returned error: {}",
                body
            )));
        }

        let data: serde_json::Value = response.json().await.map_err(|e| {
            SendError::ExternalService(format!("Failed to parse Discord getMe response: {}", e))
        })?;

        data.get("username")
            .and_then(|u| u.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                SendError::ExternalService("Discord getMe response missing username".to_string())
            })
    }

    async fn open_dm_channel(&self, user_id: &str) -> Result<String, SendError> {
        let url = format!("{}/users/@me/channels", DISCORD_API_BASE);
        let payload = json!({ "recipient_id": user_id });

        let response = self
            .http_client
            .post(&url)
            .header("Authorization", self.auth_header())
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                SendError::ExternalService(format!("Discord DM channel request failed: {}", e))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(SendError::ExternalService(format!(
                "Discord DM channel creation returned {}: {}",
                status, body
            )));
        }

        let data: serde_json::Value = response.json().await.map_err(|e| {
            SendError::ExternalService(format!(
                "Failed to parse Discord DM channel response: {}",
                e
            ))
        })?;

        data.get("id")
            .and_then(|id| id.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                SendError::ExternalService("Discord DM channel response missing id".to_string())
            })
    }
}

#[async_trait]
impl CommsSender for DiscordSender {
    fn channel(&self) -> CommsChannel {
        CommsChannel::Discord
    }

    async fn send(&self, notification: &QueuedComms) -> Result<(), SendError> {
        let channel_id = self.open_dm_channel(&notification.recipient).await?;

        let subject = notification.subject.as_deref().unwrap_or("Notification");
        let content = format!("**{}**\n\n{}", subject, notification.body);
        let payload = json!({ "content": content });
        let url = format!("{}/channels/{}/messages", DISCORD_API_BASE, channel_id);

        let mut last_error = None;
        for attempt in 0..MAX_RETRIES {
            let result = self
                .http_client
                .post(&url)
                .header("Authorization", self.auth_header())
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
                        last_error = Some(format!("Discord API returned {}", status));
                        retry_delay(attempt).await;
                        continue;
                    }
                    let body = response.text().await.unwrap_or_default();
                    return Err(SendError::ExternalService(format!(
                        "Discord API returned {}: {}",
                        status, body
                    )));
                }
                Err(e) => {
                    if e.is_timeout() {
                        if attempt < MAX_RETRIES - 1 {
                            last_error = Some("Discord request timed out".to_string());
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

    pub fn from_config(cfg: &tranquil_config::TranquilConfig) -> Option<Self> {
        let bot_token = cfg.telegram.bot_token.clone()?;
        Some(Self::new(bot_token))
    }

    pub async fn set_webhook(
        &self,
        webhook_url: &str,
        secret_token: Option<&str>,
    ) -> Result<(), SendError> {
        let url = format!("https://api.telegram.org/bot{}/setWebhook", self.bot_token);
        let mut payload = json!({ "url": webhook_url });
        if let Some(secret) = secret_token {
            payload["secret_token"] = json!(secret);
        }
        let response = self
            .http_client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| SendError::ExternalService(format!("setWebhook request failed: {}", e)))?;
        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(SendError::ExternalService(format!(
                "setWebhook returned error: {}",
                body
            )));
        }
        Ok(())
    }

    pub async fn resolve_bot_username(&self) -> Result<String, SendError> {
        let url = format!("https://api.telegram.org/bot{}/getMe", self.bot_token);
        let response = self.http_client.get(&url).send().await.map_err(|e| {
            SendError::ExternalService(format!("Telegram getMe request failed: {}", e))
        })?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(SendError::ExternalService(format!(
                "Telegram getMe returned error: {}",
                body
            )));
        }

        let data: serde_json::Value = response.json().await.map_err(|e| {
            SendError::ExternalService(format!("Failed to parse getMe response: {}", e))
        })?;

        data.get("result")
            .and_then(|r| r.get("username"))
            .and_then(|u| u.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                SendError::ExternalService("getMe response missing username".to_string())
            })
    }
}

#[async_trait]
impl CommsSender for TelegramSender {
    fn channel(&self) -> CommsChannel {
        CommsChannel::Telegram
    }

    async fn send(&self, notification: &QueuedComms) -> Result<(), SendError> {
        let chat_id = &notification.recipient;
        let subject = escape_html(notification.subject.as_deref().unwrap_or("Notification"));
        let body = escape_html(&notification.body);
        let text = format!("<b>{}</b>\n\n{}", subject, body);
        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_token);
        let payload = json!({
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML"
        });
        let mut last_error = None;
        for attempt in 0..MAX_RETRIES {
            let result = self.http_client.post(&url).json(&payload).send().await;
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
                            last_error = Some("Telegram request timed out".to_string());
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

    pub fn from_config(cfg: &tranquil_config::TranquilConfig) -> Option<Self> {
        let signal_cli_path = cfg.signal.cli_path.clone();
        let sender_number = cfg.signal.sender_number.clone()?;
        Some(Self::new(signal_cli_path, sender_number))
    }
}

const SIGNAL_TIMEOUT_SECS: u64 = 30;

fn is_retryable_signal_error(stderr: &str) -> bool {
    let lower = stderr.to_lowercase();
    lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("connection refused")
        || lower.contains("network")
        || lower.contains("temporarily")
        || lower.contains("try again")
        || lower.contains("rate limit")
}

#[async_trait]
impl CommsSender for SignalSender {
    fn channel(&self) -> CommsChannel {
        CommsChannel::Signal
    }

    async fn send(&self, notification: &QueuedComms) -> Result<(), SendError> {
        let recipient = &notification.recipient;
        if !is_valid_signal_username(recipient) {
            return Err(SendError::InvalidRecipient(format!(
                "Invalid Signal username format: {}",
                recipient
            )));
        }
        let subject = notification.subject.as_deref().unwrap_or("Notification");
        let message = format!("{}\n\n{}", subject, notification.body);

        let mut last_error = None;
        for attempt in 0..MAX_RETRIES {
            let cmd_future = Command::new(&self.signal_cli_path)
                .arg("-u")
                .arg(&self.sender_number)
                .arg("send")
                .arg("--username")
                .arg(recipient)
                .arg("-m")
                .arg(&message)
                .output();

            let result = timeout(Duration::from_secs(SIGNAL_TIMEOUT_SECS), cmd_future).await;

            match result {
                Ok(Ok(output)) if output.status.success() => return Ok(()),
                Ok(Ok(output)) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if is_retryable_signal_error(&stderr) && attempt < MAX_RETRIES - 1 {
                        last_error = Some(format!("signal-cli failed: {}", stderr));
                        retry_delay(attempt).await;
                        continue;
                    }
                    return Err(SendError::ExternalService(format!(
                        "signal-cli failed: {}",
                        stderr
                    )));
                }
                Ok(Err(e)) => {
                    if attempt < MAX_RETRIES - 1 {
                        last_error = Some(format!("signal-cli spawn failed: {}", e));
                        retry_delay(attempt).await;
                        continue;
                    }
                    return Err(SendError::ProcessSpawn {
                        command: self.signal_cli_path.clone(),
                        source: e,
                    });
                }
                Err(_) => {
                    if attempt < MAX_RETRIES - 1 {
                        last_error = Some("signal-cli timed out".to_string());
                        retry_delay(attempt).await;
                        continue;
                    }
                    return Err(SendError::Timeout);
                }
            }
        }
        Err(SendError::MaxRetriesExceeded(
            last_error.unwrap_or_else(|| "Unknown error".to_string()),
        ))
    }
}
