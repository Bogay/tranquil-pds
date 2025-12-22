use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "comms_channel", rename_all = "lowercase")]
pub enum CommsChannel {
    Email,
    Discord,
    Telegram,
    Signal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "comms_status", rename_all = "lowercase")]
pub enum CommsStatus {
    Pending,
    Processing,
    Sent,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "comms_type", rename_all = "snake_case")]
pub enum CommsType {
    Welcome,
    EmailVerification,
    PasswordReset,
    EmailUpdate,
    AccountDeletion,
    AdminEmail,
    PlcOperation,
    TwoFactorCode,
    PasskeyRecovery,
    LegacyLoginAlert,
}

#[derive(Debug, Clone, FromRow)]
pub struct QueuedComms {
    pub id: Uuid,
    pub user_id: Uuid,
    pub channel: CommsChannel,
    pub comms_type: CommsType,
    pub status: CommsStatus,
    pub recipient: String,
    pub subject: Option<String>,
    pub body: String,
    pub metadata: Option<serde_json::Value>,
    pub attempts: i32,
    pub max_attempts: i32,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub scheduled_for: DateTime<Utc>,
    pub processed_at: Option<DateTime<Utc>>,
}

pub struct NewComms {
    pub user_id: Uuid,
    pub channel: CommsChannel,
    pub comms_type: CommsType,
    pub recipient: String,
    pub subject: Option<String>,
    pub body: String,
    pub metadata: Option<serde_json::Value>,
}

impl NewComms {
    pub fn new(
        user_id: Uuid,
        channel: CommsChannel,
        comms_type: CommsType,
        recipient: String,
        subject: Option<String>,
        body: String,
    ) -> Self {
        Self {
            user_id,
            channel,
            comms_type,
            recipient,
            subject,
            body,
            metadata: None,
        }
    }

    pub fn email(
        user_id: Uuid,
        comms_type: CommsType,
        recipient: String,
        subject: String,
        body: String,
    ) -> Self {
        Self::new(
            user_id,
            CommsChannel::Email,
            comms_type,
            recipient,
            Some(subject),
            body,
        )
    }
}
