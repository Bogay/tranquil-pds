use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "notification_channel", rename_all = "lowercase")]
pub enum NotificationChannel {
    Email,
    Discord,
    Telegram,
    Signal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "notification_status", rename_all = "lowercase")]
pub enum NotificationStatus {
    Pending,
    Processing,
    Sent,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "notification_type", rename_all = "snake_case")]
pub enum NotificationType {
    Welcome,
    EmailVerification,
    PasswordReset,
    EmailUpdate,
    AccountDeletion,
}

#[derive(Debug, Clone, FromRow)]
pub struct QueuedNotification {
    pub id: Uuid,
    pub user_id: Uuid,
    pub channel: NotificationChannel,
    pub notification_type: NotificationType,
    pub status: NotificationStatus,
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

pub struct NewNotification {
    pub user_id: Uuid,
    pub channel: NotificationChannel,
    pub notification_type: NotificationType,
    pub recipient: String,
    pub subject: Option<String>,
    pub body: String,
    pub metadata: Option<serde_json::Value>,
}

impl NewNotification {
    pub fn email(
        user_id: Uuid,
        notification_type: NotificationType,
        recipient: String,
        subject: String,
        body: String,
    ) -> Self {
        Self {
            user_id,
            channel: NotificationChannel::Email,
            notification_type,
            recipient,
            subject: Some(subject),
            body,
            metadata: None,
        }
    }
}
