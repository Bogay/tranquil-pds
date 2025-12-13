use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use sqlx::PgPool;
use tokio::sync::watch;
use tokio::time::interval;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::sender::{NotificationSender, SendError};
use super::types::{NewNotification, NotificationChannel, NotificationStatus, QueuedNotification};

pub struct NotificationService {
    db: PgPool,
    senders: HashMap<NotificationChannel, Arc<dyn NotificationSender>>,
    poll_interval: Duration,
    batch_size: i64,
}

impl NotificationService {
    pub fn new(db: PgPool) -> Self {
        let poll_interval_ms: u64 = std::env::var("NOTIFICATION_POLL_INTERVAL_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1000);

        let batch_size: i64 = std::env::var("NOTIFICATION_BATCH_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);

        Self {
            db,
            senders: HashMap::new(),
            poll_interval: Duration::from_millis(poll_interval_ms),
            batch_size,
        }
    }

    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    pub fn with_batch_size(mut self, size: i64) -> Self {
        self.batch_size = size;
        self
    }

    pub fn register_sender<S: NotificationSender + 'static>(mut self, sender: S) -> Self {
        self.senders.insert(sender.channel(), Arc::new(sender));
        self
    }

    pub async fn enqueue(&self, notification: NewNotification) -> Result<Uuid, sqlx::Error> {
        let id = sqlx::query_scalar!(
            r#"
            INSERT INTO notification_queue
                (user_id, channel, notification_type, recipient, subject, body, metadata)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id
            "#,
            notification.user_id,
            notification.channel as NotificationChannel,
            notification.notification_type as super::types::NotificationType,
            notification.recipient,
            notification.subject,
            notification.body,
            notification.metadata
        )
        .fetch_one(&self.db)
        .await?;

        debug!(notification_id = %id, "Notification enqueued");
        Ok(id)
    }

    pub fn has_senders(&self) -> bool {
        !self.senders.is_empty()
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        if self.senders.is_empty() {
            warn!("Notification service starting with no senders configured. Notifications will be queued but not delivered until senders are configured.");
        }

        info!(
            poll_interval_secs = self.poll_interval.as_secs(),
            batch_size = self.batch_size,
            channels = ?self.senders.keys().collect::<Vec<_>>(),
            "Starting notification service"
        );

        let mut ticker = interval(self.poll_interval);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(e) = self.process_batch().await {
                        error!(error = %e, "Failed to process notification batch");
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("Notification service shutting down");
                        break;
                    }
                }
            }
        }
    }

    async fn process_batch(&self) -> Result<(), sqlx::Error> {
        let notifications = self.fetch_pending_notifications().await?;

        if notifications.is_empty() {
            return Ok(());
        }

        debug!(count = notifications.len(), "Processing notification batch");

        for notification in notifications {
            self.process_notification(notification).await;
        }

        Ok(())
    }

    async fn fetch_pending_notifications(&self) -> Result<Vec<QueuedNotification>, sqlx::Error> {
        let now = Utc::now();

        sqlx::query_as!(
            QueuedNotification,
            r#"
            UPDATE notification_queue
            SET status = 'processing', updated_at = NOW()
            WHERE id IN (
                SELECT id FROM notification_queue
                WHERE status = 'pending'
                  AND scheduled_for <= $1
                  AND attempts < max_attempts
                ORDER BY scheduled_for ASC
                LIMIT $2
                FOR UPDATE SKIP LOCKED
            )
            RETURNING
                id, user_id,
                channel as "channel: NotificationChannel",
                notification_type as "notification_type: super::types::NotificationType",
                status as "status: NotificationStatus",
                recipient, subject, body, metadata,
                attempts, max_attempts, last_error,
                created_at, updated_at, scheduled_for, processed_at
            "#,
            now,
            self.batch_size
        )
        .fetch_all(&self.db)
        .await
    }

    async fn process_notification(&self, notification: QueuedNotification) {
        let notification_id = notification.id;
        let channel = notification.channel;

        let result = match self.senders.get(&channel) {
            Some(sender) => sender.send(&notification).await,
            None => {
                warn!(
                    notification_id = %notification_id,
                    channel = ?channel,
                    "No sender registered for channel"
                );
                Err(SendError::NotConfigured(channel))
            }
        };

        match result {
            Ok(()) => {
                debug!(notification_id = %notification_id, "Notification sent successfully");
                if let Err(e) = self.mark_sent(notification_id).await {
                    error!(
                        notification_id = %notification_id,
                        error = %e,
                        "Failed to mark notification as sent"
                    );
                }
            }
            Err(e) => {
                let error_msg = e.to_string();
                warn!(
                    notification_id = %notification_id,
                    error = %error_msg,
                    "Failed to send notification"
                );
                if let Err(db_err) = self.mark_failed(notification_id, &error_msg).await {
                    error!(
                        notification_id = %notification_id,
                        error = %db_err,
                        "Failed to mark notification as failed"
                    );
                }
            }
        }
    }

    async fn mark_sent(&self, id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE notification_queue
            SET status = 'sent', processed_at = NOW(), updated_at = NOW()
            WHERE id = $1
            "#,
            id
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn mark_failed(&self, id: Uuid, error: &str) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE notification_queue
            SET
                status = CASE
                    WHEN attempts + 1 >= max_attempts THEN 'failed'::notification_status
                    ELSE 'pending'::notification_status
                END,
                attempts = attempts + 1,
                last_error = $2,
                updated_at = NOW(),
                scheduled_for = NOW() + (INTERVAL '1 minute' * (attempts + 1))
            WHERE id = $1
            "#,
            id,
            error
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }
}

pub async fn enqueue_notification(db: &PgPool, notification: NewNotification) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar!(
        r#"
        INSERT INTO notification_queue
            (user_id, channel, notification_type, recipient, subject, body, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id
        "#,
        notification.user_id,
        notification.channel as NotificationChannel,
        notification.notification_type as super::types::NotificationType,
        notification.recipient,
        notification.subject,
        notification.body,
        notification.metadata
    )
    .fetch_one(db)
    .await
}

pub struct UserNotificationPrefs {
    pub channel: NotificationChannel,
    pub email: Option<String>,
    pub handle: String,
}

pub async fn get_user_notification_prefs(
    db: &PgPool,
    user_id: Uuid,
) -> Result<UserNotificationPrefs, sqlx::Error> {
    let row = sqlx::query!(
        r#"
        SELECT
            email,
            handle,
            preferred_notification_channel as "channel: NotificationChannel"
        FROM users
        WHERE id = $1
        "#,
        user_id
    )
    .fetch_one(db)
    .await?;

    Ok(UserNotificationPrefs {
        channel: row.channel,
        email: row.email,
        handle: row.handle,
    })
}

pub async fn enqueue_welcome(
    db: &PgPool,
    user_id: Uuid,
    hostname: &str,
) -> Result<Uuid, sqlx::Error> {
    let prefs = get_user_notification_prefs(db, user_id).await?;

    let body = format!(
        "Welcome to {}!\n\nYour handle is: @{}\n\nThank you for joining us.",
        hostname, prefs.handle
    );

    enqueue_notification(
        db,
        NewNotification::new(
            user_id,
            prefs.channel,
            super::types::NotificationType::Welcome,
            prefs.email.clone().unwrap_or_default(),
            Some(format!("Welcome to {}", hostname)),
            body,
        ),
    )
    .await
}

pub async fn enqueue_email_verification(
    db: &PgPool,
    user_id: Uuid,
    email: &str,
    handle: &str,
    code: &str,
    hostname: &str,
) -> Result<Uuid, sqlx::Error> {
    let body = format!(
        "Hello @{},\n\nYour email verification code is: {}\n\nThis code will expire in 10 minutes.\n\nIf you did not request this, please ignore this email.",
        handle, code
    );

    enqueue_notification(
        db,
        NewNotification::email(
            user_id,
            super::types::NotificationType::EmailVerification,
            email.to_string(),
            format!("Verify your email - {}", hostname),
            body,
        ),
    )
    .await
}

pub async fn enqueue_password_reset(
    db: &PgPool,
    user_id: Uuid,
    code: &str,
    hostname: &str,
) -> Result<Uuid, sqlx::Error> {
    let prefs = get_user_notification_prefs(db, user_id).await?;

    let body = format!(
        "Hello @{},\n\nYour password reset code is: {}\n\nThis code will expire in 10 minutes.\n\nIf you did not request this, please ignore this message.",
        prefs.handle, code
    );

    enqueue_notification(
        db,
        NewNotification::new(
            user_id,
            prefs.channel,
            super::types::NotificationType::PasswordReset,
            prefs.email.clone().unwrap_or_default(),
            Some(format!("Password Reset - {}", hostname)),
            body,
        ),
    )
    .await
}

pub async fn enqueue_email_update(
    db: &PgPool,
    user_id: Uuid,
    new_email: &str,
    handle: &str,
    code: &str,
    hostname: &str,
) -> Result<Uuid, sqlx::Error> {
    let body = format!(
        "Hello @{},\n\nYour email update confirmation code is: {}\n\nThis code will expire in 10 minutes.\n\nIf you did not request this, please ignore this email.",
        handle, code
    );

    enqueue_notification(
        db,
        NewNotification::email(
            user_id,
            super::types::NotificationType::EmailUpdate,
            new_email.to_string(),
            format!("Confirm your new email - {}", hostname),
            body,
        ),
    )
    .await
}

pub async fn enqueue_account_deletion(
    db: &PgPool,
    user_id: Uuid,
    code: &str,
    hostname: &str,
) -> Result<Uuid, sqlx::Error> {
    let prefs = get_user_notification_prefs(db, user_id).await?;

    let body = format!(
        "Hello @{},\n\nYour account deletion confirmation code is: {}\n\nThis code will expire in 10 minutes.\n\nIf you did not request this, please secure your account immediately.",
        prefs.handle, code
    );

    enqueue_notification(
        db,
        NewNotification::new(
            user_id,
            prefs.channel,
            super::types::NotificationType::AccountDeletion,
            prefs.email.clone().unwrap_or_default(),
            Some(format!("Account Deletion Request - {}", hostname)),
            body,
        ),
    )
    .await
}

pub async fn enqueue_plc_operation(
    db: &PgPool,
    user_id: Uuid,
    token: &str,
    hostname: &str,
) -> Result<Uuid, sqlx::Error> {
    let prefs = get_user_notification_prefs(db, user_id).await?;

    let body = format!(
        "Hello @{},\n\nYou requested to sign a PLC operation for your account.\n\nYour verification token is: {}\n\nThis token will expire in 10 minutes.\n\nIf you did not request this, you can safely ignore this message.",
        prefs.handle, token
    );

    enqueue_notification(
        db,
        NewNotification::new(
            user_id,
            prefs.channel,
            super::types::NotificationType::PlcOperation,
            prefs.email.clone().unwrap_or_default(),
            Some(format!("{} - PLC Operation Token", hostname)),
            body,
        ),
    )
    .await
}

pub async fn enqueue_2fa_code(
    db: &PgPool,
    user_id: Uuid,
    code: &str,
    hostname: &str,
) -> Result<Uuid, sqlx::Error> {
    let prefs = get_user_notification_prefs(db, user_id).await?;

    let body = format!(
        "Hello @{},\n\nYour sign-in verification code is: {}\n\nThis code will expire in 10 minutes.\n\nIf you did not request this, please secure your account immediately.",
        prefs.handle, code
    );

    enqueue_notification(
        db,
        NewNotification::new(
            user_id,
            prefs.channel,
            super::types::NotificationType::TwoFactorCode,
            prefs.email.clone().unwrap_or_default(),
            Some(format!("Sign-in Verification - {}", hostname)),
            body,
        ),
    )
    .await
}

pub fn channel_display_name(channel: NotificationChannel) -> &'static str {
    match channel {
        NotificationChannel::Email => "email",
        NotificationChannel::Discord => "Discord",
        NotificationChannel::Telegram => "Telegram",
        NotificationChannel::Signal => "Signal",
    }
}

pub async fn enqueue_signup_verification(
    db: &PgPool,
    user_id: Uuid,
    channel: &str,
    recipient: &str,
    code: &str,
) -> Result<Uuid, sqlx::Error> {
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());

    let notification_channel = match channel {
        "email" => NotificationChannel::Email,
        "discord" => NotificationChannel::Discord,
        "telegram" => NotificationChannel::Telegram,
        "signal" => NotificationChannel::Signal,
        _ => NotificationChannel::Email,
    };

    let body = format!(
        "Welcome! Your account verification code is: {}\n\nThis code will expire in 30 minutes.\n\nEnter this code to complete your registration on {}.",
        code, hostname
    );

    let subject = match notification_channel {
        NotificationChannel::Email => Some(format!("Verify your account - {}", hostname)),
        _ => None,
    };

    enqueue_notification(
        db,
        NewNotification::new(
            user_id,
            notification_channel,
            super::types::NotificationType::EmailVerification,
            recipient.to_string(),
            subject,
            body,
        ),
    )
    .await
}
