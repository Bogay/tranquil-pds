use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use sqlx::PgPool;
use tokio::sync::watch;
use tokio::time::interval;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::locale::{format_message, get_strings};
use super::sender::{CommsSender, SendError};
use super::types::{CommsChannel, CommsStatus, NewComms, QueuedComms};

pub struct CommsService {
    db: PgPool,
    senders: HashMap<CommsChannel, Arc<dyn CommsSender>>,
    poll_interval: Duration,
    batch_size: i64,
}

impl CommsService {
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

    pub fn register_sender<S: CommsSender + 'static>(mut self, sender: S) -> Self {
        self.senders.insert(sender.channel(), Arc::new(sender));
        self
    }

    pub async fn enqueue(&self, item: NewComms) -> Result<Uuid, sqlx::Error> {
        let id = sqlx::query_scalar!(
            r#"
            INSERT INTO comms_queue
                (user_id, channel, comms_type, recipient, subject, body, metadata)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id
            "#,
            item.user_id,
            item.channel as CommsChannel,
            item.comms_type as super::types::CommsType,
            item.recipient,
            item.subject,
            item.body,
            item.metadata
        )
        .fetch_one(&self.db)
        .await?;
        debug!(comms_id = %id, "Comms enqueued");
        Ok(id)
    }

    pub fn has_senders(&self) -> bool {
        !self.senders.is_empty()
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        if self.senders.is_empty() {
            warn!(
                "Comms service starting with no senders configured. Messages will be queued but not delivered until senders are configured."
            );
        }
        info!(
            poll_interval_secs = self.poll_interval.as_secs(),
            batch_size = self.batch_size,
            channels = ?self.senders.keys().collect::<Vec<_>>(),
            "Starting comms service"
        );
        let mut ticker = interval(self.poll_interval);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(e) = self.process_batch().await {
                        error!(error = %e, "Failed to process comms batch");
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("Comms service shutting down");
                        break;
                    }
                }
            }
        }
    }

    async fn process_batch(&self) -> Result<(), sqlx::Error> {
        let items = self.fetch_pending().await?;
        if items.is_empty() {
            return Ok(());
        }
        debug!(count = items.len(), "Processing comms batch");
        for item in items {
            self.process_item(item).await;
        }
        Ok(())
    }

    async fn fetch_pending(&self) -> Result<Vec<QueuedComms>, sqlx::Error> {
        let now = Utc::now();
        sqlx::query_as!(
            QueuedComms,
            r#"
            UPDATE comms_queue
            SET status = 'processing', updated_at = NOW()
            WHERE id IN (
                SELECT id FROM comms_queue
                WHERE status = 'pending'
                  AND scheduled_for <= $1
                  AND attempts < max_attempts
                ORDER BY scheduled_for ASC
                LIMIT $2
                FOR UPDATE SKIP LOCKED
            )
            RETURNING
                id, user_id,
                channel as "channel: CommsChannel",
                comms_type as "comms_type: super::types::CommsType",
                status as "status: CommsStatus",
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

    async fn process_item(&self, item: QueuedComms) {
        let comms_id = item.id;
        let channel = item.channel;
        let result = match self.senders.get(&channel) {
            Some(sender) => sender.send(&item).await,
            None => {
                warn!(
                    comms_id = %comms_id,
                    channel = ?channel,
                    "No sender registered for channel"
                );
                Err(SendError::NotConfigured(channel))
            }
        };
        match result {
            Ok(()) => {
                debug!(comms_id = %comms_id, "Comms sent successfully");
                if let Err(e) = self.mark_sent(comms_id).await {
                    error!(
                        comms_id = %comms_id,
                        error = %e,
                        "Failed to mark comms as sent"
                    );
                }
            }
            Err(e) => {
                let error_msg = e.to_string();
                warn!(
                    comms_id = %comms_id,
                    error = %error_msg,
                    "Failed to send comms"
                );
                if let Err(db_err) = self.mark_failed(comms_id, &error_msg).await {
                    error!(
                        comms_id = %comms_id,
                        error = %db_err,
                        "Failed to mark comms as failed"
                    );
                }
            }
        }
    }

    async fn mark_sent(&self, id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE comms_queue
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
            UPDATE comms_queue
            SET
                status = CASE
                    WHEN attempts + 1 >= max_attempts THEN 'failed'::comms_status
                    ELSE 'pending'::comms_status
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

pub async fn enqueue_comms(db: &PgPool, item: NewComms) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar!(
        r#"
        INSERT INTO comms_queue
            (user_id, channel, comms_type, recipient, subject, body, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id
        "#,
        item.user_id,
        item.channel as CommsChannel,
        item.comms_type as super::types::CommsType,
        item.recipient,
        item.subject,
        item.body,
        item.metadata
    )
    .fetch_one(db)
    .await
}

pub struct UserCommsPrefs {
    pub channel: CommsChannel,
    pub email: Option<String>,
    pub handle: crate::types::Handle,
    pub locale: String,
}

pub async fn get_user_comms_prefs(
    db: &PgPool,
    user_id: Uuid,
) -> Result<UserCommsPrefs, sqlx::Error> {
    let row = sqlx::query!(
        r#"
        SELECT
            email,
            handle,
            preferred_comms_channel as "channel: CommsChannel",
            preferred_locale
        FROM users
        WHERE id = $1
        "#,
        user_id
    )
    .fetch_one(db)
    .await?;
    Ok(UserCommsPrefs {
        channel: row.channel,
        email: row.email,
        handle: row.handle.into(),
        locale: row.preferred_locale.unwrap_or_else(|| "en".to_string()),
    })
}

pub async fn enqueue_welcome(
    db: &PgPool,
    user_id: Uuid,
    hostname: &str,
) -> Result<Uuid, sqlx::Error> {
    let prefs = get_user_comms_prefs(db, user_id).await?;
    let strings = get_strings(&prefs.locale);
    let body = format_message(
        strings.welcome_body,
        &[("hostname", hostname), ("handle", &prefs.handle)],
    );
    let subject = format_message(strings.welcome_subject, &[("hostname", hostname)]);
    enqueue_comms(
        db,
        NewComms::new(
            user_id,
            prefs.channel,
            super::types::CommsType::Welcome,
            prefs.email.unwrap_or_default(),
            Some(subject),
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
    let prefs = get_user_comms_prefs(db, user_id).await?;
    let strings = get_strings(&prefs.locale);
    let body = format_message(
        strings.password_reset_body,
        &[("handle", &prefs.handle), ("code", code)],
    );
    let subject = format_message(strings.password_reset_subject, &[("hostname", hostname)]);
    enqueue_comms(
        db,
        NewComms::new(
            user_id,
            prefs.channel,
            super::types::CommsType::PasswordReset,
            prefs.email.unwrap_or_default(),
            Some(subject),
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
    let prefs = get_user_comms_prefs(db, user_id).await?;
    let strings = get_strings(&prefs.locale);
    let encoded_email = urlencoding::encode(new_email);
    let encoded_token = urlencoding::encode(code);
    let verify_page = format!("https://{}/app/verify", hostname);
    let verify_link = format!(
        "https://{}/app/verify?token={}&identifier={}",
        hostname, encoded_token, encoded_email
    );
    let body = format_message(
        strings.email_update_body,
        &[
            ("handle", handle),
            ("code", code),
            ("verify_page", &verify_page),
            ("verify_link", &verify_link),
        ],
    );
    let subject = format_message(strings.email_update_subject, &[("hostname", hostname)]);
    enqueue_comms(
        db,
        NewComms::email(
            user_id,
            super::types::CommsType::EmailUpdate,
            new_email.to_string(),
            subject,
            body,
        ),
    )
    .await
}

pub async fn enqueue_email_update_token(
    db: &PgPool,
    user_id: Uuid,
    code: &str,
    hostname: &str,
) -> Result<Uuid, sqlx::Error> {
    let prefs = get_user_comms_prefs(db, user_id).await?;
    let strings = get_strings(&prefs.locale);
    let current_email = prefs.email.unwrap_or_default();
    let verify_page = format!("https://{}/app/verify?type=email-update", hostname);
    let verify_link = format!(
        "https://{}/app/verify?type=email-update&token={}",
        hostname,
        urlencoding::encode(code)
    );
    let body = format_message(
        strings.email_update_body,
        &[
            ("handle", &prefs.handle),
            ("code", code),
            ("verify_page", &verify_page),
            ("verify_link", &verify_link),
        ],
    );
    let subject = format_message(strings.email_update_subject, &[("hostname", hostname)]);
    enqueue_comms(
        db,
        NewComms::email(
            user_id,
            super::types::CommsType::EmailUpdate,
            current_email,
            subject,
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
    let prefs = get_user_comms_prefs(db, user_id).await?;
    let strings = get_strings(&prefs.locale);
    let body = format_message(
        strings.account_deletion_body,
        &[("handle", &prefs.handle), ("code", code)],
    );
    let subject = format_message(strings.account_deletion_subject, &[("hostname", hostname)]);
    enqueue_comms(
        db,
        NewComms::new(
            user_id,
            prefs.channel,
            super::types::CommsType::AccountDeletion,
            prefs.email.unwrap_or_default(),
            Some(subject),
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
    let prefs = get_user_comms_prefs(db, user_id).await?;
    let strings = get_strings(&prefs.locale);
    let body = format_message(
        strings.plc_operation_body,
        &[("handle", &prefs.handle), ("token", token)],
    );
    let subject = format_message(strings.plc_operation_subject, &[("hostname", hostname)]);
    enqueue_comms(
        db,
        NewComms::new(
            user_id,
            prefs.channel,
            super::types::CommsType::PlcOperation,
            prefs.email.unwrap_or_default(),
            Some(subject),
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
    let prefs = get_user_comms_prefs(db, user_id).await?;
    let strings = get_strings(&prefs.locale);
    let body = format_message(
        strings.two_factor_code_body,
        &[("handle", &prefs.handle), ("code", code)],
    );
    let subject = format_message(strings.two_factor_code_subject, &[("hostname", hostname)]);
    enqueue_comms(
        db,
        NewComms::new(
            user_id,
            prefs.channel,
            super::types::CommsType::TwoFactorCode,
            prefs.email.unwrap_or_default(),
            Some(subject),
            body,
        ),
    )
    .await
}

pub async fn enqueue_passkey_recovery(
    db: &PgPool,
    user_id: Uuid,
    recovery_url: &str,
    hostname: &str,
) -> Result<Uuid, sqlx::Error> {
    let prefs = get_user_comms_prefs(db, user_id).await?;
    let strings = get_strings(&prefs.locale);
    let body = format_message(
        strings.passkey_recovery_body,
        &[("handle", &prefs.handle), ("url", recovery_url)],
    );
    let subject = format_message(strings.passkey_recovery_subject, &[("hostname", hostname)]);
    enqueue_comms(
        db,
        NewComms::new(
            user_id,
            prefs.channel,
            super::types::CommsType::PasskeyRecovery,
            prefs.email.unwrap_or_default(),
            Some(subject),
            body,
        ),
    )
    .await
}

pub fn channel_display_name(channel: CommsChannel) -> &'static str {
    match channel {
        CommsChannel::Email => "email",
        CommsChannel::Discord => "Discord",
        CommsChannel::Telegram => "Telegram",
        CommsChannel::Signal => "Signal",
    }
}

pub async fn enqueue_signup_verification(
    db: &PgPool,
    user_id: Uuid,
    channel: &str,
    recipient: &str,
    code: &str,
    locale: Option<&str>,
) -> Result<Uuid, sqlx::Error> {
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let comms_channel = match channel {
        "email" => CommsChannel::Email,
        "discord" => CommsChannel::Discord,
        "telegram" => CommsChannel::Telegram,
        "signal" => CommsChannel::Signal,
        _ => CommsChannel::Email,
    };
    let strings = get_strings(locale.unwrap_or("en"));
    let (verify_page, verify_link) = if comms_channel == CommsChannel::Email {
        let encoded_email = urlencoding::encode(recipient);
        let encoded_token = urlencoding::encode(code);
        (
            format!("https://{}/app/verify", hostname),
            format!(
                "https://{}/app/verify?token={}&identifier={}",
                hostname, encoded_token, encoded_email
            ),
        )
    } else {
        (String::new(), String::new())
    };
    let body = format_message(
        strings.signup_verification_body,
        &[
            ("code", code),
            ("hostname", &hostname),
            ("verify_page", &verify_page),
            ("verify_link", &verify_link),
        ],
    );
    let subject = match comms_channel {
        CommsChannel::Email => Some(format_message(
            strings.signup_verification_subject,
            &[("hostname", &hostname)],
        )),
        _ => None,
    };
    enqueue_comms(
        db,
        NewComms::new(
            user_id,
            comms_channel,
            super::types::CommsType::EmailVerification,
            recipient.to_string(),
            subject,
            body,
        ),
    )
    .await
}

pub async fn enqueue_migration_verification(
    db: &PgPool,
    user_id: Uuid,
    email: &str,
    token: &str,
    hostname: &str,
) -> Result<Uuid, sqlx::Error> {
    let prefs = get_user_comms_prefs(db, user_id).await?;
    let strings = get_strings(&prefs.locale);
    let encoded_email = urlencoding::encode(email);
    let encoded_token = urlencoding::encode(token);
    let verify_page = format!("https://{}/app/verify", hostname);
    let verify_link = format!(
        "https://{}/app/verify?token={}&identifier={}",
        hostname, encoded_token, encoded_email
    );
    let body = format_message(
        strings.migration_verification_body,
        &[
            ("code", token),
            ("hostname", hostname),
            ("verify_page", &verify_page),
            ("verify_link", &verify_link),
        ],
    );
    let subject = format_message(
        strings.migration_verification_subject,
        &[("hostname", hostname)],
    );
    enqueue_comms(
        db,
        NewComms::email(
            user_id,
            super::types::CommsType::MigrationVerification,
            email.to_string(),
            subject,
            body,
        ),
    )
    .await
}

pub async fn queue_legacy_login_notification(
    db: &PgPool,
    user_id: Uuid,
    hostname: &str,
    client_ip: &str,
    channel: CommsChannel,
) -> Result<Uuid, sqlx::Error> {
    let prefs = get_user_comms_prefs(db, user_id).await?;
    let strings = get_strings(&prefs.locale);
    let timestamp = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();
    let body = format_message(
        strings.legacy_login_body,
        &[
            ("handle", &prefs.handle),
            ("timestamp", &timestamp),
            ("ip", client_ip),
            ("hostname", hostname),
        ],
    );
    let subject = format_message(strings.legacy_login_subject, &[("hostname", hostname)]);
    enqueue_comms(
        db,
        NewComms::new(
            user_id,
            channel,
            super::types::CommsType::LegacyLoginAlert,
            prefs.email.unwrap_or_default(),
            Some(subject),
            body,
        ),
    )
    .await
}
