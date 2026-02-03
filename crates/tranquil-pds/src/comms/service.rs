use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use tranquil_comms::{
    CommsChannel, CommsSender, CommsStatus, CommsType, NewComms, SendError, format_message,
    get_strings,
};
use tranquil_db_traits::{InfraRepository, QueuedComms, UserCommsPrefs, UserRepository};
use uuid::Uuid;

pub struct CommsService {
    infra_repo: Arc<dyn InfraRepository>,
    senders: HashMap<CommsChannel, Arc<dyn CommsSender>>,
    poll_interval: Duration,
    batch_size: i64,
}

impl CommsService {
    pub fn new(infra_repo: Arc<dyn InfraRepository>) -> Self {
        let poll_interval_ms: u64 = std::env::var("NOTIFICATION_POLL_INTERVAL_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1000);
        let batch_size: i64 = std::env::var("NOTIFICATION_BATCH_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);
        Self {
            infra_repo,
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

    pub async fn enqueue(&self, item: NewComms) -> Result<Uuid, tranquil_db_traits::DbError> {
        let channel = match item.channel {
            CommsChannel::Email => tranquil_db_traits::CommsChannel::Email,
            CommsChannel::Discord => tranquil_db_traits::CommsChannel::Discord,
            CommsChannel::Telegram => tranquil_db_traits::CommsChannel::Telegram,
            CommsChannel::Signal => tranquil_db_traits::CommsChannel::Signal,
        };
        let comms_type = match item.comms_type {
            CommsType::Welcome => tranquil_db_traits::CommsType::Welcome,
            CommsType::EmailVerification => tranquil_db_traits::CommsType::EmailVerification,
            CommsType::PasswordReset => tranquil_db_traits::CommsType::PasswordReset,
            CommsType::EmailUpdate => tranquil_db_traits::CommsType::EmailUpdate,
            CommsType::AccountDeletion => tranquil_db_traits::CommsType::AccountDeletion,
            CommsType::AdminEmail => tranquil_db_traits::CommsType::AdminEmail,
            CommsType::PlcOperation => tranquil_db_traits::CommsType::PlcOperation,
            CommsType::TwoFactorCode => tranquil_db_traits::CommsType::TwoFactorCode,
            CommsType::PasskeyRecovery => tranquil_db_traits::CommsType::PasskeyRecovery,
            CommsType::LegacyLoginAlert => tranquil_db_traits::CommsType::LegacyLoginAlert,
            CommsType::MigrationVerification => {
                tranquil_db_traits::CommsType::MigrationVerification
            }
            CommsType::ChannelVerification => tranquil_db_traits::CommsType::ChannelVerification,
            CommsType::ChannelVerified => tranquil_db_traits::CommsType::ChannelVerified,
        };
        let id = self
            .infra_repo
            .enqueue_comms(
                Some(item.user_id),
                channel,
                comms_type,
                &item.recipient,
                item.subject.as_deref(),
                &item.body,
                item.metadata,
            )
            .await?;
        debug!(comms_id = %id, "Comms enqueued");
        Ok(id)
    }

    pub fn has_senders(&self) -> bool {
        !self.senders.is_empty()
    }

    pub async fn run(self, shutdown: CancellationToken) {
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
                _ = shutdown.cancelled() => {
                    info!("Comms service shutting down");
                    break;
                }
            }
        }
    }

    async fn process_batch(&self) -> Result<(), tranquil_db_traits::DbError> {
        let items = self.fetch_pending().await?;
        if items.is_empty() {
            return Ok(());
        }
        debug!(count = items.len(), "Processing comms batch");
        futures::future::join_all(items.into_iter().map(|item| self.process_item(item))).await;
        Ok(())
    }

    async fn fetch_pending(&self) -> Result<Vec<QueuedComms>, tranquil_db_traits::DbError> {
        let now = Utc::now();
        self.infra_repo
            .fetch_pending_comms(now, self.batch_size)
            .await
    }

    async fn process_item(&self, item: QueuedComms) {
        let comms_id = item.id;
        let channel = match item.channel {
            tranquil_db_traits::CommsChannel::Email => CommsChannel::Email,
            tranquil_db_traits::CommsChannel::Discord => CommsChannel::Discord,
            tranquil_db_traits::CommsChannel::Telegram => CommsChannel::Telegram,
            tranquil_db_traits::CommsChannel::Signal => CommsChannel::Signal,
        };
        let comms_item = tranquil_comms::QueuedComms {
            id: item.id,
            user_id: item.user_id,
            channel,
            comms_type: match item.comms_type {
                tranquil_db_traits::CommsType::Welcome => CommsType::Welcome,
                tranquil_db_traits::CommsType::EmailVerification => CommsType::EmailVerification,
                tranquil_db_traits::CommsType::PasswordReset => CommsType::PasswordReset,
                tranquil_db_traits::CommsType::EmailUpdate => CommsType::EmailUpdate,
                tranquil_db_traits::CommsType::AccountDeletion => CommsType::AccountDeletion,
                tranquil_db_traits::CommsType::AdminEmail => CommsType::AdminEmail,
                tranquil_db_traits::CommsType::PlcOperation => CommsType::PlcOperation,
                tranquil_db_traits::CommsType::TwoFactorCode => CommsType::TwoFactorCode,
                tranquil_db_traits::CommsType::PasskeyRecovery => CommsType::PasskeyRecovery,
                tranquil_db_traits::CommsType::LegacyLoginAlert => CommsType::LegacyLoginAlert,
                tranquil_db_traits::CommsType::MigrationVerification => {
                    CommsType::MigrationVerification
                }
                tranquil_db_traits::CommsType::ChannelVerification => {
                    CommsType::ChannelVerification
                }
                tranquil_db_traits::CommsType::ChannelVerified => CommsType::ChannelVerified,
            },
            status: match item.status {
                tranquil_db_traits::CommsStatus::Pending => CommsStatus::Pending,
                tranquil_db_traits::CommsStatus::Processing => CommsStatus::Processing,
                tranquil_db_traits::CommsStatus::Sent => CommsStatus::Sent,
                tranquil_db_traits::CommsStatus::Failed => CommsStatus::Failed,
            },
            recipient: item.recipient,
            subject: item.subject,
            body: item.body,
            metadata: item.metadata,
            attempts: item.attempts,
            max_attempts: item.max_attempts,
            last_error: item.last_error,
            created_at: item.created_at,
            updated_at: item.updated_at,
            scheduled_for: item.scheduled_for,
            processed_at: item.processed_at,
        };
        let result = match self.senders.get(&channel) {
            Some(sender) => sender.send(&comms_item).await,
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

    async fn mark_sent(&self, id: Uuid) -> Result<(), tranquil_db_traits::DbError> {
        self.infra_repo.mark_comms_sent(id).await
    }

    async fn mark_failed(&self, id: Uuid, error: &str) -> Result<(), tranquil_db_traits::DbError> {
        self.infra_repo.mark_comms_failed(id, error).await
    }
}

pub fn channel_display_name(channel: CommsChannel) -> &'static str {
    match channel {
        CommsChannel::Email => "email",
        CommsChannel::Discord => "Discord",
        CommsChannel::Telegram => "Telegram",
        CommsChannel::Signal => "Signal",
    }
}

struct ResolvedRecipient {
    channel: tranquil_db_traits::CommsChannel,
    recipient: String,
}

fn resolve_recipient(
    prefs: &UserCommsPrefs,
    channel: tranquil_db_traits::CommsChannel,
) -> ResolvedRecipient {
    let email_fallback = || ResolvedRecipient {
        channel: tranquil_db_traits::CommsChannel::Email,
        recipient: prefs.email.clone().unwrap_or_default(),
    };
    match channel {
        tranquil_db_traits::CommsChannel::Email => email_fallback(),
        tranquil_db_traits::CommsChannel::Telegram => prefs
            .telegram_chat_id
            .map(|id| ResolvedRecipient {
                channel,
                recipient: id.to_string(),
            })
            .unwrap_or_else(email_fallback),
        tranquil_db_traits::CommsChannel::Discord => prefs
            .discord_id
            .as_ref()
            .filter(|id| !id.is_empty())
            .map(|id| ResolvedRecipient {
                channel,
                recipient: id.clone(),
            })
            .unwrap_or_else(email_fallback),
        tranquil_db_traits::CommsChannel::Signal => prefs
            .signal_number
            .as_ref()
            .filter(|n| !n.is_empty())
            .map(|n| ResolvedRecipient {
                channel,
                recipient: n.clone(),
            })
            .unwrap_or_else(email_fallback),
    }
}

fn channel_from_str(s: &str) -> tranquil_db_traits::CommsChannel {
    match s {
        "discord" => tranquil_db_traits::CommsChannel::Discord,
        "telegram" => tranquil_db_traits::CommsChannel::Telegram,
        "signal" => tranquil_db_traits::CommsChannel::Signal,
        _ => tranquil_db_traits::CommsChannel::Email,
    }
}

pub mod repo {
    use super::*;
    use tranquil_db_traits::DbError;

    pub async fn enqueue_welcome(
        user_repo: &dyn UserRepository,
        infra_repo: &dyn InfraRepository,
        user_id: Uuid,
        hostname: &str,
    ) -> Result<Uuid, DbError> {
        let prefs = user_repo
            .get_comms_prefs(user_id)
            .await?
            .ok_or(DbError::NotFound)?;
        let strings = get_strings(prefs.preferred_locale.as_deref().unwrap_or("en"));
        let body = format_message(
            strings.welcome_body,
            &[("hostname", hostname), ("handle", &prefs.handle)],
        );
        let subject = format_message(strings.welcome_subject, &[("hostname", hostname)]);
        let resolved = resolve_recipient(&prefs, prefs.preferred_channel);
        infra_repo
            .enqueue_comms(
                Some(user_id),
                resolved.channel,
                CommsType::Welcome,
                &resolved.recipient,
                Some(&subject),
                &body,
                None,
            )
            .await
    }

    pub async fn enqueue_password_reset(
        user_repo: &dyn UserRepository,
        infra_repo: &dyn InfraRepository,
        user_id: Uuid,
        code: &str,
        hostname: &str,
    ) -> Result<Uuid, DbError> {
        let prefs = user_repo
            .get_comms_prefs(user_id)
            .await?
            .ok_or(DbError::NotFound)?;
        let strings = get_strings(prefs.preferred_locale.as_deref().unwrap_or("en"));
        let body = format_message(
            strings.password_reset_body,
            &[("handle", &prefs.handle), ("code", code)],
        );
        let subject = format_message(strings.password_reset_subject, &[("hostname", hostname)]);
        let resolved = resolve_recipient(&prefs, prefs.preferred_channel);
        infra_repo
            .enqueue_comms(
                Some(user_id),
                resolved.channel,
                CommsType::PasswordReset,
                &resolved.recipient,
                Some(&subject),
                &body,
                None,
            )
            .await
    }

    pub async fn enqueue_email_update(
        infra_repo: &dyn InfraRepository,
        user_id: Uuid,
        new_email: &str,
        handle: &str,
        code: &str,
        hostname: &str,
    ) -> Result<Uuid, DbError> {
        let strings = get_strings("en");
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
        infra_repo
            .enqueue_comms(
                Some(user_id),
                tranquil_db_traits::CommsChannel::Email,
                CommsType::EmailUpdate,
                new_email,
                Some(&subject),
                &body,
                None,
            )
            .await
    }

    pub async fn enqueue_email_update_token(
        user_repo: &dyn UserRepository,
        infra_repo: &dyn InfraRepository,
        user_id: Uuid,
        raw_token: &str,
        display_code: &str,
        hostname: &str,
    ) -> Result<Uuid, DbError> {
        let prefs = user_repo
            .get_comms_prefs(user_id)
            .await?
            .ok_or(DbError::NotFound)?;
        let strings = get_strings(prefs.preferred_locale.as_deref().unwrap_or("en"));
        let current_email = prefs.email.unwrap_or_default();
        let verify_page = format!("https://{}/app/settings", hostname);
        let verify_link = format!(
            "https://{}/xrpc/_account.authorizeEmailUpdate?token={}",
            hostname,
            urlencoding::encode(raw_token)
        );
        let body = format_message(
            strings.email_update_body,
            &[
                ("handle", &prefs.handle),
                ("code", display_code),
                ("verify_page", &verify_page),
                ("verify_link", &verify_link),
            ],
        );
        let subject = format_message(strings.email_update_subject, &[("hostname", hostname)]);
        infra_repo
            .enqueue_comms(
                Some(user_id),
                tranquil_db_traits::CommsChannel::Email,
                CommsType::EmailUpdate,
                &current_email,
                Some(&subject),
                &body,
                None,
            )
            .await
    }

    pub async fn enqueue_short_token_email(
        user_repo: &dyn UserRepository,
        infra_repo: &dyn InfraRepository,
        user_id: Uuid,
        token: &str,
        purpose: &str,
        hostname: &str,
    ) -> Result<Uuid, DbError> {
        let prefs = user_repo
            .get_comms_prefs(user_id)
            .await?
            .ok_or(DbError::NotFound)?;
        let strings = get_strings(prefs.preferred_locale.as_deref().unwrap_or("en"));
        let current_email = prefs.email.clone().unwrap_or_default();

        let (subject_template, body_template, comms_type) = match purpose {
            "email_update" => (
                strings.email_update_subject,
                strings.short_token_body,
                CommsType::EmailUpdate,
            ),
            _ => (
                strings.email_update_subject,
                strings.short_token_body,
                CommsType::EmailUpdate,
            ),
        };

        let verify_page = format!("https://{}/app/settings", hostname);
        let body = format_message(
            body_template,
            &[
                ("handle", &prefs.handle),
                ("code", token),
                ("verify_page", &verify_page),
            ],
        );
        let subject = format_message(subject_template, &[("hostname", hostname)]);
        infra_repo
            .enqueue_comms(
                Some(user_id),
                tranquil_db_traits::CommsChannel::Email,
                comms_type,
                &current_email,
                Some(&subject),
                &body,
                None,
            )
            .await
    }

    pub async fn enqueue_account_deletion(
        user_repo: &dyn UserRepository,
        infra_repo: &dyn InfraRepository,
        user_id: Uuid,
        code: &str,
        hostname: &str,
    ) -> Result<Uuid, DbError> {
        let prefs = user_repo
            .get_comms_prefs(user_id)
            .await?
            .ok_or(DbError::NotFound)?;
        let strings = get_strings(prefs.preferred_locale.as_deref().unwrap_or("en"));
        let body = format_message(
            strings.account_deletion_body,
            &[("handle", &prefs.handle), ("code", code)],
        );
        let subject = format_message(strings.account_deletion_subject, &[("hostname", hostname)]);
        let resolved = resolve_recipient(&prefs, prefs.preferred_channel);
        infra_repo
            .enqueue_comms(
                Some(user_id),
                resolved.channel,
                CommsType::AccountDeletion,
                &resolved.recipient,
                Some(&subject),
                &body,
                None,
            )
            .await
    }

    pub async fn enqueue_plc_operation(
        user_repo: &dyn UserRepository,
        infra_repo: &dyn InfraRepository,
        user_id: Uuid,
        token: &str,
        hostname: &str,
    ) -> Result<Uuid, DbError> {
        let prefs = user_repo
            .get_comms_prefs(user_id)
            .await?
            .ok_or(DbError::NotFound)?;
        let strings = get_strings(prefs.preferred_locale.as_deref().unwrap_or("en"));
        let body = format_message(
            strings.plc_operation_body,
            &[("handle", &prefs.handle), ("token", token)],
        );
        let subject = format_message(strings.plc_operation_subject, &[("hostname", hostname)]);
        let resolved = resolve_recipient(&prefs, prefs.preferred_channel);
        infra_repo
            .enqueue_comms(
                Some(user_id),
                resolved.channel,
                CommsType::PlcOperation,
                &resolved.recipient,
                Some(&subject),
                &body,
                None,
            )
            .await
    }

    pub async fn enqueue_passkey_recovery(
        user_repo: &dyn UserRepository,
        infra_repo: &dyn InfraRepository,
        user_id: Uuid,
        recovery_url: &str,
        hostname: &str,
    ) -> Result<Uuid, DbError> {
        let prefs = user_repo
            .get_comms_prefs(user_id)
            .await?
            .ok_or(DbError::NotFound)?;
        let strings = get_strings(prefs.preferred_locale.as_deref().unwrap_or("en"));
        let body = format_message(
            strings.passkey_recovery_body,
            &[("handle", &prefs.handle), ("url", recovery_url)],
        );
        let subject = format_message(strings.passkey_recovery_subject, &[("hostname", hostname)]);
        let resolved = resolve_recipient(&prefs, prefs.preferred_channel);
        infra_repo
            .enqueue_comms(
                Some(user_id),
                resolved.channel,
                CommsType::PasskeyRecovery,
                &resolved.recipient,
                Some(&subject),
                &body,
                None,
            )
            .await
    }

    pub async fn enqueue_migration_verification(
        user_repo: &dyn UserRepository,
        infra_repo: &dyn InfraRepository,
        user_id: Uuid,
        email: &str,
        token: &str,
        hostname: &str,
    ) -> Result<Uuid, DbError> {
        let prefs = user_repo
            .get_comms_prefs(user_id)
            .await?
            .ok_or(DbError::NotFound)?;
        let strings = get_strings(prefs.preferred_locale.as_deref().unwrap_or("en"));
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
        infra_repo
            .enqueue_comms(
                Some(user_id),
                tranquil_db_traits::CommsChannel::Email,
                CommsType::MigrationVerification,
                email,
                Some(&subject),
                &body,
                None,
            )
            .await
    }

    pub async fn enqueue_signup_verification(
        infra_repo: &dyn InfraRepository,
        user_id: Uuid,
        channel: &str,
        recipient: &str,
        code: &str,
        hostname: &str,
    ) -> Result<Uuid, DbError> {
        let comms_channel = channel_from_str(channel);
        let strings = get_strings("en");
        let (verify_page, verify_link) = match comms_channel {
            tranquil_db_traits::CommsChannel::Email => {
                let encoded_email = urlencoding::encode(recipient);
                let encoded_token = urlencoding::encode(code);
                (
                    format!("https://{}/app/verify", hostname),
                    format!(
                        "https://{}/app/verify?token={}&identifier={}",
                        hostname, encoded_token, encoded_email
                    ),
                )
            }
            _ => (String::new(), String::new()),
        };
        let body = format_message(
            strings.signup_verification_body,
            &[
                ("code", code),
                ("hostname", hostname),
                ("verify_page", &verify_page),
                ("verify_link", &verify_link),
            ],
        );
        let subject = match comms_channel {
            tranquil_db_traits::CommsChannel::Email => Some(format_message(
                strings.signup_verification_subject,
                &[("hostname", hostname)],
            )),
            _ => None,
        };
        infra_repo
            .enqueue_comms(
                Some(user_id),
                comms_channel,
                CommsType::EmailVerification,
                recipient,
                subject.as_deref(),
                &body,
                None,
            )
            .await
    }

    pub async fn enqueue_2fa_code(
        user_repo: &dyn UserRepository,
        infra_repo: &dyn InfraRepository,
        user_id: Uuid,
        code: &str,
        hostname: &str,
    ) -> Result<Uuid, DbError> {
        let prefs = user_repo
            .get_comms_prefs(user_id)
            .await?
            .ok_or(DbError::NotFound)?;
        let strings = get_strings(prefs.preferred_locale.as_deref().unwrap_or("en"));
        let body = format_message(
            strings.two_factor_code_body,
            &[("handle", &prefs.handle), ("code", code)],
        );
        let subject = format_message(strings.two_factor_code_subject, &[("hostname", hostname)]);
        let resolved = resolve_recipient(&prefs, prefs.preferred_channel);
        infra_repo
            .enqueue_comms(
                Some(user_id),
                resolved.channel,
                CommsType::TwoFactorCode,
                &resolved.recipient,
                Some(&subject),
                &body,
                None,
            )
            .await
    }

    pub async fn enqueue_legacy_login(
        user_repo: &dyn UserRepository,
        infra_repo: &dyn InfraRepository,
        user_id: Uuid,
        hostname: &str,
        client_ip: &str,
        channel: tranquil_db_traits::CommsChannel,
    ) -> Result<Uuid, DbError> {
        let prefs = user_repo
            .get_comms_prefs(user_id)
            .await?
            .ok_or(DbError::NotFound)?;
        let strings = get_strings(prefs.preferred_locale.as_deref().unwrap_or("en"));
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
        let resolved = resolve_recipient(&prefs, channel);
        infra_repo
            .enqueue_comms(
                Some(user_id),
                resolved.channel,
                CommsType::LegacyLoginAlert,
                &resolved.recipient,
                Some(&subject),
                &body,
                None,
            )
            .await
    }

    pub async fn enqueue_channel_verified(
        user_repo: &dyn UserRepository,
        infra_repo: &dyn InfraRepository,
        user_id: Uuid,
        channel_name: &str,
        recipient: &str,
        hostname: &str,
    ) -> Result<Uuid, DbError> {
        let prefs = user_repo
            .get_comms_prefs(user_id)
            .await?
            .ok_or(DbError::NotFound)?;
        let strings = get_strings(prefs.preferred_locale.as_deref().unwrap_or("en"));
        let display_name = match channel_name {
            "email" => "Email",
            "discord" => "Discord",
            "telegram" => "Telegram",
            "signal" => "Signal",
            other => other,
        };
        let body = format_message(
            strings.channel_verified_body,
            &[
                ("handle", &prefs.handle),
                ("channel", display_name),
                ("hostname", hostname),
            ],
        );
        let subject = format_message(strings.channel_verified_subject, &[("hostname", hostname)]);
        let comms_channel = channel_from_str(channel_name);
        infra_repo
            .enqueue_comms(
                Some(user_id),
                comms_channel,
                CommsType::ChannelVerified,
                recipient,
                Some(&subject),
                &body,
                None,
            )
            .await
    }
}
