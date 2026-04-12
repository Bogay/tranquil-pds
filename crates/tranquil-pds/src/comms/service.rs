use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;

use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use tranquil_comms::{
    CommsChannel, CommsSender, CommsType, NewComms, SendError, format_message, get_strings,
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
        let cfg = tranquil_config::get();
        let poll_interval_ms = cfg.notifications.poll_interval_ms;
        let batch_size = cfg.notifications.batch_size;
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
        let id = self
            .infra_repo
            .enqueue_comms(
                Some(item.user_id),
                item.channel,
                item.comms_type,
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
            poll_interval_ms = self.poll_interval.as_millis() as u64,
            batch_size = self.batch_size,
            channels = ?self.senders.keys().collect::<Vec<_>>(),
            "Starting comms service"
        );
        let base = self.poll_interval;
        let max_backoff = Duration::from_secs(30);
        let mut current_delay = base;
        loop {
            tokio::select! {
                _ = tokio::time::sleep(current_delay) => {
                    match self.process_batch().await {
                        Ok(had_work) => {
                            current_delay = match had_work {
                                true => base,
                                false => max_backoff.min(current_delay.saturating_mul(2)),
                            };
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to process comms batch");
                            current_delay = max_backoff.min(current_delay.saturating_mul(2));
                        }
                    }
                }
                _ = shutdown.cancelled() => {
                    info!("Comms service shutting down");
                    break;
                }
            }
        }
    }

    async fn process_batch(&self) -> Result<bool, tranquil_db_traits::DbError> {
        let items = self.fetch_pending().await?;
        if items.is_empty() {
            return Ok(false);
        }
        debug!(count = items.len(), "Processing comms batch");
        futures::future::join_all(items.into_iter().map(|item| self.process_item(item))).await;
        Ok(true)
    }

    async fn fetch_pending(&self) -> Result<Vec<QueuedComms>, tranquil_db_traits::DbError> {
        let now = Utc::now();
        self.infra_repo
            .fetch_pending_comms(now, self.batch_size)
            .await
    }

    async fn process_item(&self, item: QueuedComms) {
        let comms_id = item.id;
        let result = match self.senders.get(&item.channel) {
            Some(sender) => sender.send(&item).await,
            None => {
                warn!(
                    comms_id = %comms_id,
                    channel = ?item.channel,
                    "No sender registered for channel"
                );
                Err(SendError::NotConfigured(item.channel))
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

struct ResolvedRecipient {
    channel: tranquil_db_traits::CommsChannel,
    recipient: String,
}

pub fn resolve_delivery_channel(
    prefs: &UserCommsPrefs,
    channel: tranquil_db_traits::CommsChannel,
) -> tranquil_db_traits::CommsChannel {
    resolve_recipient(prefs, channel).channel
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
            .signal_username
            .as_ref()
            .filter(|n| !n.is_empty())
            .map(|n| ResolvedRecipient {
                channel,
                recipient: n.clone(),
            })
            .unwrap_or_else(email_fallback),
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
        hostname: &str,
    ) -> Result<Uuid, DbError> {
        let prefs = user_repo
            .get_comms_prefs(user_id)
            .await?
            .ok_or(DbError::NotFound)?;
        let strings = get_strings(prefs.preferred_locale.as_deref().unwrap_or("en"));
        let current_email = prefs.email.clone().unwrap_or_default();

        let subject_template = strings.email_update_subject;
        let body_template = strings.short_token_body;
        let comms_type = CommsType::EmailUpdate;

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
        channel: tranquil_db_traits::CommsChannel,
        recipient: &str,
        token: &str,
        hostname: &str,
    ) -> Result<Uuid, DbError> {
        let prefs = user_repo
            .get_comms_prefs(user_id)
            .await?
            .ok_or(DbError::NotFound)?;
        let strings = get_strings(prefs.preferred_locale.as_deref().unwrap_or("en"));
        let encoded_recipient = urlencoding::encode(recipient);
        let encoded_token = urlencoding::encode(token);
        let verify_page = format!("https://{}/app/verify", hostname);
        let verify_link = format!(
            "https://{}/app/verify?token={}&identifier={}",
            hostname, encoded_token, encoded_recipient
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
                channel,
                CommsType::MigrationVerification,
                recipient,
                Some(&subject),
                &body,
                None,
            )
            .await
    }

    pub async fn enqueue_signup_verification(
        user_repo: &dyn UserRepository,
        infra_repo: &dyn InfraRepository,
        user_id: Uuid,
        channel: tranquil_db_traits::CommsChannel,
        recipient: &str,
        code: &str,
        hostname: &str,
    ) -> Result<Uuid, DbError> {
        let comms_channel = channel;
        let prefs = match user_repo.get_comms_prefs(user_id).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(user_id = %user_id, error = %e, "failed to fetch comms preferences, using defaults");
                None
            }
        };
        let locale = prefs
            .as_ref()
            .and_then(|p| p.preferred_locale.as_deref())
            .unwrap_or("en");
        let strings = get_strings(locale);
        let encoded_token = urlencoding::encode(code);
        let encoded_recipient = urlencoding::encode(recipient);
        let verify_page = format!("https://{}/app/verify", hostname);
        let verify_link = format!(
            "https://{}/app/verify?token={}&identifier={}",
            hostname, encoded_token, encoded_recipient
        );
        let body = format_message(
            strings.signup_verification_body,
            &[
                ("code", code),
                ("hostname", hostname),
                ("verify_page", &verify_page),
                ("verify_link", &verify_link),
            ],
        );
        let subject = format_message(
            strings.signup_verification_subject,
            &[("hostname", hostname)],
        );
        infra_repo
            .enqueue_comms(
                Some(user_id),
                comms_channel,
                CommsType::EmailVerification,
                recipient,
                Some(&subject),
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
        channel: tranquil_db_traits::CommsChannel,
        recipient: &str,
        hostname: &str,
    ) -> Result<Uuid, DbError> {
        let prefs = user_repo
            .get_comms_prefs(user_id)
            .await?
            .ok_or(DbError::NotFound)?;
        let strings = get_strings(prefs.preferred_locale.as_deref().unwrap_or("en"));
        let body = format_message(
            strings.channel_verified_body,
            &[
                ("handle", &prefs.handle),
                ("channel", channel.display_name()),
                ("hostname", hostname),
            ],
        );
        let subject = format_message(strings.channel_verified_subject, &[("hostname", hostname)]);
        infra_repo
            .enqueue_comms(
                Some(user_id),
                channel,
                CommsType::ChannelVerified,
                recipient,
                Some(&subject),
                &body,
                None,
            )
            .await
    }
}
