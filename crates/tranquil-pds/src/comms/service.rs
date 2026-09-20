use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;

use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use tranquil_comms::{
    CommsChannel, CommsSender, CommsType, NotificationStrings, SendError, format_message,
    get_strings,
};
use tranquil_db_traits::{
    DbError, InfraRepository, QueuedComms, Recipient, UserCommsPrefs, UserRepository,
};
use tranquil_types::{DiscordUserId, EmailAddress, SignalUsername, TelegramChatId};
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

        // Re-checking because there's been a trip into the DB and back, can't trust type -> string -> *maybe* type
        let recipient = match tranquil_db_traits::Recipient::new(item.channel, &item.recipient) {
            Ok(recipient) => recipient,
            Err(e) => {
                warn!(
                    comms_id = %comms_id,
                    error = %e,
                    "We marked comms item as permanently failed because its recipient is invalid"
                );
                if let Err(db_err) = self.mark_failed_permanent(comms_id, &e.to_string()).await {
                    error!(
                        comms_id = %comms_id,
                        error = %db_err,
                        "Failed to mark comms as failed"
                    );
                }
                return;
            }
        };
        let result = match self.senders.get(&item.channel) {
            Some(sender) => sender.send(&item, &recipient).await,
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
                let permanent = e.is_permanent();
                let error_msg = e.to_string();
                warn!(
                    comms_id = %comms_id,
                    error = %error_msg,
                    permanent,
                    "Failed to send comms"
                );
                let db_result = match permanent {
                    true => self.mark_failed_permanent(comms_id, &error_msg).await,
                    false => self.mark_failed(comms_id, &error_msg).await,
                };
                if let Err(db_err) = db_result {
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

    async fn mark_failed_permanent(
        &self,
        id: Uuid,
        error: &str,
    ) -> Result<(), tranquil_db_traits::DbError> {
        self.infra_repo.mark_comms_failed_permanent(id, error).await
    }
}

// Think about the situation on Telegram and Discord where the user must message a given bot *first* in order to hydrate a chat ID into our system so that we can in fact send things.
// If we can think of a better way to simply error-out later, instead of falling back to email when say Telegram is in an aborted state, let's do that.
pub struct VerificationTarget {
    pub id: String,
    pub recipient: Recipient,
}

impl VerificationTarget {
    pub fn direct(recipient: Recipient) -> Self {
        Self {
            id: recipient.as_str().to_string(),
            recipient,
        }
    }

    pub fn resolve(
        channel: CommsChannel,
        id: &str,
        fallback: Option<&str>,
    ) -> Result<Self, crate::api::error::ApiError> {
        let direct = (!channel.verifies_via_bot())
            .then(|| Recipient::new(channel, id))
            .and_then(Result::ok);
        let recipient = direct.map_or_else(|| fallback_recipient(fallback), Ok)?;
        Ok(Self {
            id: id.to_string(),
            recipient,
        })
    }
}

fn fallback_recipient(fallback: Option<&str>) -> Result<Recipient, crate::api::error::ApiError> {
    let raw = fallback
        .map(str::trim)
        .filter(|email| !email.is_empty())
        .ok_or(crate::api::error::ApiError::InvalidRequest(
            "Verification over this channel needs an email address. Message the bot first".into(),
        ))?;
    EmailAddress::new(raw)
        .map(Recipient::Email)
        .map_err(|_| crate::api::error::ApiError::InvalidEmail)
}

pub fn recipient_for(prefs: &UserCommsPrefs, channel: CommsChannel) -> Option<Recipient> {
    let fallback = || email_recipient(prefs);
    match channel {
        CommsChannel::Email => fallback(),
        CommsChannel::Telegram => prefs
            .telegram_chat_id
            .and_then(TelegramChatId::from_i64)
            .map(Recipient::Telegram)
            .or_else(fallback),
        CommsChannel::Discord => prefs
            .discord_id
            .as_deref()
            .and_then(|id| DiscordUserId::new(id).ok())
            .map(Recipient::Discord)
            .or_else(fallback),
        CommsChannel::Signal => prefs
            .signal_username
            .as_deref()
            .and_then(|name| SignalUsername::new(name).ok())
            .map(Recipient::Signal)
            .or_else(fallback),
    }
}

fn email_recipient(prefs: &UserCommsPrefs) -> Option<Recipient> {
    prefs
        .email
        .as_deref()
        .and_then(|email| EmailAddress::new(email).ok())
        .map(Recipient::Email)
}

pub mod repo {
    use super::*;

    pub enum Notice<'a> {
        Welcome,
        PasswordReset { code: &'a str },
        TwoFactorCode { code: &'a str },
        AccountDeletion { code: &'a str },
        PlcOperation { token: &'a str },
        PasskeyRecovery { url: &'a str },
        ShortTokenEmail { token: &'a str },
        LegacyLoginAlert { channel: CommsChannel, ip: &'a str },
    }

    impl Notice<'_> {
        fn comms_type(&self) -> CommsType {
            match self {
                Self::Welcome => CommsType::Welcome,
                Self::PasswordReset { .. } => CommsType::PasswordReset,
                Self::TwoFactorCode { .. } => CommsType::TwoFactorCode,
                Self::AccountDeletion { .. } => CommsType::AccountDeletion,
                Self::PlcOperation { .. } => CommsType::PlcOperation,
                Self::PasskeyRecovery { .. } => CommsType::PasskeyRecovery,
                Self::ShortTokenEmail { .. } => CommsType::EmailUpdate,
                Self::LegacyLoginAlert { .. } => CommsType::LegacyLoginAlert,
            }
        }

        // Yes yes I know, hardcoded, non-email-based accounts will have already bailed by now, don't worry. Emails are not special.
        fn channel(&self) -> Option<CommsChannel> {
            match self {
                Self::ShortTokenEmail { .. } => Some(CommsChannel::Email),
                Self::LegacyLoginAlert { channel, .. } => Some(*channel),
                _ => None,
            }
        }

        fn subject(&self, strings: &NotificationStrings) -> &'static str {
            match self {
                Self::Welcome => strings.welcome_subject,
                Self::PasswordReset { .. } => strings.password_reset_subject,
                Self::TwoFactorCode { .. } => strings.two_factor_code_subject,
                Self::AccountDeletion { .. } => strings.account_deletion_subject,
                Self::PlcOperation { .. } => strings.plc_operation_subject,
                Self::PasskeyRecovery { .. } => strings.passkey_recovery_subject,
                Self::ShortTokenEmail { .. } => strings.email_update_subject,
                Self::LegacyLoginAlert { .. } => strings.legacy_login_subject,
            }
        }

        fn body(&self, strings: &NotificationStrings, handle: &str, hostname: &str) -> String {
            match self {
                Self::Welcome => format_message(
                    strings.welcome_body,
                    &[("hostname", hostname), ("handle", handle)],
                ),
                Self::PasswordReset { code } => format_message(
                    strings.password_reset_body,
                    &[("handle", handle), ("code", code)],
                ),
                Self::TwoFactorCode { code } => format_message(
                    strings.two_factor_code_body,
                    &[("handle", handle), ("code", code)],
                ),
                Self::AccountDeletion { code } => format_message(
                    strings.account_deletion_body,
                    &[("handle", handle), ("code", code)],
                ),
                Self::PlcOperation { token } => format_message(
                    strings.plc_operation_body,
                    &[("handle", handle), ("token", token)],
                ),
                Self::PasskeyRecovery { url } => format_message(
                    strings.passkey_recovery_body,
                    &[("handle", handle), ("url", url)],
                ),
                Self::ShortTokenEmail { token } => {
                    let verify_page = format!("https://{hostname}/app/settings");
                    format_message(
                        strings.short_token_body,
                        &[
                            ("handle", handle),
                            ("code", token),
                            ("verify_page", &verify_page),
                        ],
                    )
                }
                Self::LegacyLoginAlert { ip, .. } => {
                    let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
                    format_message(
                        strings.legacy_login_body,
                        &[
                            ("handle", handle),
                            ("timestamp", &timestamp),
                            ("ip", ip),
                            ("hostname", hostname),
                        ],
                    )
                }
            }
        }
    }

    pub async fn enqueue_notice(
        user_repo: &dyn UserRepository,
        infra_repo: &dyn InfraRepository,
        user_id: Uuid,
        notice: Notice<'_>,
        hostname: &str,
    ) -> Result<Option<Uuid>, DbError> {
        let prefs = user_repo
            .get_comms_prefs(user_id)
            .await?
            .ok_or(DbError::NotFound)?;
        let channel = notice.channel().unwrap_or(prefs.preferred_channel);
        let Some(recipient) = recipient_for(&prefs, channel) else {
            warn!(
                user_id = %user_id,
                channel = ?channel,
                "We skipped queuing this notice because the account doesn't have a valid recipient"
            );
            return Ok(None);
        };
        let strings = get_strings(locale_of(&prefs));
        let subject = format_message(notice.subject(strings), &[("hostname", hostname)]);
        let body = notice.body(strings, prefs.handle.as_str(), hostname);
        infra_repo
            .enqueue_comms(
                Some(user_id),
                &recipient,
                notice.comms_type(),
                Some(&subject),
                &body,
                None,
            )
            .await
            .map(Some)
    }

    fn locale_of(prefs: &UserCommsPrefs) -> &str {
        prefs.preferred_locale.as_deref().unwrap_or("en")
    }

    pub async fn enqueue_email_update(
        infra_repo: &dyn InfraRepository,
        user_id: Uuid,
        new_email: &EmailAddress,
        handle: &crate::types::Handle,
        code: &str,
        hostname: &str,
    ) -> Result<Uuid, DbError> {
        let strings = get_strings("en");
        let encoded_email = urlencoding::encode(new_email.as_str());
        let encoded_token = urlencoding::encode(code);
        let verify_page = format!("https://{}/app/verify", hostname);
        let verify_link = format!(
            "https://{}/app/verify?token={}&identifier={}",
            hostname, encoded_token, encoded_email
        );
        let body = format_message(
            strings.email_update_body,
            &[
                ("handle", handle.as_str()),
                ("code", code),
                ("verify_page", &verify_page),
                ("verify_link", &verify_link),
            ],
        );
        let subject = format_message(strings.email_update_subject, &[("hostname", hostname)]);
        infra_repo
            .enqueue_comms(
                Some(user_id),
                &Recipient::Email(new_email.clone()),
                CommsType::EmailUpdate,
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
        target: &VerificationTarget,
        token: &str,
        hostname: &str,
    ) -> Result<Uuid, DbError> {
        let prefs = user_repo
            .get_comms_prefs(user_id)
            .await?
            .ok_or(DbError::NotFound)?;
        let strings = get_strings(locale_of(&prefs));
        let encoded_id = urlencoding::encode(&target.id);
        let encoded_token = urlencoding::encode(token);
        let verify_page = format!("https://{}/app/verify", hostname);
        let verify_link = format!(
            "https://{}/app/verify?token={}&identifier={}",
            hostname, encoded_token, encoded_id
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
                &target.recipient,
                CommsType::MigrationVerification,
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
        target: &VerificationTarget,
        code: &str,
        hostname: &str,
    ) -> Result<Uuid, DbError> {
        let prefs = match user_repo.get_comms_prefs(user_id).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(user_id = %user_id, error = %e, "failed to fetch comms preferences, using defaults");
                None
            }
        };
        let locale = prefs.as_ref().map(locale_of).unwrap_or("en");
        let strings = get_strings(locale);
        let encoded_token = urlencoding::encode(code);
        let encoded_id = urlencoding::encode(&target.id);
        let verify_page = format!("https://{}/app/verify", hostname);
        let verify_link = format!(
            "https://{}/app/verify?token={}&identifier={}",
            hostname, encoded_token, encoded_id
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
                &target.recipient,
                CommsType::EmailVerification,
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
        recipient: &Recipient,
        hostname: &str,
    ) -> Result<Uuid, DbError> {
        let prefs = user_repo
            .get_comms_prefs(user_id)
            .await?
            .ok_or(DbError::NotFound)?;
        let strings = get_strings(locale_of(&prefs));
        let body = format_message(
            strings.channel_verified_body,
            &[
                ("handle", &prefs.handle),
                ("channel", recipient.channel().display_name()),
                ("hostname", hostname),
            ],
        );
        let subject = format_message(strings.channel_verified_subject, &[("hostname", hostname)]);
        infra_repo
            .enqueue_comms(
                Some(user_id),
                recipient,
                CommsType::ChannelVerified,
                Some(&subject),
                &body,
                None,
            )
            .await
    }

    pub async fn try_channel_verified_notice(
        user_repo: &dyn UserRepository,
        infra_repo: &dyn InfraRepository,
        user_id: Uuid,
        recipient: &Recipient,
        hostname: &str,
    ) {
        if let Err(e) =
            enqueue_channel_verified(user_repo, infra_repo, user_id, recipient, hostname).await
        {
            warn!(error = %e, "Failed to enqueue channel verified notification");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bot_channel_recipients_fall_back_to_email() {
        let telegram =
            VerificationTarget::resolve(CommsChannel::Telegram, "123456789", Some("user@jola.dev"))
                .unwrap();
        assert_eq!(telegram.recipient.channel(), CommsChannel::Email);

        let discord = VerificationTarget::resolve(
            CommsChannel::Discord,
            "274656283714826240",
            Some("user@jola.dev"),
        )
        .unwrap();
        assert_eq!(discord.recipient.channel(), CommsChannel::Email);
    }

    #[test]
    fn resolution_keeps_id_for_bot_channels() {
        let target =
            VerificationTarget::resolve(CommsChannel::Telegram, "oys_01", Some("user@jola.dev"))
                .unwrap();
        assert_eq!(target.id, "oys_01");
        assert_eq!(target.recipient.channel(), CommsChannel::Email);
    }

    #[test]
    fn direct_channels_parse_id() {
        let email = VerificationTarget::resolve(CommsChannel::Email, "user@nel.pet", None).unwrap();
        assert_eq!(email.recipient.as_str(), "user@nel.pet");

        let signal = VerificationTarget::resolve(CommsChannel::Signal, "oys.01", None).unwrap();
        assert_eq!(signal.recipient.channel(), CommsChannel::Signal);
    }

    #[test]
    fn signal_falls_back_when_id_isnt_username() {
        let target =
            VerificationTarget::resolve(CommsChannel::Signal, "oys", Some("user@jola.dev"))
                .unwrap();
        assert_eq!(target.recipient.channel(), CommsChannel::Email);
    }

    #[test]
    fn resolve_fails_without_fallback() {
        assert!(VerificationTarget::resolve(CommsChannel::Telegram, "oys_01", None).is_err());
        assert!(VerificationTarget::resolve(CommsChannel::Signal, "oys", None).is_err());
    }
}

#[cfg(test)]
mod recipient_for_tests {
    use super::*;

    fn undeliverable_prefs() -> UserCommsPrefs {
        UserCommsPrefs {
            email: None,
            handle: "oys.nel.pet".parse().unwrap(),
            preferred_channel: CommsChannel::Telegram,
            preferred_locale: None,
            telegram_chat_id: None,
            discord_id: None,
            signal_username: None,
        }
    }

    #[test]
    fn undeliverable_prefs_resolve_to_none_on_every_channel() {
        let prefs = undeliverable_prefs();
        assert_eq!(recipient_for(&prefs, CommsChannel::Telegram), None);
        assert_eq!(recipient_for(&prefs, CommsChannel::Email), None);
    }

    #[test]
    fn zero_chat_id_falls_back_to_email() {
        let prefs = UserCommsPrefs {
            telegram_chat_id: Some(0),
            email: Some("oys@jola.dev".into()),
            ..undeliverable_prefs()
        };
        assert_eq!(
            recipient_for(&prefs, CommsChannel::Telegram),
            Some(Recipient::Email(EmailAddress::new("oys@jola.dev").unwrap()))
        );
    }
}
