use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;

use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use tranquil_comms::locale::{
    AccountDeletionBody, AccountDeletionSubject, ChannelVerificationBody,
    ChannelVerificationSubject, ChannelVerifiedBody, ChannelVerifiedSubject,
    EmailUpdateApprovalBody, EmailUpdateConfirmationBody, EmailUpdateSubject, LegacyLoginBody,
    LegacyLoginSubject, MigrationVerificationBody, MigrationVerificationSubject,
    PasskeyRecoveryBody, PasskeyRecoverySubject, PasswordResetBody, PasswordResetSubject,
    PlcOperationBody, PlcOperationSubject, SignupVerificationBody, SignupVerificationSubject,
    TwoFactorCodeBody, TwoFactorCodeSubject, WelcomeBody, WelcomeSubject, get_strings,
    localized_duration,
};
use tranquil_comms::{
    CommsChannel, CommsMessageType, CommsSender, NotificationStrings, RenderedTemplate, SendError,
    TemplateError, TemplateId, render_html,
};
use tranquil_db_traits::{
    DbError, InfraRepository, QueuedComms, Recipient, UserCommsPrefs, UserRepository,
};
use tranquil_types::{DiscordUserId, EmailAddress, Locale, SignalUsername, TelegramChatId};
use uuid::Uuid;

use crate::auth::verification_token::VerificationPurpose;

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

#[derive(Debug)]
pub enum NotificationError {
    InvalidRequest(String),
    RequiresBot,
    DbError(DbError),
    PreferredLocaleNotFound(DbError),
    TemplateRenderingError(String),
}

impl fmt::Display for NotificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(e) => write!(f, "Invalid request: {}", e),
            Self::RequiresBot => write!(f, "Requires bot"),
            Self::DbError(e) => write!(f, "DB error: {}", e),
            Self::PreferredLocaleNotFound(e) => write!(f, "Preferred locale not found: {}", e),
            Self::TemplateRenderingError(e) => write!(f, "Template rendering error: {}", e),
        }
    }
}

impl std::error::Error for NotificationError {}

pub mod repo {
    use super::*;

    fn render_err(e: TemplateError) -> NotificationError {
        NotificationError::TemplateRenderingError(e.to_string())
    }

    pub enum Notice<'a> {
        Welcome,
        PasswordReset { code: &'a str, valid_for: Duration },
        TwoFactorCode { code: &'a str, valid_for: Duration },
        AccountDeletion { code: &'a str, valid_for: Duration },
        PlcOperation { token: &'a str, valid_for: Duration },
        PasskeyRecovery { url: &'a str, valid_for: Duration },
        ShortTokenEmail { token: &'a str, valid_for: Duration },
        LegacyLoginAlert { channel: CommsChannel, ip: &'a str },
    }

    impl Notice<'_> {
        fn comms_type(&self) -> CommsMessageType {
            match self {
                Self::Welcome => CommsMessageType::Welcome,
                Self::PasswordReset { .. } => CommsMessageType::PasswordReset,
                Self::TwoFactorCode { .. } => CommsMessageType::TwoFactorCode,
                Self::AccountDeletion { .. } => CommsMessageType::AccountDeletion,
                Self::PlcOperation { .. } => CommsMessageType::PlcOperation,
                Self::PasskeyRecovery { .. } => CommsMessageType::PasskeyRecovery,
                // Unfortunate naming inconsistency, EmailUpdate is the correct name for this.
                Self::ShortTokenEmail { .. } => CommsMessageType::EmailUpdate,
                Self::LegacyLoginAlert { .. } => CommsMessageType::LegacyLoginAlert,
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

        fn rendered(
            &self,
            strings: &NotificationStrings,
            locale: Locale,
            handle: &crate::types::Handle,
            hostname: &str,
        ) -> Result<RenderedTemplate, NotificationError> {
            match self {
                Self::Welcome => {
                    let v = WelcomeBody { hostname, handle };
                    let vars = v.as_vars();
                    Ok(RenderedTemplate {
                        subject: strings
                            .welcome_subject(locale, &WelcomeSubject { hostname })
                            .map_err(render_err)?,
                        body: strings.welcome_body(locale, &v).map_err(render_err)?,
                        html_body: render_html(TemplateId::Welcome, locale, &vars)
                            .map_err(render_err)?,
                    })
                }
                Self::PasswordReset { code, valid_for } => {
                    let v = PasswordResetBody {
                        handle,
                        code,
                        valid_for: &localized_duration(locale, *valid_for),
                    };
                    let vars = v.as_vars();
                    Ok(RenderedTemplate {
                        subject: strings
                            .password_reset_subject(locale, &PasswordResetSubject { hostname })
                            .map_err(render_err)?,
                        body: strings
                            .password_reset_body(locale, &v)
                            .map_err(render_err)?,
                        html_body: render_html(TemplateId::PasswordReset, locale, &vars)
                            .map_err(render_err)?,
                    })
                }
                Self::TwoFactorCode { code, valid_for } => {
                    let v = TwoFactorCodeBody {
                        handle,
                        code,
                        valid_for: &localized_duration(locale, *valid_for),
                    };
                    let vars = v.as_vars();
                    Ok(RenderedTemplate {
                        subject: strings
                            .two_factor_code_subject(locale, &TwoFactorCodeSubject { hostname })
                            .map_err(render_err)?,
                        body: strings
                            .two_factor_code_body(locale, &v)
                            .map_err(render_err)?,
                        html_body: render_html(TemplateId::TwoFactorCode, locale, &vars)
                            .map_err(render_err)?,
                    })
                }
                Self::AccountDeletion { code, valid_for } => {
                    let v = AccountDeletionBody {
                        handle,
                        code,
                        valid_for: &localized_duration(locale, *valid_for),
                    };
                    let vars = v.as_vars();
                    Ok(RenderedTemplate {
                        subject: strings
                            .account_deletion_subject(locale, &AccountDeletionSubject { hostname })
                            .map_err(render_err)?,
                        body: strings
                            .account_deletion_body(locale, &v)
                            .map_err(render_err)?,
                        html_body: render_html(TemplateId::AccountDeletion, locale, &vars)
                            .map_err(render_err)?,
                    })
                }
                Self::PlcOperation { token, valid_for } => {
                    let v = PlcOperationBody {
                        handle,
                        token,
                        valid_for: &localized_duration(locale, *valid_for),
                    };
                    let vars = v.as_vars();
                    Ok(RenderedTemplate {
                        subject: strings
                            .plc_operation_subject(locale, &PlcOperationSubject { hostname })
                            .map_err(render_err)?,
                        body: strings.plc_operation_body(locale, &v).map_err(render_err)?,
                        html_body: render_html(TemplateId::PlcOperation, locale, &vars)
                            .map_err(render_err)?,
                    })
                }
                Self::PasskeyRecovery { url, valid_for } => {
                    let v = PasskeyRecoveryBody {
                        handle,
                        url,
                        valid_for: &localized_duration(locale, *valid_for),
                    };
                    let vars = v.as_vars();
                    Ok(RenderedTemplate {
                        subject: strings
                            .passkey_recovery_subject(locale, &PasskeyRecoverySubject { hostname })
                            .map_err(render_err)?,
                        body: strings
                            .passkey_recovery_body(locale, &v)
                            .map_err(render_err)?,
                        html_body: render_html(TemplateId::PasskeyRecovery, locale, &vars)
                            .map_err(render_err)?,
                    })
                }
                Self::ShortTokenEmail { token, valid_for } => {
                    let verify_page = format!("https://{hostname}/app/settings");
                    let v = EmailUpdateApprovalBody {
                        handle,
                        code: token,
                        verify_page: &verify_page,
                        valid_for: &localized_duration(locale, *valid_for),
                    };
                    let vars = v.as_vars();
                    Ok(RenderedTemplate {
                        subject: strings
                            .short_token_subject(locale, &EmailUpdateSubject { hostname })
                            .map_err(render_err)?,
                        body: strings
                            .email_update_approval_body(locale, &v)
                            .map_err(render_err)?,
                        html_body: render_html(TemplateId::ShortToken, locale, &vars)
                            .map_err(render_err)?,
                    })
                }
                Self::LegacyLoginAlert { ip, .. } => {
                    let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
                    let v = LegacyLoginBody {
                        handle,
                        timestamp: &timestamp,
                        ip,
                        hostname,
                    };
                    let vars = v.as_vars();
                    Ok(RenderedTemplate {
                        subject: strings
                            .legacy_login_subject(locale, &LegacyLoginSubject { hostname })
                            .map_err(render_err)?,
                        body: strings.legacy_login_body(locale, &v).map_err(render_err)?,
                        html_body: render_html(TemplateId::LegacyLogin, locale, &vars)
                            .map_err(render_err)?,
                    })
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
    ) -> Result<Option<Uuid>, NotificationError> {
        let prefs = get_comms_prefs(user_repo, user_id).await?;
        let channel = notice.channel().unwrap_or(prefs.preferred_channel);
        let Some(recipient) = recipient_for(&prefs, channel) else {
            warn!(
                user_id = %user_id,
                channel = ?channel,
                "We skipped queuing this notice because the account doesn't have a valid recipient"
            );
            return Ok(None);
        };
        let locale = locale_of(&prefs);
        let rendered = notice.rendered(get_strings(locale), locale, &prefs.handle, hostname)?;
        infra_repo
            .enqueue_comms(
                Some(user_id),
                &recipient,
                notice.comms_type(),
                Some(&rendered.subject),
                &rendered.body,
                rendered.metadata(),
            )
            .await
            .map_err(NotificationError::DbError)
            .map(Some)
    }

    fn locale_of(prefs: &UserCommsPrefs) -> Locale {
        prefs
            .preferred_locale
            .as_deref()
            .unwrap_or("en")
            .parse()
            .unwrap_or_default()
    }

    pub async fn get_comms_prefs(
        user_repo: &dyn UserRepository,
        user_id: Uuid,
    ) -> Result<UserCommsPrefs, NotificationError> {
        let user = user_repo.get_comms_prefs(user_id).await;
        match user {
            Ok(Some(prefs)) => Ok(prefs),
            Ok(None) => Err(NotificationError::PreferredLocaleNotFound(
                DbError::NotFound,
            )),
            Err(e) => Err(NotificationError::PreferredLocaleNotFound(e)),
        }
    }

    pub async fn enqueue_email_update(
        infra_repo: &dyn InfraRepository,
        user_id: Uuid,
        new_email: &EmailAddress,
        handle: &crate::types::Handle,
        code: &str,
        hostname: &str,
    ) -> Result<Uuid, NotificationError> {
        // TODO support user locale for email update
        let locale = Locale::default();
        let strings = get_strings(locale);
        let encoded_email = urlencoding::encode(new_email.as_str());
        let encoded_token = urlencoding::encode(code);
        let verify_page = format!("https://{hostname}/app/verify");
        let verify_link = format!(
            "https://{}/app/verify?token={}&identifier={}",
            hostname, encoded_token, encoded_email
        );
        let v = EmailUpdateConfirmationBody {
            handle,
            code,
            verify_page: &verify_page,
            verify_link: &verify_link,
            valid_for: &localized_duration(
                locale,
                Duration::from_secs(VerificationPurpose::ChannelUpdate.default_expiry_seconds()),
            ),
        };
        let vars = v.as_vars();
        let rendered = RenderedTemplate {
            subject: strings
                .email_update_subject(locale, &EmailUpdateSubject { hostname })
                .map_err(render_err)?,
            body: strings
                .email_update_confirmation_body(locale, &v)
                .map_err(render_err)?,
            html_body: render_html(TemplateId::EmailUpdate, locale, &vars).map_err(render_err)?,
        };
        infra_repo
            .enqueue_comms(
                Some(user_id),
                &Recipient::Email(new_email.clone()),
                CommsMessageType::EmailUpdate,
                Some(&rendered.subject),
                &rendered.body,
                rendered.metadata(),
            )
            .await
            .map_err(NotificationError::DbError)
    }

    pub async fn enqueue_migration_verification(
        user_repo: &dyn UserRepository,
        infra_repo: &dyn InfraRepository,
        user_id: Uuid,
        target: &VerificationTarget,
        token: &str,
        hostname: &str,
    ) -> Result<Uuid, NotificationError> {
        let prefs = get_comms_prefs(user_repo, user_id).await?;
        let locale = locale_of(&prefs);
        let strings = get_strings(locale);
        let encoded_id = urlencoding::encode(&target.id);
        let encoded_token = urlencoding::encode(token);
        let verify_page = format!("https://{hostname}/app/verify");
        let verify_link = format!(
            "https://{}/app/verify?token={}&identifier={}",
            hostname, encoded_token, encoded_id
        );
        let v = MigrationVerificationBody {
            code: token,
            hostname,
            verify_page: &verify_page,
            verify_link: &verify_link,
            valid_for: &localized_duration(
                locale,
                Duration::from_secs(VerificationPurpose::Migration.default_expiry_seconds()),
            ),
        };
        let vars = v.as_vars();
        let rendered = RenderedTemplate {
            subject: strings
                .migration_verification_subject(locale, &MigrationVerificationSubject { hostname })
                .map_err(render_err)?,
            body: strings
                .migration_verification_body(locale, &v)
                .map_err(render_err)?,
            html_body: render_html(TemplateId::MigrationVerification, locale, &vars)
                .map_err(render_err)?,
        };
        infra_repo
            .enqueue_comms(
                Some(user_id),
                &target.recipient,
                CommsMessageType::MigrationVerification,
                Some(&rendered.subject),
                &rendered.body,
                rendered.metadata(),
            )
            .await
            .map_err(NotificationError::DbError)
    }

    pub async fn enqueue_signup_verification(
        user_repo: &dyn UserRepository,
        infra_repo: &dyn InfraRepository,
        user_id: Uuid,
        target: &VerificationTarget,
        code: &str,
        hostname: &str,
    ) -> Result<Uuid, NotificationError> {
        let prefs = match user_repo.get_comms_prefs(user_id).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(user_id = %user_id, error = %e, "failed to fetch comms preferences, using defaults");
                None
            }
        };
        let locale = prefs.as_ref().map(locale_of).unwrap_or_default();
        let strings = get_strings(locale);
        let encoded_token = urlencoding::encode(code);
        let encoded_id = urlencoding::encode(&target.id);
        let verify_page = format!("https://{hostname}/app/verify");
        let verify_link = format!(
            "https://{}/app/verify?token={}&identifier={}",
            hostname, encoded_token, encoded_id
        );
        let v = SignupVerificationBody {
            code,
            hostname,
            verify_page: &verify_page,
            verify_link: &verify_link,
            valid_for: &localized_duration(
                locale,
                Duration::from_secs(VerificationPurpose::Signup.default_expiry_seconds()),
            ),
        };
        let vars = v.as_vars();
        let rendered = RenderedTemplate {
            subject: strings
                .signup_verification_subject(locale, &SignupVerificationSubject { hostname })
                .map_err(render_err)?,
            body: strings
                .signup_verification_body(locale, &v)
                .map_err(render_err)?,
            html_body: render_html(TemplateId::SignupVerification, locale, &vars)
                .map_err(render_err)?,
        };
        infra_repo
            .enqueue_comms(
                Some(user_id),
                &target.recipient,
                CommsMessageType::EmailVerification,
                Some(&rendered.subject),
                &rendered.body,
                rendered.metadata(),
            )
            .await
            .map_err(NotificationError::DbError)
    }

    pub async fn enqueue_channel_verification(
        user_repo: &dyn UserRepository,
        infra_repo: &dyn InfraRepository,
        user_id: Uuid,
        target: &VerificationTarget,
        code: &str,
        hostname: &str,
        channel: CommsChannel,
    ) -> Result<Uuid, NotificationError> {
        if channel.verifies_via_bot() {
            warn!(
                user_id = %user_id,
                channel = ?channel,
                "This channel verifies through a bot. Please message the bot first so that it's able to reply with useful info for channel {}",
                channel.display_name(),
            );
            return Err(NotificationError::RequiresBot);
        }
        let prefs = get_comms_prefs(user_repo, user_id).await?;
        let locale = locale_of(&prefs);
        let strings = get_strings(locale);
        // TODO clean up identifier encoding within the rendering
        let encoded_token = urlencoding::encode(code);
        let encoded_id = urlencoding::encode(&target.id);
        let verify_link = format!(
            "https://{}/app/verify?token={}&identifier={}",
            hostname, encoded_token, encoded_id
        );
        let v = ChannelVerificationBody {
            code,
            verify_link: &verify_link,
        };
        let vars = v.as_vars();
        let rendered = RenderedTemplate {
            subject: strings
                .channel_verification_subject(locale, &ChannelVerificationSubject { hostname })
                .map_err(render_err)?,
            body: strings
                .channel_verification_body(locale, &v)
                .map_err(render_err)?,
            html_body: render_html(TemplateId::ChannelVerification, locale, &vars)
                .map_err(render_err)?,
        };
        infra_repo
            .enqueue_comms(
                Some(user_id),
                &target.recipient,
                CommsMessageType::ChannelVerification,
                Some(&rendered.subject),
                &rendered.body,
                rendered.metadata(),
            )
            .await
            .map_err(NotificationError::DbError)
    }

    pub async fn enqueue_channel_verified(
        user_repo: &dyn UserRepository,
        infra_repo: &dyn InfraRepository,
        user_id: Uuid,
        recipient: &Recipient,
        hostname: &str,
    ) -> Result<Uuid, NotificationError> {
        let prefs = get_comms_prefs(user_repo, user_id).await?;
        let locale = locale_of(&prefs);
        let strings = get_strings(locale);
        let v = ChannelVerifiedBody {
            handle: &prefs.handle,
            channel: recipient.channel(),
            hostname,
        };
        let vars = v.as_vars();
        let rendered = RenderedTemplate {
            subject: strings
                .channel_verified_subject(locale, &ChannelVerifiedSubject { hostname })
                .map_err(render_err)?,
            body: strings
                .channel_verified_body(locale, &v)
                .map_err(render_err)?,
            html_body: render_html(TemplateId::ChannelVerified, locale, &vars)
                .map_err(render_err)?,
        };
        infra_repo
            .enqueue_comms(
                Some(user_id),
                recipient,
                CommsMessageType::ChannelVerified,
                Some(&rendered.subject),
                &rendered.body,
                rendered.metadata(),
            )
            .await
            .map_err(NotificationError::DbError)
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

    #[cfg(test)]
    mod notice_render_tests {
        use super::*;

        fn test_handle() -> crate::types::Handle {
            "nel.nel.pet".parse().unwrap()
        }

        fn code_line(body: &str) -> String {
            body.lines()
                .skip_while(|line| !line.contains("verification code"))
                .nth(1)
                .map(|line| line.trim().to_string())
                .expect("a code, after verif code heading")
        }

        #[test]
        fn short_token_email_renders_approval_body_with_settings_page() {
            let notice = Notice::ShortTokenEmail {
                token: "abc",
                valid_for: Duration::from_secs(600),
            };
            let rendered = notice
                .rendered(
                    get_strings(Locale::En),
                    Locale::En,
                    &test_handle(),
                    "nel.pet",
                )
                .unwrap();
            assert!(rendered.subject.contains("nel.pet"), "{}", rendered.subject);
            assert_eq!(code_line(&rendered.body), "abc");
            assert!(rendered.body.contains("https://nel.pet/app/settings"));
            assert!(!rendered.body.contains('{'), "{}", rendered.body);
            assert!(rendered.html_body.is_none());
        }

        #[test]
        fn email_update_confirmation_substitutes_verify_page_and_link() {
            let strings = get_strings(Locale::En);
            let body = strings
                .email_update_confirmation_body(
                    Locale::En,
                    &EmailUpdateConfirmationBody {
                        handle: &test_handle(),
                        code: "abc",
                        verify_page: "https://nel.pet/app/verify",
                        verify_link: "https://nel.pet/app/verify?token=abc&identifier=nel%40jola.dev",
                        valid_for: "10 minutes",
                    },
                )
                .unwrap();
            assert_eq!(code_line(&body), "abc");
            assert!(
                body.contains("https://nel.pet/app/verify?token=abc&identifier=nel%40jola.dev"),
                "{body}"
            );
            assert!(!body.contains('{'), "{body}");
        }

        #[test]
        fn migration_verification_substitutes_verify_page_and_link() {
            let strings = get_strings(Locale::En);
            let body = strings
                .migration_verification_body(
                    Locale::En,
                    &MigrationVerificationBody {
                        code: "abc",
                        hostname: "nel.pet",
                        verify_page: "https://nel.pet/app/verify",
                        verify_link: "https://nel.pet/app/verify?token=abc&identifier=nel",
                        valid_for: "48 hours",
                    },
                )
                .unwrap();
            assert_eq!(code_line(&body), "abc");
            assert!(body.contains("https://nel.pet/app/verify"), "{body}");
            assert!(
                body.contains("https://nel.pet/app/verify?token=abc&identifier=nel"),
                "{body}"
            );
            assert!(!body.contains('{'), "{body}");
        }

        #[test]
        fn signup_verification_substitutes_verify_page_and_link() {
            let strings = get_strings(Locale::En);
            let body = strings
                .signup_verification_body(
                    Locale::En,
                    &SignupVerificationBody {
                        code: "abc",
                        hostname: "nel.pet",
                        verify_page: "https://nel.pet/app/verify",
                        verify_link: "https://nel.pet/app/verify?token=abc&identifier=nel",
                        valid_for: "30 minutes",
                    },
                )
                .unwrap();
            assert_eq!(code_line(&body), "abc");
            assert!(body.contains("https://nel.pet/app/verify"), "{body}");
            assert!(
                body.contains("https://nel.pet/app/verify?token=abc&identifier=nel"),
                "{body}"
            );
            assert!(!body.contains('{'), "{body}");
        }

        #[test]
        fn channel_verification_substitutes_verify_link() {
            let strings = get_strings(Locale::En);
            let body = strings
                .channel_verification_body(
                    Locale::En,
                    &ChannelVerificationBody {
                        code: "abc",
                        verify_link: "https://nel.pet/app/verify?token=abc&identifier=nel",
                    },
                )
                .unwrap();
            assert_eq!(code_line(&body), "abc");
            assert!(
                body.contains("https://nel.pet/app/verify?token=abc&identifier=nel"),
                "{body}"
            );
            assert!(!body.contains('{'), "{body}");
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
