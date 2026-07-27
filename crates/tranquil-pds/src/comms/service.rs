use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;

use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use tranquil_comms::{
    CommsChannel, CommsMessageType, CommsSender, RenderedTemplate, SendError, TemplateId,
    render_template,
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

    pub enum Notice<'a> {
        Welcome {
            hostname: &'a str,
            handle: &'a str,
        },
        PasswordReset {
            hostname: &'a str,
            handle: &'a str,
            code: &'a str,
        },
        TwoFactorCode {
            hostname: &'a str,
            handle: &'a str,
            code: &'a str,
        },
        AccountDeletion {
            hostname: &'a str,
            handle: &'a str,
            code: &'a str,
        },
        PlcOperation {
            hostname: &'a str,
            handle: &'a str,
            token: &'a str,
        },
        PasskeyRecovery {
            hostname: &'a str,
            handle: &'a str,
            url: &'a str,
        },
        ShortTokenEmail {
            hostname: &'a str,
            handle: &'a str,
            code: &'a str,
            verify_page: &'a str,
            verify_link: &'a str,
        },
        LegacyLoginAlert {
            hostname: &'a str,
            handle: &'a str,
            timestamp: &'a str,
            ip: &'a str,
            channel: CommsChannel, // Used for logging purposes
        },
        EmailUpdate {
            hostname: &'a str,
            handle: &'a str,
            code: &'a str,
            verify_page: &'a str,
            verify_link: &'a str,
        },
        MigrationVerification {
            hostname: &'a str,
            handle: &'a str,
            code: &'a str,
            verify_page: &'a str,
            verify_link: &'a str,
        },
        SignupVerification {
            hostname: &'a str,
            handle: &'a str,
            code: &'a str,
            verify_page: &'a str,
            verify_link: &'a str,
        },
        ChannelVerification {
            hostname: &'a str,
            code: &'a str,
            verify_link: &'a str,
        },
        ChannelVerified {
            hostname: &'a str,
            handle: &'a str,
            channel: CommsChannel,
        },
    }

    impl Notice<'_> {
        fn comms_type(&self) -> CommsMessageType {
            match self {
                Self::Welcome { .. } => CommsMessageType::Welcome,
                Self::PasswordReset { .. } => CommsMessageType::PasswordReset,
                Self::TwoFactorCode { .. } => CommsMessageType::TwoFactorCode,
                Self::AccountDeletion { .. } => CommsMessageType::AccountDeletion,
                Self::PlcOperation { .. } => CommsMessageType::PlcOperation,
                Self::PasskeyRecovery { .. } => CommsMessageType::PasskeyRecovery,
                Self::ShortTokenEmail { .. } => CommsMessageType::EmailUpdate, // Unfortunate naming inconsistency, EmailUpdate is the correct name for this.
                Self::LegacyLoginAlert { .. } => CommsMessageType::LegacyLoginAlert,
                Self::EmailUpdate { .. } => CommsMessageType::EmailUpdate,
                Self::MigrationVerification { .. } => CommsMessageType::MigrationVerification,
                Self::SignupVerification { .. } => CommsMessageType::EmailVerification,
                Self::ChannelVerification { .. } => CommsMessageType::ChannelVerification,
                Self::ChannelVerified { .. } => CommsMessageType::ChannelVerified,
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

        fn rendered(&self, locale: &str) -> Result<RenderedTemplate, NotificationError> {
            let result = match self {
                Self::Welcome { hostname, handle } => render_template(
                    TemplateId::Welcome,
                    locale,
                    &[("hostname", hostname), ("handle", handle)],
                ),
                Self::PasswordReset {
                    hostname,
                    handle,
                    code,
                } => render_template(
                    TemplateId::PasswordReset,
                    locale,
                    &[("hostname", hostname), ("handle", handle), ("code", code)],
                ),
                Self::TwoFactorCode {
                    hostname,
                    handle,
                    code,
                } => render_template(
                    TemplateId::TwoFactorCode,
                    locale,
                    &[("hostname", hostname), ("handle", handle), ("code", code)],
                ),
                Self::AccountDeletion {
                    hostname,
                    handle,
                    code,
                } => render_template(
                    TemplateId::AccountDeletion,
                    locale,
                    &[("hostname", hostname), ("handle", handle), ("code", code)],
                ),
                Self::PlcOperation {
                    hostname,
                    handle,
                    token,
                } => render_template(
                    TemplateId::PlcOperation,
                    locale,
                    &[("hostname", hostname), ("handle", handle), ("token", token)],
                ),
                Self::PasskeyRecovery {
                    hostname,
                    handle,
                    url,
                } => render_template(
                    TemplateId::PasskeyRecovery,
                    locale,
                    &[("hostname", hostname), ("handle", handle), ("url", url)],
                ),
                Self::ShortTokenEmail {
                    hostname,
                    handle,
                    code,
                    verify_page,
                    verify_link,
                } => render_template(
                    TemplateId::EmailUpdate,
                    locale,
                    &[
                        ("hostname", hostname),
                        ("handle", handle),
                        ("code", code),
                        ("verify_page", verify_page),
                        ("verify_link", verify_link),
                    ],
                ),
                Self::LegacyLoginAlert {
                    #[allow(unused)]
                    channel,
                    hostname,
                    handle,
                    timestamp,
                    ip,
                } => render_template(
                    TemplateId::LegacyLogin,
                    locale,
                    &[
                        ("handle", handle),
                        ("timestamp", timestamp),
                        ("ip", ip),
                        ("hostname", hostname),
                    ],
                ),
                Self::EmailUpdate {
                    hostname,
                    handle,
                    code,
                    verify_page,
                    verify_link,
                } => render_template(
                    TemplateId::EmailUpdate,
                    locale,
                    &[
                        ("hostname", hostname),
                        ("handle", handle),
                        ("code", code),
                        ("verify_page", verify_page),
                        ("verify_link", verify_link),
                    ],
                ),
                Self::MigrationVerification {
                    hostname,
                    handle,
                    code,
                    verify_page,
                    verify_link,
                } => render_template(
                    TemplateId::MigrationVerification,
                    locale,
                    &[
                        ("hostname", hostname),
                        ("handle", handle),
                        ("code", code),
                        ("verify_page", verify_page),
                        ("verify_link", verify_link),
                    ],
                ),
                Self::SignupVerification {
                    hostname,
                    handle,
                    code,
                    verify_page,
                    verify_link,
                } => render_template(
                    TemplateId::SignupVerification,
                    locale,
                    &[
                        ("hostname", hostname),
                        ("handle", handle),
                        ("code", code),
                        ("verify_page", verify_page),
                        ("verify_link", verify_link),
                    ],
                ),
                Self::ChannelVerification {
                    hostname,
                    code,
                    verify_link,
                } => render_template(
                    TemplateId::ChannelVerification,
                    locale,
                    &[
                        ("hostname", hostname),
                        ("code", code),
                        ("verify_link", verify_link),
                    ],
                ),
                Self::ChannelVerified {
                    hostname,
                    handle,
                    channel,
                } => render_template(
                    TemplateId::ChannelVerified,
                    locale,
                    &[
                        ("hostname", hostname),
                        ("handle", handle),
                        ("channel", channel.display_name()),
                    ],
                ),
            };

            match result {
                Ok(template) => Ok(template),
                Err(e) => Err(NotificationError::TemplateRenderingError(e.to_string())),
            }
        }
    }

    pub async fn enqueue_notice(
        user_repo: &dyn UserRepository,
        infra_repo: &dyn InfraRepository,
        user_id: Uuid,
        notice: Notice<'_>,
    ) -> Result<Option<Uuid>, NotificationError> {
        // TODO extract this to a function
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
        let locale: &str = locale_of(&prefs);
        let rendered = notice.rendered(locale)?;
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

    fn locale_of(prefs: &UserCommsPrefs) -> &str {
        prefs.preferred_locale.as_deref().unwrap_or("en")
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
        let locale: &str = "en";
        let verify_page = format!("https://{hostname}/app/verify?type=email-update");
        let verify_link = format!(
            "https://{}/app/verify?type=email-update&token={}",
            hostname,
            urlencoding::encode(code)
        );
        let notice = Notice::EmailUpdate {
            hostname,
            handle: handle.as_str(),
            code,
            verify_page: &verify_page,
            verify_link: &verify_link,
        };
        let rendered = notice.rendered(locale)?;
        infra_repo
            .enqueue_comms(
                Some(user_id),
                &Recipient::Email(new_email.clone()),
                notice.comms_type(),
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
        let locale: &str = locale_of(&prefs);
        let verify_page = format!("https://{hostname}/app/verify");
        let verify_link = format!(
            "https://{}/app/verify?token={}&identifier={}",
            hostname,
            urlencoding::encode(token),
            urlencoding::encode(&target.id)
        );
        let notice = Notice::MigrationVerification {
            hostname,
            handle: target.recipient.as_str(),
            code: token,
            verify_page: &verify_page,
            verify_link: &verify_link,
        };
        let rendered = notice.rendered(locale)?;
        infra_repo
            .enqueue_comms(
                Some(user_id),
                &target.recipient,
                notice.comms_type(),
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
        let prefs = get_comms_prefs(user_repo, user_id).await?;
        let locale = locale_of(&prefs);
        let verify_page = format!("https://{hostname}/app/verify");
        let verify_link = format!(
            "https://{}/app/verify?token={}&identifier={}",
            hostname,
            urlencoding::encode(code),
            urlencoding::encode(&target.id)
        );
        let notice = Notice::SignupVerification {
            hostname,
            handle: target.recipient.as_str(),
            code,
            verify_page: &verify_page,
            verify_link: &verify_link,
        };
        let rendered = notice.rendered(locale)?;
        infra_repo
            .enqueue_comms(
                Some(user_id),
                &target.recipient,
                notice.comms_type(),
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
        let locale: &str = locale_of(&prefs);
        // TODO clean up identifier encoding within the rendering
        let encoded_token = urlencoding::encode(code);
        let encoded_id = urlencoding::encode(&target.id);
        let verify_link = format!(
            "https://{}/app/verify?token={}&identifier={}",
            hostname, encoded_token, encoded_id
        );
        let notice = Notice::ChannelVerification {
            hostname,
            code,
            verify_link: &verify_link,
        };
        let rendered = notice.rendered(locale)?;
        infra_repo
            .enqueue_comms(
                Some(user_id),
                &target.recipient,
                notice.comms_type(),
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
        channel: CommsChannel,
    ) -> Result<Uuid, NotificationError> {
        let prefs = get_comms_prefs(user_repo, user_id).await?;
        let locale: &str = locale_of(&prefs);
        let notice = Notice::ChannelVerified {
            hostname,
            handle: prefs.handle.as_str(),
            channel,
        };
        let rendered = notice.rendered(locale)?;
        infra_repo
            .enqueue_comms(
                Some(user_id),
                recipient,
                notice.comms_type(),
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
        channel: CommsChannel,
    ) {
        if let Err(e) =
            enqueue_channel_verified(user_repo, infra_repo, user_id, recipient, hostname, channel)
                .await
        {
            warn!(error = %e, "Failed to enqueue channel verified notification");
        }
    }

    #[cfg(test)]
    mod notice_render_tests {
        use super::Notice;

        fn builtins() {
            let _ = tranquil_comms::init_templates(&tranquil_config::CommsConfig {
                templates_dir: None,
                template_locales: Vec::new(),
                fallback_to_builtin: true,
            });
        }

        fn assert_page_and_link(body: &str, page: &str, link: &str) {
            assert!(body.contains(page), "{body}");
            assert!(body.contains(link), "{body}");
            assert!(!body.contains("{{"), "{body}");
        }

        #[test]
        fn email_update_substitutes_verify_page_and_link() {
            builtins();
            let page = "https://example.com/app/verify?type=email-update";
            let link = "https://example.com/app/verify?type=email-update&token=abc";
            let notice = Notice::EmailUpdate {
                hostname: "example.com",
                handle: "alice",
                code: "abc",
                verify_page: page,
                verify_link: link,
            };
            assert_page_and_link(&notice.rendered("en").unwrap().body, page, link);
            assert!(
                notice
                    .rendered("en")
                    .unwrap()
                    .subject
                    .contains("example.com")
            );
        }

        #[test]
        fn short_token_email_substitutes_verify_page_and_link() {
            builtins();
            let page = "https://example.com/app/verify?type=email-update";
            let link = "https://example.com/app/verify?type=email-update&token=abc";
            let notice = Notice::ShortTokenEmail {
                hostname: "example.com",
                handle: "alice",
                code: "abc",
                verify_page: page,
                verify_link: link,
            };
            assert_page_and_link(&notice.rendered("en").unwrap().body, page, link);
            assert!(notice.rendered("en").unwrap().body.contains("abc"));
        }

        #[test]
        fn migration_verification_substitutes_verify_page_and_link() {
            builtins();
            let page = "https://example.com/app/verify";
            let link = "https://example.com/app/verify?token=abc&identifier=user%40example.com";
            let notice = Notice::MigrationVerification {
                hostname: "example.com",
                handle: "alice",
                code: "abc",
                verify_page: page,
                verify_link: link,
            };
            let body = notice.rendered("en").unwrap().body;
            assert_page_and_link(&body, page, link);
            assert!(body.contains("example.com"));
            assert!(body.contains("abc"));
        }

        #[test]
        fn signup_verification_substitutes_verify_page_and_link() {
            builtins();
            let page = "https://example.com/app/verify";
            let link = "https://example.com/app/verify?token=abc&identifier=user%40example.com";
            let notice = Notice::SignupVerification {
                hostname: "example.com",
                handle: "alice",
                code: "abc",
                verify_page: page,
                verify_link: link,
            };
            let body = notice.rendered("en").unwrap().body;
            assert_page_and_link(&body, page, link);
            assert!(body.contains("example.com"));
            assert!(
                notice
                    .rendered("en")
                    .unwrap()
                    .subject
                    .contains("example.com")
            );
        }

        #[test]
        fn channel_verification_substitutes_verify_link() {
            builtins();
            let link = "https://example.com/app/verify?token=abc&identifier=user%40example.com";
            let notice = Notice::ChannelVerification {
                hostname: "example.com",
                code: "abc",
                verify_link: link,
            };
            let body = notice.rendered("en").unwrap().body;
            assert!(body.contains(link), "{body}");
            assert!(body.contains("abc"), "{body}");
            assert!(!body.contains("{{"), "{body}");
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
