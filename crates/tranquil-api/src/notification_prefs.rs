use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::info;
use tranquil_db_traits::{CommsChannel, CommsStatus, CommsType};
use tranquil_pds::api::error::{ApiError, DbResultExt};
use tranquil_pds::auth::{Active, Auth};
use tranquil_pds::state::AppState;
use tranquil_types::{Did, Handle};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationPrefsOutput {
    pub preferred_channel: CommsChannel,
    pub email: String,
    pub discord_username: Option<String>,
    pub discord_verified: bool,
    pub telegram_username: Option<String>,
    pub telegram_verified: bool,
    pub signal_username: Option<String>,
    pub signal_verified: bool,
    pub legacy_login_alerts: bool,
}

pub async fn get_notification_prefs(
    State(state): State<AppState>,
    auth: Auth<Active>,
) -> Result<Json<NotificationPrefsOutput>, ApiError> {
    let prefs = state
        .repos
        .user
        .get_notification_prefs(&auth.did)
        .await
        .log_db_err("get notification prefs")?
        .ok_or(ApiError::AccountNotFound)?;

    let user_id = state
        .repos
        .user
        .get_id_by_did(&auth.did)
        .await
        .log_db_err("get user by did")?
        .ok_or(ApiError::AccountNotFound)?;

    let legacy_login_alerts = state
        .repos
        .infra
        .get_account_preferences(user_id)
        .await
        .log_db_err("get legacy login alert prefs")?
        .iter()
        .find(|(name, _)| name == "legacy_login_alerts")
        .and_then(|(_, value)| value.as_bool())
        .unwrap_or(true);

    Ok(Json(NotificationPrefsOutput {
        preferred_channel: prefs.preferred_channel,
        email: prefs.email,
        discord_username: prefs.discord_username,
        discord_verified: prefs.discord_verified,
        telegram_username: prefs.telegram_username,
        telegram_verified: prefs.telegram_verified,
        signal_username: prefs.signal_username,
        signal_verified: prefs.signal_verified,
        legacy_login_alerts,
    }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationHistoryEntry {
    pub created_at: String,
    pub channel: CommsChannel,
    pub comms_type: CommsType,
    pub status: CommsStatus,
    pub subject: Option<String>,
    pub body: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetNotificationHistoryOutput {
    pub notifications: Vec<NotificationHistoryEntry>,
}

pub async fn get_notification_history(
    State(state): State<AppState>,
    auth: Auth<Active>,
) -> Result<Json<GetNotificationHistoryOutput>, ApiError> {
    let user_id = state
        .repos
        .user
        .get_id_by_did(&auth.did)
        .await
        .log_db_err("get user id by did")?
        .ok_or(ApiError::AccountNotFound)?;

    let rows = state
        .repos
        .infra
        .get_notification_history(user_id, 50)
        .await
        .log_db_err("get notification history")?;

    let sensitive_types = [
        CommsType::EmailVerification,
        CommsType::PasswordReset,
        CommsType::EmailUpdate,
        CommsType::TwoFactorCode,
        CommsType::PasskeyRecovery,
        CommsType::MigrationVerification,
        CommsType::PlcOperation,
        CommsType::ChannelVerification,
    ];

    let notifications = rows
        .iter()
        .map(|row| {
            let body = if sensitive_types.contains(&row.comms_type) {
                "[Code redacted for security]".to_string()
            } else {
                row.body.clone()
            };
            NotificationHistoryEntry {
                created_at: row.created_at.to_rfc3339(),
                channel: row.channel,
                comms_type: row.comms_type,
                status: row.status,
                subject: row.subject.clone(),
                body,
            }
        })
        .collect();

    Ok(Json(GetNotificationHistoryOutput { notifications }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateNotificationPrefsInput {
    pub preferred_channel: Option<String>,
    pub email: Option<String>,
    pub discord_username: Option<String>,
    pub telegram_username: Option<String>,
    pub signal_username: Option<String>,
    pub legacy_login_alerts: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateNotificationPrefsOutput {
    pub success: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub verification_required: Vec<CommsChannel>,
}

pub async fn request_channel_verification(
    state: &AppState,
    user_id: uuid::Uuid,
    did: &Did,
    channel: CommsChannel,
    id: &str,
    handle: Option<&Handle>,
) -> Result<String, ApiError> {
    if channel.verifies_via_bot() {
        return Err(ApiError::InvalidRequest(
            "This channel verifies through a bot. Please message the bot first so that it's able to reply with useful info".into(),
        ));
    }
    let token =
        tranquil_pds::auth::verification_token::generate_channel_update_token(did, channel, id);
    let formatted_token = tranquil_pds::auth::verification_token::format_token_for_display(&token);

    match channel {
        CommsChannel::Email => {
            let hostname = &tranquil_config::get().server.hostname;
            let handle = handle.ok_or_else(|| {
                ApiError::InternalError(Some("Email verification requires a handle".into()))
            })?;
            let new_email = tranquil_types::EmailAddress::new(id)?;
            tranquil_pds::comms::comms_repo::enqueue_email_update(
                state.repos.infra.as_ref(),
                user_id,
                &new_email,
                handle,
                &formatted_token,
                hostname,
            )
            .await
            .log_db_err("enqueue email verification")?;
        }
        _ => {
            let hostname = &tranquil_config::get().server.hostname;
            let encoded_token = urlencoding::encode(&formatted_token);
            let encoded_id = urlencoding::encode(id);
            let verify_link = format!(
                "https://{}/app/verify?token={}&identifier={}",
                hostname, encoded_token, encoded_id
            );
            let prefs = state
                .repos
                .user
                .get_comms_prefs(user_id)
                .await
                .ok()
                .flatten();
            let locale = prefs
                .as_ref()
                .and_then(|p| p.preferred_locale.as_deref())
                .unwrap_or("en");
            let strings = tranquil_pds::comms::get_strings(locale);
            let body = tranquil_pds::comms::format_message(
                strings.channel_verification_body,
                &[("code", &formatted_token), ("verify_link", &verify_link)],
            );
            let subject = tranquil_pds::comms::format_message(
                strings.channel_verification_subject,
                &[("hostname", hostname)],
            );
            let recipient = tranquil_db_traits::Recipient::new(channel, id)?;
            state
                .repos
                .infra
                .enqueue_comms(
                    Some(user_id),
                    &recipient,
                    tranquil_db_traits::CommsType::ChannelVerification,
                    Some(&subject),
                    &body,
                    Some(json!({"code": formatted_token})),
                )
                .await
                .log_db_err("enqueue channel verification")?;
        }
    }

    Ok(token)
}

async fn process_messaging_channel_update(
    state: &AppState,
    user_id: uuid::Uuid,
    did: &Did,
    channel: CommsChannel,
    raw_value: &str,
    effective_channel: CommsChannel,
    verification_required: &mut Vec<CommsChannel>,
) -> Result<(), ApiError> {
    if raw_value.trim().is_empty() {
        if effective_channel == channel {
            return Err(ApiError::InvalidRequest(format!(
                "Cannot remove {:?} while it is the preferred notification channel",
                channel
            )));
        }
        match channel {
            CommsChannel::Discord => state
                .repos
                .user
                .clear_discord(user_id)
                .await
                .log_db_err("clear discord")?,
            CommsChannel::Telegram => state
                .repos
                .user
                .clear_telegram(user_id)
                .await
                .log_db_err("clear telegram")?,
            CommsChannel::Signal => state
                .repos
                .user
                .clear_signal(user_id)
                .await
                .log_db_err("clear signal")?,
            CommsChannel::Email => {}
        };
        info!(did = %did, channel = ?channel, "Cleared channel");
        return Ok(());
    }

    let clean = match channel {
        CommsChannel::Discord => tranquil_types::DiscordUsername::new(raw_value)?.to_string(),
        CommsChannel::Telegram => tranquil_types::TelegramUsername::new(raw_value)?.to_string(),
        CommsChannel::Signal => tranquil_types::SignalUsername::new(raw_value)?.to_string(),
        CommsChannel::Email => tranquil_types::EmailAddress::new(raw_value)?.to_string(),
    };

    match channel {
        CommsChannel::Discord => state
            .repos
            .user
            .set_unverified_discord(user_id, &clean)
            .await
            .log_db_err("set unverified discord")?,
        CommsChannel::Telegram => state
            .repos
            .user
            .set_unverified_telegram(user_id, &clean)
            .await
            .log_db_err("set unverified telegram")?,
        CommsChannel::Signal => state
            .repos
            .user
            .set_unverified_signal(user_id, &clean)
            .await
            .log_db_err("set unverified signal")?,
        CommsChannel::Email => {}
    };

    if matches!(channel, CommsChannel::Signal) {
        request_channel_verification(state, user_id, did, channel, &clean, None).await?;
    }

    verification_required.push(channel);
    info!(did = %did, channel = ?channel, value = %clean, "Stored unverified channel username");
    Ok(())
}

pub async fn update_notification_prefs(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<UpdateNotificationPrefsInput>,
) -> Result<Json<UpdateNotificationPrefsOutput>, ApiError> {
    let user_row = state
        .repos
        .user
        .get_id_handle_email_by_did(&auth.did)
        .await
        .log_db_err("get user by did")?
        .ok_or(ApiError::AccountNotFound)?;

    let user_id = user_row.id;
    let handle = user_row.handle;
    let current_email = user_row.email;

    let current_prefs = state
        .repos
        .user
        .get_notification_prefs(&auth.did)
        .await
        .log_db_err("get notification prefs for update")?
        .ok_or(ApiError::AccountNotFound)?;

    let effective_channel = input
        .preferred_channel
        .as_deref()
        .map(|ch| {
            ch.parse::<CommsChannel>().map_err(|_| {
                ApiError::InvalidRequest(
                    "Invalid channel. Must be one of: email, discord, telegram, signal".into(),
                )
            })
        })
        .transpose()?
        .unwrap_or(current_prefs.preferred_channel);

    let mut verification_required: Vec<CommsChannel> = Vec::new();

    if input.preferred_channel.is_some() {
        state
            .repos
            .user
            .update_preferred_comms_channel(&auth.did, effective_channel)
            .await
            .log_db_err("update preferred channel")?;
        info!(did = %auth.did, channel = ?effective_channel, "Updated preferred notification channel");
    }

    if let Some(new_email) = &input.email {
        let email = tranquil_types::EmailAddress::new(new_email).map_err(|_| {
            if new_email.trim().is_empty() {
                ApiError::InvalidRequest("Email can't be empty".into())
            } else {
                ApiError::InvalidEmail
            }
        })?;

        if !current_email
            .as_deref()
            .is_some_and(|e| e.eq_ignore_ascii_case(email.as_str()))
        {
            request_channel_verification(
                &state,
                user_id,
                &auth.did,
                CommsChannel::Email,
                email.as_str(),
                Some(&handle),
            )
            .await?;
            verification_required.push(CommsChannel::Email);
            info!(did = %auth.did, "Requested email verification");
        }
    }

    if let Some(ref discord_username) = input.discord_username {
        process_messaging_channel_update(
            &state,
            user_id,
            &auth.did,
            CommsChannel::Discord,
            discord_username,
            effective_channel,
            &mut verification_required,
        )
        .await?;
    }

    if let Some(ref telegram) = input.telegram_username {
        process_messaging_channel_update(
            &state,
            user_id,
            &auth.did,
            CommsChannel::Telegram,
            telegram,
            effective_channel,
            &mut verification_required,
        )
        .await?;
    }

    if let Some(ref signal) = input.signal_username {
        process_messaging_channel_update(
            &state,
            user_id,
            &auth.did,
            CommsChannel::Signal,
            signal,
            effective_channel,
            &mut verification_required,
        )
        .await?;
    }

    if let Some(alerts) = input.legacy_login_alerts {
        state
            .repos
            .infra
            .upsert_account_preference(user_id, "legacy_login_alerts", json!(alerts))
            .await
            .log_db_err("update legacy login alert prefs")?;
    }

    Ok(Json(UpdateNotificationPrefsOutput {
        success: true,
        verification_required,
    }))
}
