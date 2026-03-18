use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::info;
use tranquil_db_traits::{CommsChannel, CommsStatus, CommsType};
use tranquil_pds::api::error::ApiError;
use tranquil_pds::auth::{Active, Auth};
use tranquil_pds::state::AppState;
use tranquil_types::Did;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationPrefsResponse {
    pub preferred_channel: CommsChannel,
    pub email: String,
    pub discord_username: Option<String>,
    pub discord_verified: bool,
    pub telegram_username: Option<String>,
    pub telegram_verified: bool,
    pub signal_username: Option<String>,
    pub signal_verified: bool,
}

pub async fn get_notification_prefs(
    State(state): State<AppState>,
    auth: Auth<Active>,
) -> Result<Response, ApiError> {
    let prefs = state
        .user_repo
        .get_notification_prefs(&auth.did)
        .await
        .map_err(|e| ApiError::InternalError(Some(format!("Database error: {}", e))))?
        .ok_or(ApiError::AccountNotFound)?;
    Ok(Json(NotificationPrefsResponse {
        preferred_channel: prefs.preferred_channel,
        email: prefs.email,
        discord_username: prefs.discord_username,
        discord_verified: prefs.discord_verified,
        telegram_username: prefs.telegram_username,
        telegram_verified: prefs.telegram_verified,
        signal_username: prefs.signal_username,
        signal_verified: prefs.signal_verified,
    })
    .into_response())
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
pub struct GetNotificationHistoryResponse {
    pub notifications: Vec<NotificationHistoryEntry>,
}

pub async fn get_notification_history(
    State(state): State<AppState>,
    auth: Auth<Active>,
) -> Result<Response, ApiError> {
    let user_id = state
        .user_repo
        .get_id_by_did(&auth.did)
        .await
        .map_err(|e| ApiError::InternalError(Some(format!("Database error: {}", e))))?
        .ok_or(ApiError::AccountNotFound)?;

    let rows = state
        .infra_repo
        .get_notification_history(user_id, 50)
        .await
        .map_err(|e| ApiError::InternalError(Some(format!("Database error: {}", e))))?;

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

    Ok(Json(GetNotificationHistoryResponse { notifications }).into_response())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateNotificationPrefsInput {
    pub preferred_channel: Option<String>,
    pub email: Option<String>,
    pub discord_username: Option<String>,
    pub telegram_username: Option<String>,
    pub signal_username: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateNotificationPrefsResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub verification_required: Vec<CommsChannel>,
}

pub async fn request_channel_verification(
    state: &AppState,
    user_id: uuid::Uuid,
    did: &Did,
    channel: CommsChannel,
    identifier: &str,
    handle: Option<&str>,
) -> Result<String, ApiError> {
    let token = tranquil_pds::auth::verification_token::generate_channel_update_token(
        did, channel, identifier,
    );
    let formatted_token = tranquil_pds::auth::verification_token::format_token_for_display(&token);

    match channel {
        CommsChannel::Email => {
            let hostname = &tranquil_config::get().server.hostname;
            let handle_str = handle.unwrap_or("user");
            tranquil_pds::comms::comms_repo::enqueue_email_update(
                state.infra_repo.as_ref(),
                user_id,
                identifier,
                handle_str,
                &formatted_token,
                hostname,
            )
            .await
            .map_err(|e| {
                ApiError::InternalError(Some(format!(
                    "Failed to enqueue email notification: {}",
                    e
                )))
            })?;
        }
        _ => {
            let hostname = &tranquil_config::get().server.hostname;
            let encoded_token = urlencoding::encode(&formatted_token);
            let encoded_identifier = urlencoding::encode(identifier);
            let verify_link = format!(
                "https://{}/app/verify?token={}&identifier={}",
                hostname, encoded_token, encoded_identifier
            );
            let prefs = state
                .user_repo
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
            let recipient = match channel {
                CommsChannel::Telegram => state
                    .user_repo
                    .get_telegram_chat_id(user_id)
                    .await
                    .ok()
                    .flatten()
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| identifier.to_string()),
                _ => identifier.to_string(),
            };
            state
                .infra_repo
                .enqueue_comms(
                    Some(user_id),
                    channel,
                    tranquil_db_traits::CommsType::ChannelVerification,
                    &recipient,
                    Some(&subject),
                    &body,
                    Some(json!({"code": formatted_token})),
                )
                .await
                .map_err(|e| {
                    ApiError::InternalError(Some(format!("Failed to enqueue notification: {}", e)))
                })?;
        }
    }

    Ok(token)
}

pub async fn update_notification_prefs(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<UpdateNotificationPrefsInput>,
) -> Result<Response, ApiError> {
    let user_row = state
        .user_repo
        .get_id_handle_email_by_did(&auth.did)
        .await
        .map_err(|e| ApiError::InternalError(Some(format!("Database error: {}", e))))?
        .ok_or(ApiError::AccountNotFound)?;

    let user_id = user_row.id;
    let handle = user_row.handle;
    let current_email = user_row.email;

    let current_prefs = state
        .user_repo
        .get_notification_prefs(&auth.did)
        .await
        .map_err(|e| ApiError::InternalError(Some(format!("Database error: {}", e))))?
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
            .user_repo
            .update_preferred_comms_channel(&auth.did, effective_channel)
            .await
            .map_err(|e| ApiError::InternalError(Some(format!("Database error: {}", e))))?;
        info!(did = %auth.did, channel = ?effective_channel, "Updated preferred notification channel");
    }

    if let Some(ref new_email) = input.email {
        let email_clean = new_email.trim().to_lowercase();
        if email_clean.is_empty() {
            return Err(ApiError::InvalidRequest("Email cannot be empty".into()));
        }

        if !tranquil_pds::api::validation::is_valid_email(&email_clean) {
            return Err(ApiError::InvalidEmail);
        }

        if current_email.as_ref().map(|e| e.to_lowercase()) != Some(email_clean.clone()) {
            request_channel_verification(
                &state,
                user_id,
                &auth.did,
                CommsChannel::Email,
                &email_clean,
                Some(&handle),
            )
            .await?;
            verification_required.push(CommsChannel::Email);
            info!(did = %auth.did, "Requested email verification");
        }
    }

    if let Some(ref discord_username) = input.discord_username {
        let discord_clean = discord_username.trim().to_lowercase();
        if discord_clean.is_empty() {
            if effective_channel == CommsChannel::Discord {
                return Err(ApiError::InvalidRequest(
                    "Cannot remove Discord while it is the preferred notification channel".into(),
                ));
            }
            state
                .user_repo
                .clear_discord(user_id)
                .await
                .map_err(|e| ApiError::InternalError(Some(format!("Database error: {}", e))))?;
            info!(did = %auth.did, "Cleared Discord");
        } else if !tranquil_pds::api::validation::is_valid_discord_username(&discord_clean) {
            return Err(ApiError::InvalidRequest(
                "Invalid Discord username. Must be 2-32 lowercase characters (letters, numbers, underscores, periods)"
                    .into(),
            ));
        } else {
            state
                .user_repo
                .set_unverified_discord(user_id, &discord_clean)
                .await
                .map_err(|e| ApiError::InternalError(Some(format!("Database error: {}", e))))?;
            verification_required.push(CommsChannel::Discord);
            info!(did = %auth.did, discord_username = %discord_clean, "Stored unverified Discord username");
        }
    }

    if let Some(ref telegram) = input.telegram_username {
        let telegram_clean = telegram.trim_start_matches('@');
        if telegram_clean.is_empty() {
            if effective_channel == CommsChannel::Telegram {
                return Err(ApiError::InvalidRequest(
                    "Cannot remove Telegram while it is the preferred notification channel".into(),
                ));
            }
            state
                .user_repo
                .clear_telegram(user_id)
                .await
                .map_err(|e| ApiError::InternalError(Some(format!("Database error: {}", e))))?;
            info!(did = %auth.did, "Cleared Telegram username");
        } else if !tranquil_pds::api::validation::is_valid_telegram_username(telegram_clean) {
            return Err(ApiError::InvalidRequest(
                "Invalid Telegram username. Must be 5-32 characters, alphanumeric or underscore"
                    .into(),
            ));
        } else {
            state
                .user_repo
                .set_unverified_telegram(user_id, telegram_clean)
                .await
                .map_err(|e| ApiError::InternalError(Some(format!("Database error: {}", e))))?;
            verification_required.push(CommsChannel::Telegram);
            info!(did = %auth.did, telegram_username = %telegram_clean, "Stored unverified Telegram username");
        }
    }

    if let Some(ref signal) = input.signal_username {
        let signal_clean = signal.trim().trim_start_matches('@').to_lowercase();
        if signal_clean.is_empty() {
            if effective_channel == CommsChannel::Signal {
                return Err(ApiError::InvalidRequest(
                    "Cannot remove Signal while it is the preferred notification channel".into(),
                ));
            }
            state
                .user_repo
                .clear_signal(user_id)
                .await
                .map_err(|e| ApiError::InternalError(Some(format!("Database error: {}", e))))?;
            info!(did = %auth.did, "Cleared Signal username");
        } else if !tranquil_pds::comms::is_valid_signal_username(&signal_clean) {
            return Err(ApiError::InvalidRequest(
                "Invalid Signal username. Must be 3-32 characters followed by .XX (e.g. username.01)"
                    .into(),
            ));
        } else {
            state
                .user_repo
                .set_unverified_signal(user_id, &signal_clean)
                .await
                .map_err(|e| ApiError::InternalError(Some(format!("Database error: {}", e))))?;
            request_channel_verification(
                &state,
                user_id,
                &auth.did,
                CommsChannel::Signal,
                &signal_clean,
                None,
            )
            .await?;
            verification_required.push(CommsChannel::Signal);
            info!(did = %auth.did, signal_username = %signal_clean, "Stored unverified Signal username");
        }
    }

    Ok(Json(UpdateNotificationPrefsResponse {
        success: true,
        verification_required,
    })
    .into_response())
}
