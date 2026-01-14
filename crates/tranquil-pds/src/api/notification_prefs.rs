use crate::api::error::ApiError;
use crate::auth::BearerAuth;
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::info;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationPrefsResponse {
    pub preferred_channel: String,
    pub email: String,
    pub discord_id: Option<String>,
    pub discord_verified: bool,
    pub telegram_username: Option<String>,
    pub telegram_verified: bool,
    pub signal_number: Option<String>,
    pub signal_verified: bool,
}

pub async fn get_notification_prefs(State(state): State<AppState>, auth: BearerAuth) -> Response {
    let user = auth.0;
    let prefs = match state.user_repo.get_notification_prefs(&user.did).await {
        Ok(Some(p)) => p,
        Ok(None) => return ApiError::AccountNotFound.into_response(),
        Err(e) => {
            return ApiError::InternalError(Some(format!("Database error: {}", e))).into_response();
        }
    };
    Json(NotificationPrefsResponse {
        preferred_channel: prefs.preferred_channel,
        email: prefs.email,
        discord_id: prefs.discord_id,
        discord_verified: prefs.discord_verified,
        telegram_username: prefs.telegram_username,
        telegram_verified: prefs.telegram_verified,
        signal_number: prefs.signal_number,
        signal_verified: prefs.signal_verified,
    })
    .into_response()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationHistoryEntry {
    pub created_at: String,
    pub channel: String,
    pub comms_type: String,
    pub status: String,
    pub subject: Option<String>,
    pub body: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetNotificationHistoryResponse {
    pub notifications: Vec<NotificationHistoryEntry>,
}

pub async fn get_notification_history(State(state): State<AppState>, auth: BearerAuth) -> Response {
    let user = auth.0;

    let user_id: uuid::Uuid = match state.user_repo.get_id_by_did(&user.did).await {
        Ok(Some(id)) => id,
        Ok(None) => return ApiError::AccountNotFound.into_response(),
        Err(e) => {
            return ApiError::InternalError(Some(format!("Database error: {}", e))).into_response();
        }
    };

    let rows = match state.infra_repo.get_notification_history(user_id, 50).await {
        Ok(r) => r,
        Err(e) => {
            return ApiError::InternalError(Some(format!("Database error: {}", e))).into_response();
        }
    };

    let sensitive_types = [
        "email_verification",
        "password_reset",
        "email_update",
        "two_factor_code",
        "passkey_recovery",
        "migration_verification",
        "plc_operation",
        "channel_verification",
        "signup_verification",
    ];

    let notifications = rows
        .iter()
        .map(|row| {
            let body = if sensitive_types.contains(&row.comms_type.as_str()) {
                "[Code redacted for security]".to_string()
            } else {
                row.body.clone()
            };
            NotificationHistoryEntry {
                created_at: row.created_at.to_rfc3339(),
                channel: row.channel.clone(),
                comms_type: row.comms_type.clone(),
                status: row.status.clone(),
                subject: row.subject.clone(),
                body,
            }
        })
        .collect();

    Json(GetNotificationHistoryResponse { notifications }).into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateNotificationPrefsInput {
    pub preferred_channel: Option<String>,
    pub email: Option<String>,
    pub discord_id: Option<String>,
    pub telegram_username: Option<String>,
    pub signal_number: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateNotificationPrefsResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub verification_required: Vec<String>,
}

pub async fn request_channel_verification(
    state: &AppState,
    user_id: uuid::Uuid,
    did: &str,
    channel: &str,
    identifier: &str,
    handle: Option<&str>,
) -> Result<String, String> {
    let token =
        crate::auth::verification_token::generate_channel_update_token(did, channel, identifier);
    let formatted_token = crate::auth::verification_token::format_token_for_display(&token);

    if channel == "email" {
        let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
        let handle_str = handle.unwrap_or("user");
        crate::comms::comms_repo::enqueue_email_update(
            state.infra_repo.as_ref(),
            user_id,
            identifier,
            handle_str,
            &formatted_token,
            &hostname,
        )
        .await
        .map_err(|e| format!("Failed to enqueue email notification: {}", e))?;
    } else {
        let comms_channel = match channel {
            "discord" => tranquil_db_traits::CommsChannel::Discord,
            "telegram" => tranquil_db_traits::CommsChannel::Telegram,
            "signal" => tranquil_db_traits::CommsChannel::Signal,
            _ => return Err("Invalid channel".to_string()),
        };
        state
            .infra_repo
            .enqueue_comms(
                Some(user_id),
                comms_channel,
                tranquil_db_traits::CommsType::ChannelVerification,
                identifier,
                Some("Verify your channel"),
                &format!("Your verification code is: {}", formatted_token),
                Some(json!({"code": formatted_token})),
            )
            .await
            .map_err(|e| format!("Failed to enqueue notification: {}", e))?;
    }

    Ok(token)
}

pub async fn update_notification_prefs(
    State(state): State<AppState>,
    auth: BearerAuth,
    Json(input): Json<UpdateNotificationPrefsInput>,
) -> Response {
    let user = auth.0;

    let user_row = match state
        .user_repo
        .get_id_handle_email_by_did(&user.did)
        .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return ApiError::AccountNotFound.into_response(),
        Err(e) => {
            return ApiError::InternalError(Some(format!("Database error: {}", e))).into_response();
        }
    };

    let user_id = user_row.id;
    let handle = user_row.handle;
    let current_email = user_row.email;

    let mut verification_required: Vec<String> = Vec::new();

    if let Some(ref channel) = input.preferred_channel {
        let valid_channels = ["email", "discord", "telegram", "signal"];
        if !valid_channels.contains(&channel.as_str()) {
            return ApiError::InvalidRequest(
                "Invalid channel. Must be one of: email, discord, telegram, signal".into(),
            )
            .into_response();
        }
        if let Err(e) = state
            .user_repo
            .update_preferred_comms_channel(&user.did, channel)
            .await
        {
            return ApiError::InternalError(Some(format!("Database error: {}", e))).into_response();
        }
        info!(did = %user.did, channel = %channel, "Updated preferred notification channel");
    }

    if let Some(ref new_email) = input.email {
        let email_clean = new_email.trim().to_lowercase();
        if email_clean.is_empty() {
            return ApiError::InvalidRequest("Email cannot be empty".into()).into_response();
        }

        if !crate::api::validation::is_valid_email(&email_clean) {
            return ApiError::InvalidEmail.into_response();
        }

        if current_email.as_ref().map(|e| e.to_lowercase()) == Some(email_clean.clone()) {
            info!(did = %user.did, "Email unchanged, skipping");
        } else {
            match state.user_repo.check_email_exists(&email_clean, user_id).await {
                Ok(true) => return ApiError::EmailTaken.into_response(),
                Err(e) => {
                    return ApiError::InternalError(Some(format!("Database error: {}", e)))
                        .into_response();
                }
                Ok(false) => {}
            }

            if let Err(e) = request_channel_verification(
                &state,
                user_id,
                &user.did,
                "email",
                &email_clean,
                Some(&handle),
            )
            .await
            {
                return ApiError::InternalError(Some(e)).into_response();
            }
            verification_required.push("email".to_string());
            info!(did = %user.did, "Requested email verification");
        }
    }

    if let Some(ref discord_id) = input.discord_id {
        if discord_id.is_empty() {
            if let Err(e) = state.user_repo.clear_discord(user_id).await {
                return ApiError::InternalError(Some(format!("Database error: {}", e)))
                    .into_response();
            }
            info!(did = %user.did, "Cleared Discord ID");
        } else {
            if let Err(e) =
                request_channel_verification(&state, user_id, &user.did, "discord", discord_id, None)
                    .await
            {
                return ApiError::InternalError(Some(e)).into_response();
            }
            verification_required.push("discord".to_string());
            info!(did = %user.did, "Requested Discord verification");
        }
    }

    if let Some(ref telegram) = input.telegram_username {
        let telegram_clean = telegram.trim_start_matches('@');
        if telegram_clean.is_empty() {
            if let Err(e) = state.user_repo.clear_telegram(user_id).await {
                return ApiError::InternalError(Some(format!("Database error: {}", e)))
                    .into_response();
            }
            info!(did = %user.did, "Cleared Telegram username");
        } else {
            if let Err(e) = request_channel_verification(
                &state,
                user_id,
                &user.did,
                "telegram",
                telegram_clean,
                None,
            )
            .await
            {
                return ApiError::InternalError(Some(e)).into_response();
            }
            verification_required.push("telegram".to_string());
            info!(did = %user.did, "Requested Telegram verification");
        }
    }

    if let Some(ref signal) = input.signal_number {
        if signal.is_empty() {
            if let Err(e) = state.user_repo.clear_signal(user_id).await {
                return ApiError::InternalError(Some(format!("Database error: {}", e)))
                    .into_response();
            }
            info!(did = %user.did, "Cleared Signal number");
        } else {
            if let Err(e) =
                request_channel_verification(&state, user_id, &user.did, "signal", signal, None)
                    .await
            {
                return ApiError::InternalError(Some(e)).into_response();
            }
            verification_required.push("signal".to_string());
            info!(did = %user.did, "Requested Signal verification");
        }
    }

    Json(UpdateNotificationPrefsResponse {
        success: true,
        verification_required,
    })
    .into_response()
}
