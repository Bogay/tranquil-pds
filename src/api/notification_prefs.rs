use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
use tracing::info;
use crate::auth::validate_bearer_token;
use crate::state::AppState;

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

pub async fn get_notification_prefs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationRequired", "message": "Authentication required"})),
            )
                .into_response()
        }
    };
    let user = match validate_bearer_token(&state.db, &token).await {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationFailed", "message": "Invalid token"})),
            )
                .into_response()
        }
    };
    let row = match sqlx::query(
        r#"
        SELECT
            email,
            preferred_notification_channel::text as channel,
            discord_id,
            discord_verified,
            telegram_username,
            telegram_verified,
            signal_number,
            signal_verified
        FROM users
        WHERE did = $1
        "#
    )
    .bind(&user.did)
    .fetch_one(&state.db)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": format!("Database error: {}", e)})),
            )
                .into_response()
        }
    };
    let email: String = row.get("email");
    let channel: String = row.get("channel");
    let discord_id: Option<String> = row.get("discord_id");
    let discord_verified: bool = row.get("discord_verified");
    let telegram_username: Option<String> = row.get("telegram_username");
    let telegram_verified: bool = row.get("telegram_verified");
    let signal_number: Option<String> = row.get("signal_number");
    let signal_verified: bool = row.get("signal_verified");
    Json(NotificationPrefsResponse {
        preferred_channel: channel,
        email,
        discord_id,
        discord_verified,
        telegram_username,
        telegram_verified,
        signal_number,
        signal_verified,
    })
    .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateNotificationPrefsInput {
    pub preferred_channel: Option<String>,
    pub discord_id: Option<String>,
    pub telegram_username: Option<String>,
    pub signal_number: Option<String>,
}

pub async fn update_notification_prefs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<UpdateNotificationPrefsInput>,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationRequired", "message": "Authentication required"})),
            )
                .into_response()
        }
    };
    let user = match validate_bearer_token(&state.db, &token).await {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationFailed", "message": "Invalid token"})),
            )
                .into_response()
        }
    };
    if let Some(ref channel) = input.preferred_channel {
        let valid_channels = ["email", "discord", "telegram", "signal"];
        if !valid_channels.contains(&channel.as_str()) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "InvalidRequest",
                    "message": "Invalid channel. Must be one of: email, discord, telegram, signal"
                })),
            )
                .into_response();
        }
        if let Err(e) = sqlx::query(
            r#"UPDATE users SET preferred_notification_channel = $1::notification_channel, updated_at = NOW() WHERE did = $2"#
        )
        .bind(channel)
        .bind(&user.did)
        .execute(&state.db)
        .await
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": format!("Database error: {}", e)})),
            )
                .into_response();
        }
        info!(did = %user.did, channel = %channel, "Updated preferred notification channel");
    }
    if let Some(ref discord_id) = input.discord_id {
        let discord_id_clean: Option<&str> = if discord_id.is_empty() {
            None
        } else {
            Some(discord_id.as_str())
        };
        if let Err(e) = sqlx::query(
            r#"UPDATE users SET discord_id = $1, discord_verified = FALSE, updated_at = NOW() WHERE did = $2"#
        )
        .bind(discord_id_clean)
        .bind(&user.did)
        .execute(&state.db)
        .await
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": format!("Database error: {}", e)})),
            )
                .into_response();
        }
        info!(did = %user.did, "Updated Discord ID");
    }
    if let Some(ref telegram) = input.telegram_username {
        let telegram_clean: Option<&str> = if telegram.is_empty() {
            None
        } else {
            Some(telegram.trim_start_matches('@'))
        };
        if let Err(e) = sqlx::query(
            r#"UPDATE users SET telegram_username = $1, telegram_verified = FALSE, updated_at = NOW() WHERE did = $2"#
        )
        .bind(telegram_clean)
        .bind(&user.did)
        .execute(&state.db)
        .await
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": format!("Database error: {}", e)})),
            )
                .into_response();
        }
        info!(did = %user.did, "Updated Telegram username");
    }
    if let Some(ref signal) = input.signal_number {
        let signal_clean: Option<&str> = if signal.is_empty() { None } else { Some(signal.as_str()) };
        if let Err(e) = sqlx::query(
            r#"UPDATE users SET signal_number = $1, signal_verified = FALSE, updated_at = NOW() WHERE did = $2"#
        )
        .bind(signal_clean)
        .bind(&user.did)
        .execute(&state.db)
        .await
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": format!("Database error: {}", e)})),
            )
                .into_response();
        }
        info!(did = %user.did, "Updated Signal number");
    }
    Json(json!({"success": true})).into_response()
}
