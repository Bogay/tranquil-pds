use crate::auth::validate_bearer_token;
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
use tracing::info;

fn generate_verification_code() -> String {
    rand::thread_rng()
        .sample_iter(&rand::distributions::Uniform::new(0, 10))
        .take(6)
        .map(|x| x.to_string())
        .collect()
}

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

pub async fn get_notification_prefs(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired", "message": "Authentication required"})),
        )
            .into_response(),
    };
    let user = match validate_bearer_token(&state.db, &token).await {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationFailed", "message": "Invalid token"})),
            )
                .into_response();
        }
    };
    let row =
        match sqlx::query(
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
        "#,
        )
        .bind(&user.did)
        .fetch_one(&state.db)
        .await
        {
            Ok(r) => r,
            Err(e) => return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({"error": "InternalError", "message": format!("Database error: {}", e)}),
                ),
            )
                .into_response(),
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationHistoryEntry {
    pub created_at: String,
    pub channel: String,
    pub notification_type: String,
    pub status: String,
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
    headers: HeaderMap,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired", "message": "Authentication required"})),
        )
            .into_response(),
    };
    let user = match validate_bearer_token(&state.db, &token).await {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationFailed", "message": "Invalid token"})),
            )
                .into_response();
        }
    };

    let user_id: uuid::Uuid = match sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", user.did)
        .fetch_one(&state.db)
        .await
    {
        Ok(id) => id,
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": format!("Database error: {}", e)})),
        )
            .into_response(),
    };

    let rows = match sqlx::query!(
        r#"
        SELECT
            created_at,
            channel as "channel: String",
            notification_type as "notification_type: String",
            status as "status: String",
            subject,
            body
        FROM notification_queue
        WHERE user_id = $1
        ORDER BY created_at DESC
        LIMIT 50
        "#,
        user_id
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(r) => r,
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": format!("Database error: {}", e)})),
        )
            .into_response(),
    };

    let notifications = rows.iter().map(|row| {
        NotificationHistoryEntry {
            created_at: row.created_at.to_rfc3339(),
            channel: row.channel.clone(),
            notification_type: row.notification_type.clone(),
            status: row.status.clone(),
            subject: row.subject.clone(),
            body: row.body.clone(),
        }
    }).collect();

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
    db: &sqlx::PgPool,
    user_id: uuid::Uuid,
    channel: &str,
    identifier: &str,
    handle: Option<&str>,
) -> Result<String, String> {
    let code = generate_verification_code();
    let expires_at = Utc::now() + Duration::minutes(10);

    sqlx::query!(
        r#"
        INSERT INTO channel_verifications (user_id, channel, code, pending_identifier, expires_at)
        VALUES ($1, $2::notification_channel, $3, $4, $5)
        ON CONFLICT (user_id, channel) DO UPDATE
        SET code = $3, pending_identifier = $4, expires_at = $5, created_at = NOW()
        "#,
        user_id,
        channel as _,
        code,
        identifier,
        expires_at
    )
    .execute(db)
    .await
    .map_err(|e| format!("Database error: {}", e))?;

    if channel == "email" {
        let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
        let handle_str = handle.unwrap_or("user");
        crate::notifications::enqueue_email_update(db, user_id, identifier, handle_str, &code, &hostname)
            .await
            .map_err(|e| format!("Failed to enqueue email notification: {}", e))?;
    } else {
        sqlx::query!(
            r#"
            INSERT INTO notification_queue (user_id, channel, notification_type, recipient, subject, body, metadata)
            VALUES ($1, $2::notification_channel, 'channel_verification', $3, 'Verify your channel', $4, $5)
            "#,
            user_id,
            channel as _,
            identifier,
            format!("Your verification code is: {}", code),
            json!({"code": code})
        )
        .execute(db)
        .await
        .map_err(|e| format!("Failed to enqueue notification: {}", e))?;
    }

    Ok(code)
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
        None => return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired", "message": "Authentication required"})),
        )
            .into_response(),
    };
    let user = match validate_bearer_token(&state.db, &token).await {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationFailed", "message": "Invalid token"})),
            )
                .into_response();
        }
    };

    let user_row = match sqlx::query!(
        "SELECT id, handle, email FROM users WHERE did = $1",
        user.did
    )
    .fetch_one(&state.db)
    .await
    {
        Ok(row) => row,
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": format!("Database error: {}", e)})),
        )
            .into_response(),
    };

    let user_id = user_row.id;
    let handle = user_row.handle;
    let current_email = user_row.email;

    let mut verification_required: Vec<String> = Vec::new();

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

    if let Some(ref new_email) = input.email {
        let email_clean = new_email.trim().to_lowercase();
        if email_clean.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidRequest", "message": "Email cannot be empty"})),
            )
                .into_response();
        }

        if !crate::api::validation::is_valid_email(&email_clean) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidEmail", "message": "Invalid email format"})),
            )
                .into_response();
        }

        if current_email.as_ref().map(|e| e.to_lowercase()) == Some(email_clean.clone()) {
            info!(did = %user.did, "Email unchanged, skipping");
        } else {
            let exists = sqlx::query!(
                "SELECT 1 as one FROM users WHERE LOWER(email) = $1 AND id != $2",
                email_clean,
                user_id
            )
            .fetch_optional(&state.db)
            .await;

            if let Ok(Some(_)) = exists {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "EmailTaken", "message": "Email already in use"})),
                )
                    .into_response();
            }

            if let Err(e) = request_channel_verification(&state.db, user_id, "email", &email_clean, Some(&handle)).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError", "message": e})),
                )
                    .into_response();
            }
            verification_required.push("email".to_string());
            info!(did = %user.did, "Requested email verification");
        }
    }

    if let Some(ref discord_id) = input.discord_id {
        if discord_id.is_empty() {
            if let Err(e) = sqlx::query!(
                "UPDATE users SET discord_id = NULL, discord_verified = FALSE, updated_at = NOW() WHERE id = $1",
                user_id
            )
            .execute(&state.db)
            .await
            {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError", "message": format!("Database error: {}", e)})),
                )
                    .into_response();
            }
            let _ = sqlx::query!(
                "DELETE FROM channel_verifications WHERE user_id = $1 AND channel = 'discord'",
                user_id
            )
            .execute(&state.db)
            .await;
            info!(did = %user.did, "Cleared Discord ID");
        } else {
            if let Err(e) = request_channel_verification(&state.db, user_id, "discord", discord_id, None).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError", "message": e})),
                )
                    .into_response();
            }
            verification_required.push("discord".to_string());
            info!(did = %user.did, "Requested Discord verification");
        }
    }

    if let Some(ref telegram) = input.telegram_username {
        let telegram_clean = telegram.trim_start_matches('@');
        if telegram_clean.is_empty() {
            if let Err(e) = sqlx::query!(
                "UPDATE users SET telegram_username = NULL, telegram_verified = FALSE, updated_at = NOW() WHERE id = $1",
                user_id
            )
            .execute(&state.db)
            .await
            {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError", "message": format!("Database error: {}", e)})),
                )
                    .into_response();
            }
            let _ = sqlx::query!(
                "DELETE FROM channel_verifications WHERE user_id = $1 AND channel = 'telegram'",
                user_id
            )
            .execute(&state.db)
            .await;
            info!(did = %user.did, "Cleared Telegram username");
        } else {
            if let Err(e) = request_channel_verification(&state.db, user_id, "telegram", telegram_clean, None).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError", "message": e})),
                )
                    .into_response();
            }
            verification_required.push("telegram".to_string());
            info!(did = %user.did, "Requested Telegram verification");
        }
    }

    if let Some(ref signal) = input.signal_number {
        if signal.is_empty() {
            if let Err(e) = sqlx::query!(
                "UPDATE users SET signal_number = NULL, signal_verified = FALSE, updated_at = NOW() WHERE id = $1",
                user_id
            )
            .execute(&state.db)
            .await
            {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError", "message": format!("Database error: {}", e)})),
                )
                    .into_response();
            }
            let _ = sqlx::query!(
                "DELETE FROM channel_verifications WHERE user_id = $1 AND channel = 'signal'",
                user_id
            )
            .execute(&state.db)
            .await;
            info!(did = %user.did, "Cleared Signal number");
        } else {
            if let Err(e) = request_channel_verification(&state.db, user_id, "signal", signal, None).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError", "message": e})),
                )
                    .into_response();
            }
            verification_required.push("signal".to_string());
            info!(did = %user.did, "Requested Signal verification");
        }
    }

    Json(UpdateNotificationPrefsResponse {
        success: true,
        verification_required,
    }).into_response()
}
