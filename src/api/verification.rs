use crate::auth::validate_bearer_token;
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use tracing::{error, info};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmChannelVerificationInput {
    pub channel: String,
    pub code: String,
}

pub async fn confirm_channel_verification(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ConfirmChannelVerificationInput>,
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

    let user_id = match sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", user.did)
        .fetch_one(&state.db)
        .await
    {
        Ok(id) => id,
        Err(_) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": "User not found"})),
        )
            .into_response(),
    };

    let channel_str = input.channel.as_str();
    if !["email", "discord", "telegram", "signal"].contains(&channel_str) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "Invalid channel"})),
        )
            .into_response();
    }

    let record = match sqlx::query!(
        r#"
        SELECT code, pending_identifier, expires_at FROM channel_verifications
        WHERE user_id = $1 AND channel = $2::notification_channel
        "#,
        user_id,
        channel_str as _
    )
    .fetch_optional(&state.db)
    .await {
        Ok(Some(r)) => r,
        Ok(None) => return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "No pending verification found. Update notification preferences first."})),
        )
            .into_response(),
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": format!("Database error: {}", e)})),
        )
            .into_response(),
    };

    let pending_identifier = match record.pending_identifier {
        Some(p) => p,
        None => return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "No pending identifier found"})),
        )
            .into_response(),
    };

    if record.expires_at < Utc::now() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "ExpiredToken", "message": "Verification code expired"})),
        )
            .into_response();
    }

    if record.code != input.code {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidCode", "message": "Invalid verification code"})),
        )
            .into_response();
    }

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(_) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response(),
    };

    let update_result = match channel_str {
        "email" => sqlx::query!(
            "UPDATE users SET email = $1, updated_at = NOW() WHERE id = $2",
            pending_identifier,
            user_id
        ).execute(&mut *tx).await,
        "discord" => sqlx::query!(
            "UPDATE users SET discord_id = $1, discord_verified = TRUE, updated_at = NOW() WHERE id = $2",
            pending_identifier,
            user_id
        ).execute(&mut *tx).await,
        "telegram" => sqlx::query!(
            "UPDATE users SET telegram_username = $1, telegram_verified = TRUE, updated_at = NOW() WHERE id = $2",
            pending_identifier,
            user_id
        ).execute(&mut *tx).await,
        "signal" => sqlx::query!(
            "UPDATE users SET signal_number = $1, signal_verified = TRUE, updated_at = NOW() WHERE id = $2",
            pending_identifier,
            user_id
        ).execute(&mut *tx).await,
        _ => unreachable!(),
    };

    if let Err(e) = update_result {
        error!("Failed to update user channel: {:?}", e);
        if channel_str == "email" && e.as_database_error().map(|db| db.is_unique_violation()).unwrap_or(false) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "EmailTaken", "message": "Email already in use"})),
            )
                .into_response();
        }
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": "Failed to update channel"})),
        )
            .into_response();
    }

    if let Err(e) = sqlx::query!(
        "DELETE FROM channel_verifications WHERE user_id = $1 AND channel = $2::notification_channel",
        user_id,
        channel_str as _
    )
    .execute(&mut *tx)
    .await {
        error!("Failed to delete verification record: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    if let Err(_) = tx.commit().await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    info!(did = %user.did, channel = %channel_str, "Channel verified successfully");

    Json(json!({"success": true})).into_response()
}
