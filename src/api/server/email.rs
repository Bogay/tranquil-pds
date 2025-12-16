use crate::api::ApiError;
use crate::state::{AppState, RateLimitKind};
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use tracing::{error, info, warn};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestEmailUpdateInput {
    pub email: String,
}

pub async fn request_email_update(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<RequestEmailUpdateInput>,
) -> Response {
    let client_ip = crate::rate_limit::extract_client_ip(&headers, None);
    if !state
        .check_rate_limit(RateLimitKind::EmailUpdate, &client_ip)
        .await
    {
        warn!(ip = %client_ip, "Email update rate limit exceeded");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "RateLimitExceeded",
                "message": "Too many requests. Please try again later."
            })),
        )
            .into_response();
    }

    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationRequired"})),
            )
                .into_response();
        }
    };

    let auth_result = crate::auth::validate_bearer_token(&state.db, &token).await;
    let did = match auth_result {
        Ok(user) => user.did,
        Err(e) => return ApiError::from(e).into_response(),
    };

    let user = match sqlx::query!("SELECT id, handle, email FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(row)) => row,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let user_id = user.id;
    let handle = user.handle;
    let current_email = user.email;
    let email = input.email.trim().to_lowercase();

    if !crate::api::validation::is_valid_email(&email) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidEmail", "message": "Invalid email format"})),
        )
            .into_response();
    }

    if current_email.as_ref().map(|e| e.to_lowercase()) == Some(email.clone()) {
        return (StatusCode::OK, Json(json!({ "tokenRequired": false }))).into_response();
    }

    let exists = sqlx::query!(
        "SELECT 1 as one FROM users WHERE LOWER(email) = $1 AND id != $2",
        email,
        user_id
    )
    .fetch_optional(&state.db)
    .await;

    if let Ok(Some(_)) = exists {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "EmailTaken", "message": "Email already taken"})),
        )
            .into_response();
    }

    if let Err(e) = crate::api::notification_prefs::request_channel_verification(
        &state.db,
        user_id,
        "email",
        &email,
        Some(&handle),
    )
    .await
    {
        error!("Failed to request email verification: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    info!("Email update requested for user {}", user_id);
    (StatusCode::OK, Json(json!({ "tokenRequired": true }))).into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmEmailInput {
    pub email: String,
    pub token: String,
}

pub async fn confirm_email(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<ConfirmEmailInput>,
) -> Response {
    let client_ip = crate::rate_limit::extract_client_ip(&headers, None);
    if !state
        .check_rate_limit(RateLimitKind::AppPassword, &client_ip)
        .await
    {
        warn!(ip = %client_ip, "Confirm email rate limit exceeded");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "RateLimitExceeded",
                "message": "Too many requests. Please try again later."
            })),
        )
            .into_response();
    }

    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationRequired"})),
            )
                .into_response();
        }
    };

    let auth_result = crate::auth::validate_bearer_token(&state.db, &token).await;
    let did = match auth_result {
        Ok(user) => user.did,
        Err(e) => return ApiError::from(e).into_response(),
    };

    let user_id = match sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did)
        .fetch_one(&state.db)
        .await
    {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let verification = match sqlx::query!(
        "SELECT code, pending_identifier, expires_at FROM channel_verifications WHERE user_id = $1 AND channel = 'email'",
        user_id
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => row,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidRequest", "message": "No pending email update found"})),
            )
                .into_response();
        }
    };

    let pending_email = verification.pending_identifier.unwrap_or_default();
    let email = input.email.trim().to_lowercase();
    let confirmation_code = input.token.trim();

    if pending_email != email {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "Email does not match pending update"})),
        )
            .into_response();
    }

    if verification.code != confirmation_code {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidToken", "message": "Invalid token"})),
        )
            .into_response();
    }

    if Utc::now() > verification.expires_at {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "ExpiredToken", "message": "Token has expired"})),
        )
            .into_response();
    }

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(_) => return ApiError::InternalError.into_response(),
    };

    let update = sqlx::query!(
        "UPDATE users SET email = $1, updated_at = NOW() WHERE id = $2",
        pending_email,
        user_id
    )
    .execute(&mut *tx)
    .await;

    if let Err(e) = update {
        error!("DB error finalizing email update: {:?}", e);
        if e.as_database_error()
            .map(|db_err| db_err.is_unique_violation())
            .unwrap_or(false)
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "EmailTaken", "message": "Email already taken"})),
            )
                .into_response();
        }
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    if let Err(e) = sqlx::query!(
        "DELETE FROM channel_verifications WHERE user_id = $1 AND channel = 'email'",
        user_id
    )
    .execute(&mut *tx)
    .await
    {
        error!("Failed to delete verification record: {:?}", e);
        return ApiError::InternalError.into_response();
    }

    if let Err(_) = tx.commit().await {
        return ApiError::InternalError.into_response();
    }

    info!("Email updated for user {}", user_id);
    (StatusCode::OK, Json(json!({}))).into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateEmailInput {
    pub email: String,
    #[serde(default)]
    pub email_auth_factor: Option<bool>,
    pub token: Option<String>,
}

pub async fn update_email(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<UpdateEmailInput>,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationRequired"})),
            )
                .into_response();
        }
    };

    let auth_result = crate::auth::validate_bearer_token(&state.db, &token).await;
    let did = match auth_result {
        Ok(user) => user.did,
        Err(e) => return ApiError::from(e).into_response(),
    };

    let user = match sqlx::query!(
        "SELECT id, email FROM users WHERE did = $1",
        did
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => row,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let user_id = user.id;
    let current_email = user.email;
    let new_email = input.email.trim().to_lowercase();

    if !crate::api::validation::is_valid_email(&new_email) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidEmail", "message": "Invalid email format"})),
        )
            .into_response();
    }

    if let Some(ref current) = current_email
        && new_email == current.to_lowercase()
    {
        return (StatusCode::OK, Json(json!({}))).into_response();
    }

    let verification = sqlx::query!(
        "SELECT code, pending_identifier, expires_at FROM channel_verifications WHERE user_id = $1 AND channel = 'email'",
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    if let Some(ver) = verification {
        let confirmation_token = match &input.token {
            Some(t) => t.trim(),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "TokenRequired", "message": "Token required. Call requestEmailUpdate first."})),
                )
                    .into_response();
            }
        };

        let pending_email = ver.pending_identifier.unwrap_or_default();
        if pending_email.to_lowercase() != new_email {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidRequest", "message": "Email does not match pending update"})),
            )
                .into_response();
        }

        if ver.code != confirmation_token {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidToken", "message": "Invalid token"})),
            )
                .into_response();
        }

        if Utc::now() > ver.expires_at {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "ExpiredToken", "message": "Token has expired"})),
            )
                .into_response();
        }
    }

    let exists = sqlx::query!(
        "SELECT 1 as one FROM users WHERE LOWER(email) = $1 AND id != $2",
        new_email,
        user_id
    )
    .fetch_optional(&state.db)
    .await;

    if let Ok(Some(_)) = exists {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "Email already in use"})),
        )
            .into_response();
    }

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(_) => return ApiError::InternalError.into_response(),
    };

    let update = sqlx::query!(
        "UPDATE users SET email = $1, updated_at = NOW() WHERE id = $2",
        new_email,
        user_id
    )
    .execute(&mut *tx)
    .await;

    if let Err(e) = update {
        error!("DB error finalizing email update: {:?}", e);
        if e.as_database_error()
            .map(|db_err| db_err.is_unique_violation())
            .unwrap_or(false)
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidRequest", "message": "Email already in use"})),
            )
                .into_response();
        }
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    let _ = sqlx::query!(
        "DELETE FROM channel_verifications WHERE user_id = $1 AND channel = 'email'",
        user_id
    )
    .execute(&mut *tx)
    .await;

    if let Err(_) = tx.commit().await {
        return ApiError::InternalError.into_response();
    }

    match sqlx::query!(
        "INSERT INTO account_preferences (user_id, name, value_json) VALUES ($1, 'email_auth_factor', $2) ON CONFLICT (user_id, name) DO UPDATE SET value_json = $2",
        user_id,
        json!(input.email_auth_factor.unwrap_or(false))
    )
    .execute(&state.db)
    .await
    {
        Ok(_) => {}
        Err(e) => warn!("Failed to update email_auth_factor preference: {}", e),
    }

    info!("Email updated for user {}", user_id);
    (StatusCode::OK, Json(json!({}))).into_response()
}
