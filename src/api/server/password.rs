use crate::auth::BearerAuth;
use crate::state::{AppState, RateLimitKind};
use crate::validation::validate_password;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use bcrypt::{DEFAULT_COST, hash, verify};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::json;
use tracing::{error, info, warn};
use uuid::Uuid;

fn generate_reset_code() -> String {
    crate::util::generate_token_code()
}
fn extract_client_ip(headers: &HeaderMap) -> String {
    if let Some(forwarded) = headers.get("x-forwarded-for")
        && let Ok(value) = forwarded.to_str()
        && let Some(first_ip) = value.split(',').next()
    {
        return first_ip.trim().to_string();
    }
    if let Some(real_ip) = headers.get("x-real-ip")
        && let Ok(value) = real_ip.to_str()
    {
        return value.trim().to_string();
    }
    "unknown".to_string()
}

#[derive(Deserialize)]
pub struct RequestPasswordResetInput {
    #[serde(alias = "identifier")]
    pub email: String,
}

pub async fn request_password_reset(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<RequestPasswordResetInput>,
) -> Response {
    let client_ip = extract_client_ip(&headers);
    if !state
        .check_rate_limit(RateLimitKind::PasswordReset, &client_ip)
        .await
    {
        warn!(ip = %client_ip, "Password reset rate limit exceeded");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "RateLimitExceeded",
                "message": "Too many password reset requests. Please try again later."
            })),
        )
            .into_response();
    }
    let identifier = input.email.trim();
    if identifier.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "email or handle is required"})),
        )
            .into_response();
    }
    let pds_hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let normalized = identifier.to_lowercase();
    let normalized = normalized.strip_prefix('@').unwrap_or(&normalized);
    let normalized_handle = if normalized.contains('@') || normalized.contains('.') {
        normalized.to_string()
    } else {
        format!("{}.{}", normalized, pds_hostname)
    };
    let user = sqlx::query!(
        "SELECT id FROM users WHERE LOWER(email) = $1 OR handle = $2",
        normalized,
        normalized_handle
    )
    .fetch_optional(&state.db)
    .await;
    let user_id = match user {
        Ok(Some(row)) => row.id,
        Ok(None) => {
            info!("Password reset requested for unknown identifier");
            return (StatusCode::OK, Json(json!({}))).into_response();
        }
        Err(e) => {
            error!("DB error in request_password_reset: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let code = generate_reset_code();
    let expires_at = Utc::now() + Duration::minutes(10);
    let update = sqlx::query!(
        "UPDATE users SET password_reset_code = $1, password_reset_code_expires_at = $2 WHERE id = $3",
        code,
        expires_at,
        user_id
    )
    .execute(&state.db)
    .await;
    if let Err(e) = update {
        error!("DB error setting reset code: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    if let Err(e) = crate::comms::enqueue_password_reset(&state.db, user_id, &code, &hostname).await
    {
        warn!("Failed to enqueue password reset notification: {:?}", e);
    }
    info!("Password reset requested for user {}", user_id);
    (StatusCode::OK, Json(json!({}))).into_response()
}

#[derive(Deserialize)]
pub struct ResetPasswordInput {
    pub token: String,
    pub password: String,
}

pub async fn reset_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ResetPasswordInput>,
) -> Response {
    let client_ip = extract_client_ip(&headers);
    if !state
        .check_rate_limit(RateLimitKind::ResetPassword, &client_ip)
        .await
    {
        warn!(ip = %client_ip, "Reset password rate limit exceeded");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "RateLimitExceeded",
                "message": "Too many requests. Please try again later."
            })),
        )
            .into_response();
    }
    let token = input.token.trim();
    let password = &input.password;
    if token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidToken", "message": "token is required"})),
        )
            .into_response();
    }
    if password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "password is required"})),
        )
            .into_response();
    }
    if let Err(e) = validate_password(password) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "InvalidPassword",
                "message": e.to_string()
            })),
        )
            .into_response();
    }
    let user = sqlx::query!(
        "SELECT id, password_reset_code, password_reset_code_expires_at FROM users WHERE password_reset_code = $1",
        token
    )
    .fetch_optional(&state.db)
    .await;
    let (user_id, expires_at) = match user {
        Ok(Some(row)) => {
            let expires = row.password_reset_code_expires_at;
            (row.id, expires)
        }
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidToken", "message": "Invalid or expired token"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error in reset_password: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    if let Some(exp) = expires_at {
        if Utc::now() > exp {
            if let Err(e) = sqlx::query!(
                "UPDATE users SET password_reset_code = NULL, password_reset_code_expires_at = NULL WHERE id = $1",
                user_id
            )
            .execute(&state.db)
            .await
            {
                error!("Failed to clear expired reset code: {:?}", e);
            }
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "ExpiredToken", "message": "Token has expired"})),
            )
                .into_response();
        }
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidToken", "message": "Invalid or expired token"})),
        )
            .into_response();
    }
    let password_hash = match hash(password, DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to hash password: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            error!("Failed to begin transaction: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    if let Err(e) = sqlx::query!(
        "UPDATE users SET password_hash = $1, password_reset_code = NULL, password_reset_code_expires_at = NULL, password_required = TRUE WHERE id = $2",
        password_hash,
        user_id
    )
    .execute(&mut *tx)
    .await
    {
        error!("DB error updating password: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }
    let user_did = match sqlx::query_scalar!("SELECT did FROM users WHERE id = $1", user_id)
        .fetch_one(&mut *tx)
        .await
    {
        Ok(did) => did,
        Err(e) => {
            error!("Failed to get DID for user {}: {:?}", user_id, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let session_jtis: Vec<String> = match sqlx::query_scalar!(
        "SELECT access_jti FROM session_tokens WHERE did = $1",
        user_did
    )
    .fetch_all(&mut *tx)
    .await
    {
        Ok(jtis) => jtis,
        Err(e) => {
            error!("Failed to fetch session JTIs: {:?}", e);
            vec![]
        }
    };
    if let Err(e) = sqlx::query!("DELETE FROM session_tokens WHERE did = $1", user_did)
        .execute(&mut *tx)
        .await
    {
        error!(
            "Failed to invalidate sessions after password reset: {:?}",
            e
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }
    if let Err(e) = tx.commit().await {
        error!("Failed to commit password reset transaction: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }
    for jti in session_jtis {
        let cache_key = format!("auth:session:{}:{}", user_did, jti);
        if let Err(e) = state.cache.delete(&cache_key).await {
            warn!(
                "Failed to invalidate session cache for {}: {:?}",
                cache_key, e
            );
        }
    }
    info!("Password reset completed for user {}", user_id);
    (StatusCode::OK, Json(json!({}))).into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordInput {
    pub current_password: String,
    pub new_password: String,
}

pub async fn change_password(
    State(state): State<AppState>,
    auth: BearerAuth,
    Json(input): Json<ChangePasswordInput>,
) -> Response {
    if !crate::api::server::reauth::check_legacy_session_mfa(&state.db, &auth.0.did).await {
        return crate::api::server::reauth::legacy_mfa_required_response(&state.db, &auth.0.did)
            .await;
    }

    let current_password = &input.current_password;
    let new_password = &input.new_password;
    if current_password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "currentPassword is required"})),
        )
            .into_response();
    }
    if new_password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "newPassword is required"})),
        )
            .into_response();
    }
    if let Err(e) = validate_password(new_password) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "InvalidPassword",
                "message": e.to_string()
            })),
        )
            .into_response();
    }
    let user =
        sqlx::query_as::<_, (Uuid, String)>("SELECT id, password_hash FROM users WHERE did = $1")
            .bind(&auth.0.did)
            .fetch_optional(&state.db)
            .await;
    let (user_id, password_hash) = match user {
        Ok(Some(row)) => row,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "AccountNotFound", "message": "Account not found"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error in change_password: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let valid = match verify(current_password, &password_hash) {
        Ok(v) => v,
        Err(e) => {
            error!("Password verification error: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    if !valid {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "InvalidPassword", "message": "Current password is incorrect"})),
        )
            .into_response();
    }
    let new_hash = match hash(new_password, DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to hash password: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    if let Err(e) = sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
        .bind(&new_hash)
        .bind(user_id)
        .execute(&state.db)
        .await
    {
        error!("DB error updating password: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }
    info!(did = %auth.0.did, "Password changed successfully");
    (StatusCode::OK, Json(json!({}))).into_response()
}

pub async fn get_password_status(State(state): State<AppState>, auth: BearerAuth) -> Response {
    let user = sqlx::query!(
        "SELECT password_hash IS NOT NULL as has_password FROM users WHERE did = $1",
        auth.0.did
    )
    .fetch_optional(&state.db)
    .await;

    match user {
        Ok(Some(row)) => {
            Json(json!({"hasPassword": row.has_password.unwrap_or(false)})).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "AccountNotFound"})),
        )
            .into_response(),
        Err(e) => {
            error!("DB error: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

pub async fn remove_password(State(state): State<AppState>, auth: BearerAuth) -> Response {
    if !crate::api::server::reauth::check_legacy_session_mfa(&state.db, &auth.0.did).await {
        return crate::api::server::reauth::legacy_mfa_required_response(&state.db, &auth.0.did)
            .await;
    }

    if crate::api::server::reauth::check_reauth_required_cached(
        &state.db,
        &state.cache,
        &auth.0.did,
    )
    .await
    {
        return crate::api::server::reauth::reauth_required_response(&state.db, &auth.0.did).await;
    }

    let has_passkeys =
        crate::api::server::passkeys::has_passkeys_for_user_db(&state.db, &auth.0.did).await;
    if !has_passkeys {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "NoPasskeys",
                "message": "You must have at least one passkey registered before removing your password"
            })),
        )
            .into_response();
    }

    let user = sqlx::query!(
        "SELECT id, password_hash FROM users WHERE did = $1",
        auth.0.did
    )
    .fetch_optional(&state.db)
    .await;

    let user = match user {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "AccountNotFound"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    if user.password_hash.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "NoPassword",
                "message": "Account already has no password"
            })),
        )
            .into_response();
    }

    if let Err(e) = sqlx::query!(
        "UPDATE users SET password_hash = NULL, password_required = FALSE WHERE id = $1",
        user.id
    )
    .execute(&state.db)
    .await
    {
        error!("DB error removing password: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    info!(did = %auth.0.did, "Password removed - account is now passkey-only");
    (StatusCode::OK, Json(json!({"success": true}))).into_response()
}
