use crate::api::ApiError;
use crate::state::{AppState, RateLimitKind};
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
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
    let auth_user = match auth_result {
        Ok(user) => user,
        Err(e) => return ApiError::from(e).into_response(),
    };

    if let Err(e) = crate::auth::scope_check::check_account_scope(
        auth_user.is_oauth,
        auth_user.scope.as_deref(),
        crate::oauth::scopes::AccountAttr::Email,
        crate::oauth::scopes::AccountAction::Manage,
    ) {
        return e;
    }

    let did = auth_user.did.clone();
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
        &did,
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
    let auth_user = match auth_result {
        Ok(user) => user,
        Err(e) => return ApiError::from(e).into_response(),
    };

    if let Err(e) = crate::auth::scope_check::check_account_scope(
        auth_user.is_oauth,
        auth_user.scope.as_deref(),
        crate::oauth::scopes::AccountAttr::Email,
        crate::oauth::scopes::AccountAction::Manage,
    ) {
        return e;
    }

    let did = auth_user.did;
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

    let email = input.email.trim().to_lowercase();
    let confirmation_code =
        crate::auth::verification_token::normalize_token_input(input.token.trim());

    let verified = crate::auth::verification_token::verify_channel_update_token(
        &confirmation_code,
        "email",
        &email,
    );

    match verified {
        Ok(token_data) => {
            if token_data.did != did {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(
                        json!({"error": "InvalidToken", "message": "Token does not match account"}),
                    ),
                )
                    .into_response();
            }
        }
        Err(crate::auth::verification_token::VerifyError::Expired) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "ExpiredToken", "message": "Token has expired"})),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidToken", "message": "Invalid token"})),
            )
                .into_response();
        }
    }

    let update = sqlx::query!(
        "UPDATE users SET email = $1, email_verified = TRUE, updated_at = NOW() WHERE id = $2",
        email,
        user_id
    )
    .execute(&state.db)
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
    let auth_user = match auth_result {
        Ok(user) => user,
        Err(e) => return ApiError::from(e).into_response(),
    };

    if let Err(e) = crate::auth::scope_check::check_account_scope(
        auth_user.is_oauth,
        auth_user.scope.as_deref(),
        crate::oauth::scopes::AccountAttr::Email,
        crate::oauth::scopes::AccountAction::Manage,
    ) {
        return e;
    }

    let did = auth_user.did;
    let user = match sqlx::query!("SELECT id, email FROM users WHERE did = $1", did)
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

    let confirmation_token = match &input.token {
        Some(t) => crate::auth::verification_token::normalize_token_input(t.trim()),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "TokenRequired", "message": "Token required. Call requestEmailUpdate first."})),
            )
                .into_response();
        }
    };

    let verified = crate::auth::verification_token::verify_channel_update_token(
        &confirmation_token,
        "email",
        &new_email,
    );

    match verified {
        Ok(token_data) => {
            if token_data.did != did {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(
                        json!({"error": "InvalidToken", "message": "Token does not match account"}),
                    ),
                )
                    .into_response();
            }
        }
        Err(crate::auth::verification_token::VerifyError::Expired) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "ExpiredToken", "message": "Token has expired"})),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidToken", "message": "Invalid token"})),
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

    let update = sqlx::query!(
        "UPDATE users SET email = $1, email_verified = TRUE, updated_at = NOW() WHERE id = $2",
        new_email,
        user_id
    )
    .execute(&state.db)
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
