use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use rand::Rng;
use serde::Deserialize;
use serde_json::json;
use tracing::{error, info, warn};

fn generate_confirmation_code() -> String {
    let mut rng = rand::thread_rng();
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz234567".chars().collect();
    let part1: String = (0..5).map(|_| chars[rng.gen_range(0..chars.len())]).collect();
    let part2: String = (0..5).map(|_| chars[rng.gen_range(0..chars.len())]).collect();
    format!("{}-{}", part1, part2)
}

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
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok())
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
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": e})),
            )
                .into_response();
        }
    };

    let user = match sqlx::query!("SELECT id, handle FROM users WHERE did = $1", did)
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

    let email = input.email.trim().to_lowercase();
    if email.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "email is required"})),
        )
            .into_response();
    }

    let exists = sqlx::query!("SELECT 1 as one FROM users WHERE LOWER(email) = $1", email)
        .fetch_optional(&state.db)
        .await;

    if let Ok(Some(_)) = exists {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "EmailTaken", "message": "Email already taken"})),
        )
            .into_response();
    }

    let code = generate_confirmation_code();
    let expires_at = Utc::now() + Duration::minutes(10);

    let update = sqlx::query!(
        "UPDATE users SET email_pending_verification = $1, email_confirmation_code = $2, email_confirmation_code_expires_at = $3 WHERE id = $4",
        email,
        code,
        expires_at,
        user_id
    )
    .execute(&state.db)
    .await;

    if let Err(e) = update {
        error!("DB error setting email update code: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    if let Err(e) = crate::notifications::enqueue_email_update(
        &state.db,
        user_id,
        &email,
        &handle,
        &code,
        &hostname,
    )
    .await
    {
        warn!("Failed to enqueue email update notification: {:?}", e);
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
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok())
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
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": e})),
            )
                .into_response();
        }
    };

    let user = match sqlx::query!(
        "SELECT id, email_confirmation_code, email_confirmation_code_expires_at, email_pending_verification FROM users WHERE did = $1",
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
    let stored_code = user.email_confirmation_code;
    let expires_at = user.email_confirmation_code_expires_at;
    let email_pending_verification = user.email_pending_verification;

    let email = input.email.trim().to_lowercase();
    let confirmation_code = input.token.trim();

    if email_pending_verification.is_none() || stored_code.is_none() || expires_at.is_none() {
         return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "No pending email update found"})),
        )
            .into_response();
    }

    let email_pending_verification = email_pending_verification.unwrap();
    if email_pending_verification != email {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "Email does not match pending update"})),
        )
            .into_response();
    }

    if stored_code.unwrap() != confirmation_code {
         return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidToken", "message": "Invalid token"})),
        )
            .into_response();
    }

    if Utc::now() > expires_at.unwrap() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "ExpiredToken", "message": "Token has expired"})),
        )
            .into_response();
    }

    let update = sqlx::query!(
        "UPDATE users SET email = $1, email_pending_verification = NULL, email_confirmation_code = NULL, email_confirmation_code_expires_at = NULL WHERE id = $2",
        email_pending_verification,
        user_id
    )
    .execute(&state.db)
    .await;

    if let Err(e) = update {
        error!("DB error finalizing email update: {:?}", e);
         if e.as_database_error().map(|db_err| db_err.is_unique_violation()).unwrap_or(false) {
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
        headers.get("Authorization").and_then(|h| h.to_str().ok())
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
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": e})),
            )
                .into_response();
        }
    };

    let user = match sqlx::query!(
        "SELECT id, email, email_confirmation_code, email_confirmation_code_expires_at, email_pending_verification FROM users WHERE did = $1",
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
    let stored_code = user.email_confirmation_code;
    let expires_at = user.email_confirmation_code_expires_at;
    let email_pending_verification = user.email_pending_verification;

    let new_email = input.email.trim().to_lowercase();
    if new_email.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "email is required"})),
        )
            .into_response();
    }

    if !new_email.contains('@') || !new_email.contains('.') {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "Invalid email format"})),
        )
            .into_response();
    }

    if new_email == current_email.to_lowercase() {
        return (StatusCode::OK, Json(json!({}))).into_response();
    }

    let email_confirmed = stored_code.is_some() && email_pending_verification.is_some();

    if email_confirmed {
        let confirmation_token = match &input.token {
            Some(t) => t.trim(),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "TokenRequired", "message": "Token required for confirmed accounts. Call requestEmailUpdate first."})),
                )
                    .into_response();
            }
        };

        let pending_email = email_pending_verification.unwrap();
        if pending_email.to_lowercase() != new_email {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidRequest", "message": "Email does not match pending update"})),
            )
                .into_response();
        }

        if stored_code.unwrap() != confirmation_token {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidToken", "message": "Invalid token"})),
            )
                .into_response();
        }

        if let Some(exp) = expires_at {
            if Utc::now() > exp {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "ExpiredToken", "message": "Token has expired"})),
                )
                    .into_response();
            }
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
        r#"
        UPDATE users
        SET email = $1,
            email_pending_verification = NULL,
            email_confirmation_code = NULL,
            email_confirmation_code_expires_at = NULL,
            updated_at = NOW()
        WHERE id = $2
        "#,
        new_email,
        user_id
    )
    .execute(&state.db)
    .await;

    match update {
        Ok(_) => {
            info!("Email updated to {} for user {}", new_email, user_id);
            (StatusCode::OK, Json(json!({}))).into_response()
        }
        Err(e) => {
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

            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}
