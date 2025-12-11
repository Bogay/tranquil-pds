use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use bcrypt::{hash, DEFAULT_COST};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::json;
use tracing::{error, info, warn};

fn generate_reset_code() -> String {
    crate::util::generate_token_code()
}

#[derive(Deserialize)]
pub struct RequestPasswordResetInput {
    pub email: String,
}

pub async fn request_password_reset(
    State(state): State<AppState>,
    Json(input): Json<RequestPasswordResetInput>,
) -> Response {
    let email = input.email.trim().to_lowercase();
    if email.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "email is required"})),
        )
            .into_response();
    }

    let user = sqlx::query!("SELECT id FROM users WHERE LOWER(email) = $1", email)
        .fetch_optional(&state.db)
        .await;

    let user_id = match user {
        Ok(Some(row)) => row.id,
        Ok(None) => {
            info!("Password reset requested for unknown email");
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
    if let Err(e) =
        crate::notifications::enqueue_password_reset(&state.db, user_id, &code, &hostname).await
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
    Json(input): Json<ResetPasswordInput>,
) -> Response {
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
        "UPDATE users SET password_hash = $1, password_reset_code = NULL, password_reset_code_expires_at = NULL WHERE id = $2",
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

    if let Err(e) = sqlx::query!("DELETE FROM session_tokens WHERE did = (SELECT did FROM users WHERE id = $1)", user_id)
        .execute(&mut *tx)
        .await
    {
        error!("Failed to invalidate sessions after password reset: {:?}", e);
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

    info!("Password reset completed for user {}", user_id);

    (StatusCode::OK, Json(json!({}))).into_response()
}
