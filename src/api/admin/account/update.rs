use crate::auth::BearerAuthAdmin;
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use tracing::error;

#[derive(Deserialize)]
pub struct UpdateAccountEmailInput {
    pub account: String,
    pub email: String,
}

pub async fn update_account_email(
    State(state): State<AppState>,
    _auth: BearerAuthAdmin,
    Json(input): Json<UpdateAccountEmailInput>,
) -> Response {
    let account = input.account.trim();
    let email = input.email.trim();
    if account.is_empty() || email.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "account and email are required"})),
        )
            .into_response();
    }
    let result = sqlx::query!("UPDATE users SET email = $1 WHERE did = $2", email, account)
        .execute(&state.db)
        .await;
    match result {
        Ok(r) => {
            if r.rows_affected() == 0 {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "AccountNotFound", "message": "Account not found"})),
                )
                    .into_response();
            }
            (StatusCode::OK, Json(json!({}))).into_response()
        }
        Err(e) => {
            error!("DB error updating email: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct UpdateAccountHandleInput {
    pub did: String,
    pub handle: String,
}

pub async fn update_account_handle(
    State(state): State<AppState>,
    _auth: BearerAuthAdmin,
    Json(input): Json<UpdateAccountHandleInput>,
) -> Response {
    let did = input.did.trim();
    let input_handle = input.handle.trim();
    if did.is_empty() || input_handle.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "did and handle are required"})),
        )
            .into_response();
    }
    if !input_handle
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({"error": "InvalidHandle", "message": "Handle contains invalid characters"}),
            ),
        )
            .into_response();
    }
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let handle = if !input_handle.contains('.') {
        format!("{}.{}", input_handle, hostname)
    } else {
        input_handle.to_string()
    };
    let old_handle = sqlx::query_scalar!("SELECT handle FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    let existing = sqlx::query!(
        "SELECT id FROM users WHERE handle = $1 AND did != $2",
        handle,
        did
    )
    .fetch_optional(&state.db)
    .await;
    if let Ok(Some(_)) = existing {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "HandleTaken", "message": "Handle is already in use"})),
        )
            .into_response();
    }
    let result = sqlx::query!("UPDATE users SET handle = $1 WHERE did = $2", handle, did)
        .execute(&state.db)
        .await;
    match result {
        Ok(r) => {
            if r.rows_affected() == 0 {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "AccountNotFound", "message": "Account not found"})),
                )
                    .into_response();
            }
            if let Some(old) = old_handle {
                let _ = state.cache.delete(&format!("handle:{}", old)).await;
            }
            let _ = state.cache.delete(&format!("handle:{}", handle)).await;
            (StatusCode::OK, Json(json!({}))).into_response()
        }
        Err(e) => {
            error!("DB error updating handle: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct UpdateAccountPasswordInput {
    pub did: String,
    pub password: String,
}

pub async fn update_account_password(
    State(state): State<AppState>,
    _auth: BearerAuthAdmin,
    Json(input): Json<UpdateAccountPasswordInput>,
) -> Response {
    let did = input.did.trim();
    let password = input.password.trim();
    if did.is_empty() || password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "did and password are required"})),
        )
            .into_response();
    }
    let password_hash = match bcrypt::hash(password, bcrypt::DEFAULT_COST) {
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
    let result = sqlx::query!(
        "UPDATE users SET password_hash = $1 WHERE did = $2",
        password_hash,
        did
    )
    .execute(&state.db)
    .await;
    match result {
        Ok(r) => {
            if r.rows_affected() == 0 {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "AccountNotFound", "message": "Account not found"})),
                )
                    .into_response();
            }
            (StatusCode::OK, Json(json!({}))).into_response()
        }
        Err(e) => {
            error!("DB error updating password: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}
