use crate::api::ApiError;
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use bcrypt::verify;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{error, info, warn};
use uuid::Uuid;
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckAccountStatusOutput {
    pub activated: bool,
    pub valid_did: bool,
    pub repo_commit: String,
    pub repo_rev: String,
    pub repo_blocks: i64,
    pub indexed_records: i64,
    pub private_state_values: i64,
    pub expected_blobs: i64,
    pub imported_blobs: i64,
}
pub async fn check_account_status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok())
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };
    let did = match crate::auth::validate_bearer_token_allow_deactivated(&state.db, &token).await {
        Ok(user) => user.did,
        Err(e) => return ApiError::from(e).into_response(),
    };
    let user_id = match sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(id)) => id,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let user_status = sqlx::query!("SELECT deactivated_at FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await;
    let deactivated_at = match user_status {
        Ok(Some(row)) => row.deactivated_at,
        _ => None,
    };
    let repo_result = sqlx::query!("SELECT repo_root_cid FROM repos WHERE user_id = $1", user_id)
        .fetch_optional(&state.db)
        .await;
    let repo_commit = match repo_result {
        Ok(Some(row)) => row.repo_root_cid,
        _ => String::new(),
    };
    let record_count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM records WHERE repo_id = $1", user_id)
        .fetch_one(&state.db)
        .await
        .unwrap_or(Some(0))
        .unwrap_or(0);
    let blob_count: i64 =
        sqlx::query_scalar!("SELECT COUNT(*) FROM blobs WHERE created_by_user = $1", user_id)
            .fetch_one(&state.db)
            .await
            .unwrap_or(Some(0))
            .unwrap_or(0);
    let valid_did = did.starts_with("did:");
    (
        StatusCode::OK,
        Json(CheckAccountStatusOutput {
            activated: deactivated_at.is_none(),
            valid_did,
            repo_commit: repo_commit.clone(),
            repo_rev: chrono::Utc::now().timestamp_millis().to_string(),
            repo_blocks: 0,
            indexed_records: record_count,
            private_state_values: 0,
            expected_blobs: blob_count,
            imported_blobs: blob_count,
        }),
    )
        .into_response()
}
pub async fn activate_account(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok())
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };
    let did = match crate::auth::validate_bearer_token_allow_deactivated(&state.db, &token).await {
        Ok(user) => user.did,
        Err(e) => return ApiError::from(e).into_response(),
    };
    let handle = sqlx::query_scalar!("SELECT handle FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    let result = sqlx::query!("UPDATE users SET deactivated_at = NULL WHERE did = $1", did)
        .execute(&state.db)
        .await;
    match result {
        Ok(_) => {
            if let Some(h) = handle {
                let _ = state.cache.delete(&format!("handle:{}", h)).await;
            }
            (StatusCode::OK, Json(json!({}))).into_response()
        }
        Err(e) => {
            error!("DB error activating account: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeactivateAccountInput {
    pub delete_after: Option<String>,
}
pub async fn deactivate_account(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(_input): Json<DeactivateAccountInput>,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok())
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };
    let did = match crate::auth::validate_bearer_token(&state.db, &token).await {
        Ok(user) => user.did,
        Err(e) => return ApiError::from(e).into_response(),
    };
    let handle = sqlx::query_scalar!("SELECT handle FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    let result = sqlx::query!("UPDATE users SET deactivated_at = NOW() WHERE did = $1", did)
        .execute(&state.db)
        .await;
    match result {
        Ok(_) => {
            if let Some(h) = handle {
                let _ = state.cache.delete(&format!("handle:{}", h)).await;
            }
            (StatusCode::OK, Json(json!({}))).into_response()
        }
        Err(e) => {
            error!("DB error deactivating account: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}
pub async fn request_account_delete(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok())
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };
    let did = match crate::auth::validate_bearer_token_allow_deactivated(&state.db, &token).await {
        Ok(user) => user.did,
        Err(e) => return ApiError::from(e).into_response(),
    };
    let user_id = match sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(id)) => id,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let confirmation_token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::minutes(15);
    let insert = sqlx::query!(
        "INSERT INTO account_deletion_requests (token, did, expires_at) VALUES ($1, $2, $3)",
        confirmation_token,
        did,
        expires_at
    )
    .execute(&state.db)
    .await;
    if let Err(e) = insert {
        error!("DB error creating deletion token: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    if let Err(e) =
        crate::notifications::enqueue_account_deletion(&state.db, user_id, &confirmation_token, &hostname).await
    {
        warn!("Failed to enqueue account deletion notification: {:?}", e);
    }
    info!("Account deletion requested for user {}", did);
    (StatusCode::OK, Json(json!({}))).into_response()
}
#[derive(Deserialize)]
pub struct DeleteAccountInput {
    pub did: String,
    pub password: String,
    pub token: String,
}
pub async fn delete_account(
    State(state): State<AppState>,
    Json(input): Json<DeleteAccountInput>,
) -> Response {
    let did = input.did.trim();
    let password = &input.password;
    let token = input.token.trim();
    if did.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "did is required"})),
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
    if token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidToken", "message": "token is required"})),
        )
            .into_response();
    }
    let user = sqlx::query!(
        "SELECT id, password_hash, handle FROM users WHERE did = $1",
        did
    )
    .fetch_optional(&state.db)
    .await;
    let (user_id, password_hash, handle) = match user {
        Ok(Some(row)) => (row.id, row.password_hash, row.handle),
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "AccountNotFound", "message": "Account not found"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error in delete_account: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let password_valid = if verify(password, &password_hash).unwrap_or(false) {
        true
    } else {
        let app_pass_rows = sqlx::query!(
            "SELECT password_hash FROM app_passwords WHERE user_id = $1",
            user_id
        )
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();
        app_pass_rows
            .iter()
            .any(|row| verify(password, &row.password_hash).unwrap_or(false))
    };
    if !password_valid {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationFailed", "message": "Invalid password"})),
        )
            .into_response();
    }
    let deletion_request = sqlx::query!(
        "SELECT did, expires_at FROM account_deletion_requests WHERE token = $1",
        token
    )
    .fetch_optional(&state.db)
    .await;
    let (token_did, expires_at) = match deletion_request {
        Ok(Some(row)) => (row.did, row.expires_at),
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidToken", "message": "Invalid or expired token"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error fetching deletion token: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    if token_did != did {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidToken", "message": "Token does not match account"})),
        )
            .into_response();
    }
    if Utc::now() > expires_at {
        let _ = sqlx::query!("DELETE FROM account_deletion_requests WHERE token = $1", token)
            .execute(&state.db)
            .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "ExpiredToken", "message": "Token has expired"})),
        )
            .into_response();
    }
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
    let deletion_result: Result<(), sqlx::Error> = async {
        sqlx::query!("DELETE FROM session_tokens WHERE did = $1", did)
            .execute(&mut *tx)
            .await?;
        sqlx::query!("DELETE FROM records WHERE repo_id = $1", user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query!("DELETE FROM repos WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query!("DELETE FROM blobs WHERE created_by_user = $1", user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query!("DELETE FROM user_keys WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query!("DELETE FROM app_passwords WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query!("DELETE FROM account_deletion_requests WHERE did = $1", did)
            .execute(&mut *tx)
            .await?;
        sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
            .execute(&mut *tx)
            .await?;
        Ok(())
    }
    .await;
    match deletion_result {
        Ok(()) => {
            if let Err(e) = tx.commit().await {
                error!("Failed to commit account deletion transaction: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }
            let _ = state.cache.delete(&format!("handle:{}", handle)).await;
            info!("Account {} deleted successfully", did);
            (StatusCode::OK, Json(json!({}))).into_response()
        }
        Err(e) => {
            error!("DB error deleting account, rolling back: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}
