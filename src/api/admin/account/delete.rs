use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use tracing::{error, warn};
#[derive(Deserialize)]
pub struct DeleteAccountInput {
    pub did: String,
}
pub async fn delete_account(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<DeleteAccountInput>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }
    let did = input.did.trim();
    if did.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "did is required"})),
        )
            .into_response();
    }
    let user = sqlx::query!("SELECT id, handle FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await;
    let (user_id, handle) = match user {
        Ok(Some(row)) => (row.id, row.handle),
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
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
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            error!("Failed to begin transaction for account deletion: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    if let Err(e) = sqlx::query!("DELETE FROM session_tokens WHERE did = $1", did)
        .execute(&mut *tx)
        .await
    {
        error!("Failed to delete session tokens for {}: {:?}", did, e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": "Failed to delete session tokens"})),
        )
            .into_response();
    }
    if let Err(e) = sqlx::query!("DELETE FROM used_refresh_tokens WHERE session_id IN (SELECT id FROM session_tokens WHERE did = $1)", did)
        .execute(&mut *tx)
        .await
    {
        error!("Failed to delete used refresh tokens for {}: {:?}", did, e);
    }
    if let Err(e) = sqlx::query!("DELETE FROM records WHERE repo_id = $1", user_id)
        .execute(&mut *tx)
        .await
    {
        error!("Failed to delete records for user {}: {:?}", user_id, e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": "Failed to delete records"})),
        )
            .into_response();
    }
    if let Err(e) = sqlx::query!("DELETE FROM repos WHERE user_id = $1", user_id)
        .execute(&mut *tx)
        .await
    {
        error!("Failed to delete repos for user {}: {:?}", user_id, e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": "Failed to delete repos"})),
        )
            .into_response();
    }
    if let Err(e) = sqlx::query!("DELETE FROM blobs WHERE created_by_user = $1", user_id)
        .execute(&mut *tx)
        .await
    {
        error!("Failed to delete blobs for user {}: {:?}", user_id, e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": "Failed to delete blobs"})),
        )
            .into_response();
    }
    if let Err(e) = sqlx::query!("DELETE FROM app_passwords WHERE user_id = $1", user_id)
        .execute(&mut *tx)
        .await
    {
        error!("Failed to delete app passwords for user {}: {:?}", user_id, e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": "Failed to delete app passwords"})),
        )
            .into_response();
    }
    if let Err(e) = sqlx::query!("DELETE FROM invite_code_uses WHERE used_by_user = $1", user_id)
        .execute(&mut *tx)
        .await
    {
        error!("Failed to delete invite code uses for user {}: {:?}", user_id, e);
    }
    if let Err(e) = sqlx::query!("DELETE FROM invite_codes WHERE created_by_user = $1", user_id)
        .execute(&mut *tx)
        .await
    {
        error!("Failed to delete invite codes for user {}: {:?}", user_id, e);
    }
    if let Err(e) = sqlx::query!("DELETE FROM user_keys WHERE user_id = $1", user_id)
        .execute(&mut *tx)
        .await
    {
        error!("Failed to delete user keys for user {}: {:?}", user_id, e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": "Failed to delete user keys"})),
        )
            .into_response();
    }
    if let Err(e) = sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
        .execute(&mut *tx)
        .await
    {
        error!("Failed to delete user {}: {:?}", user_id, e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": "Failed to delete user"})),
        )
            .into_response();
    }
    if let Err(e) = tx.commit().await {
        error!("Failed to commit account deletion transaction: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": "Failed to commit deletion"})),
        )
            .into_response();
    }
    if let Err(e) = crate::api::repo::record::sequence_account_event(&state, did, false, Some("deleted")).await {
        warn!("Failed to sequence account deletion event for {}: {}", did, e);
    }
    let _ = state.cache.delete(&format!("handle:{}", handle)).await;
    (StatusCode::OK, Json(json!({}))).into_response()
}
