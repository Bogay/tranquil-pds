use crate::api::error::ApiError;
use crate::api::EmptyResponse;
use crate::auth::BearerAuthAdmin;
use crate::state::AppState;
use crate::types::Did;
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use tracing::{error, warn};

#[derive(Deserialize)]
pub struct DeleteAccountInput {
    pub did: Did,
}

pub async fn delete_account(
    State(state): State<AppState>,
    _auth: BearerAuthAdmin,
    Json(input): Json<DeleteAccountInput>,
) -> Response {
    let did = &input.did;
    let user = sqlx::query!("SELECT id, handle FROM users WHERE did = $1", did.as_str())
        .fetch_optional(&state.db)
        .await;
    let (user_id, handle) = match user {
        Ok(Some(row)) => (row.id, row.handle),
        Ok(None) => {
            return ApiError::AccountNotFound.into_response();
        }
        Err(e) => {
            error!("DB error in delete_account: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            error!("Failed to begin transaction for account deletion: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    if let Err(e) = sqlx::query!("DELETE FROM session_tokens WHERE did = $1", did.as_str())
        .execute(&mut *tx)
        .await
    {
        error!("Failed to delete session tokens for {}: {:?}", did, e);
        return ApiError::InternalError(Some("Failed to delete session tokens".into())).into_response();
    }
    if let Err(e) = sqlx::query!("DELETE FROM used_refresh_tokens WHERE session_id IN (SELECT id FROM session_tokens WHERE did = $1)", did.as_str())
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
        return ApiError::InternalError(Some("Failed to delete records".into())).into_response();
    }
    if let Err(e) = sqlx::query!("DELETE FROM repos WHERE user_id = $1", user_id)
        .execute(&mut *tx)
        .await
    {
        error!("Failed to delete repos for user {}: {:?}", user_id, e);
        return ApiError::InternalError(Some("Failed to delete repos".into())).into_response();
    }
    if let Err(e) = sqlx::query!("DELETE FROM blobs WHERE created_by_user = $1", user_id)
        .execute(&mut *tx)
        .await
    {
        error!("Failed to delete blobs for user {}: {:?}", user_id, e);
        return ApiError::InternalError(Some("Failed to delete blobs".into())).into_response();
    }
    if let Err(e) = sqlx::query!("DELETE FROM app_passwords WHERE user_id = $1", user_id)
        .execute(&mut *tx)
        .await
    {
        error!(
            "Failed to delete app passwords for user {}: {:?}",
            user_id, e
        );
        return ApiError::InternalError(Some("Failed to delete app passwords".into())).into_response();
    }
    if let Err(e) = sqlx::query!(
        "DELETE FROM invite_code_uses WHERE used_by_user = $1",
        user_id
    )
    .execute(&mut *tx)
    .await
    {
        error!(
            "Failed to delete invite code uses for user {}: {:?}",
            user_id, e
        );
    }
    if let Err(e) = sqlx::query!(
        "DELETE FROM invite_codes WHERE created_by_user = $1",
        user_id
    )
    .execute(&mut *tx)
    .await
    {
        error!(
            "Failed to delete invite codes for user {}: {:?}",
            user_id, e
        );
    }
    if let Err(e) = sqlx::query!("DELETE FROM user_keys WHERE user_id = $1", user_id)
        .execute(&mut *tx)
        .await
    {
        error!("Failed to delete user keys for user {}: {:?}", user_id, e);
        return ApiError::InternalError(Some("Failed to delete user keys".into())).into_response();
    }
    if let Err(e) = sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
        .execute(&mut *tx)
        .await
    {
        error!("Failed to delete user {}: {:?}", user_id, e);
        return ApiError::InternalError(Some("Failed to delete user".into())).into_response();
    }
    if let Err(e) = tx.commit().await {
        error!("Failed to commit account deletion transaction: {:?}", e);
        return ApiError::InternalError(Some("Failed to commit deletion".into())).into_response();
    }
    if let Err(e) =
        crate::api::repo::record::sequence_account_event(&state, did.as_str(), false, Some("deleted")).await
    {
        warn!(
            "Failed to sequence account deletion event for {}: {}",
            did, e
        );
    }
    let _ = state.cache.delete(&format!("handle:{}", handle)).await;
    EmptyResponse::ok().into_response()
}
