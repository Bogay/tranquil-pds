use crate::api::EmptyResponse;
use crate::api::error::ApiError;
use crate::auth::{Admin, Auth};
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
    _auth: Auth<Admin>,
    Json(input): Json<DeleteAccountInput>,
) -> Result<Response, ApiError> {
    let did = &input.did;
    let (user_id, handle) = state
        .user_repo
        .get_id_and_handle_by_did(did)
        .await
        .map_err(|e| {
            error!("DB error in delete_account: {:?}", e);
            ApiError::InternalError(None)
        })?
        .ok_or(ApiError::AccountNotFound)
        .map(|row| (row.id, row.handle))?;

    state
        .user_repo
        .admin_delete_account_complete(user_id, did)
        .await
        .map_err(|e| {
            error!("Failed to delete account {}: {:?}", did, e);
            ApiError::InternalError(Some("Failed to delete account".into()))
        })?;

    if let Err(e) =
        crate::api::repo::record::sequence_account_event(&state, did, false, Some("deleted")).await
    {
        warn!(
            "Failed to sequence account deletion event for {}: {}",
            did, e
        );
    }
    let _ = state.cache.delete(&format!("handle:{}", handle)).await;
    Ok(EmptyResponse::ok().into_response())
}
