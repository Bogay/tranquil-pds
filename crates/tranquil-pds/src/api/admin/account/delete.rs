use crate::api::EmptyResponse;
use crate::api::error::ApiError;
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
    let (user_id, handle) = match state.user_repo.get_id_and_handle_by_did(did).await {
        Ok(Some(row)) => (row.id, row.handle),
        Ok(None) => {
            return ApiError::AccountNotFound.into_response();
        }
        Err(e) => {
            error!("DB error in delete_account: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    if let Err(e) = state
        .user_repo
        .admin_delete_account_complete(user_id, did)
        .await
    {
        error!("Failed to delete account {}: {:?}", did, e);
        return ApiError::InternalError(Some("Failed to delete account".into())).into_response();
    }
    if let Err(e) =
        crate::api::repo::record::sequence_account_event(&state, did, false, Some("deleted")).await
    {
        warn!(
            "Failed to sequence account deletion event for {}: {}",
            did, e
        );
    }
    let _ = state.cache.delete(&format!("handle:{}", handle)).await;
    EmptyResponse::ok().into_response()
}
