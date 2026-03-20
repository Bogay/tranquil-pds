use axum::{Json, extract::State};
use serde::Deserialize;
use tracing::warn;
use tranquil_pds::api::EmptyResponse;
use tranquil_pds::api::error::{ApiError, DbResultExt};
use tranquil_pds::auth::{Admin, Auth};
use tranquil_pds::state::AppState;
use tranquil_pds::types::Did;

#[derive(Deserialize)]
pub struct DeleteAccountInput {
    pub did: Did,
}

pub async fn delete_account(
    State(state): State<AppState>,
    _auth: Auth<Admin>,
    Json(input): Json<DeleteAccountInput>,
) -> Result<Json<EmptyResponse>, ApiError> {
    let did = &input.did;
    let (user_id, handle) = state
        .repos.user
        .get_id_and_handle_by_did(did)
        .await
        .log_db_err("in delete_account")?
        .ok_or(ApiError::AccountNotFound)
        .map(|row| (row.id, row.handle))?;

    state
        .repos.user
        .admin_delete_account_complete(user_id, did)
        .await
        .log_db_err("deleting account")?;

    if let Err(e) = tranquil_pds::repo_ops::sequence_account_event(
        &state,
        did,
        tranquil_db_traits::AccountStatus::Deleted,
    )
    .await
    {
        warn!(
            "Failed to sequence account deletion event for {}: {}",
            did, e
        );
    }
    let _ = state
        .cache
        .delete(&tranquil_pds::cache_keys::handle_key(&handle))
        .await;
    Ok(Json(EmptyResponse {}))
}
