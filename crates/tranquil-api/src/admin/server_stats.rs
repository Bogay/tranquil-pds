use axum::{Json, extract::State};
use serde::Serialize;
use tranquil_pds::api::error::ApiError;
use tranquil_pds::auth::{Admin, Auth};
use tranquil_pds::state::AppState;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerStatsOutput {
    pub user_count: i64,
    pub repo_count: i64,
    pub record_count: i64,
    pub blob_storage_bytes: i64,
}

pub async fn get_server_stats(
    State(state): State<AppState>,
    _auth: Auth<Admin>,
) -> Result<Json<ServerStatsOutput>, ApiError> {
    let user_count = state.user_repo.count_users().await.unwrap_or(0);
    let repo_count = state.repo_repo.count_repos().await.unwrap_or(0);
    let record_count = state.repo_repo.count_all_records().await.unwrap_or(0);
    let blob_storage_bytes = state.blob_repo.sum_blob_storage().await.unwrap_or(0);

    Ok(Json(ServerStatsOutput {
        user_count,
        repo_count,
        record_count,
        blob_storage_bytes,
    }))
}
