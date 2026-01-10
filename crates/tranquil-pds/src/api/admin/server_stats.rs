use crate::auth::BearerAuthAdmin;
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerStatsResponse {
    pub user_count: i64,
    pub repo_count: i64,
    pub record_count: i64,
    pub blob_storage_bytes: i64,
}

pub async fn get_server_stats(State(state): State<AppState>, _auth: BearerAuthAdmin) -> Response {
    let user_count: i64 = match sqlx::query_scalar!("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await
    {
        Ok(Some(count)) => count,
        Ok(None) => 0,
        Err(_) => 0,
    };

    let repo_count: i64 = match sqlx::query_scalar!("SELECT COUNT(*) FROM repos")
        .fetch_one(&state.db)
        .await
    {
        Ok(Some(count)) => count,
        Ok(None) => 0,
        Err(_) => 0,
    };

    let record_count: i64 = match sqlx::query_scalar!("SELECT COUNT(*) FROM records")
        .fetch_one(&state.db)
        .await
    {
        Ok(Some(count)) => count,
        Ok(None) => 0,
        Err(_) => 0,
    };

    let blob_storage_bytes: i64 =
        match sqlx::query_scalar!("SELECT COALESCE(SUM(size_bytes), 0)::BIGINT FROM blobs")
            .fetch_one(&state.db)
            .await
        {
            Ok(Some(bytes)) => bytes,
            Ok(None) => 0,
            Err(_) => 0,
        };

    Json(ServerStatsResponse {
        user_count,
        repo_count,
        record_count,
        blob_storage_bytes,
    })
    .into_response()
}
