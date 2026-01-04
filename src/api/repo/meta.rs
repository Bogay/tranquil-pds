use crate::api::error::ApiError;
use crate::state::AppState;
use crate::types::AtIdentifier;
use axum::{
    Json,
    extract::{Query, State},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct DescribeRepoInput {
    pub repo: AtIdentifier,
}

pub async fn describe_repo(
    State(state): State<AppState>,
    Query(input): Query<DescribeRepoInput>,
) -> Response {
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let user_row = if input.repo.is_did() {
        sqlx::query!(
            "SELECT id, handle, did FROM users WHERE did = $1",
            input.repo.as_str()
        )
        .fetch_optional(&state.db)
        .await
        .map(|opt| opt.map(|r| (r.id, r.handle, r.did)))
    } else {
        let repo_str = input.repo.as_str();
        let handle = if !repo_str.contains('.') {
            format!("{}.{}", repo_str, hostname)
        } else {
            repo_str.to_string()
        };
        sqlx::query!(
            "SELECT id, handle, did FROM users WHERE handle = $1",
            handle
        )
        .fetch_optional(&state.db)
        .await
        .map(|opt| opt.map(|r| (r.id, r.handle, r.did)))
    };
    let (user_id, handle, did) = match user_row {
        Ok(Some((id, handle, did))) => (id, handle, did),
        Ok(None) => {
            return ApiError::RepoNotFound(Some("Repo not found".into())).into_response();
        }
        Err(_) => {
            return ApiError::InternalError(None).into_response();
        }
    };
    let collections_query = sqlx::query!(
        "SELECT DISTINCT collection FROM records WHERE repo_id = $1",
        user_id
    )
    .fetch_all(&state.db)
    .await;
    let collections: Vec<String> = match collections_query {
        Ok(rows) => rows.iter().map(|r| r.collection.clone()).collect(),
        Err(_) => Vec::new(),
    };
    let did_doc = json!({
        "id": did,
        "alsoKnownAs": [format!("at://{}", handle)]
    });
    Json(json!({
        "handle": handle,
        "did": did,
        "didDoc": did_doc,
        "collections": collections,
        "handleIsCorrect": true
    }))
    .into_response()
}
