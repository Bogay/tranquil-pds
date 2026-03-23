use crate::common;
use axum::{
    Json,
    extract::{Query, State},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use tranquil_pds::state::AppState;
use tranquil_pds::types::AtIdentifier;

#[derive(Deserialize)]
pub struct DescribeRepoInput {
    pub repo: AtIdentifier,
}

pub async fn describe_repo(
    State(state): State<AppState>,
    Query(input): Query<DescribeRepoInput>,
) -> Response {
    let resolved = match common::resolve_repo(state.repos.user.as_ref(), &input.repo).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let collections = state
        .repos
        .repo
        .list_collections(resolved.user_id)
        .await
        .unwrap_or_default();
    let did_doc = json!({
        "id": resolved.did,
        "alsoKnownAs": [format!("at://{}", resolved.handle)]
    });
    Json(json!({
        "handle": resolved.handle,
        "did": resolved.did,
        "didDoc": did_doc,
        "collections": collections,
        "handleIsCorrect": true
    }))
    .into_response()
}
