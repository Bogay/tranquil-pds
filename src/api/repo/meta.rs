use crate::state::AppState;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct DescribeRepoInput {
    pub repo: String,
}

pub async fn describe_repo(
    State(state): State<AppState>,
    Query(input): Query<DescribeRepoInput>,
) -> Response {
    let user_row = if input.repo.starts_with("did:") {
        sqlx::query!(
            "SELECT id, handle, did FROM users WHERE did = $1",
            input.repo
        )
        .fetch_optional(&state.db)
        .await
        .map(|opt| opt.map(|r| (r.id, r.handle, r.did)))
    } else {
        sqlx::query!(
            "SELECT id, handle, did FROM users WHERE handle = $1",
            input.repo
        )
        .fetch_optional(&state.db)
        .await
        .map(|opt| opt.map(|r| (r.id, r.handle, r.did)))
    };
    let (user_id, handle, did) = match user_row {
        Ok(Some((id, handle, did))) => (id, handle, did),
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "RepoNotFound", "message": "Repo not found"})),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
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
