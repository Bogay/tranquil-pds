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
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());

    let user_row = if input.repo.starts_with("did:") {
        sqlx::query!("SELECT id, handle, did FROM users WHERE did = $1", input.repo)
            .fetch_optional(&state.db)
            .await
            .map(|opt| opt.map(|r| (r.id, r.handle, r.did)))
    } else {
        let suffix = format!(".{}", hostname);
        let short_handle = if input.repo.ends_with(&suffix) {
            input.repo.strip_suffix(&suffix).unwrap_or(&input.repo)
        } else {
            &input.repo
        };
        sqlx::query!("SELECT id, handle, did FROM users WHERE handle = $1", short_handle)
            .fetch_optional(&state.db)
            .await
            .map(|opt| opt.map(|r| (r.id, r.handle, r.did)))
    };

    let (user_id, handle, did) = match user_row {
        Ok(Some((id, handle, did))) => (id, handle, did),
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "NotFound", "message": "Repo not found"})),
            )
                .into_response();
        }
    };

    let collections_query =
        sqlx::query!("SELECT DISTINCT collection FROM records WHERE repo_id = $1", user_id)
            .fetch_all(&state.db)
            .await;

    let collections: Vec<String> = match collections_query {
        Ok(rows) => rows.iter().map(|r| r.collection.clone()).collect(),
        Err(_) => Vec::new(),
    };

    let full_handle = format!("{}.{}", handle, hostname);
    let did_doc = json!({
        "id": did,
        "alsoKnownAs": [format!("at://{}", full_handle)]
    });

    Json(json!({
        "handle": full_handle,
        "did": did,
        "didDoc": did_doc,
        "collections": collections,
        "handleIsCorrect": true
    }))
    .into_response()
}
