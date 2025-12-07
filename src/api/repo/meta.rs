use crate::state::AppState;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use sqlx::Row;

#[derive(Deserialize)]
pub struct DescribeRepoInput {
    pub repo: String,
}

pub async fn describe_repo(
    State(state): State<AppState>,
    Query(input): Query<DescribeRepoInput>,
) -> Response {
    let user_row = if input.repo.starts_with("did:") {
        sqlx::query("SELECT id, handle, did FROM users WHERE did = $1")
            .bind(&input.repo)
            .fetch_optional(&state.db)
            .await
    } else {
        sqlx::query("SELECT id, handle, did FROM users WHERE handle = $1")
            .bind(&input.repo)
            .fetch_optional(&state.db)
            .await
    };

    let (user_id, handle, did) = match user_row {
        Ok(Some(row)) => (
            row.get::<uuid::Uuid, _>("id"),
            row.get::<String, _>("handle"),
            row.get::<String, _>("did"),
        ),
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "NotFound", "message": "Repo not found"})),
            )
                .into_response();
        }
    };

    let collections_query =
        sqlx::query("SELECT DISTINCT collection FROM records WHERE repo_id = $1")
            .bind(user_id)
            .fetch_all(&state.db)
            .await;

    let collections: Vec<String> = match collections_query {
        Ok(rows) => rows.iter().map(|r| r.get("collection")).collect(),
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
