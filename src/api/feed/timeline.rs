// Yes, I know, this endpoint is an appview one, not for PDS. Who cares!!
// Yes, this only gets posts that our DB/instance knows about. Who cares!!!

use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use jacquard_repo::storage::BlockStore;
use serde::Serialize;
use serde_json::{Value, json};
use tracing::error;

#[derive(Serialize)]
pub struct TimelineOutput {
    pub feed: Vec<FeedViewPost>,
    pub cursor: Option<String>,
}

#[derive(Serialize)]
pub struct FeedViewPost {
    pub post: PostView,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostView {
    pub uri: String,
    pub cid: String,
    pub author: AuthorView,
    pub record: Value,
    pub indexed_at: String,
}

#[derive(Serialize)]
pub struct AuthorView {
    pub did: String,
    pub handle: String,
}

pub async fn get_timeline(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok())
    ) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationRequired"})),
            )
                .into_response();
        }
    };

    let auth_user = match crate::auth::validate_bearer_token(&state.db, &token).await {
        Ok(user) => user,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationFailed"})),
            )
                .into_response();
        }
    };

    let user_query = sqlx::query!("SELECT id FROM users WHERE did = $1", auth_user.did)
        .fetch_optional(&state.db)
        .await;

    let user_id = match user_query {
        Ok(Some(row)) => row.id,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "User not found"})),
            )
                .into_response();
        }
    };

    let follows_query = sqlx::query!(
        "SELECT record_cid FROM records WHERE repo_id = $1 AND collection = 'app.bsky.graph.follow'",
        user_id
    )
        .fetch_all(&state.db)
        .await;

    let follow_cids: Vec<String> = match follows_query {
        Ok(rows) => rows.iter().map(|r| r.record_cid.clone()).collect(),
        Err(e) => {
            error!("Failed to get follows: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let mut followed_dids: Vec<String> = Vec::new();
    for cid_str in follow_cids {
        let cid = match cid_str.parse::<cid::Cid>() {
            Ok(c) => c,
            Err(_) => continue,
        };

        let block_bytes = match state.block_store.get(&cid).await {
            Ok(Some(b)) => b,
            _ => continue,
        };

        let record: Value = match serde_ipld_dagcbor::from_slice(&block_bytes) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if let Some(subject) = record.get("subject").and_then(|s| s.as_str()) {
            followed_dids.push(subject.to_string());
        }
    }

    if followed_dids.is_empty() {
        return (
            StatusCode::OK,
            Json(TimelineOutput {
                feed: vec![],
                cursor: None,
            }),
        )
            .into_response();
    }

    let posts_result = sqlx::query!(
        "SELECT r.record_cid, r.rkey, r.created_at, u.did, u.handle
         FROM records r
         JOIN repos rp ON r.repo_id = rp.user_id
         JOIN users u ON rp.user_id = u.id
         WHERE u.did = ANY($1) AND r.collection = 'app.bsky.feed.post'
         ORDER BY r.created_at DESC
         LIMIT 50",
        &followed_dids
    )
    .fetch_all(&state.db)
    .await;

    let posts = match posts_result {
        Ok(rows) => rows,
        Err(e) => {
            error!("Failed to get posts: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let mut feed: Vec<FeedViewPost> = Vec::new();

    for row in posts {
        let record_cid: String = row.record_cid;
        let rkey: String = row.rkey;
        let created_at: chrono::DateTime<chrono::Utc> = row.created_at;
        let author_did: String = row.did;
        let author_handle: String = row.handle;

        let cid = match record_cid.parse::<cid::Cid>() {
            Ok(c) => c,
            Err(_) => continue,
        };

        let block_bytes = match state.block_store.get(&cid).await {
            Ok(Some(b)) => b,
            _ => continue,
        };

        let record: Value = match serde_ipld_dagcbor::from_slice(&block_bytes) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let uri = format!("at://{}/app.bsky.feed.post/{}", author_did, rkey);

        feed.push(FeedViewPost {
            post: PostView {
                uri,
                cid: record_cid,
                author: AuthorView {
                    did: author_did,
                    handle: author_handle,
                },
                record,
                indexed_at: created_at.to_rfc3339(),
            },
        });
    }

    (StatusCode::OK, Json(TimelineOutput { feed, cursor: None })).into_response()
}
