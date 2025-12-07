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
use sqlx::Row;
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
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }
    let token = auth_header
        .unwrap()
        .to_str()
        .unwrap_or("")
        .replace("Bearer ", "");

    let session = sqlx::query(
        "SELECT s.did, k.key_bytes FROM sessions s JOIN users u ON s.did = u.did JOIN user_keys k ON u.id = k.user_id WHERE s.access_jwt = $1"
    )
        .bind(&token)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

    let (did, key_bytes) = match session {
        Some(row) => (
            row.get::<String, _>("did"),
            row.get::<Vec<u8>, _>("key_bytes"),
        ),
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationFailed"})),
            )
                .into_response();
        }
    };

    if crate::auth::verify_token(&token, &key_bytes).is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationFailed", "message": "Invalid token signature"})),
        )
            .into_response();
    }

    let user_query = sqlx::query("SELECT id FROM users WHERE did = $1")
        .bind(&did)
        .fetch_optional(&state.db)
        .await;

    let user_id: uuid::Uuid = match user_query {
        Ok(Some(row)) => row.get("id"),
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "User not found"})),
            )
                .into_response();
        }
    };

    let follows_query = sqlx::query(
        "SELECT record_cid FROM records WHERE repo_id = $1 AND collection = 'app.bsky.graph.follow'"
    )
        .bind(user_id)
        .fetch_all(&state.db)
        .await;

    let follow_cids: Vec<String> = match follows_query {
        Ok(rows) => rows.iter().map(|r| r.get("record_cid")).collect(),
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

    let placeholders: Vec<String> = followed_dids
        .iter()
        .enumerate()
        .map(|(i, _)| format!("${}", i + 1))
        .collect();

    let posts_query = format!(
        "SELECT r.record_cid, r.rkey, r.created_at, u.did, u.handle
         FROM records r
         JOIN repos rp ON r.repo_id = rp.user_id
         JOIN users u ON rp.user_id = u.id
         WHERE u.did IN ({}) AND r.collection = 'app.bsky.feed.post'
         ORDER BY r.created_at DESC
         LIMIT 50",
        placeholders.join(", ")
    );

    let mut query = sqlx::query(&posts_query);
    for did in &followed_dids {
        query = query.bind(did);
    }

    let posts_result = query.fetch_all(&state.db).await;

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
        let record_cid: String = row.get("record_cid");
        let rkey: String = row.get("rkey");
        let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");
        let author_did: String = row.get("did");
        let author_handle: String = row.get("handle");

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
