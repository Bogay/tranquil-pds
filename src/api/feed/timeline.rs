use crate::api::read_after_write::{
    extract_repo_rev, format_local_post, format_munged_response, get_local_lag,
    get_records_since_rev, insert_posts_into_feed, proxy_to_appview, FeedOutput, FeedViewPost,
    PostView,
};
use crate::state::AppState;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use jacquard_repo::storage::BlockStore;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use tracing::warn;

#[derive(Deserialize)]
pub struct GetTimelineParams {
    pub algorithm: Option<String>,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

pub async fn get_timeline(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<GetTimelineParams>,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
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
    match std::env::var("APPVIEW_URL") {
        Ok(url) if !url.starts_with("http://127.0.0.1") => {
            return get_timeline_with_appview(&state, &headers, &params, &auth_user.did).await;
        }
        _ => {}
    }
    get_timeline_local_only(&state, &auth_user.did).await
}

async fn get_timeline_with_appview(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    params: &GetTimelineParams,
    auth_did: &str,
) -> Response {
    let auth_header = headers.get("Authorization").and_then(|h| h.to_str().ok());
    let mut query_params = HashMap::new();
    if let Some(algo) = &params.algorithm {
        query_params.insert("algorithm".to_string(), algo.clone());
    }
    if let Some(limit) = params.limit {
        query_params.insert("limit".to_string(), limit.to_string());
    }
    if let Some(cursor) = &params.cursor {
        query_params.insert("cursor".to_string(), cursor.clone());
    }
    let proxy_result =
        match proxy_to_appview("app.bsky.feed.getTimeline", &query_params, auth_header).await {
            Ok(r) => r,
            Err(e) => return e,
        };
    if !proxy_result.status.is_success() {
        return (proxy_result.status, proxy_result.body).into_response();
    }
    let rev = extract_repo_rev(&proxy_result.headers);
    if rev.is_none() {
        return (proxy_result.status, proxy_result.body).into_response();
    }
    let rev = rev.unwrap();
    let mut feed_output: FeedOutput = match serde_json::from_slice(&proxy_result.body) {
        Ok(f) => f,
        Err(e) => {
            warn!("Failed to parse timeline response: {:?}", e);
            return (proxy_result.status, proxy_result.body).into_response();
        }
    };
    let local_records = match get_records_since_rev(state, auth_did, &rev).await {
        Ok(r) => r,
        Err(e) => {
            warn!("Failed to get local records: {}", e);
            return (proxy_result.status, proxy_result.body).into_response();
        }
    };
    if local_records.count == 0 {
        return (proxy_result.status, proxy_result.body).into_response();
    }
    let handle = match sqlx::query_scalar!("SELECT handle FROM users WHERE did = $1", auth_did)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(h)) => h,
        Ok(None) => auth_did.to_string(),
        Err(e) => {
            warn!("Database error fetching handle: {:?}", e);
            auth_did.to_string()
        }
    };
    let local_posts: Vec<_> = local_records
        .posts
        .iter()
        .map(|p| format_local_post(p, auth_did, &handle, local_records.profile.as_ref()))
        .collect();
    insert_posts_into_feed(&mut feed_output.feed, local_posts);
    let lag = get_local_lag(&local_records);
    format_munged_response(feed_output, lag)
}

async fn get_timeline_local_only(state: &AppState, auth_did: &str) -> Response {
    let user_id: uuid::Uuid = match sqlx::query_scalar!(
        "SELECT id FROM users WHERE did = $1",
        auth_did
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(id)) => id,
        Ok(None) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "User not found"})),
            )
                .into_response();
        }
        Err(e) => {
            warn!("Database error fetching user: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Database error"})),
            )
                .into_response();
        }
    };
    let follows_query = sqlx::query!(
        "SELECT record_cid FROM records WHERE repo_id = $1 AND collection = 'app.bsky.graph.follow' LIMIT 5000",
        user_id
    )
    .fetch_all(&state.db)
    .await;
    let follow_cids: Vec<String> = match follows_query {
        Ok(rows) => rows.iter().map(|r| r.record_cid.clone()).collect(),
        Err(_) => {
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
            Json(FeedOutput {
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
        Err(_) => {
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
                author: crate::api::read_after_write::AuthorView {
                    did: author_did,
                    handle: author_handle,
                    display_name: None,
                    avatar: None,
                    extra: HashMap::new(),
                },
                record,
                indexed_at: created_at.to_rfc3339(),
                embed: None,
                reply_count: 0,
                repost_count: 0,
                like_count: 0,
                quote_count: 0,
                extra: HashMap::new(),
            },
            reply: None,
            reason: None,
            feed_context: None,
            extra: HashMap::new(),
        });
    }
    (StatusCode::OK, Json(FeedOutput { feed, cursor: None })).into_response()
}
