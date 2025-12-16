use crate::api::read_after_write::{
    PostRecord, PostView, RecordDescript, extract_repo_rev, format_local_post,
    format_munged_response, get_local_lag, get_records_since_rev, proxy_to_appview,
};
use crate::state::AppState;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use tracing::warn;

#[derive(Deserialize)]
pub struct GetPostThreadParams {
    pub uri: String,
    pub depth: Option<u32>,
    #[serde(rename = "parentHeight")]
    pub parent_height: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreadViewPost {
    #[serde(rename = "$type")]
    pub thread_type: Option<String>,
    pub post: PostView,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<Box<ThreadNode>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replies: Option<Vec<ThreadNode>>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ThreadNode {
    Post(Box<ThreadViewPost>),
    NotFound(ThreadNotFound),
    Blocked(ThreadBlocked),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreadNotFound {
    #[serde(rename = "$type")]
    pub thread_type: String,
    pub uri: String,
    pub not_found: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreadBlocked {
    #[serde(rename = "$type")]
    pub thread_type: String,
    pub uri: String,
    pub blocked: bool,
    pub author: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostThreadOutput {
    pub thread: ThreadNode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threadgate: Option<Value>,
}

const MAX_THREAD_DEPTH: usize = 10;

fn add_replies_to_thread(
    thread: &mut ThreadViewPost,
    local_posts: &[RecordDescript<PostRecord>],
    author_did: &str,
    author_handle: &str,
    depth: usize,
) {
    if depth >= MAX_THREAD_DEPTH {
        return;
    }
    let thread_uri = &thread.post.uri;
    let replies: Vec<_> = local_posts
        .iter()
        .filter(|p| {
            p.record
                .reply
                .as_ref()
                .and_then(|r| r.get("parent"))
                .and_then(|parent| parent.get("uri"))
                .and_then(|u| u.as_str())
                == Some(thread_uri)
        })
        .map(|p| {
            let post_view = format_local_post(p, author_did, author_handle, None);
            ThreadNode::Post(Box::new(ThreadViewPost {
                thread_type: Some("app.bsky.feed.defs#threadViewPost".to_string()),
                post: post_view,
                parent: None,
                replies: None,
                extra: HashMap::new(),
            }))
        })
        .collect();
    if !replies.is_empty() {
        match &mut thread.replies {
            Some(existing) => existing.extend(replies),
            None => thread.replies = Some(replies),
        }
    }
    if let Some(ref mut existing_replies) = thread.replies {
        for reply in existing_replies.iter_mut() {
            if let ThreadNode::Post(reply_thread) = reply {
                add_replies_to_thread(
                    reply_thread,
                    local_posts,
                    author_did,
                    author_handle,
                    depth + 1,
                );
            }
        }
    }
}

pub async fn get_post_thread(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<GetPostThreadParams>,
) -> Response {
    let auth_header = headers.get("Authorization").and_then(|h| h.to_str().ok());
    let auth_user = if let Some(h) = auth_header {
        if let Some(token) = crate::auth::extract_bearer_token_from_header(Some(h)) {
            crate::auth::validate_bearer_token(&state.db, &token)
                .await
                .ok()
        } else {
            None
        }
    } else {
        None
    };
    let auth_did = auth_user.as_ref().map(|u| u.did.clone());
    let auth_key_bytes = auth_user.as_ref().and_then(|u| u.key_bytes.clone());
    let mut query_params = HashMap::new();
    query_params.insert("uri".to_string(), params.uri.clone());
    if let Some(depth) = params.depth {
        query_params.insert("depth".to_string(), depth.to_string());
    }
    if let Some(parent_height) = params.parent_height {
        query_params.insert("parentHeight".to_string(), parent_height.to_string());
    }
    let proxy_result = match proxy_to_appview(
        "app.bsky.feed.getPostThread",
        &query_params,
        auth_did.as_deref().unwrap_or(""),
        auth_key_bytes.as_deref(),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return e,
    };
    if proxy_result.status == StatusCode::NOT_FOUND {
        return handle_not_found(&state, &params.uri, auth_did, &proxy_result.headers).await;
    }
    if !proxy_result.status.is_success() {
        return proxy_result.into_response();
    }
    let rev = match extract_repo_rev(&proxy_result.headers) {
        Some(r) => r,
        None => return proxy_result.into_response(),
    };
    let mut thread_output: PostThreadOutput = match serde_json::from_slice(&proxy_result.body) {
        Ok(t) => t,
        Err(e) => {
            warn!("Failed to parse post thread response: {:?}", e);
            return proxy_result.into_response();
        }
    };
    let requester_did = match auth_did {
        Some(d) => d,
        None => return (StatusCode::OK, Json(thread_output)).into_response(),
    };
    let local_records = match get_records_since_rev(&state, &requester_did, &rev).await {
        Ok(r) => r,
        Err(e) => {
            warn!("Failed to get local records: {}", e);
            return proxy_result.into_response();
        }
    };
    if local_records.posts.is_empty() {
        return (StatusCode::OK, Json(thread_output)).into_response();
    }
    let handle = match sqlx::query_scalar!("SELECT handle FROM users WHERE did = $1", requester_did)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(h)) => h,
        Ok(None) => requester_did.clone(),
        Err(e) => {
            warn!("Database error fetching handle: {:?}", e);
            requester_did.clone()
        }
    };
    if let ThreadNode::Post(ref mut thread_post) = thread_output.thread {
        add_replies_to_thread(
            thread_post,
            &local_records.posts,
            &requester_did,
            &handle,
            0,
        );
    }
    let lag = get_local_lag(&local_records);
    format_munged_response(thread_output, lag)
}

async fn handle_not_found(
    state: &AppState,
    uri: &str,
    auth_did: Option<String>,
    headers: &axum::http::HeaderMap,
) -> Response {
    let rev = match extract_repo_rev(headers) {
        Some(r) => r,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "NotFound", "message": "Post not found"})),
            )
                .into_response();
        }
    };
    let requester_did = match auth_did {
        Some(d) => d,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "NotFound", "message": "Post not found"})),
            )
                .into_response();
        }
    };
    let uri_parts: Vec<&str> = uri.trim_start_matches("at://").split('/').collect();
    if uri_parts.len() != 3 {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "NotFound", "message": "Post not found"})),
        )
            .into_response();
    }
    let post_did = uri_parts[0];
    if post_did != requester_did {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "NotFound", "message": "Post not found"})),
        )
            .into_response();
    }
    let local_records = match get_records_since_rev(state, &requester_did, &rev).await {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "NotFound", "message": "Post not found"})),
            )
                .into_response();
        }
    };
    let local_post = local_records.posts.iter().find(|p| p.uri == uri);
    let local_post = match local_post {
        Some(p) => p,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "NotFound", "message": "Post not found"})),
            )
                .into_response();
        }
    };
    let handle = match sqlx::query_scalar!("SELECT handle FROM users WHERE did = $1", requester_did)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(h)) => h,
        Ok(None) => requester_did.clone(),
        Err(e) => {
            warn!("Database error fetching handle: {:?}", e);
            requester_did.clone()
        }
    };
    let post_view = format_local_post(
        local_post,
        &requester_did,
        &handle,
        local_records.profile.as_ref(),
    );
    let thread = PostThreadOutput {
        thread: ThreadNode::Post(Box::new(ThreadViewPost {
            thread_type: Some("app.bsky.feed.defs#threadViewPost".to_string()),
            post: post_view,
            parent: None,
            replies: None,
            extra: HashMap::new(),
        })),
        threadgate: None,
    };
    let lag = get_local_lag(&local_records);
    format_munged_response(thread, lag)
}
