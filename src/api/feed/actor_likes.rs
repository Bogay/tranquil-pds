use crate::api::read_after_write::{
    FeedOutput, FeedViewPost, LikeRecord, PostView, RecordDescript, extract_repo_rev,
    format_munged_response, get_local_lag, get_records_since_rev, proxy_to_appview_via_registry,
};
use crate::state::AppState;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use tracing::warn;

#[derive(Deserialize)]
pub struct GetActorLikesParams {
    pub actor: String,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

fn insert_likes_into_feed(feed: &mut Vec<FeedViewPost>, likes: &[RecordDescript<LikeRecord>]) {
    for like in likes {
        let like_time = &like.indexed_at.to_rfc3339();
        let idx = feed
            .iter()
            .position(|fi| &fi.post.indexed_at < like_time)
            .unwrap_or(feed.len());
        let placeholder_post = PostView {
            uri: like.record.subject.uri.clone(),
            cid: like.record.subject.cid.clone(),
            author: crate::api::read_after_write::AuthorView {
                did: String::new(),
                handle: String::new(),
                display_name: None,
                avatar: None,
                extra: HashMap::new(),
            },
            record: Value::Null,
            indexed_at: like.indexed_at.to_rfc3339(),
            embed: None,
            reply_count: 0,
            repost_count: 0,
            like_count: 0,
            quote_count: 0,
            extra: HashMap::new(),
        };
        feed.insert(
            idx,
            FeedViewPost {
                post: placeholder_post,
                reply: None,
                reason: None,
                feed_context: None,
                extra: HashMap::new(),
            },
        );
    }
}

pub async fn get_actor_likes(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<GetActorLikesParams>,
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
    query_params.insert("actor".to_string(), params.actor.clone());
    if let Some(limit) = params.limit {
        query_params.insert("limit".to_string(), limit.to_string());
    }
    if let Some(cursor) = &params.cursor {
        query_params.insert("cursor".to_string(), cursor.clone());
    }
    let proxy_result = match proxy_to_appview_via_registry(
        &state,
        "app.bsky.feed.getActorLikes",
        &query_params,
        auth_did.as_deref().unwrap_or(""),
        auth_key_bytes.as_deref(),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return e,
    };
    if !proxy_result.status.is_success() {
        return proxy_result.into_response();
    }
    let rev = match extract_repo_rev(&proxy_result.headers) {
        Some(r) => r,
        None => return proxy_result.into_response(),
    };
    let mut feed_output: FeedOutput = match serde_json::from_slice(&proxy_result.body) {
        Ok(f) => f,
        Err(e) => {
            warn!("Failed to parse actor likes response: {:?}", e);
            return proxy_result.into_response();
        }
    };
    let requester_did = match &auth_did {
        Some(d) => d.clone(),
        None => return (StatusCode::OK, Json(feed_output)).into_response(),
    };
    let actor_did = if params.actor.starts_with("did:") {
        params.actor.clone()
    } else {
        let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
        let suffix = format!(".{}", hostname);
        let short_handle = if params.actor.ends_with(&suffix) {
            params.actor.strip_suffix(&suffix).unwrap_or(&params.actor)
        } else {
            &params.actor
        };
        match sqlx::query_scalar!("SELECT did FROM users WHERE handle = $1", short_handle)
            .fetch_optional(&state.db)
            .await
        {
            Ok(Some(did)) => did,
            Ok(None) => return (StatusCode::OK, Json(feed_output)).into_response(),
            Err(e) => {
                warn!("Database error resolving actor handle: {:?}", e);
                return proxy_result.into_response();
            }
        }
    };
    if actor_did != requester_did {
        return (StatusCode::OK, Json(feed_output)).into_response();
    }
    let local_records = match get_records_since_rev(&state, &requester_did, &rev).await {
        Ok(r) => r,
        Err(e) => {
            warn!("Failed to get local records: {}", e);
            return proxy_result.into_response();
        }
    };
    if local_records.likes.is_empty() {
        return (StatusCode::OK, Json(feed_output)).into_response();
    }
    insert_likes_into_feed(&mut feed_output.feed, &local_records.likes);
    let lag = get_local_lag(&local_records);
    format_munged_response(feed_output, lag)
}
