use crate::api::read_after_write::{
    extract_repo_rev, format_local_post, format_munged_response, get_local_lag,
    get_records_since_rev, insert_posts_into_feed, proxy_to_appview, FeedOutput, FeedViewPost,
    ProfileRecord, RecordDescript,
};
use crate::state::AppState;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::collections::HashMap;
use tracing::warn;

#[derive(Deserialize)]
pub struct GetAuthorFeedParams {
    pub actor: String,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
    pub filter: Option<String>,
    #[serde(rename = "includePins")]
    pub include_pins: Option<bool>,
}

fn update_author_profile_in_feed(
    feed: &mut [FeedViewPost],
    author_did: &str,
    local_profile: &RecordDescript<ProfileRecord>,
) {
    for item in feed.iter_mut() {
        if item.post.author.did == author_did {
            if let Some(ref display_name) = local_profile.record.display_name {
                item.post.author.display_name = Some(display_name.clone());
            }
        }
    }
}

pub async fn get_author_feed(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<GetAuthorFeedParams>,
) -> Response {
    let auth_header = headers.get("Authorization").and_then(|h| h.to_str().ok());

    let auth_did = if let Some(h) = auth_header {
        if let Some(token) = crate::auth::extract_bearer_token_from_header(Some(h)) {
            match crate::auth::validate_bearer_token(&state.db, &token).await {
                Ok(user) => Some(user.did),
                Err(_) => None,
            }
        } else {
            None
        }
    } else {
        None
    };

    let mut query_params = HashMap::new();
    query_params.insert("actor".to_string(), params.actor.clone());
    if let Some(limit) = params.limit {
        query_params.insert("limit".to_string(), limit.to_string());
    }
    if let Some(cursor) = &params.cursor {
        query_params.insert("cursor".to_string(), cursor.clone());
    }
    if let Some(filter) = &params.filter {
        query_params.insert("filter".to_string(), filter.clone());
    }
    if let Some(include_pins) = params.include_pins {
        query_params.insert("includePins".to_string(), include_pins.to_string());
    }

    let proxy_result =
        match proxy_to_appview("app.bsky.feed.getAuthorFeed", &query_params, auth_header).await {
            Ok(r) => r,
            Err(e) => return e,
        };

    if !proxy_result.status.is_success() {
        return (proxy_result.status, proxy_result.body).into_response();
    }

    let rev = match extract_repo_rev(&proxy_result.headers) {
        Some(r) => r,
        None => return (proxy_result.status, proxy_result.body).into_response(),
    };

    let mut feed_output: FeedOutput = match serde_json::from_slice(&proxy_result.body) {
        Ok(f) => f,
        Err(e) => {
            warn!("Failed to parse author feed response: {:?}", e);
            return (proxy_result.status, proxy_result.body).into_response();
        }
    };

    let requester_did = match auth_did {
        Some(d) => d,
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
                return (proxy_result.status, proxy_result.body).into_response();
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
            return (proxy_result.status, proxy_result.body).into_response();
        }
    };

    if local_records.count == 0 {
        return (StatusCode::OK, Json(feed_output)).into_response();
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

    if let Some(ref local_profile) = local_records.profile {
        update_author_profile_in_feed(&mut feed_output.feed, &requester_did, local_profile);
    }

    let local_posts: Vec<_> = local_records
        .posts
        .iter()
        .map(|p| {
            format_local_post(
                p,
                &requester_did,
                &handle,
                local_records.profile.as_ref(),
            )
        })
        .collect();

    insert_posts_into_feed(&mut feed_output.feed, local_posts);

    let lag = get_local_lag(&local_records);
    format_munged_response(feed_output, lag)
}
