use crate::api::proxy_client::{
    is_ssrf_safe, proxy_client, validate_at_uri, validate_limit, MAX_RESPONSE_SIZE,
};
use crate::api::ApiError;
use crate::state::AppState;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::collections::HashMap;
use tracing::{error, info};

#[derive(Deserialize)]
pub struct GetFeedParams {
    pub feed: String,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

pub async fn get_feed(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<GetFeedParams>,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };
    let auth_user = match crate::auth::validate_bearer_token(&state.db, &token).await {
        Ok(user) => user,
        Err(e) => return ApiError::from(e).into_response(),
    };
    if let Err(e) = validate_at_uri(&params.feed) {
        return ApiError::InvalidRequest(format!("Invalid feed URI: {}", e)).into_response();
    }
    let appview_url = match std::env::var("APPVIEW_URL") {
        Ok(url) => url,
        Err(_) => {
            return ApiError::UpstreamUnavailable("No upstream AppView configured".to_string())
                .into_response();
        }
    };
    if let Err(e) = is_ssrf_safe(&appview_url) {
        error!("SSRF check failed for appview URL: {}", e);
        return ApiError::UpstreamUnavailable(format!("Invalid upstream URL: {}", e))
            .into_response();
    }
    let limit = validate_limit(params.limit, 50, 100);
    let mut query_params = HashMap::new();
    query_params.insert("feed".to_string(), params.feed.clone());
    query_params.insert("limit".to_string(), limit.to_string());
    if let Some(cursor) = &params.cursor {
        query_params.insert("cursor".to_string(), cursor.clone());
    }
    let target_url = format!("{}/xrpc/app.bsky.feed.getFeed", appview_url);
    info!(target = %target_url, feed = %params.feed, "Proxying getFeed request");
    let client = proxy_client();
    let mut request_builder = client.get(&target_url).query(&query_params);
    if let Some(key_bytes) = auth_user.key_bytes.as_ref() {
        let appview_did = std::env::var("APPVIEW_DID").unwrap_or_else(|_| "did:web:api.bsky.app".to_string());
        match crate::auth::create_service_token(&auth_user.did, &appview_did, "app.bsky.feed.getFeed", key_bytes) {
            Ok(service_token) => {
                request_builder = request_builder.header("Authorization", format!("Bearer {}", service_token));
            }
            Err(e) => {
                error!(error = ?e, "Failed to create service token for getFeed");
                return ApiError::InternalError.into_response();
            }
        }
    }
    match request_builder.send().await {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let content_length = resp.content_length().unwrap_or(0);
            if content_length > MAX_RESPONSE_SIZE {
                error!(
                    content_length,
                    max = MAX_RESPONSE_SIZE,
                    "getFeed response too large"
                );
                return ApiError::UpstreamFailure.into_response();
            }
            let resp_headers = resp.headers().clone();
            let body = match resp.bytes().await {
                Ok(b) => {
                    if b.len() as u64 > MAX_RESPONSE_SIZE {
                        error!(len = b.len(), "getFeed response body exceeded limit");
                        return ApiError::UpstreamFailure.into_response();
                    }
                    b
                }
                Err(e) => {
                    error!(error = ?e, "Error reading getFeed response");
                    return ApiError::UpstreamFailure.into_response();
                }
            };
            let mut response_builder = axum::response::Response::builder().status(status);
            if let Some(ct) = resp_headers.get("content-type") {
                response_builder = response_builder.header("content-type", ct);
            }
            match response_builder.body(axum::body::Body::from(body)) {
                Ok(r) => r,
                Err(e) => {
                    error!(error = ?e, "Error building getFeed response");
                    ApiError::UpstreamFailure.into_response()
                }
            }
        }
        Err(e) => {
            error!(error = ?e, "Error proxying getFeed");
            if e.is_timeout() {
                ApiError::UpstreamTimeout.into_response()
            } else if e.is_connect() {
                ApiError::UpstreamUnavailable("Failed to connect to upstream".to_string())
                    .into_response()
            } else {
                ApiError::UpstreamFailure.into_response()
            }
        }
    }
}
