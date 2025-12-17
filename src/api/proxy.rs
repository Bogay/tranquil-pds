use crate::api::proxy_client::proxy_client;
use crate::state::AppState;
use axum::{
    body::Bytes,
    extract::{Path, RawQuery, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};
use tracing::{error, info, warn};

pub async fn proxy_handler(
    State(state): State<AppState>,
    Path(method): Path<String>,
    method_verb: Method,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    let proxy_header = headers
        .get("atproto-proxy")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let (appview_url, service_aud) = match &proxy_header {
        Some(did_str) => {
            let did_without_fragment = did_str.split('#').next().unwrap_or(did_str).to_string();
            match state.appview_registry.resolve_appview_did(&did_without_fragment).await {
                Some(resolved) => (resolved.url, Some(resolved.did)),
                None => {
                    error!(did = %did_str, "Could not resolve service DID");
                    return (StatusCode::BAD_GATEWAY, "Could not resolve service DID")
                        .into_response();
                }
            }
        }
        None => {
            match state.appview_registry.get_appview_for_method(&method).await {
                Some(resolved) => (resolved.url, Some(resolved.did)),
                None => {
                    return (StatusCode::BAD_GATEWAY, "No upstream AppView configured for this method")
                        .into_response();
                }
            }
        }
    };
    let target_url = match &query {
        Some(q) => format!("{}/xrpc/{}?{}", appview_url, method, q),
        None => format!("{}/xrpc/{}", appview_url, method),
    };
    info!("Proxying {} request to {}", method_verb, target_url);
    let client = proxy_client();
    let mut request_builder = client.request(method_verb, &target_url);
    let mut auth_header_val = headers.get("Authorization").cloned();
    if let Some(aud) = &service_aud {
        if let Some(token) = crate::auth::extract_bearer_token_from_header(
            headers.get("Authorization").and_then(|h| h.to_str().ok()),
        ) {
            match crate::auth::validate_bearer_token(&state.db, &token).await {
                Ok(auth_user) => {
                    if let Some(key_bytes) = auth_user.key_bytes {
                        match crate::auth::create_service_token(&auth_user.did, aud, &method, &key_bytes) {
                            Ok(new_token) => {
                                if let Ok(val) = axum::http::HeaderValue::from_str(&format!("Bearer {}", new_token)) {
                                    auth_header_val = Some(val);
                                }
                            }
                            Err(e) => {
                                warn!("Failed to create service token: {:?}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Token validation failed: {:?}", e);
                }
            }
        }
    }
    if let Some(val) = auth_header_val {
        request_builder = request_builder.header("Authorization", val);
    }
    for header_name in crate::api::proxy_client::HEADERS_TO_FORWARD {
        if let Some(val) = headers.get(*header_name) {
            request_builder = request_builder.header(*header_name, val);
        }
    }
    if !body.is_empty() {
        request_builder = request_builder.body(body);
    }
    match request_builder.send().await {
        Ok(resp) => {
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = match resp.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    error!("Error reading proxy response body: {:?}", e);
                    return (StatusCode::BAD_GATEWAY, "Error reading upstream response")
                        .into_response();
                }
            };
            let mut response_builder = Response::builder().status(status);
            for header_name in crate::api::proxy_client::RESPONSE_HEADERS_TO_FORWARD {
                if let Some(val) = headers.get(*header_name) {
                    response_builder = response_builder.header(*header_name, val);
                }
            }
            match response_builder.body(axum::body::Body::from(body)) {
                Ok(r) => r,
                Err(e) => {
                    error!("Error building proxy response: {:?}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
                }
            }
        }
        Err(e) => {
            error!("Error sending proxy request: {:?}", e);
            if e.is_timeout() {
                (StatusCode::GATEWAY_TIMEOUT, "Upstream Timeout").into_response()
            } else {
                (StatusCode::BAD_GATEWAY, "Upstream Error").into_response()
            }
        }
    }
}
