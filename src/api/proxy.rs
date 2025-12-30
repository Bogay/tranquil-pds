use crate::api::proxy_client::proxy_client;
use crate::state::AppState;
use axum::{
    Json,
    body::Bytes,
    extract::{Path, RawQuery, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;
use tracing::{error, info, warn};

const PROTECTED_METHODS: &[&str] = &[
    "com.atproto.admin.sendEmail",
    "com.atproto.identity.requestPlcOperationSignature",
    "com.atproto.identity.signPlcOperation",
    "com.atproto.identity.updateHandle",
    "com.atproto.server.activateAccount",
    "com.atproto.server.confirmEmail",
    "com.atproto.server.createAppPassword",
    "com.atproto.server.deactivateAccount",
    "com.atproto.server.getAccountInviteCodes",
    "com.atproto.server.getSession",
    "com.atproto.server.listAppPasswords",
    "com.atproto.server.requestAccountDelete",
    "com.atproto.server.requestEmailConfirmation",
    "com.atproto.server.requestEmailUpdate",
    "com.atproto.server.revokeAppPassword",
    "com.atproto.server.updateEmail",
];

fn is_protected_method(method: &str) -> bool {
    PROTECTED_METHODS.contains(&method)
}

pub async fn proxy_handler(
    State(state): State<AppState>,
    Path(method): Path<String>,
    method_verb: Method,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    if is_protected_method(&method) {
        warn!(method = %method, "Attempted to proxy protected method");
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "InvalidRequest",
                "message": format!("Cannot proxy protected method: {}", method)
            })),
        )
            .into_response();
    }

    let proxy_header = match headers.get("atproto-proxy").and_then(|h| h.to_str().ok()) {
        Some(h) => h.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "InvalidRequest",
                    "message": "Missing required atproto-proxy header"
                })),
            )
                .into_response();
        }
    };

    let did = proxy_header.split('#').next().unwrap_or(&proxy_header);
    let resolved = match state.did_resolver.resolve_did(did).await {
        Some(r) => r,
        None => {
            error!(did = %did, "Could not resolve service DID");
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": "UpstreamFailure",
                    "message": "Could not resolve service DID"
                })),
            )
                .into_response();
        }
    };

    let target_url = match &query {
        Some(q) => format!("{}/xrpc/{}?{}", resolved.url, method, q),
        None => format!("{}/xrpc/{}", resolved.url, method),
    };
    info!("Proxying {} request to {}", method_verb, target_url);

    let client = proxy_client();
    let mut request_builder = client.request(method_verb, &target_url);

    let mut auth_header_val = headers.get("Authorization").cloned();
    if let Some(token) = crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        match crate::auth::validate_bearer_token(&state.db, &token).await {
            Ok(auth_user) => {
                if let Err(e) = crate::auth::scope_check::check_rpc_scope(
                    auth_user.is_oauth,
                    auth_user.scope.as_deref(),
                    &resolved.did,
                    &method,
                ) {
                    return e;
                }

                if let Some(key_bytes) = auth_user.key_bytes {
                    match crate::auth::create_service_token(
                        &auth_user.did,
                        &resolved.did,
                        &method,
                        &key_bytes,
                    ) {
                        Ok(new_token) => {
                            if let Ok(val) =
                                axum::http::HeaderValue::from_str(&format!("Bearer {}", new_token))
                            {
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
                if matches!(e, crate::auth::TokenValidationError::TokenExpired) {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "ExpiredToken",
                            "message": "Token has expired"
                        })),
                    )
                        .into_response();
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
