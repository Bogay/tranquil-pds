use crate::api::proxy_client::{is_ssrf_safe, proxy_client, validate_did};
use crate::api::ApiError;
use crate::state::AppState;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use tracing::{error, info};
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterPushInput {
    pub service_did: String,
    pub token: String,
    pub platform: String,
    pub app_id: String,
}
const VALID_PLATFORMS: &[&str] = &["ios", "android", "web"];
pub async fn register_push(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<RegisterPushInput>,
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
    if let Err(e) = validate_did(&input.service_did) {
        return ApiError::InvalidRequest(format!("Invalid serviceDid: {}", e)).into_response();
    }
    if input.token.is_empty() || input.token.len() > 4096 {
        return ApiError::InvalidRequest("Invalid push token".to_string()).into_response();
    }
    if !VALID_PLATFORMS.contains(&input.platform.as_str()) {
        return ApiError::InvalidRequest(format!(
            "Invalid platform. Must be one of: {}",
            VALID_PLATFORMS.join(", ")
        ))
        .into_response();
    }
    if input.app_id.is_empty() || input.app_id.len() > 256 {
        return ApiError::InvalidRequest("Invalid appId".to_string()).into_response();
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
    let key_row = match sqlx::query!(
        "SELECT key_bytes, encryption_version FROM user_keys k JOIN users u ON k.user_id = u.id WHERE u.did = $1",
        auth_user.did
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            error!(did = %auth_user.did, "No signing key found for user");
            return ApiError::InternalError.into_response();
        }
        Err(e) => {
            error!(error = ?e, "Database error fetching signing key");
            return ApiError::DatabaseError.into_response();
        }
    };
    let decrypted_key =
        match crate::config::decrypt_key(&key_row.key_bytes, key_row.encryption_version) {
            Ok(k) => k,
            Err(e) => {
                error!(error = ?e, "Failed to decrypt signing key");
                return ApiError::InternalError.into_response();
            }
        };
    let service_token = match crate::auth::create_service_token(
        &auth_user.did,
        &input.service_did,
        "app.bsky.notification.registerPush",
        &decrypted_key,
    ) {
        Ok(t) => t,
        Err(e) => {
            error!(error = ?e, "Failed to create service token");
            return ApiError::InternalError.into_response();
        }
    };
    let target_url = format!("{}/xrpc/app.bsky.notification.registerPush", appview_url);
    info!(
        target = %target_url,
        service_did = %input.service_did,
        platform = %input.platform,
        "Proxying registerPush request"
    );
    let client = proxy_client();
    let request_body = json!({
        "serviceDid": input.service_did,
        "token": input.token,
        "platform": input.platform,
        "appId": input.app_id
    });
    match client
        .post(&target_url)
        .header("Authorization", format!("Bearer {}", service_token))
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await
    {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            if status.is_success() {
                StatusCode::OK.into_response()
            } else {
                let body = resp.bytes().await.unwrap_or_default();
                error!(
                    status = %status,
                    "registerPush upstream error"
                );
                ApiError::from_upstream_response(status.as_u16(), &body).into_response()
            }
        }
        Err(e) => {
            error!(error = ?e, "Error proxying registerPush");
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
