mod grants;
mod helpers;
mod introspect;
mod types;

use crate::oauth::OAuthError;
use crate::state::{AppState, RateLimitKind};
use axum::body::Bytes;
use axum::{Json, extract::State, http::HeaderMap};

pub use grants::{handle_authorization_code_grant, handle_refresh_token_grant};
pub use helpers::{TokenClaims, create_access_token, extract_token_claims, verify_pkce};
pub use introspect::{
    IntrospectRequest, IntrospectResponse, RevokeRequest, introspect_token, revoke_token,
};
pub use types::{ClientAuthParams, GrantType, TokenGrant, TokenRequest, TokenResponse, ValidatedTokenRequest};

fn extract_client_ip(headers: &HeaderMap) -> String {
    if let Some(forwarded) = headers.get("x-forwarded-for")
        && let Ok(value) = forwarded.to_str()
        && let Some(first_ip) = value.split(',').next()
    {
        return first_ip.trim().to_string();
    }
    if let Some(real_ip) = headers.get("x-real-ip")
        && let Ok(value) = real_ip.to_str()
    {
        return value.trim().to_string();
    }
    "unknown".to_string()
}

pub async fn token_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(HeaderMap, Json<TokenResponse>), OAuthError> {
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let request: TokenRequest = if content_type.starts_with("application/json") {
        serde_json::from_slice(&body)
            .map_err(|e| OAuthError::InvalidRequest(format!("Invalid JSON: {}", e)))?
    } else if content_type.starts_with("application/x-www-form-urlencoded") {
        serde_urlencoded::from_bytes(&body)
            .map_err(|e| OAuthError::InvalidRequest(format!("Invalid form data: {}", e)))?
    } else {
        return Err(OAuthError::InvalidRequest(
            "Content-Type must be application/json or application/x-www-form-urlencoded"
                .to_string(),
        ));
    };
    let client_ip = extract_client_ip(&headers);
    if !state
        .check_rate_limit(RateLimitKind::OAuthToken, &client_ip)
        .await
    {
        tracing::warn!(ip = %client_ip, "OAuth token rate limit exceeded");
        return Err(OAuthError::InvalidRequest(
            "Too many requests. Please try again later.".to_string(),
        ));
    }
    let dpop_proof = headers
        .get("DPoP")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let validated = request.validate()?;
    match validated.grant {
        TokenGrant::AuthorizationCode { .. } => {
            handle_authorization_code_grant(state, headers, validated, dpop_proof).await
        }
        TokenGrant::RefreshToken { .. } => {
            handle_refresh_token_grant(state, headers, validated, dpop_proof).await
        }
    }
}
