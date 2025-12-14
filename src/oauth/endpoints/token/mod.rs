mod grants;
mod helpers;
mod introspect;
mod types;
use axum::{
    Form, Json,
    extract::State,
    http::HeaderMap,
};
use crate::state::{AppState, RateLimitKind};
use crate::oauth::OAuthError;
pub use grants::{handle_authorization_code_grant, handle_refresh_token_grant};
pub use helpers::{create_access_token, extract_token_claims, verify_pkce, TokenClaims};
pub use introspect::{
    introspect_token, revoke_token, IntrospectRequest, IntrospectResponse, RevokeRequest,
};
pub use types::{TokenRequest, TokenResponse};
fn extract_client_ip(headers: &HeaderMap) -> String {
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(value) = forwarded.to_str() {
            if let Some(first_ip) = value.split(',').next() {
                return first_ip.trim().to_string();
            }
        }
    }
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(value) = real_ip.to_str() {
            return value.trim().to_string();
        }
    }
    "unknown".to_string()
}
pub async fn token_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(request): Form<TokenRequest>,
) -> Result<(HeaderMap, Json<TokenResponse>), OAuthError> {
    let client_ip = extract_client_ip(&headers);
    if !state.check_rate_limit(RateLimitKind::OAuthToken, &client_ip).await {
        tracing::warn!(ip = %client_ip, "OAuth token rate limit exceeded");
        return Err(OAuthError::InvalidRequest(
            "Too many requests. Please try again later.".to_string(),
        ));
    }
    let dpop_proof = headers
        .get("DPoP")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    match request.grant_type.as_str() {
        "authorization_code" => {
            handle_authorization_code_grant(state, headers, request, dpop_proof).await
        }
        "refresh_token" => {
            handle_refresh_token_grant(state, headers, request, dpop_proof).await
        }
        _ => Err(OAuthError::UnsupportedGrantType(format!(
            "Unsupported grant_type: {}",
            request.grant_type
        ))),
    }
}
