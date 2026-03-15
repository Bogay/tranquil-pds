mod grants;
mod helpers;
mod introspect;
mod types;

use tranquil_pds::oauth::OAuthError;
use tranquil_pds::rate_limit::{OAuthRateLimited, OAuthTokenLimit};
use tranquil_pds::state::AppState;
use axum::body::Bytes;
use axum::{Json, extract::State, http::HeaderMap};

pub use grants::{handle_authorization_code_grant, handle_refresh_token_grant};
pub use helpers::{TokenClaims, create_access_token, extract_token_claims, verify_pkce};
pub use introspect::{
    IntrospectRequest, IntrospectResponse, RevokeRequest, introspect_token, revoke_token,
};
pub use types::{
    GrantType, RequestClientAuth, TokenGrant, TokenRequest, TokenResponse, ValidatedTokenRequest,
};

pub async fn token_endpoint(
    State(state): State<AppState>,
    _rate_limit: OAuthRateLimited<OAuthTokenLimit>,
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
    let dpop_proof = headers
        .get(tranquil_pds::util::HEADER_DPOP)
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
