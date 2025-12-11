mod grants;
mod helpers;
mod introspect;
mod types;

use axum::{
    Form, Json,
    extract::State,
    http::HeaderMap,
};

use crate::state::AppState;
use crate::oauth::OAuthError;

pub use grants::{handle_authorization_code_grant, handle_refresh_token_grant};
pub use helpers::{create_access_token, extract_token_claims, verify_pkce, TokenClaims};
pub use introspect::{
    introspect_token, revoke_token, IntrospectRequest, IntrospectResponse, RevokeRequest,
};
pub use types::{TokenRequest, TokenResponse};

pub async fn token_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(request): Form<TokenRequest>,
) -> Result<(HeaderMap, Json<TokenResponse>), OAuthError> {
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
