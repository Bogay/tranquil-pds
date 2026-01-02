use axum::{
    Json,
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;
use sqlx::PgPool;
use subtle::ConstantTimeEq;

use super::OAuthError;
use super::db;
use super::dpop::DPoPVerifier;
use super::scopes::ScopePermissions;
use crate::config::AuthConfig;
use crate::state::AppState;

pub struct OAuthTokenInfo {
    pub did: String,
    pub token_id: String,
    pub client_id: String,
    pub scope: Option<String>,
    pub dpop_jkt: Option<String>,
    pub controller_did: Option<String>,
}

pub struct VerifyResult {
    pub did: String,
    pub token_id: String,
    pub client_id: String,
    pub scope: Option<String>,
}

pub async fn verify_oauth_access_token(
    pool: &PgPool,
    access_token: &str,
    dpop_proof: Option<&str>,
    http_method: &str,
    http_uri: &str,
) -> Result<VerifyResult, OAuthError> {
    let token_info = extract_oauth_token_info(access_token)?;
    tracing::debug!(
        token_id = %token_info.token_id,
        has_dpop_proof = dpop_proof.is_some(),
        "Verifying OAuth access token"
    );
    let token_data = db::get_token_by_id(pool, &token_info.token_id)
        .await?
        .ok_or_else(|| {
            tracing::warn!(token_id = %token_info.token_id, "Token not found in database");
            OAuthError::InvalidToken("Token not found or revoked".to_string())
        })?;
    let now = chrono::Utc::now();
    if token_data.expires_at < now {
        return Err(OAuthError::ExpiredToken(
            "Token session has expired".to_string(),
        ));
    }
    if let Some(expected_jkt) = &token_data.parameters.dpop_jkt {
        tracing::debug!(expected_jkt = %expected_jkt, "Token requires DPoP");
        let proof = dpop_proof.ok_or_else(|| {
            tracing::warn!("DPoP proof required but not provided");
            OAuthError::UseDpopNonce("DPoP proof required".to_string())
        })?;
        let config = AuthConfig::get();
        let verifier = DPoPVerifier::new(config.dpop_secret().as_bytes());
        let access_token_hash = compute_ath(access_token);
        let result = verifier
            .verify_proof(proof, http_method, http_uri, Some(&access_token_hash))
            .map_err(|e| {
                tracing::warn!(error = ?e, http_method = %http_method, http_uri = %http_uri, "DPoP proof verification failed");
                e
            })?;
        if !db::check_and_record_dpop_jti(pool, &result.jti).await? {
            return Err(OAuthError::InvalidDpopProof(
                "DPoP proof has already been used".to_string(),
            ));
        }
        if &result.jkt != expected_jkt {
            return Err(OAuthError::InvalidDpopProof(
                "DPoP key binding mismatch".to_string(),
            ));
        }
    }
    Ok(VerifyResult {
        did: token_data.did,
        token_id: token_info.token_id,
        client_id: token_data.client_id,
        scope: token_data.scope,
    })
}

pub fn extract_oauth_token_info(token: &str) -> Result<OAuthTokenInfo, OAuthError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(OAuthError::InvalidToken("Invalid token format".to_string()));
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| OAuthError::InvalidToken("Invalid token encoding".to_string()))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|_| OAuthError::InvalidToken("Invalid token header".to_string()))?;
    if header.get("typ").and_then(|t| t.as_str()) != Some("at+jwt") {
        return Err(OAuthError::InvalidToken(
            "Not an OAuth access token".to_string(),
        ));
    }
    if header.get("alg").and_then(|a| a.as_str()) != Some("HS256") {
        return Err(OAuthError::InvalidToken(
            "Unsupported algorithm".to_string(),
        ));
    }
    let config = AuthConfig::get();
    let secret = config.jwt_secret();
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let provided_sig = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| OAuthError::InvalidToken("Invalid signature encoding".to_string()))?;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| OAuthError::ServerError("HMAC initialization failed".to_string()))?;
    mac.update(signing_input.as_bytes());
    let expected_sig = mac.finalize().into_bytes();
    if !bool::from(expected_sig.ct_eq(&provided_sig)) {
        return Err(OAuthError::InvalidToken(
            "Invalid token signature".to_string(),
        ));
    }
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| OAuthError::InvalidToken("Invalid payload encoding".to_string()))?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|_| OAuthError::InvalidToken("Invalid token payload".to_string()))?;
    let exp = payload
        .get("exp")
        .and_then(|e| e.as_i64())
        .ok_or_else(|| OAuthError::InvalidToken("Missing exp claim".to_string()))?;
    let now = chrono::Utc::now().timestamp();
    if exp < now {
        return Err(OAuthError::ExpiredToken("Token has expired".to_string()));
    }
    let token_id = payload
        .get("jti")
        .and_then(|j| j.as_str())
        .ok_or_else(|| OAuthError::InvalidToken("Missing jti claim".to_string()))?
        .to_string();
    let did = payload
        .get("sub")
        .and_then(|s| s.as_str())
        .ok_or_else(|| OAuthError::InvalidToken("Missing sub claim".to_string()))?
        .to_string();
    let scope = payload
        .get("scope")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string());
    let dpop_jkt = payload
        .get("cnf")
        .and_then(|c| c.get("jkt"))
        .and_then(|j| j.as_str())
        .map(|s| s.to_string());
    let client_id = payload
        .get("client_id")
        .and_then(|c| c.as_str())
        .map(|s| s.to_string())
        .unwrap_or_default();
    let controller_did = payload
        .get("act")
        .and_then(|a| a.get("sub"))
        .and_then(|s| s.as_str())
        .map(|s| s.to_string());
    Ok(OAuthTokenInfo {
        did,
        token_id,
        client_id,
        scope,
        dpop_jkt,
        controller_did,
    })
}

fn compute_ath(access_token: &str) -> String {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(access_token.as_bytes());
    let hash = hasher.finalize();
    URL_SAFE_NO_PAD.encode(hash)
}

pub fn generate_dpop_nonce() -> String {
    let config = AuthConfig::get();
    let verifier = DPoPVerifier::new(config.dpop_secret().as_bytes());
    verifier.generate_nonce()
}

pub struct OAuthUser {
    pub did: String,
    pub client_id: Option<String>,
    pub scope: Option<String>,
    pub is_oauth: bool,
    pub permissions: ScopePermissions,
}

pub struct OAuthAuthError {
    pub status: StatusCode,
    pub error: String,
    pub message: String,
    pub dpop_nonce: Option<String>,
    pub www_authenticate: Option<String>,
}

impl IntoResponse for OAuthAuthError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(json!({
                "error": self.error,
                "message": self.message
            })),
        )
            .into_response();
        if let Some(nonce) = self.dpop_nonce {
            response
                .headers_mut()
                .insert("DPoP-Nonce", nonce.parse().unwrap());
        }
        if let Some(www_auth) = self.www_authenticate {
            response
                .headers_mut()
                .insert("WWW-Authenticate", www_auth.parse().unwrap());
        }
        response
    }
}

impl FromRequestParts<AppState> for OAuthUser {
    type Rejection = OAuthAuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| OAuthAuthError {
                status: StatusCode::UNAUTHORIZED,
                error: "AuthenticationRequired".to_string(),
                message: "Authorization header required".to_string(),
                dpop_nonce: None,
                www_authenticate: None,
            })?;
        let auth_header_trimmed = auth_header.trim();
        let (token, is_dpop_token) = if auth_header_trimmed.len() >= 7
            && auth_header_trimmed[..7].eq_ignore_ascii_case("bearer ")
        {
            (auth_header_trimmed[7..].trim(), false)
        } else if auth_header_trimmed.len() >= 5
            && auth_header_trimmed[..5].eq_ignore_ascii_case("dpop ")
        {
            (auth_header_trimmed[5..].trim(), true)
        } else {
            return Err(OAuthAuthError {
                status: StatusCode::UNAUTHORIZED,
                error: "InvalidRequest".to_string(),
                message: "Invalid authorization scheme".to_string(),
                dpop_nonce: None,
                www_authenticate: None,
            });
        };
        let dpop_proof = parts.headers.get("DPoP").and_then(|v| v.to_str().ok());
        if let Ok(result) = try_legacy_auth(&state.db, token).await {
            return Ok(OAuthUser {
                did: result.did,
                client_id: None,
                scope: None,
                is_oauth: false,
                permissions: ScopePermissions::default(),
            });
        }
        let http_method = parts.method.as_str();
        let http_uri = crate::util::build_full_url(&parts.uri.to_string());
        match verify_oauth_access_token(&state.db, token, dpop_proof, http_method, &http_uri).await
        {
            Ok(result) => {
                let permissions = ScopePermissions::from_scope_string(result.scope.as_deref());
                Ok(OAuthUser {
                    did: result.did,
                    client_id: Some(result.client_id),
                    scope: result.scope,
                    is_oauth: true,
                    permissions,
                })
            }
            Err(OAuthError::UseDpopNonce(nonce)) => Err(OAuthAuthError {
                status: StatusCode::UNAUTHORIZED,
                error: "use_dpop_nonce".to_string(),
                message: "DPoP nonce required".to_string(),
                dpop_nonce: Some(nonce),
                www_authenticate: Some("DPoP error=\"use_dpop_nonce\"".to_string()),
            }),
            Err(OAuthError::InvalidDpopProof(msg)) => {
                let nonce = generate_dpop_nonce();
                Err(OAuthAuthError {
                    status: StatusCode::UNAUTHORIZED,
                    error: "invalid_dpop_proof".to_string(),
                    message: msg,
                    dpop_nonce: Some(nonce),
                    www_authenticate: None,
                })
            }
            Err(OAuthError::ExpiredToken(msg)) => {
                let nonce = if is_dpop_token {
                    Some(generate_dpop_nonce())
                } else {
                    None
                };
                let scheme = if is_dpop_token { "DPoP" } else { "Bearer" };
                let www_auth = format!(
                    "{} error=\"invalid_token\", error_description=\"{}\"",
                    scheme, msg
                );
                Err(OAuthAuthError {
                    status: StatusCode::UNAUTHORIZED,
                    error: "ExpiredToken".to_string(),
                    message: msg,
                    dpop_nonce: nonce,
                    www_authenticate: Some(www_auth),
                })
            }
            Err(OAuthError::InvalidToken(msg)) => {
                let nonce = if is_dpop_token {
                    Some(generate_dpop_nonce())
                } else {
                    None
                };
                let scheme = if is_dpop_token { "DPoP" } else { "Bearer" };
                let www_auth = format!(
                    "{} error=\"invalid_token\", error_description=\"{}\"",
                    scheme, msg
                );
                Err(OAuthAuthError {
                    status: StatusCode::UNAUTHORIZED,
                    error: "InvalidToken".to_string(),
                    message: msg,
                    dpop_nonce: nonce,
                    www_authenticate: Some(www_auth),
                })
            }
            Err(e) => {
                let nonce = if is_dpop_token {
                    Some(generate_dpop_nonce())
                } else {
                    None
                };
                Err(OAuthAuthError {
                    status: StatusCode::UNAUTHORIZED,
                    error: "AuthenticationFailed".to_string(),
                    message: format!("{:?}", e),
                    dpop_nonce: nonce,
                    www_authenticate: None,
                })
            }
        }
    }
}

struct LegacyAuthResult {
    did: String,
}

async fn try_legacy_auth(pool: &PgPool, token: &str) -> Result<LegacyAuthResult, ()> {
    match crate::auth::validate_bearer_token(pool, token).await {
        Ok(user) if !user.is_oauth => Ok(LegacyAuthResult { did: user.did }),
        _ => Err(()),
    }
}
