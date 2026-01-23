use axum::{
    extract::FromRequestParts,
    http::{StatusCode, header::AUTHORIZATION, request::Parts},
    response::{IntoResponse, Response},
};
use tracing::{debug, error, info};

use super::{
    AccountStatus, AuthenticatedUser, ServiceTokenClaims, ServiceTokenVerifier, is_service_token,
    validate_bearer_token, validate_bearer_token_allow_deactivated,
    validate_bearer_token_allow_takendown,
};
use crate::api::error::ApiError;
use crate::state::AppState;
use crate::types::Did;
use crate::util::build_full_url;

pub struct BearerAuth(pub AuthenticatedUser);

#[derive(Debug)]
pub enum AuthError {
    MissingToken,
    InvalidFormat,
    AuthenticationFailed,
    TokenExpired,
    AccountDeactivated,
    AccountTakedown,
    AdminRequired,
    OAuthExpiredToken(String),
    UseDpopNonce(String),
    InvalidDpopProof(String),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        match self {
            Self::UseDpopNonce(nonce) => (
                StatusCode::UNAUTHORIZED,
                [
                    ("DPoP-Nonce", nonce.as_str()),
                    ("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\""),
                ],
                axum::Json(serde_json::json!({
                    "error": "use_dpop_nonce",
                    "message": "DPoP nonce required"
                })),
            )
                .into_response(),
            Self::OAuthExpiredToken(msg) => ApiError::OAuthExpiredToken(Some(msg)).into_response(),
            Self::InvalidDpopProof(msg) => (
                StatusCode::UNAUTHORIZED,
                [("WWW-Authenticate", "DPoP error=\"invalid_dpop_proof\"")],
                axum::Json(serde_json::json!({
                    "error": "invalid_dpop_proof",
                    "message": msg
                })),
            )
                .into_response(),
            other => ApiError::from(other).into_response(),
        }
    }
}

#[cfg(test)]
fn extract_bearer_token(auth_header: &str) -> Result<&str, AuthError> {
    let auth_header = auth_header.trim();

    if auth_header.len() < 8 {
        return Err(AuthError::InvalidFormat);
    }

    let prefix = &auth_header[..7];
    if !prefix.eq_ignore_ascii_case("bearer ") {
        return Err(AuthError::InvalidFormat);
    }

    let token = auth_header[7..].trim();
    if token.is_empty() {
        return Err(AuthError::InvalidFormat);
    }

    Ok(token)
}

pub fn extract_bearer_token_from_header(auth_header: Option<&str>) -> Option<String> {
    let header = auth_header?;
    let header = header.trim();

    if header.len() < 7 {
        return None;
    }

    if !header[..7].eq_ignore_ascii_case("bearer ") {
        return None;
    }

    let token = header[7..].trim();
    if token.is_empty() {
        return None;
    }

    Some(token.to_string())
}

pub struct ExtractedToken {
    pub token: String,
    pub is_dpop: bool,
}

pub fn extract_auth_token_from_header(auth_header: Option<&str>) -> Option<ExtractedToken> {
    let header = auth_header?;
    let header = header.trim();

    if header.len() >= 7 && header[..7].eq_ignore_ascii_case("bearer ") {
        let token = header[7..].trim();
        if token.is_empty() {
            return None;
        }
        return Some(ExtractedToken {
            token: token.to_string(),
            is_dpop: false,
        });
    }

    if header.len() >= 5 && header[..5].eq_ignore_ascii_case("dpop ") {
        let token = header[5..].trim();
        if token.is_empty() {
            return None;
        }
        return Some(ExtractedToken {
            token: token.to_string(),
            is_dpop: true,
        });
    }

    None
}

#[derive(Default)]
struct StatusCheckFlags {
    allow_deactivated: bool,
    allow_takendown: bool,
}

async fn verify_oauth_token_and_build_user(
    state: &AppState,
    token: &str,
    dpop_proof: Option<&str>,
    method: &str,
    uri: &str,
    flags: StatusCheckFlags,
) -> Result<AuthenticatedUser, AuthError> {
    match crate::oauth::verify::verify_oauth_access_token(
        state.oauth_repo.as_ref(),
        token,
        dpop_proof,
        method,
        uri,
    )
    .await
    {
        Ok(result) => {
            let user_info = state
                .user_repo
                .get_user_info_by_did(&result.did)
                .await
                .ok()
                .flatten()
                .ok_or(AuthError::AuthenticationFailed)?;
            let status = AccountStatus::from_db_fields(
                user_info.takedown_ref.as_deref(),
                user_info.deactivated_at,
            );
            if !flags.allow_deactivated && status.is_deactivated() {
                return Err(AuthError::AccountDeactivated);
            }
            if !flags.allow_takendown && status.is_takendown() {
                return Err(AuthError::AccountTakedown);
            }
            Ok(AuthenticatedUser {
                did: result.did,
                key_bytes: user_info.key_bytes.and_then(|kb| {
                    crate::config::decrypt_key(&kb, user_info.encryption_version).ok()
                }),
                is_oauth: true,
                is_admin: user_info.is_admin,
                status,
                scope: result.scope,
                controller_did: None,
            })
        }
        Err(crate::oauth::OAuthError::ExpiredToken(msg)) => Err(AuthError::OAuthExpiredToken(msg)),
        Err(crate::oauth::OAuthError::UseDpopNonce(nonce)) => Err(AuthError::UseDpopNonce(nonce)),
        Err(crate::oauth::OAuthError::InvalidDpopProof(msg)) => {
            Err(AuthError::InvalidDpopProof(msg))
        }
        Err(_) => Err(AuthError::AuthenticationFailed),
    }
}

impl FromRequestParts<AppState> for BearerAuth {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .ok_or(AuthError::MissingToken)?
            .to_str()
            .map_err(|_| AuthError::InvalidFormat)?;

        let extracted =
            extract_auth_token_from_header(Some(auth_header)).ok_or(AuthError::InvalidFormat)?;

        let dpop_proof = parts.headers.get("DPoP").and_then(|h| h.to_str().ok());
        let method = parts.method.as_str();
        let uri = build_full_url(&parts.uri.to_string());

        match validate_bearer_token(state.user_repo.as_ref(), &extracted.token).await {
            Ok(user) if !user.is_oauth => {
                return if user.status.is_deactivated() {
                    Err(AuthError::AccountDeactivated)
                } else if user.status.is_takendown() {
                    Err(AuthError::AccountTakedown)
                } else {
                    Ok(BearerAuth(user))
                };
            }
            Ok(_) => {}
            Err(super::TokenValidationError::AccountDeactivated) => {
                return Err(AuthError::AccountDeactivated);
            }
            Err(super::TokenValidationError::AccountTakedown) => {
                return Err(AuthError::AccountTakedown);
            }
            Err(super::TokenValidationError::TokenExpired) => {
                info!("JWT access token expired in BearerAuth, returning ExpiredToken");
                return Err(AuthError::TokenExpired);
            }
            Err(_) => {}
        }

        verify_oauth_token_and_build_user(
            state,
            &extracted.token,
            dpop_proof,
            method,
            &uri,
            StatusCheckFlags::default(),
        )
        .await
        .map(BearerAuth)
    }
}

pub struct BearerAuthAllowDeactivated(pub AuthenticatedUser);

impl FromRequestParts<AppState> for BearerAuthAllowDeactivated {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .ok_or(AuthError::MissingToken)?
            .to_str()
            .map_err(|_| AuthError::InvalidFormat)?;

        let extracted =
            extract_auth_token_from_header(Some(auth_header)).ok_or(AuthError::InvalidFormat)?;

        let dpop_proof = parts.headers.get("DPoP").and_then(|h| h.to_str().ok());
        let method = parts.method.as_str();
        let uri = build_full_url(&parts.uri.to_string());

        match validate_bearer_token_allow_deactivated(state.user_repo.as_ref(), &extracted.token)
            .await
        {
            Ok(user) if !user.is_oauth => {
                return if user.status.is_takendown() {
                    Err(AuthError::AccountTakedown)
                } else {
                    Ok(BearerAuthAllowDeactivated(user))
                };
            }
            Ok(_) => {}
            Err(super::TokenValidationError::AccountTakedown) => {
                return Err(AuthError::AccountTakedown);
            }
            Err(super::TokenValidationError::TokenExpired) => {
                return Err(AuthError::TokenExpired);
            }
            Err(_) => {}
        }

        verify_oauth_token_and_build_user(
            state,
            &extracted.token,
            dpop_proof,
            method,
            &uri,
            StatusCheckFlags {
                allow_deactivated: true,
                allow_takendown: false,
            },
        )
        .await
        .map(BearerAuthAllowDeactivated)
    }
}

pub struct BearerAuthAllowTakendown(pub AuthenticatedUser);

impl FromRequestParts<AppState> for BearerAuthAllowTakendown {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .ok_or(AuthError::MissingToken)?
            .to_str()
            .map_err(|_| AuthError::InvalidFormat)?;

        let extracted =
            extract_auth_token_from_header(Some(auth_header)).ok_or(AuthError::InvalidFormat)?;

        let dpop_proof = parts.headers.get("DPoP").and_then(|h| h.to_str().ok());
        let method = parts.method.as_str();
        let uri = build_full_url(&parts.uri.to_string());

        match validate_bearer_token_allow_takendown(state.user_repo.as_ref(), &extracted.token)
            .await
        {
            Ok(user) if !user.is_oauth => {
                return if user.status.is_deactivated() {
                    Err(AuthError::AccountDeactivated)
                } else {
                    Ok(BearerAuthAllowTakendown(user))
                };
            }
            Ok(_) => {}
            Err(super::TokenValidationError::AccountDeactivated) => {
                return Err(AuthError::AccountDeactivated);
            }
            Err(super::TokenValidationError::TokenExpired) => {
                return Err(AuthError::TokenExpired);
            }
            Err(_) => {}
        }

        verify_oauth_token_and_build_user(
            state,
            &extracted.token,
            dpop_proof,
            method,
            &uri,
            StatusCheckFlags {
                allow_deactivated: false,
                allow_takendown: true,
            },
        )
        .await
        .map(BearerAuthAllowTakendown)
    }
}

pub struct BearerAuthAdmin(pub AuthenticatedUser);

impl FromRequestParts<AppState> for BearerAuthAdmin {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .ok_or(AuthError::MissingToken)?
            .to_str()
            .map_err(|_| AuthError::InvalidFormat)?;

        let extracted =
            extract_auth_token_from_header(Some(auth_header)).ok_or(AuthError::InvalidFormat)?;

        let dpop_proof = parts.headers.get("DPoP").and_then(|h| h.to_str().ok());
        let method = parts.method.as_str();
        let uri = build_full_url(&parts.uri.to_string());

        match validate_bearer_token(state.user_repo.as_ref(), &extracted.token).await {
            Ok(user) if !user.is_oauth => {
                if user.status.is_deactivated() {
                    return Err(AuthError::AccountDeactivated);
                }
                if user.status.is_takendown() {
                    return Err(AuthError::AccountTakedown);
                }
                if !user.is_admin {
                    return Err(AuthError::AdminRequired);
                }
                return Ok(BearerAuthAdmin(user));
            }
            Ok(_) => {}
            Err(super::TokenValidationError::AccountDeactivated) => {
                return Err(AuthError::AccountDeactivated);
            }
            Err(super::TokenValidationError::AccountTakedown) => {
                return Err(AuthError::AccountTakedown);
            }
            Err(super::TokenValidationError::TokenExpired) => {
                return Err(AuthError::TokenExpired);
            }
            Err(_) => {}
        }

        let user = verify_oauth_token_and_build_user(
            state,
            &extracted.token,
            dpop_proof,
            method,
            &uri,
            StatusCheckFlags::default(),
        )
        .await?;

        if !user.is_admin {
            return Err(AuthError::AdminRequired);
        }
        Ok(BearerAuthAdmin(user))
    }
}

pub struct OptionalBearerAuth(pub Option<AuthenticatedUser>);

impl FromRequestParts<AppState> for OptionalBearerAuth {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = match parts.headers.get(AUTHORIZATION) {
            Some(h) => match h.to_str() {
                Ok(s) => s,
                Err(_) => return Ok(OptionalBearerAuth(None)),
            },
            None => return Ok(OptionalBearerAuth(None)),
        };

        let extracted = match extract_auth_token_from_header(Some(auth_header)) {
            Some(e) => e,
            None => return Ok(OptionalBearerAuth(None)),
        };

        let dpop_proof = parts.headers.get("DPoP").and_then(|h| h.to_str().ok());
        let method = parts.method.as_str();
        let uri = build_full_url(&parts.uri.to_string());

        if let Ok(user) = validate_bearer_token(state.user_repo.as_ref(), &extracted.token).await
            && !user.is_oauth
        {
            return if user.status.is_deactivated() || user.status.is_takendown() {
                Ok(OptionalBearerAuth(None))
            } else {
                Ok(OptionalBearerAuth(Some(user)))
            };
        }

        Ok(OptionalBearerAuth(
            verify_oauth_token_and_build_user(
                state,
                &extracted.token,
                dpop_proof,
                method,
                &uri,
                StatusCheckFlags::default(),
            )
            .await
            .ok(),
        ))
    }
}

pub struct ServiceAuth {
    pub claims: ServiceTokenClaims,
    pub did: Did,
}

impl FromRequestParts<AppState> for ServiceAuth {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .ok_or(AuthError::MissingToken)?
            .to_str()
            .map_err(|_| AuthError::InvalidFormat)?;

        let extracted =
            extract_auth_token_from_header(Some(auth_header)).ok_or(AuthError::InvalidFormat)?;

        if !is_service_token(&extracted.token) {
            return Err(AuthError::InvalidFormat);
        }

        let verifier = ServiceTokenVerifier::new();
        let claims = verifier
            .verify_service_token(&extracted.token, None)
            .await
            .map_err(|e| {
                error!("Service token verification failed: {:?}", e);
                AuthError::AuthenticationFailed
            })?;

        let did: Did = claims
            .iss
            .parse()
            .map_err(|_| AuthError::AuthenticationFailed)?;

        debug!("Service token verified for DID: {}", did);

        Ok(ServiceAuth { claims, did })
    }
}

pub struct OptionalServiceAuth(pub Option<ServiceTokenClaims>);

impl FromRequestParts<AppState> for OptionalServiceAuth {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = match parts.headers.get(AUTHORIZATION) {
            Some(h) => match h.to_str() {
                Ok(s) => s,
                Err(_) => return Ok(OptionalServiceAuth(None)),
            },
            None => return Ok(OptionalServiceAuth(None)),
        };

        let extracted = match extract_auth_token_from_header(Some(auth_header)) {
            Some(e) => e,
            None => return Ok(OptionalServiceAuth(None)),
        };

        if !is_service_token(&extracted.token) {
            return Ok(OptionalServiceAuth(None));
        }

        let verifier = ServiceTokenVerifier::new();
        match verifier.verify_service_token(&extracted.token, None).await {
            Ok(claims) => {
                debug!("Service token verified for DID: {}", claims.iss);
                Ok(OptionalServiceAuth(Some(claims)))
            }
            Err(e) => {
                debug!("Service token verification failed (optional): {:?}", e);
                Ok(OptionalServiceAuth(None))
            }
        }
    }
}

pub enum BlobAuthResult {
    Service { did: Did },
    User(AuthenticatedUser),
}

pub struct BlobAuth(pub BlobAuthResult);

impl FromRequestParts<AppState> for BlobAuth {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .ok_or(AuthError::MissingToken)?
            .to_str()
            .map_err(|_| AuthError::InvalidFormat)?;

        let extracted =
            extract_auth_token_from_header(Some(auth_header)).ok_or(AuthError::InvalidFormat)?;

        if is_service_token(&extracted.token) {
            debug!("Verifying service token for blob upload");
            let verifier = ServiceTokenVerifier::new();
            let claims = verifier
                .verify_service_token(&extracted.token, Some("com.atproto.repo.uploadBlob"))
                .await
                .map_err(|e| {
                    error!("Service token verification failed: {:?}", e);
                    AuthError::AuthenticationFailed
                })?;

            let did: Did = claims
                .iss
                .parse()
                .map_err(|_| AuthError::AuthenticationFailed)?;

            debug!("Service token verified for DID: {}", did);
            return Ok(BlobAuth(BlobAuthResult::Service { did }));
        }

        let dpop_proof = parts.headers.get("DPoP").and_then(|h| h.to_str().ok());
        let uri = build_full_url("/xrpc/com.atproto.repo.uploadBlob");

        if let Ok(user) =
            validate_bearer_token_allow_deactivated(state.user_repo.as_ref(), &extracted.token)
                .await
            && !user.is_oauth
        {
            return if user.status.is_takendown() {
                Err(AuthError::AccountTakedown)
            } else {
                Ok(BlobAuth(BlobAuthResult::User(user)))
            };
        }

        verify_oauth_token_and_build_user(
            state,
            &extracted.token,
            dpop_proof,
            "POST",
            &uri,
            StatusCheckFlags {
                allow_deactivated: true,
                allow_takendown: false,
            },
        )
        .await
        .map(|user| BlobAuth(BlobAuthResult::User(user)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_bearer_token() {
        assert_eq!(extract_bearer_token("Bearer abc123").unwrap(), "abc123");
        assert_eq!(extract_bearer_token("bearer abc123").unwrap(), "abc123");
        assert_eq!(extract_bearer_token("BEARER abc123").unwrap(), "abc123");
        assert_eq!(extract_bearer_token("Bearer  abc123").unwrap(), "abc123");
        assert_eq!(extract_bearer_token(" Bearer abc123 ").unwrap(), "abc123");

        assert!(extract_bearer_token("Basic abc123").is_err());
        assert!(extract_bearer_token("Bearer").is_err());
        assert!(extract_bearer_token("Bearer ").is_err());
        assert!(extract_bearer_token("abc123").is_err());
        assert!(extract_bearer_token("").is_err());
    }
}
