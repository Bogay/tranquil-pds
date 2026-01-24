use std::marker::PhantomData;

use axum::{
    extract::{FromRequestParts, OptionalFromRequestParts},
    http::{StatusCode, header::AUTHORIZATION, request::Parts},
    response::{IntoResponse, Response},
};
use tracing::{debug, error, info};

use super::{
    AccountStatus, AuthSource, AuthenticatedUser, ServiceTokenClaims, ServiceTokenVerifier,
    is_service_token, validate_bearer_token_for_service_auth,
};
use crate::api::error::ApiError;
use crate::oauth::scopes::{RepoAction, ScopePermissions};
use crate::state::AppState;
use crate::types::Did;
use crate::util::build_full_url;

#[derive(Debug)]
pub enum AuthError {
    MissingToken,
    InvalidFormat,
    AuthenticationFailed,
    TokenExpired,
    AccountDeactivated,
    AccountTakedown,
    AdminRequired,
    ServiceAuthNotAllowed,
    InsufficientScope(String),
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
            Self::InsufficientScope(msg) => ApiError::InsufficientScope(Some(msg)).into_response(),
            other => ApiError::from(other).into_response(),
        }
    }
}

pub struct ExtractedToken {
    pub token: String,
    pub is_dpop: bool,
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

pub trait AuthPolicy: Send + Sync + 'static {
    fn validate(user: &AuthenticatedUser) -> Result<(), AuthError>;
}

pub struct Permissive;

impl AuthPolicy for Permissive {
    fn validate(_user: &AuthenticatedUser) -> Result<(), AuthError> {
        Ok(())
    }
}

pub struct Active;

impl AuthPolicy for Active {
    fn validate(user: &AuthenticatedUser) -> Result<(), AuthError> {
        if user.status.is_deactivated() {
            return Err(AuthError::AccountDeactivated);
        }
        if user.status.is_takendown() {
            return Err(AuthError::AccountTakedown);
        }
        Ok(())
    }
}

pub struct NotTakendown;

impl AuthPolicy for NotTakendown {
    fn validate(user: &AuthenticatedUser) -> Result<(), AuthError> {
        if user.status.is_takendown() {
            return Err(AuthError::AccountTakedown);
        }
        Ok(())
    }
}

pub struct AnyUser;

impl AuthPolicy for AnyUser {
    fn validate(_user: &AuthenticatedUser) -> Result<(), AuthError> {
        Ok(())
    }
}

pub struct Admin;

impl AuthPolicy for Admin {
    fn validate(user: &AuthenticatedUser) -> Result<(), AuthError> {
        if user.status.is_deactivated() {
            return Err(AuthError::AccountDeactivated);
        }
        if user.status.is_takendown() {
            return Err(AuthError::AccountTakedown);
        }
        if !user.is_admin {
            return Err(AuthError::AdminRequired);
        }
        Ok(())
    }
}

impl AuthenticatedUser {
    pub fn require_active(&self) -> Result<&Self, ApiError> {
        if self.status.is_deactivated() {
            return Err(ApiError::AccountDeactivated);
        }
        if self.status.is_takendown() {
            return Err(ApiError::AccountTakedown);
        }
        Ok(self)
    }

    pub fn require_not_takendown(&self) -> Result<&Self, ApiError> {
        if self.status.is_takendown() {
            return Err(ApiError::AccountTakedown);
        }
        Ok(self)
    }

    pub fn require_admin(&self) -> Result<&Self, ApiError> {
        if !self.is_admin {
            return Err(ApiError::AdminRequired);
        }
        Ok(self)
    }
}

async fn verify_oauth_token_and_build_user(
    state: &AppState,
    token: &str,
    dpop_proof: Option<&str>,
    method: &str,
    uri: &str,
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
            Ok(AuthenticatedUser {
                did: result.did,
                key_bytes: user_info.key_bytes.and_then(|kb| {
                    crate::config::decrypt_key(&kb, user_info.encryption_version).ok()
                }),
                is_admin: user_info.is_admin,
                status,
                scope: result.scope,
                controller_did: None,
                auth_source: AuthSource::OAuth,
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

async fn verify_service_token(token: &str) -> Result<ServiceTokenClaims, AuthError> {
    let verifier = ServiceTokenVerifier::new();
    let claims = verifier
        .verify_service_token(token, None)
        .await
        .map_err(|e| {
            error!("Service token verification failed: {:?}", e);
            AuthError::AuthenticationFailed
        })?;

    debug!("Service token verified for DID: {}", claims.iss);
    Ok(claims)
}

enum ExtractedAuth {
    User(AuthenticatedUser),
    Service(ServiceTokenClaims),
}

async fn extract_auth_internal(
    parts: &mut Parts,
    state: &AppState,
) -> Result<ExtractedAuth, AuthError> {
    let auth_header = parts
        .headers
        .get(AUTHORIZATION)
        .ok_or(AuthError::MissingToken)?
        .to_str()
        .map_err(|_| AuthError::InvalidFormat)?;

    let extracted =
        extract_auth_token_from_header(Some(auth_header)).ok_or(AuthError::InvalidFormat)?;

    if is_service_token(&extracted.token) {
        let claims = verify_service_token(&extracted.token).await?;
        return Ok(ExtractedAuth::Service(claims));
    }

    let dpop_proof = parts.headers.get("DPoP").and_then(|h| h.to_str().ok());
    let method = parts.method.as_str();
    let uri = build_full_url(&parts.uri.to_string());

    match validate_bearer_token_for_service_auth(state.user_repo.as_ref(), &extracted.token).await {
        Ok(user) if !user.auth_source.is_oauth() => {
            return Ok(ExtractedAuth::User(user));
        }
        Ok(_) => {}
        Err(super::TokenValidationError::TokenExpired) => {
            info!("JWT access token expired, returning ExpiredToken");
            return Err(AuthError::TokenExpired);
        }
        Err(_) => {}
    }

    let user = verify_oauth_token_and_build_user(state, &extracted.token, dpop_proof, method, &uri)
        .await?;
    Ok(ExtractedAuth::User(user))
}

async fn extract_user_auth_internal(
    parts: &mut Parts,
    state: &AppState,
) -> Result<AuthenticatedUser, AuthError> {
    match extract_auth_internal(parts, state).await? {
        ExtractedAuth::User(user) => Ok(user),
        ExtractedAuth::Service(_) => Err(AuthError::ServiceAuthNotAllowed),
    }
}

pub struct Auth<P: AuthPolicy = Active>(pub AuthenticatedUser, PhantomData<P>);

impl<P: AuthPolicy> Auth<P> {
    pub fn into_inner(self) -> AuthenticatedUser {
        self.0
    }

    pub fn needs_scope_check(&self) -> bool {
        self.0.is_oauth()
    }

    pub fn permissions(&self) -> ScopePermissions {
        self.0.permissions()
    }

    #[allow(clippy::result_large_err)]
    pub fn check_repo_scope(&self, action: RepoAction, collection: &str) -> Result<(), Response> {
        if !self.needs_scope_check() {
            return Ok(());
        }
        self.permissions()
            .assert_repo(action, collection)
            .map_err(|e| ApiError::InsufficientScope(Some(e.to_string())).into_response())
    }
}

impl<P: AuthPolicy> std::ops::Deref for Auth<P> {
    type Target = AuthenticatedUser;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<P: AuthPolicy> FromRequestParts<AppState> for Auth<P> {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let user = extract_user_auth_internal(parts, state).await?;
        P::validate(&user)?;
        Ok(Auth(user, PhantomData))
    }
}

impl<P: AuthPolicy> OptionalFromRequestParts<AppState> for Auth<P> {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Option<Self>, Self::Rejection> {
        match extract_user_auth_internal(parts, state).await {
            Ok(user) => {
                P::validate(&user)?;
                Ok(Some(Auth(user, PhantomData)))
            }
            Err(AuthError::MissingToken) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

pub struct ServiceAuth {
    pub did: Did,
    pub claims: ServiceTokenClaims,
}

impl ServiceAuth {
    pub fn require_lxm(&self, expected_lxm: &str) -> Result<(), ApiError> {
        match &self.claims.lxm {
            Some(lxm) if lxm == "*" || lxm == expected_lxm => Ok(()),
            Some(lxm) => Err(ApiError::AuthorizationError(format!(
                "Token lxm '{}' does not permit '{}'",
                lxm, expected_lxm
            ))),
            None => Err(ApiError::AuthorizationError(
                "Token missing lxm claim".to_string(),
            )),
        }
    }
}

impl FromRequestParts<AppState> for ServiceAuth {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        match extract_auth_internal(parts, state).await? {
            ExtractedAuth::Service(claims) => {
                let did: Did = claims
                    .iss
                    .parse()
                    .map_err(|_| AuthError::AuthenticationFailed)?;
                Ok(ServiceAuth { did, claims })
            }
            ExtractedAuth::User(_) => Err(AuthError::AuthenticationFailed),
        }
    }
}

impl OptionalFromRequestParts<AppState> for ServiceAuth {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Option<Self>, Self::Rejection> {
        match extract_auth_internal(parts, state).await {
            Ok(ExtractedAuth::Service(claims)) => {
                let did: Did = claims
                    .iss
                    .parse()
                    .map_err(|_| AuthError::AuthenticationFailed)?;
                Ok(Some(ServiceAuth { did, claims }))
            }
            Ok(ExtractedAuth::User(_)) => Err(AuthError::AuthenticationFailed),
            Err(AuthError::MissingToken) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

pub enum AuthAny<P: AuthPolicy = Active> {
    User(Auth<P>),
    Service(ServiceAuth),
}

impl<P: AuthPolicy> AuthAny<P> {
    pub fn did(&self) -> &Did {
        match self {
            Self::User(auth) => &auth.did,
            Self::Service(auth) => &auth.did,
        }
    }

    pub fn as_user(&self) -> Option<&Auth<P>> {
        match self {
            Self::User(auth) => Some(auth),
            Self::Service(_) => None,
        }
    }

    pub fn as_service(&self) -> Option<&ServiceAuth> {
        match self {
            Self::User(_) => None,
            Self::Service(auth) => Some(auth),
        }
    }

    pub fn is_service(&self) -> bool {
        matches!(self, Self::Service(_))
    }

    pub fn require_lxm(&self, expected_lxm: &str) -> Result<(), ApiError> {
        match self {
            Self::User(_) => Ok(()),
            Self::Service(auth) => auth.require_lxm(expected_lxm),
        }
    }
}

impl<P: AuthPolicy> FromRequestParts<AppState> for AuthAny<P> {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        match extract_auth_internal(parts, state).await? {
            ExtractedAuth::User(user) => {
                P::validate(&user)?;
                Ok(AuthAny::User(Auth(user, PhantomData)))
            }
            ExtractedAuth::Service(claims) => {
                let did: Did = claims
                    .iss
                    .parse()
                    .map_err(|_| AuthError::AuthenticationFailed)?;
                Ok(AuthAny::Service(ServiceAuth { did, claims }))
            }
        }
    }
}

impl<P: AuthPolicy> OptionalFromRequestParts<AppState> for AuthAny<P> {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Option<Self>, Self::Rejection> {
        match extract_auth_internal(parts, state).await {
            Ok(ExtractedAuth::User(user)) => {
                P::validate(&user)?;
                Ok(Some(AuthAny::User(Auth(user, PhantomData))))
            }
            Ok(ExtractedAuth::Service(claims)) => {
                let did: Did = claims
                    .iss
                    .parse()
                    .map_err(|_| AuthError::AuthenticationFailed)?;
                Ok(Some(AuthAny::Service(ServiceAuth { did, claims })))
            }
            Err(AuthError::MissingToken) => Ok(None),
            Err(e) => Err(e),
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
