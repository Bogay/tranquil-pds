use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use crate::cache::Cache;
use crate::oauth::scopes::ScopePermissions;

pub mod extractor;
pub mod scope_check;
pub mod service;
pub mod token;
pub mod totp;
pub mod verification_token;
pub mod verify;
pub mod webauthn;

pub use extractor::{
    AuthError, BearerAuth, BearerAuthAdmin, BearerAuthAllowDeactivated, ExtractedToken,
    extract_auth_token_from_header, extract_bearer_token_from_header,
};
pub use service::{ServiceTokenClaims, ServiceTokenVerifier, is_service_token};
pub use token::{
    SCOPE_ACCESS, SCOPE_APP_PASS, SCOPE_APP_PASS_PRIVILEGED, SCOPE_REFRESH, TOKEN_TYPE_ACCESS,
    TOKEN_TYPE_REFRESH, TOKEN_TYPE_SERVICE, TokenWithMetadata, create_access_token,
    create_access_token_with_delegation, create_access_token_with_metadata,
    create_access_token_with_scope_metadata, create_refresh_token,
    create_refresh_token_with_metadata, create_service_token,
};
pub use verify::{
    TokenVerifyError, get_did_from_token, get_jti_from_token, verify_access_token,
    verify_access_token_typed, verify_refresh_token, verify_token,
};

const KEY_CACHE_TTL_SECS: u64 = 300;
const SESSION_CACHE_TTL_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenValidationError {
    AccountDeactivated,
    AccountTakedown,
    KeyDecryptionFailed,
    AuthenticationFailed,
    TokenExpired,
}

impl fmt::Display for TokenValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccountDeactivated => write!(f, "AccountDeactivated"),
            Self::AccountTakedown => write!(f, "AccountTakedown"),
            Self::KeyDecryptionFailed => write!(f, "KeyDecryptionFailed"),
            Self::AuthenticationFailed => write!(f, "AuthenticationFailed"),
            Self::TokenExpired => write!(f, "ExpiredToken"),
        }
    }
}

pub struct AuthenticatedUser {
    pub did: String,
    pub key_bytes: Option<Vec<u8>>,
    pub is_oauth: bool,
    pub is_admin: bool,
    pub is_takendown: bool,
    pub scope: Option<String>,
    pub controller_did: Option<String>,
}

impl AuthenticatedUser {
    pub fn permissions(&self) -> ScopePermissions {
        if let Some(ref scope) = self.scope
            && scope != SCOPE_ACCESS
        {
            return ScopePermissions::from_scope_string(Some(scope));
        }
        if !self.is_oauth {
            return ScopePermissions::from_scope_string(Some("atproto"));
        }
        ScopePermissions::from_scope_string(self.scope.as_deref())
    }
}

pub async fn validate_bearer_token(
    db: &PgPool,
    token: &str,
) -> Result<AuthenticatedUser, TokenValidationError> {
    validate_bearer_token_with_options_internal(db, None, token, false, false).await
}

pub async fn validate_bearer_token_allow_deactivated(
    db: &PgPool,
    token: &str,
) -> Result<AuthenticatedUser, TokenValidationError> {
    validate_bearer_token_with_options_internal(db, None, token, true, false).await
}

pub async fn validate_bearer_token_cached(
    db: &PgPool,
    cache: &Arc<dyn Cache>,
    token: &str,
) -> Result<AuthenticatedUser, TokenValidationError> {
    validate_bearer_token_with_options_internal(db, Some(cache), token, false, false).await
}

pub async fn validate_bearer_token_cached_allow_deactivated(
    db: &PgPool,
    cache: &Arc<dyn Cache>,
    token: &str,
) -> Result<AuthenticatedUser, TokenValidationError> {
    validate_bearer_token_with_options_internal(db, Some(cache), token, true, false).await
}

pub async fn validate_bearer_token_for_service_auth(
    db: &PgPool,
    token: &str,
) -> Result<AuthenticatedUser, TokenValidationError> {
    validate_bearer_token_with_options_internal(db, None, token, true, true).await
}

pub async fn validate_bearer_token_allow_takendown(
    db: &PgPool,
    token: &str,
) -> Result<AuthenticatedUser, TokenValidationError> {
    validate_bearer_token_with_options_internal(db, None, token, false, true).await
}

async fn validate_bearer_token_with_options_internal(
    db: &PgPool,
    cache: Option<&Arc<dyn Cache>>,
    token: &str,
    allow_deactivated: bool,
    allow_takendown: bool,
) -> Result<AuthenticatedUser, TokenValidationError> {
    let did_from_token = get_did_from_token(token).ok();

    if let Some(ref did) = did_from_token {
        let key_cache_key = format!("auth:key:{}", did);
        let mut cached_key: Option<Vec<u8>> = None;

        if let Some(c) = cache {
            cached_key = c.get_bytes(&key_cache_key).await;
            if cached_key.is_some() {
                crate::metrics::record_auth_cache_hit("key");
            } else {
                crate::metrics::record_auth_cache_miss("key");
            }
        }

        let (decrypted_key, deactivated_at, takedown_ref, is_admin) = if let Some(key) = cached_key
        {
            let user_status = sqlx::query!(
                "SELECT deactivated_at, takedown_ref, is_admin FROM users WHERE did = $1",
                did
            )
            .fetch_optional(db)
            .await
            .ok()
            .flatten();

            match user_status {
                Some(status) => (
                    Some(key),
                    status.deactivated_at,
                    status.takedown_ref,
                    status.is_admin,
                ),
                None => (None, None, None, false),
            }
        } else if let Some(user) = sqlx::query!(
            "SELECT k.key_bytes, k.encryption_version, u.deactivated_at, u.takedown_ref, u.is_admin
             FROM users u
             JOIN user_keys k ON u.id = k.user_id
             WHERE u.did = $1",
            did
        )
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        {
            let key = crate::config::decrypt_key(&user.key_bytes, user.encryption_version)
                .map_err(|_| TokenValidationError::KeyDecryptionFailed)?;

            if let Some(c) = cache {
                let _ = c
                    .set_bytes(
                        &key_cache_key,
                        &key,
                        Duration::from_secs(KEY_CACHE_TTL_SECS),
                    )
                    .await;
            }

            (
                Some(key),
                user.deactivated_at,
                user.takedown_ref,
                user.is_admin,
            )
        } else {
            (None, None, None, false)
        };

        if let Some(decrypted_key) = decrypted_key {
            if !allow_deactivated && deactivated_at.is_some() {
                return Err(TokenValidationError::AccountDeactivated);
            }

            if !allow_takendown && takedown_ref.is_some() {
                return Err(TokenValidationError::AccountTakedown);
            }

            match verify_access_token_typed(token, &decrypted_key) {
                Ok(token_data) => {
                    let jti = &token_data.claims.jti;
                    let session_cache_key = format!("auth:session:{}:{}", did, jti);
                    let mut session_valid = false;

                    if let Some(c) = cache {
                        if let Some(cached_value) = c.get(&session_cache_key).await {
                            session_valid = cached_value == "1";
                            crate::metrics::record_auth_cache_hit("session");
                        } else {
                            crate::metrics::record_auth_cache_miss("session");
                        }
                    }

                    if !session_valid {
                        let session_row = sqlx::query!(
                            "SELECT access_expires_at FROM session_tokens WHERE did = $1 AND access_jti = $2",
                            did,
                            jti
                        )
                        .fetch_optional(db)
                        .await
                        .ok()
                        .flatten();

                        if let Some(row) = session_row {
                            if row.access_expires_at > chrono::Utc::now() {
                                session_valid = true;
                                if let Some(c) = cache {
                                    let _ = c
                                        .set(
                                            &session_cache_key,
                                            "1",
                                            Duration::from_secs(SESSION_CACHE_TTL_SECS),
                                        )
                                        .await;
                                }
                            } else {
                                return Err(TokenValidationError::TokenExpired);
                            }
                        }
                    }

                    if session_valid {
                        let controller_did = token_data.claims.act.as_ref().map(|a| a.sub.clone());
                        return Ok(AuthenticatedUser {
                            did: did.clone(),
                            key_bytes: Some(decrypted_key),
                            is_oauth: false,
                            is_admin,
                            is_takendown: takedown_ref.is_some(),
                            scope: token_data.claims.scope.clone(),
                            controller_did,
                        });
                    }
                }
                Err(verify::TokenVerifyError::Expired) => {
                    return Err(TokenValidationError::TokenExpired);
                }
                Err(verify::TokenVerifyError::Invalid) => {}
            }
        }
    }

    if let Ok(oauth_info) = crate::oauth::verify::extract_oauth_token_info(token)
        && let Some(oauth_token) = sqlx::query!(
            r#"SELECT t.did, t.expires_at, u.deactivated_at, u.takedown_ref, u.is_admin,
                      k.key_bytes as "key_bytes?", k.encryption_version as "encryption_version?"
               FROM oauth_token t
               JOIN users u ON t.did = u.did
               LEFT JOIN user_keys k ON u.id = k.user_id
               WHERE t.token_id = $1"#,
            oauth_info.token_id
        )
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
    {
        if !allow_deactivated && oauth_token.deactivated_at.is_some() {
            return Err(TokenValidationError::AccountDeactivated);
        }

        let is_takendown = oauth_token.takedown_ref.is_some();
        if !allow_takendown && is_takendown {
            return Err(TokenValidationError::AccountTakedown);
        }

        let now = chrono::Utc::now();
        if oauth_token.expires_at > now {
            let key_bytes = if let (Some(kb), Some(ev)) =
                (&oauth_token.key_bytes, oauth_token.encryption_version)
            {
                crate::config::decrypt_key(kb, Some(ev)).ok()
            } else {
                None
            };
            return Ok(AuthenticatedUser {
                did: oauth_token.did,
                key_bytes,
                is_oauth: true,
                is_admin: oauth_token.is_admin,
                is_takendown,
                scope: oauth_info.scope,
                controller_did: oauth_info.controller_did,
            });
        } else {
            return Err(TokenValidationError::TokenExpired);
        }
    }

    Err(TokenValidationError::AuthenticationFailed)
}

pub async fn invalidate_auth_cache(cache: &Arc<dyn Cache>, did: &str) {
    let key_cache_key = format!("auth:key:{}", did);
    let _ = cache.delete(&key_cache_key).await;
}

pub async fn validate_token_with_dpop(
    db: &PgPool,
    token: &str,
    is_dpop_token: bool,
    dpop_proof: Option<&str>,
    http_method: &str,
    http_uri: &str,
    allow_deactivated: bool,
) -> Result<AuthenticatedUser, TokenValidationError> {
    if !is_dpop_token {
        if allow_deactivated {
            return validate_bearer_token_allow_deactivated(db, token).await;
        } else {
            return validate_bearer_token(db, token).await;
        }
    }
    match crate::oauth::verify::verify_oauth_access_token(
        db,
        token,
        dpop_proof,
        http_method,
        http_uri,
    )
    .await
    {
        Ok(result) => {
            let user_info = sqlx::query!(
                r#"SELECT u.deactivated_at, u.takedown_ref, u.is_admin,
                          k.key_bytes as "key_bytes?", k.encryption_version as "encryption_version?"
                   FROM users u
                   LEFT JOIN user_keys k ON u.id = k.user_id
                   WHERE u.did = $1"#,
                result.did
            )
            .fetch_optional(db)
            .await
            .ok()
            .flatten();
            let Some(user_info) = user_info else {
                return Err(TokenValidationError::AuthenticationFailed);
            };
            if !allow_deactivated && user_info.deactivated_at.is_some() {
                return Err(TokenValidationError::AccountDeactivated);
            }
            let is_takendown = user_info.takedown_ref.is_some();
            if is_takendown {
                return Err(TokenValidationError::AccountTakedown);
            }
            let key_bytes = if let (Some(kb), Some(ev)) =
                (&user_info.key_bytes, user_info.encryption_version)
            {
                crate::config::decrypt_key(kb, Some(ev)).ok()
            } else {
                None
            };
            Ok(AuthenticatedUser {
                did: result.did,
                key_bytes,
                is_oauth: true,
                is_admin: user_info.is_admin,
                is_takendown,
                scope: result.scope,
                controller_did: None,
            })
        }
        Err(crate::oauth::OAuthError::ExpiredToken(_)) => Err(TokenValidationError::TokenExpired),
        Err(_) => Err(TokenValidationError::AuthenticationFailed),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActClaim {
    pub sub: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lxm: Option<String>,
    pub jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<ActClaim>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Header {
    pub alg: String,
    pub typ: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnsafeClaims {
    pub iss: String,
    pub sub: Option<String>,
}

pub struct TokenData<T> {
    pub claims: T,
}
