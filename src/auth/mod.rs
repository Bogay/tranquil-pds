use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use crate::cache::Cache;

pub mod extractor;
pub mod token;
pub mod verify;

pub use extractor::{BearerAuth, BearerAuthAllowDeactivated, AuthError, extract_bearer_token_from_header};
pub use token::{
    create_access_token, create_refresh_token, create_service_token,
    create_access_token_with_metadata, create_refresh_token_with_metadata,
    TokenWithMetadata,
    TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH, TOKEN_TYPE_SERVICE,
    SCOPE_ACCESS, SCOPE_REFRESH, SCOPE_APP_PASS, SCOPE_APP_PASS_PRIVILEGED,
};
pub use verify::{get_did_from_token, get_jti_from_token, verify_token, verify_access_token, verify_refresh_token};

const KEY_CACHE_TTL_SECS: u64 = 300;
const SESSION_CACHE_TTL_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenValidationError {
    AccountDeactivated,
    AccountTakedown,
    KeyDecryptionFailed,
    AuthenticationFailed,
}

impl fmt::Display for TokenValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccountDeactivated => write!(f, "AccountDeactivated"),
            Self::AccountTakedown => write!(f, "AccountTakedown"),
            Self::KeyDecryptionFailed => write!(f, "KeyDecryptionFailed"),
            Self::AuthenticationFailed => write!(f, "AuthenticationFailed"),
        }
    }
}

pub struct AuthenticatedUser {
    pub did: String,
    pub key_bytes: Option<Vec<u8>>,
    pub is_oauth: bool,
}

pub async fn validate_bearer_token(
    db: &PgPool,
    token: &str,
) -> Result<AuthenticatedUser, TokenValidationError> {
    validate_bearer_token_with_options_internal(db, None, token, false).await
}

pub async fn validate_bearer_token_allow_deactivated(
    db: &PgPool,
    token: &str,
) -> Result<AuthenticatedUser, TokenValidationError> {
    validate_bearer_token_with_options_internal(db, None, token, true).await
}

pub async fn validate_bearer_token_cached(
    db: &PgPool,
    cache: &Arc<dyn Cache>,
    token: &str,
) -> Result<AuthenticatedUser, TokenValidationError> {
    validate_bearer_token_with_options_internal(db, Some(cache), token, false).await
}

pub async fn validate_bearer_token_cached_allow_deactivated(
    db: &PgPool,
    cache: &Arc<dyn Cache>,
    token: &str,
) -> Result<AuthenticatedUser, TokenValidationError> {
    validate_bearer_token_with_options_internal(db, Some(cache), token, true).await
}

async fn validate_bearer_token_with_options_internal(
    db: &PgPool,
    cache: Option<&Arc<dyn Cache>>,
    token: &str,
    allow_deactivated: bool,
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

        let (decrypted_key, deactivated_at, takedown_ref) = if let Some(key) = cached_key {
            let user_status = sqlx::query!(
                "SELECT deactivated_at, takedown_ref FROM users WHERE did = $1",
                did
            )
            .fetch_optional(db)
            .await
            .ok()
            .flatten();

            match user_status {
                Some(status) => (Some(key), status.deactivated_at, status.takedown_ref),
                None => (None, None, None),
            }
        } else {
            if let Some(user) = sqlx::query!(
                "SELECT k.key_bytes, k.encryption_version, u.deactivated_at, u.takedown_ref
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
                    let _ = c.set_bytes(&key_cache_key, &key, Duration::from_secs(KEY_CACHE_TTL_SECS)).await;
                }

                (Some(key), user.deactivated_at, user.takedown_ref)
            } else {
                (None, None, None)
            }
        };

        if let Some(decrypted_key) = decrypted_key {
            if !allow_deactivated && deactivated_at.is_some() {
                return Err(TokenValidationError::AccountDeactivated);
            }
            if takedown_ref.is_some() {
                return Err(TokenValidationError::AccountTakedown);
            }

            if let Ok(token_data) = verify_access_token(token, &decrypted_key) {
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
                    let session_exists = sqlx::query_scalar!(
                        "SELECT 1 as one FROM session_tokens WHERE did = $1 AND access_jti = $2 AND access_expires_at > NOW()",
                        did,
                        jti
                    )
                    .fetch_optional(db)
                    .await
                    .ok()
                    .flatten();

                    session_valid = session_exists.is_some();

                    if session_valid {
                        if let Some(c) = cache {
                            let _ = c.set(&session_cache_key, "1", Duration::from_secs(SESSION_CACHE_TTL_SECS)).await;
                        }
                    }
                }

                if session_valid {
                    return Ok(AuthenticatedUser {
                        did: did.clone(),
                        key_bytes: Some(decrypted_key),
                        is_oauth: false,
                    });
                }
            }
        }
    }

    if let Ok(oauth_info) = crate::oauth::verify::extract_oauth_token_info(token) {
        if let Some(oauth_token) = sqlx::query!(
            r#"SELECT t.did, t.expires_at, u.deactivated_at, u.takedown_ref
               FROM oauth_token t
               JOIN users u ON t.did = u.did
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
            if oauth_token.takedown_ref.is_some() {
                return Err(TokenValidationError::AccountTakedown);
            }

            let now = chrono::Utc::now();
            if oauth_token.expires_at > now {
                return Ok(AuthenticatedUser {
                    did: oauth_token.did,
                    key_bytes: None,
                    is_oauth: true,
                });
            }
        }
    }

    Err(TokenValidationError::AuthenticationFailed)
}

pub async fn invalidate_auth_cache(cache: &Arc<dyn Cache>, did: &str) {
    let key_cache_key = format!("auth:key:{}", did);
    let _ = cache.delete(&key_cache_key).await;
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

// fancy boy TokenData equivalent for compatibility/structure
pub struct TokenData<T> {
    pub claims: T,
}
