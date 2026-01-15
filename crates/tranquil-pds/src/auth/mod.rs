use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;

use crate::AccountStatus;
use crate::cache::Cache;
use crate::oauth::scopes::ScopePermissions;
use crate::types::Did;
use tranquil_db::UserRepository;
use tranquil_db_traits::OAuthRepository;

pub mod extractor;
pub mod scope_check;
pub mod service;
pub mod verification_token;
pub mod webauthn;

pub use extractor::{
    AuthError, BearerAuth, BearerAuthAdmin, BearerAuthAllowDeactivated, ExtractedToken,
    extract_auth_token_from_header, extract_bearer_token_from_header,
};
pub use service::{ServiceTokenClaims, ServiceTokenVerifier, is_service_token};

pub use tranquil_auth::{
    ActClaim, Claims, Header, SCOPE_ACCESS, SCOPE_APP_PASS, SCOPE_APP_PASS_PRIVILEGED,
    SCOPE_REFRESH, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH, TOKEN_TYPE_SERVICE, TokenData,
    TokenVerifyError, TokenWithMetadata, UnsafeClaims, create_access_token,
    create_access_token_hs256, create_access_token_hs256_with_metadata,
    create_access_token_with_delegation, create_access_token_with_metadata,
    create_access_token_with_scope_metadata, create_refresh_token, create_refresh_token_hs256,
    create_refresh_token_hs256_with_metadata, create_refresh_token_with_metadata,
    create_service_token, create_service_token_hs256, generate_backup_codes,
    generate_qr_png_base64, generate_totp_secret, generate_totp_uri, get_algorithm_from_token,
    get_did_from_token, get_jti_from_token, hash_backup_code, is_backup_code_format,
    verify_access_token, verify_access_token_hs256, verify_access_token_typed, verify_backup_code,
    verify_refresh_token, verify_refresh_token_hs256, verify_token, verify_totp_code,
};

pub fn encrypt_totp_secret(secret: &[u8]) -> Result<Vec<u8>, String> {
    crate::config::encrypt_key(secret)
}

pub fn decrypt_totp_secret(encrypted: &[u8], version: i32) -> Result<Vec<u8>, String> {
    crate::config::decrypt_key(encrypted, Some(version))
}

const KEY_CACHE_TTL_SECS: u64 = 300;
const SESSION_CACHE_TTL_SECS: u64 = 60;
const USER_STATUS_CACHE_TTL_SECS: u64 = 60;

#[derive(Serialize, Deserialize)]
struct CachedUserStatus {
    deactivated: bool,
    takendown: bool,
    is_admin: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenValidationError {
    AccountDeactivated,
    AccountTakedown,
    KeyDecryptionFailed,
    AuthenticationFailed,
    TokenExpired,
    OAuthTokenExpired,
    InvalidToken,
}

impl fmt::Display for TokenValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccountDeactivated => write!(f, "AccountDeactivated"),
            Self::AccountTakedown => write!(f, "AccountTakedown"),
            Self::KeyDecryptionFailed => write!(f, "KeyDecryptionFailed"),
            Self::AuthenticationFailed => write!(f, "AuthenticationFailed"),
            Self::TokenExpired | Self::OAuthTokenExpired => write!(f, "ExpiredToken"),
            Self::InvalidToken => write!(f, "InvalidToken"),
        }
    }
}

pub struct AuthenticatedUser {
    pub did: Did,
    pub key_bytes: Option<Vec<u8>>,
    pub is_oauth: bool,
    pub is_admin: bool,
    pub status: AccountStatus,
    pub scope: Option<String>,
    pub controller_did: Option<Did>,
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

    pub fn is_takendown(&self) -> bool {
        self.status.is_takendown()
    }
}

pub async fn validate_bearer_token(
    user_repo: &dyn UserRepository,
    token: &str,
) -> Result<AuthenticatedUser, TokenValidationError> {
    validate_bearer_token_with_options_internal(user_repo, None, token, false, false).await
}

pub async fn validate_bearer_token_allow_deactivated(
    user_repo: &dyn UserRepository,
    token: &str,
) -> Result<AuthenticatedUser, TokenValidationError> {
    validate_bearer_token_with_options_internal(user_repo, None, token, true, false).await
}

pub async fn validate_bearer_token_cached(
    user_repo: &dyn UserRepository,
    cache: &dyn Cache,
    token: &str,
) -> Result<AuthenticatedUser, TokenValidationError> {
    validate_bearer_token_with_options_internal(user_repo, Some(cache), token, false, false).await
}

pub async fn validate_bearer_token_cached_allow_deactivated(
    user_repo: &dyn UserRepository,
    cache: &dyn Cache,
    token: &str,
) -> Result<AuthenticatedUser, TokenValidationError> {
    validate_bearer_token_with_options_internal(user_repo, Some(cache), token, true, false).await
}

pub async fn validate_bearer_token_for_service_auth(
    user_repo: &dyn UserRepository,
    token: &str,
) -> Result<AuthenticatedUser, TokenValidationError> {
    validate_bearer_token_with_options_internal(user_repo, None, token, true, true).await
}

pub async fn validate_bearer_token_allow_takendown(
    user_repo: &dyn UserRepository,
    token: &str,
) -> Result<AuthenticatedUser, TokenValidationError> {
    validate_bearer_token_with_options_internal(user_repo, None, token, false, true).await
}

async fn validate_bearer_token_with_options_internal(
    user_repo: &dyn UserRepository,
    cache: Option<&dyn Cache>,
    token: &str,
    allow_deactivated: bool,
    allow_takendown: bool,
) -> Result<AuthenticatedUser, TokenValidationError> {
    let did_from_token = get_did_from_token(token).ok();

    if let Some(ref did_str) = did_from_token {
        let did: tranquil_types::Did = match did_str.parse() {
            Ok(d) => d,
            Err(_) => return Err(TokenValidationError::InvalidToken),
        };
        let key_cache_key = format!("auth:key:{}", did_str);
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
            let status_cache_key = format!("auth:status:{}", did_str);
            let cached_status: Option<CachedUserStatus> = if let Some(c) = cache {
                c.get(&status_cache_key)
                    .await
                    .and_then(|s| serde_json::from_str(&s).ok())
            } else {
                None
            };

            if let Some(status) = cached_status {
                (
                    Some(key),
                    if status.deactivated {
                        Some(chrono::Utc::now())
                    } else {
                        None
                    },
                    if status.takendown {
                        Some("takendown".to_string())
                    } else {
                        None
                    },
                    status.is_admin,
                )
            } else {
                let user_status = user_repo.get_status_by_did(&did).await.ok().flatten();

                match user_status {
                    Some(status) => {
                        if let Some(c) = cache {
                            let cached = CachedUserStatus {
                                deactivated: status.deactivated_at.is_some(),
                                takendown: status.takedown_ref.is_some(),
                                is_admin: status.is_admin,
                            };
                            if let Ok(json) = serde_json::to_string(&cached) {
                                let _ = c
                                    .set(
                                        &status_cache_key,
                                        &json,
                                        Duration::from_secs(USER_STATUS_CACHE_TTL_SECS),
                                    )
                                    .await;
                            }
                        }
                        (
                            Some(key),
                            status.deactivated_at,
                            status.takedown_ref,
                            status.is_admin,
                        )
                    }
                    None => (None, None, None, false),
                }
            }
        } else if let Some(user) = user_repo.get_with_key_by_did(&did).await.ok().flatten() {
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

                let status_cache_key = format!("auth:status:{}", did);
                let cached = CachedUserStatus {
                    deactivated: user.deactivated_at.is_some(),
                    takendown: user.takedown_ref.is_some(),
                    is_admin: user.is_admin,
                };
                if let Ok(json) = serde_json::to_string(&cached) {
                    let _ = c
                        .set(
                            &status_cache_key,
                            &json,
                            Duration::from_secs(USER_STATUS_CACHE_TTL_SECS),
                        )
                        .await;
                }
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
                        let session_expiry = user_repo
                            .get_session_access_expiry(&did, jti)
                            .await
                            .ok()
                            .flatten();

                        if let Some(expires_at) = session_expiry {
                            if expires_at > chrono::Utc::now() {
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
                        let controller_did = token_data
                            .claims
                            .act
                            .as_ref()
                            .map(|a| Did::new_unchecked(a.sub.clone()));
                        let status =
                            AccountStatus::from_db_fields(takedown_ref.as_deref(), deactivated_at);
                        return Ok(AuthenticatedUser {
                            did: did.clone(),
                            key_bytes: Some(decrypted_key),
                            is_oauth: false,
                            is_admin,
                            status,
                            scope: token_data.claims.scope.clone(),
                            controller_did,
                        });
                    }
                }
                Err(TokenVerifyError::Expired) => {
                    return Err(TokenValidationError::TokenExpired);
                }
                Err(TokenVerifyError::Invalid) => {}
            }
        }
    }

    if let Ok(oauth_info) = crate::oauth::verify::extract_oauth_token_info(token)
        && let Some(oauth_token) = user_repo
            .get_oauth_token_with_user(&oauth_info.token_id)
            .await
            .ok()
            .flatten()
    {
        let status = AccountStatus::from_db_fields(
            oauth_token.takedown_ref.as_deref(),
            oauth_token.deactivated_at,
        );

        if !allow_deactivated && status.is_deactivated() {
            return Err(TokenValidationError::AccountDeactivated);
        }

        if !allow_takendown && status.is_takendown() {
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
                did: Did::new_unchecked(oauth_token.did),
                key_bytes,
                is_oauth: true,
                is_admin: oauth_token.is_admin,
                status,
                scope: oauth_info.scope,
                controller_did: oauth_info.controller_did.map(Did::new_unchecked),
            });
        } else {
            return Err(TokenValidationError::TokenExpired);
        }
    }

    Err(TokenValidationError::AuthenticationFailed)
}

pub async fn invalidate_auth_cache(cache: &dyn Cache, did: &str) {
    let key_cache_key = format!("auth:key:{}", did);
    let status_cache_key = format!("auth:status:{}", did);
    let _ = cache.delete(&key_cache_key).await;
    let _ = cache.delete(&status_cache_key).await;
}

#[allow(clippy::too_many_arguments)]
pub async fn validate_token_with_dpop(
    user_repo: &dyn UserRepository,
    oauth_repo: &dyn OAuthRepository,
    token: &str,
    is_dpop_token: bool,
    dpop_proof: Option<&str>,
    http_method: &str,
    http_uri: &str,
    allow_deactivated: bool,
    allow_takendown: bool,
) -> Result<AuthenticatedUser, TokenValidationError> {
    if !is_dpop_token {
        if allow_takendown {
            return validate_bearer_token_allow_takendown(user_repo, token).await;
        } else if allow_deactivated {
            return validate_bearer_token_allow_deactivated(user_repo, token).await;
        } else {
            return validate_bearer_token(user_repo, token).await;
        }
    }
    match crate::oauth::verify::verify_oauth_access_token(
        oauth_repo,
        token,
        dpop_proof,
        http_method,
        http_uri,
    )
    .await
    {
        Ok(result) => {
            let result_did: Did = result
                .did
                .parse()
                .map_err(|_| TokenValidationError::InvalidToken)?;
            let user_info = user_repo
                .get_user_info_by_did(&result_did)
                .await
                .ok()
                .flatten();
            let Some(user_info) = user_info else {
                return Err(TokenValidationError::AuthenticationFailed);
            };
            let status = AccountStatus::from_db_fields(
                user_info.takedown_ref.as_deref(),
                user_info.deactivated_at,
            );
            if !allow_deactivated && status.is_deactivated() {
                return Err(TokenValidationError::AccountDeactivated);
            }
            if !allow_takendown && status.is_takendown() {
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
                did: Did::new_unchecked(result.did),
                key_bytes,
                is_oauth: true,
                is_admin: user_info.is_admin,
                status,
                scope: result.scope,
                controller_did: None,
            })
        }
        Err(crate::oauth::OAuthError::ExpiredToken(_)) => {
            Err(TokenValidationError::OAuthTokenExpired)
        }
        Err(_) => Err(TokenValidationError::AuthenticationFailed),
    }
}
