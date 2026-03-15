use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use serde::Serialize;
use tranquil_db_traits::{SessionRepository, UserRepository};

pub const REAUTH_WINDOW_SECONDS: i64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReauthMethod {
    Password,
    Totp,
    Passkey,
}

fn is_reauth_required(last_reauth_at: Option<chrono::DateTime<Utc>>) -> bool {
    match last_reauth_at {
        None => true,
        Some(t) => {
            let elapsed = Utc::now().signed_duration_since(t);
            elapsed.num_seconds() > REAUTH_WINDOW_SECONDS
        }
    }
}

async fn get_available_reauth_methods(
    user_repo: &dyn UserRepository,
    _session_repo: &dyn SessionRepository,
    did: &crate::types::Did,
) -> Vec<ReauthMethod> {
    let mut methods = Vec::new();

    let has_password = user_repo
        .get_password_hash_by_did(did)
        .await
        .ok()
        .flatten()
        .is_some();

    if has_password {
        methods.push(ReauthMethod::Password);
    }

    let has_totp = user_repo.has_totp_enabled(did).await.unwrap_or(false);
    if has_totp {
        methods.push(ReauthMethod::Totp);
    }

    let has_passkeys = user_repo.has_passkeys(did).await.unwrap_or(false);
    if has_passkeys {
        methods.push(ReauthMethod::Passkey);
    }

    methods
}

pub async fn check_reauth_required_cached(
    session_repo: &dyn SessionRepository,
    cache: &std::sync::Arc<dyn crate::cache::Cache>,
    did: &crate::types::Did,
) -> bool {
    let cache_key = crate::cache_keys::reauth_key(did);
    if let Some(timestamp_str) = cache.get(&cache_key).await
        && let Ok(timestamp) = timestamp_str.parse::<i64>()
    {
        let reauth_time = chrono::DateTime::from_timestamp(timestamp, 0);
        if let Some(t) = reauth_time {
            let elapsed = Utc::now().signed_duration_since(t);
            if elapsed.num_seconds() <= REAUTH_WINDOW_SECONDS {
                return false;
            }
        }
    }
    match session_repo.get_last_reauth_at(did).await {
        Ok(last_reauth_at) => is_reauth_required(last_reauth_at),
        _ => true,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReauthRequiredError {
    pub error: String,
    pub message: String,
    pub reauth_methods: Vec<ReauthMethod>,
}

pub async fn reauth_required_response(
    user_repo: &dyn UserRepository,
    session_repo: &dyn SessionRepository,
    did: &crate::types::Did,
) -> Response {
    let methods = get_available_reauth_methods(user_repo, session_repo, did).await;
    (
        StatusCode::UNAUTHORIZED,
        Json(ReauthRequiredError {
            error: "ReauthRequired".to_string(),
            message: "Re-authentication required for this action".to_string(),
            reauth_methods: methods,
        }),
    )
        .into_response()
}

pub async fn check_legacy_session_mfa(
    session_repo: &dyn SessionRepository,
    did: &crate::types::Did,
) -> bool {
    match session_repo.get_session_mfa_status(did).await {
        Ok(Some(status)) => {
            if status.login_type.is_modern() {
                return true;
            }
            if status.mfa_verified {
                return true;
            }
            if let Some(last_reauth) = status.last_reauth_at {
                let elapsed = chrono::Utc::now().signed_duration_since(last_reauth);
                if elapsed.num_seconds() <= REAUTH_WINDOW_SECONDS {
                    return true;
                }
            }
            false
        }
        _ => true,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MfaVerificationRequiredError {
    pub error: String,
    pub message: String,
    pub reauth_methods: Vec<ReauthMethod>,
}

pub async fn legacy_mfa_required_response(
    user_repo: &dyn UserRepository,
    session_repo: &dyn SessionRepository,
    did: &crate::types::Did,
) -> Response {
    let methods = get_available_reauth_methods(user_repo, session_repo, did).await;
    (
        StatusCode::FORBIDDEN,
        Json(MfaVerificationRequiredError {
            error: "MfaVerificationRequired".to_string(),
            message: "This sensitive operation requires MFA verification. Your session was created via a legacy app that doesn't support MFA during login.".to_string(),
            reauth_methods: methods,
        }),
    )
        .into_response()
}
