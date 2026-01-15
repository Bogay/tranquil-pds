use crate::api::error::ApiError;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use tranquil_db_traits::{SessionRepository, UserRepository};

use crate::auth::BearerAuth;
use crate::state::{AppState, RateLimitKind};
use crate::types::PlainPassword;

const REAUTH_WINDOW_SECONDS: i64 = 300;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReauthStatusResponse {
    pub last_reauth_at: Option<DateTime<Utc>>,
    pub reauth_required: bool,
    pub available_methods: Vec<String>,
}

pub async fn get_reauth_status(State(state): State<AppState>, auth: BearerAuth) -> Response {
    let last_reauth_at = match state.session_repo.get_last_reauth_at(&auth.0.did).await {
        Ok(t) => t,
        Err(e) => {
            error!("DB error: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let reauth_required = is_reauth_required(last_reauth_at);
    let available_methods =
        get_available_reauth_methods(&*state.user_repo, &*state.session_repo, &auth.0.did).await;

    Json(ReauthStatusResponse {
        last_reauth_at,
        reauth_required,
        available_methods,
    })
    .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordReauthInput {
    pub password: PlainPassword,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReauthResponse {
    pub reauthed_at: DateTime<Utc>,
}

pub async fn reauth_password(
    State(state): State<AppState>,
    auth: BearerAuth,
    Json(input): Json<PasswordReauthInput>,
) -> Response {
    let password_hash = match state.user_repo.get_password_hash_by_did(&auth.0.did).await {
        Ok(Some(hash)) => hash,
        Ok(None) => {
            return ApiError::AccountNotFound.into_response();
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let password_valid = bcrypt::verify(&input.password, &password_hash).unwrap_or(false);

    if !password_valid {
        let app_password_hashes = state
            .session_repo
            .get_app_password_hashes_by_did(&auth.0.did)
            .await
            .unwrap_or_default();

        let app_password_valid = app_password_hashes
            .iter()
            .any(|h| bcrypt::verify(&input.password, h).unwrap_or(false));

        if !app_password_valid {
            warn!(did = %&auth.0.did, "Re-auth failed: invalid password");
            return ApiError::InvalidPassword("Password is incorrect".into()).into_response();
        }
    }

    match update_last_reauth_cached(&*state.session_repo, &state.cache, &auth.0.did).await {
        Ok(reauthed_at) => {
            info!(did = %&auth.0.did, "Re-auth successful via password");
            Json(ReauthResponse { reauthed_at }).into_response()
        }
        Err(e) => {
            error!("DB error updating reauth: {:?}", e);
            ApiError::InternalError(None).into_response()
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpReauthInput {
    pub code: String,
}

pub async fn reauth_totp(
    State(state): State<AppState>,
    auth: BearerAuth,
    Json(input): Json<TotpReauthInput>,
) -> Response {
    if !state
        .check_rate_limit(RateLimitKind::TotpVerify, &auth.0.did)
        .await
    {
        warn!(did = %&auth.0.did, "TOTP verification rate limit exceeded");
        return ApiError::RateLimitExceeded(Some(
            "Too many verification attempts. Please try again in a few minutes.".into(),
        ))
        .into_response();
    }

    let valid =
        crate::api::server::totp::verify_totp_or_backup_for_user(&state, &auth.0.did, &input.code)
            .await;

    if !valid {
        warn!(did = %&auth.0.did, "Re-auth failed: invalid TOTP code");
        return ApiError::InvalidCode(Some("Invalid TOTP or backup code".into())).into_response();
    }

    match update_last_reauth_cached(&*state.session_repo, &state.cache, &auth.0.did).await {
        Ok(reauthed_at) => {
            info!(did = %&auth.0.did, "Re-auth successful via TOTP");
            Json(ReauthResponse { reauthed_at }).into_response()
        }
        Err(e) => {
            error!("DB error updating reauth: {:?}", e);
            ApiError::InternalError(None).into_response()
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyReauthStartResponse {
    pub options: serde_json::Value,
}

pub async fn reauth_passkey_start(State(state): State<AppState>, auth: BearerAuth) -> Response {
    let pds_hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());

    let stored_passkeys = match state.user_repo.get_passkeys_for_user(&auth.0.did).await {
        Ok(pks) => pks,
        Err(e) => {
            error!("Failed to get passkeys: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    if stored_passkeys.is_empty() {
        return ApiError::NoPasskeys.into_response();
    }

    let passkeys: Vec<webauthn_rs::prelude::SecurityKey> = stored_passkeys
        .iter()
        .filter_map(|sp| serde_json::from_slice(&sp.public_key).ok())
        .collect();

    if passkeys.is_empty() {
        return ApiError::InternalError(Some("Failed to load passkeys".into())).into_response();
    }

    let webauthn = match crate::auth::webauthn::WebAuthnConfig::new(&pds_hostname) {
        Ok(w) => w,
        Err(e) => {
            error!("Failed to create WebAuthn config: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let (rcr, auth_state) = match webauthn.start_authentication(passkeys) {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to start passkey authentication: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let state_json = match serde_json::to_string(&auth_state) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to serialize authentication state: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    if let Err(e) = state
        .user_repo
        .save_webauthn_challenge(&auth.0.did, "authentication", &state_json)
        .await
    {
        error!("Failed to save authentication state: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }

    let options = serde_json::to_value(&rcr).unwrap_or(serde_json::json!({}));
    Json(PasskeyReauthStartResponse { options }).into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyReauthFinishInput {
    pub credential: serde_json::Value,
}

pub async fn reauth_passkey_finish(
    State(state): State<AppState>,
    auth: BearerAuth,
    Json(input): Json<PasskeyReauthFinishInput>,
) -> Response {
    let pds_hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());

    let auth_state_json = match state
        .user_repo
        .load_webauthn_challenge(&auth.0.did, "authentication")
        .await
    {
        Ok(Some(json)) => json,
        Ok(None) => {
            return ApiError::NoChallengeInProgress.into_response();
        }
        Err(e) => {
            error!("Failed to load authentication state: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let auth_state: webauthn_rs::prelude::SecurityKeyAuthentication =
        match serde_json::from_str(&auth_state_json) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to deserialize authentication state: {:?}", e);
                return ApiError::InternalError(None).into_response();
            }
        };

    let credential: webauthn_rs::prelude::PublicKeyCredential =
        match serde_json::from_value(input.credential) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to parse credential: {:?}", e);
                return ApiError::InvalidCredential.into_response();
            }
        };

    let webauthn = match crate::auth::webauthn::WebAuthnConfig::new(&pds_hostname) {
        Ok(w) => w,
        Err(e) => {
            error!("Failed to create WebAuthn config: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let auth_result = match webauthn.finish_authentication(&credential, &auth_state) {
        Ok(r) => r,
        Err(e) => {
            warn!(did = %&auth.0.did, "Passkey re-auth failed: {:?}", e);
            return ApiError::AuthenticationFailed(Some("Passkey authentication failed".into()))
                .into_response();
        }
    };

    let cred_id_bytes = auth_result.cred_id().as_ref();
    match state
        .user_repo
        .update_passkey_counter(cred_id_bytes, auth_result.counter() as i32)
        .await
    {
        Ok(false) => {
            warn!(did = %&auth.0.did, "Passkey counter anomaly detected - possible cloned key");
            let _ = state
                .user_repo
                .delete_webauthn_challenge(&auth.0.did, "authentication")
                .await;
            return ApiError::PasskeyCounterAnomaly.into_response();
        }
        Err(e) => {
            error!("Failed to update passkey counter: {:?}", e);
        }
        Ok(true) => {}
    }

    let _ = state
        .user_repo
        .delete_webauthn_challenge(&auth.0.did, "authentication")
        .await;

    match update_last_reauth_cached(&*state.session_repo, &state.cache, &auth.0.did).await {
        Ok(reauthed_at) => {
            info!(did = %&auth.0.did, "Re-auth successful via passkey");
            Json(ReauthResponse { reauthed_at }).into_response()
        }
        Err(e) => {
            error!("DB error updating reauth: {:?}", e);
            ApiError::InternalError(None).into_response()
        }
    }
}

pub async fn update_last_reauth_cached(
    session_repo: &dyn SessionRepository,
    cache: &std::sync::Arc<dyn crate::cache::Cache>,
    did: &crate::types::Did,
) -> Result<DateTime<Utc>, tranquil_db_traits::DbError> {
    let now = session_repo.update_last_reauth(did).await?;
    let cache_key = format!("reauth:{}", did);
    let _ = cache
        .set(
            &cache_key,
            &now.timestamp().to_string(),
            std::time::Duration::from_secs(REAUTH_WINDOW_SECONDS as u64),
        )
        .await;
    Ok(now)
}

fn is_reauth_required(last_reauth_at: Option<DateTime<Utc>>) -> bool {
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
) -> Vec<String> {
    let mut methods = Vec::new();

    let has_password = user_repo
        .get_password_hash_by_did(did)
        .await
        .ok()
        .flatten()
        .is_some();

    if has_password {
        methods.push("password".to_string());
    }

    let has_totp = user_repo.has_totp_enabled(did).await.unwrap_or(false);
    if has_totp {
        methods.push("totp".to_string());
    }

    let has_passkeys = user_repo.has_passkeys(did).await.unwrap_or(false);
    if has_passkeys {
        methods.push("passkey".to_string());
    }

    methods
}

pub async fn check_reauth_required(
    session_repo: &dyn SessionRepository,
    did: &crate::types::Did,
) -> bool {
    match session_repo.get_last_reauth_at(did).await {
        Ok(last_reauth_at) => is_reauth_required(last_reauth_at),
        _ => true,
    }
}

pub async fn check_reauth_required_cached(
    session_repo: &dyn SessionRepository,
    cache: &std::sync::Arc<dyn crate::cache::Cache>,
    did: &crate::types::Did,
) -> bool {
    let cache_key = format!("reauth:{}", did);
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
    pub reauth_methods: Vec<String>,
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
            if !status.legacy_login {
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

pub async fn update_mfa_verified(
    session_repo: &dyn SessionRepository,
    did: &crate::types::Did,
) -> Result<(), tranquil_db_traits::DbError> {
    session_repo.update_mfa_verified(did).await
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MfaVerificationRequiredError {
    pub error: String,
    pub message: String,
    pub reauth_methods: Vec<String>,
}
