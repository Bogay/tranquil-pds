use tranquil_pds::api::error::{ApiError, DbResultExt};
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use tranquil_db_traits::{SessionRepository, UserRepository, WebauthnChallengeType};

use tranquil_pds::auth::{Active, Auth};
use tranquil_pds::rate_limit::{TotpVerifyLimit, check_user_rate_limit_with_message};
use tranquil_pds::state::AppState;
use tranquil_pds::types::PlainPassword;

pub const REAUTH_WINDOW_SECONDS: i64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReauthMethod {
    Password,
    Totp,
    Passkey,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReauthStatusResponse {
    pub last_reauth_at: Option<DateTime<Utc>>,
    pub reauth_required: bool,
    pub available_methods: Vec<ReauthMethod>,
}

pub async fn get_reauth_status(
    State(state): State<AppState>,
    auth: Auth<Active>,
) -> Result<Response, ApiError> {
    let last_reauth_at = state
        .session_repo
        .get_last_reauth_at(&auth.did)
        .await
        .log_db_err("getting last reauth")?;

    let reauth_required = is_reauth_required(last_reauth_at);
    let available_methods =
        get_available_reauth_methods(&*state.user_repo, &*state.session_repo, &auth.did).await;

    Ok(Json(ReauthStatusResponse {
        last_reauth_at,
        reauth_required,
        available_methods,
    })
    .into_response())
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
    auth: Auth<Active>,
    Json(input): Json<PasswordReauthInput>,
) -> Result<Response, ApiError> {
    let password_hash = state
        .user_repo
        .get_password_hash_by_did(&auth.did)
        .await
        .log_db_err("fetching password hash")?
        .ok_or(ApiError::AccountNotFound)?;

    let password_valid = bcrypt::verify(&input.password, &password_hash).unwrap_or(false);

    if !password_valid {
        let app_password_hashes = state
            .session_repo
            .get_app_password_hashes_by_did(&auth.did)
            .await
            .unwrap_or_default();

        let app_password_valid = app_password_hashes.iter().fold(false, |acc, h| {
            acc | bcrypt::verify(&input.password, h).unwrap_or(false)
        });

        if !app_password_valid {
            warn!(did = %&auth.did, "Re-auth failed: invalid password");
            return Err(ApiError::InvalidPassword("Password is incorrect".into()));
        }
    }

    let reauthed_at = update_last_reauth_cached(&*state.session_repo, &state.cache, &auth.did)
        .await
        .log_db_err("updating reauth")?;

    info!(did = %&auth.did, "Re-auth successful via password");
    Ok(Json(ReauthResponse { reauthed_at }).into_response())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpReauthInput {
    pub code: String,
}

pub async fn reauth_totp(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<TotpReauthInput>,
) -> Result<Response, ApiError> {
    let _rate_limit = check_user_rate_limit_with_message::<TotpVerifyLimit>(
        &state,
        &auth.did,
        "Too many verification attempts. Please try again in a few minutes.",
    )
    .await?;

    let valid =
        crate::server::totp::verify_totp_or_backup_for_user(&state, &auth.did, &input.code)
            .await;

    if !valid {
        warn!(did = %&auth.did, "Re-auth failed: invalid TOTP code");
        return Err(ApiError::InvalidCode(Some(
            "Invalid TOTP or backup code".into(),
        )));
    }

    let reauthed_at = update_last_reauth_cached(&*state.session_repo, &state.cache, &auth.did)
        .await
        .log_db_err("updating reauth")?;

    info!(did = %&auth.did, "Re-auth successful via TOTP");
    Ok(Json(ReauthResponse { reauthed_at }).into_response())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyReauthStartResponse {
    pub options: serde_json::Value,
}

pub async fn reauth_passkey_start(
    State(state): State<AppState>,
    auth: Auth<Active>,
) -> Result<Response, ApiError> {
    let stored_passkeys = state
        .user_repo
        .get_passkeys_for_user(&auth.did)
        .await
        .log_db_err("getting passkeys")?;

    if stored_passkeys.is_empty() {
        return Err(ApiError::NoPasskeys);
    }

    let passkeys: Vec<webauthn_rs::prelude::SecurityKey> = stored_passkeys
        .iter()
        .filter_map(|sp| serde_json::from_slice(&sp.public_key).ok())
        .collect();

    if passkeys.is_empty() {
        return Err(ApiError::InternalError(Some(
            "Failed to load passkeys".into(),
        )));
    }

    let webauthn = &state.webauthn_config;

    let (rcr, auth_state) = webauthn.start_authentication(passkeys).map_err(|e| {
        error!("Failed to start passkey authentication: {:?}", e);
        ApiError::InternalError(None)
    })?;

    let state_json = serde_json::to_string(&auth_state).map_err(|e| {
        error!("Failed to serialize authentication state: {:?}", e);
        ApiError::InternalError(None)
    })?;

    state
        .user_repo
        .save_webauthn_challenge(
            &auth.did,
            WebauthnChallengeType::Authentication,
            &state_json,
        )
        .await
        .log_db_err("saving authentication state")?;

    let options = serde_json::to_value(&rcr).unwrap_or(serde_json::json!({}));
    Ok(Json(PasskeyReauthStartResponse { options }).into_response())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyReauthFinishInput {
    pub credential: serde_json::Value,
}

pub async fn reauth_passkey_finish(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<PasskeyReauthFinishInput>,
) -> Result<Response, ApiError> {
    let auth_state_json = state
        .user_repo
        .load_webauthn_challenge(&auth.did, WebauthnChallengeType::Authentication)
        .await
        .log_db_err("loading authentication state")?
        .ok_or(ApiError::NoChallengeInProgress)?;

    let auth_state: webauthn_rs::prelude::SecurityKeyAuthentication =
        serde_json::from_str(&auth_state_json).map_err(|e| {
            error!("Failed to deserialize authentication state: {:?}", e);
            ApiError::InternalError(None)
        })?;

    let credential: webauthn_rs::prelude::PublicKeyCredential =
        serde_json::from_value(input.credential).map_err(|e| {
            warn!("Failed to parse credential: {:?}", e);
            ApiError::InvalidCredential
        })?;

    let auth_result = state
        .webauthn_config
        .finish_authentication(&credential, &auth_state)
        .map_err(|e| {
            warn!(did = %&auth.did, "Passkey re-auth failed: {:?}", e);
            ApiError::AuthenticationFailed(Some("Passkey authentication failed".into()))
        })?;

    let cred_id_bytes = auth_result.cred_id().as_ref();
    match state
        .user_repo
        .update_passkey_counter(
            cred_id_bytes,
            i32::try_from(auth_result.counter()).unwrap_or(i32::MAX),
        )
        .await
    {
        Ok(false) => {
            warn!(did = %&auth.did, "Passkey counter anomaly detected - possible cloned key");
            let _ = state
                .user_repo
                .delete_webauthn_challenge(&auth.did, WebauthnChallengeType::Authentication)
                .await;
            return Err(ApiError::PasskeyCounterAnomaly);
        }
        Err(e) => {
            error!("Failed to update passkey counter: {:?}", e);
        }
        Ok(true) => {}
    }

    let _ = state
        .user_repo
        .delete_webauthn_challenge(&auth.did, WebauthnChallengeType::Authentication)
        .await;

    let reauthed_at = update_last_reauth_cached(&*state.session_repo, &state.cache, &auth.did)
        .await
        .log_db_err("updating reauth")?;

    info!(did = %&auth.did, "Re-auth successful via passkey");
    Ok(Json(ReauthResponse { reauthed_at }).into_response())
}

pub async fn update_last_reauth_cached(
    session_repo: &dyn SessionRepository,
    cache: &std::sync::Arc<dyn tranquil_pds::cache::Cache>,
    did: &tranquil_pds::types::Did,
) -> Result<DateTime<Utc>, tranquil_db_traits::DbError> {
    let now = session_repo.update_last_reauth(did).await?;
    let cache_key = tranquil_pds::cache_keys::reauth_key(did);
    let _ = cache
        .set(
            &cache_key,
            &now.timestamp().to_string(),
            std::time::Duration::from_secs(u64::try_from(REAUTH_WINDOW_SECONDS).unwrap_or(300)),
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
    did: &tranquil_pds::types::Did,
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

pub async fn check_reauth_required(
    session_repo: &dyn SessionRepository,
    did: &tranquil_pds::types::Did,
) -> bool {
    match session_repo.get_last_reauth_at(did).await {
        Ok(last_reauth_at) => is_reauth_required(last_reauth_at),
        _ => true,
    }
}

pub async fn check_reauth_required_cached(
    session_repo: &dyn SessionRepository,
    cache: &std::sync::Arc<dyn tranquil_pds::cache::Cache>,
    did: &tranquil_pds::types::Did,
) -> bool {
    let cache_key = tranquil_pds::cache_keys::reauth_key(did);
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
    did: &tranquil_pds::types::Did,
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
    did: &tranquil_pds::types::Did,
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

pub async fn update_mfa_verified(
    session_repo: &dyn SessionRepository,
    did: &tranquil_pds::types::Did,
) -> Result<(), tranquil_db_traits::DbError> {
    session_repo.update_mfa_verified(did).await
}

pub async fn legacy_mfa_required_response(
    user_repo: &dyn UserRepository,
    session_repo: &dyn SessionRepository,
    did: &tranquil_pds::types::Did,
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
    pub reauth_methods: Vec<ReauthMethod>,
}
