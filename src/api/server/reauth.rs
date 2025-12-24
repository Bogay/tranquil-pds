use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use tracing::{error, info, warn};

use crate::auth::BearerAuth;
use crate::state::{AppState, RateLimitKind};

const REAUTH_WINDOW_SECONDS: i64 = 300;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReauthStatusResponse {
    pub last_reauth_at: Option<DateTime<Utc>>,
    pub reauth_required: bool,
    pub available_methods: Vec<String>,
}

pub async fn get_reauth_status(State(state): State<AppState>, auth: BearerAuth) -> Response {
    let session = sqlx::query!(
        "SELECT last_reauth_at FROM session_tokens WHERE did = $1 ORDER BY created_at DESC LIMIT 1",
        auth.0.did
    )
    .fetch_optional(&state.db)
    .await;

    let last_reauth_at = match session {
        Ok(Some(row)) => row.last_reauth_at,
        Ok(None) => None,
        Err(e) => {
            error!("DB error: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let reauth_required = is_reauth_required(last_reauth_at);
    let available_methods = get_available_reauth_methods(&state.db, &auth.0.did).await;

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
    pub password: String,
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
    let user = sqlx::query!("SELECT password_hash FROM users WHERE did = $1", auth.0.did)
        .fetch_optional(&state.db)
        .await;

    let password_hash = match user {
        Ok(Some(row)) => row.password_hash,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "AccountNotFound"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let password_valid = password_hash
        .as_ref()
        .map(|h| bcrypt::verify(&input.password, h).unwrap_or(false))
        .unwrap_or(false);

    if !password_valid {
        let app_passwords = sqlx::query!(
            "SELECT ap.password_hash FROM app_passwords ap
             JOIN users u ON ap.user_id = u.id
             WHERE u.did = $1",
            auth.0.did
        )
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

        let app_password_valid = app_passwords
            .iter()
            .any(|ap| bcrypt::verify(&input.password, &ap.password_hash).unwrap_or(false));

        if !app_password_valid {
            warn!(did = %auth.0.did, "Re-auth failed: invalid password");
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "InvalidPassword",
                    "message": "Password is incorrect"
                })),
            )
                .into_response();
        }
    }

    match update_last_reauth_cached(&state.db, &state.cache, &auth.0.did).await {
        Ok(reauthed_at) => {
            info!(did = %auth.0.did, "Re-auth successful via password");
            Json(ReauthResponse { reauthed_at }).into_response()
        }
        Err(e) => {
            error!("DB error updating reauth: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
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
        warn!(did = %auth.0.did, "TOTP verification rate limit exceeded");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "RateLimitExceeded",
                "message": "Too many verification attempts. Please try again in a few minutes."
            })),
        )
            .into_response();
    }

    let valid =
        crate::api::server::totp::verify_totp_or_backup_for_user(&state, &auth.0.did, &input.code)
            .await;

    if !valid {
        warn!(did = %auth.0.did, "Re-auth failed: invalid TOTP code");
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "InvalidCode",
                "message": "Invalid TOTP or backup code"
            })),
        )
            .into_response();
    }

    match update_last_reauth_cached(&state.db, &state.cache, &auth.0.did).await {
        Ok(reauthed_at) => {
            info!(did = %auth.0.did, "Re-auth successful via TOTP");
            Json(ReauthResponse { reauthed_at }).into_response()
        }
        Err(e) => {
            error!("DB error updating reauth: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
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

    let stored_passkeys =
        match crate::auth::webauthn::get_passkeys_for_user(&state.db, &auth.0.did).await {
            Ok(pks) => pks,
            Err(e) => {
                error!("Failed to get passkeys: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }
        };

    if stored_passkeys.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "NoPasskeys",
                "message": "No passkeys registered for this account"
            })),
        )
            .into_response();
    }

    let passkeys: Vec<webauthn_rs::prelude::SecurityKey> = stored_passkeys
        .iter()
        .filter_map(|sp| sp.to_security_key().ok())
        .collect();

    if passkeys.is_empty() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": "Failed to load passkeys"})),
        )
            .into_response();
    }

    let webauthn = match crate::auth::webauthn::WebAuthnConfig::new(&pds_hostname) {
        Ok(w) => w,
        Err(e) => {
            error!("Failed to create WebAuthn config: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let (rcr, auth_state) = match webauthn.start_authentication(passkeys) {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to start passkey authentication: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    if let Err(e) =
        crate::auth::webauthn::save_authentication_state(&state.db, &auth.0.did, &auth_state).await
    {
        error!("Failed to save authentication state: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    let options = serde_json::to_value(&rcr).unwrap_or(json!({}));
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

    let auth_state =
        match crate::auth::webauthn::load_authentication_state(&state.db, &auth.0.did).await {
            Ok(Some(s)) => s,
            Ok(None) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "NoChallengeInProgress",
                        "message": "No passkey authentication in progress or challenge expired"
                    })),
                )
                    .into_response();
            }
            Err(e) => {
                error!("Failed to load authentication state: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }
        };

    let credential: webauthn_rs::prelude::PublicKeyCredential =
        match serde_json::from_value(input.credential) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to parse credential: {:?}", e);
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "InvalidCredential",
                        "message": "Failed to parse credential response"
                    })),
                )
                    .into_response();
            }
        };

    let webauthn = match crate::auth::webauthn::WebAuthnConfig::new(&pds_hostname) {
        Ok(w) => w,
        Err(e) => {
            error!("Failed to create WebAuthn config: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let auth_result = match webauthn.finish_authentication(&credential, &auth_state) {
        Ok(r) => r,
        Err(e) => {
            warn!(did = %auth.0.did, "Passkey re-auth failed: {:?}", e);
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "AuthenticationFailed",
                    "message": "Passkey authentication failed"
                })),
            )
                .into_response();
        }
    };

    let cred_id_bytes = auth_result.cred_id().as_ref();
    match crate::auth::webauthn::update_passkey_counter(
        &state.db,
        cred_id_bytes,
        auth_result.counter(),
    )
    .await
    {
        Ok(false) => {
            warn!(did = %auth.0.did, "Passkey counter anomaly detected - possible cloned key");
            let _ =
                crate::auth::webauthn::delete_authentication_state(&state.db, &auth.0.did).await;
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "PasskeyCounterAnomaly",
                    "message": "Authentication failed: security key counter anomaly detected. This may indicate a cloned key."
                })),
            )
                .into_response();
        }
        Err(e) => {
            error!("Failed to update passkey counter: {:?}", e);
        }
        Ok(true) => {}
    }

    let _ = crate::auth::webauthn::delete_authentication_state(&state.db, &auth.0.did).await;

    match update_last_reauth_cached(&state.db, &state.cache, &auth.0.did).await {
        Ok(reauthed_at) => {
            info!(did = %auth.0.did, "Re-auth successful via passkey");
            Json(ReauthResponse { reauthed_at }).into_response()
        }
        Err(e) => {
            error!("DB error updating reauth: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

pub async fn update_last_reauth_cached(
    db: &PgPool,
    cache: &std::sync::Arc<dyn crate::cache::Cache>,
    did: &str,
) -> Result<DateTime<Utc>, sqlx::Error> {
    let now = Utc::now();
    sqlx::query!(
        "UPDATE session_tokens SET last_reauth_at = $1, mfa_verified = TRUE WHERE did = $2",
        now,
        did
    )
    .execute(db)
    .await?;
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

async fn get_available_reauth_methods(db: &PgPool, did: &str) -> Vec<String> {
    let mut methods = Vec::new();

    let has_password = sqlx::query_scalar!(
        "SELECT password_hash IS NOT NULL as has_pw FROM users WHERE did = $1",
        did
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .unwrap_or(Some(false));

    if has_password == Some(true) {
        methods.push("password".to_string());
    }

    let has_totp = crate::api::server::totp::has_totp_enabled_db(db, did).await;
    if has_totp {
        methods.push("totp".to_string());
    }

    let has_passkeys = crate::api::server::passkeys::has_passkeys_for_user_db(db, did).await;
    if has_passkeys {
        methods.push("passkey".to_string());
    }

    methods
}

pub async fn check_reauth_required(db: &PgPool, did: &str) -> bool {
    let session = sqlx::query!(
        "SELECT last_reauth_at FROM session_tokens WHERE did = $1 ORDER BY created_at DESC LIMIT 1",
        did
    )
    .fetch_optional(db)
    .await;

    match session {
        Ok(Some(row)) => is_reauth_required(row.last_reauth_at),
        _ => true,
    }
}

pub async fn check_reauth_required_cached(
    db: &PgPool,
    cache: &std::sync::Arc<dyn crate::cache::Cache>,
    did: &str,
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
    let session = sqlx::query!(
        "SELECT last_reauth_at FROM session_tokens WHERE did = $1 ORDER BY created_at DESC LIMIT 1",
        did
    )
    .fetch_optional(db)
    .await;

    match session {
        Ok(Some(row)) => is_reauth_required(row.last_reauth_at),
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

pub async fn reauth_required_response(db: &PgPool, did: &str) -> Response {
    let methods = get_available_reauth_methods(db, did).await;
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

pub async fn check_legacy_session_mfa(db: &PgPool, did: &str) -> bool {
    let session = sqlx::query!(
        "SELECT legacy_login, mfa_verified, last_reauth_at FROM session_tokens WHERE did = $1 ORDER BY created_at DESC LIMIT 1",
        did
    )
    .fetch_optional(db)
    .await;

    match session {
        Ok(Some(row)) => {
            if !row.legacy_login {
                return true;
            }
            if row.mfa_verified {
                return true;
            }
            if let Some(last_reauth) = row.last_reauth_at {
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

pub async fn update_mfa_verified(db: &PgPool, did: &str) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE session_tokens SET mfa_verified = TRUE, last_reauth_at = NOW() WHERE did = $1",
        did
    )
    .execute(db)
    .await?;
    Ok(())
}

pub async fn legacy_mfa_required_response(db: &PgPool, did: &str) -> Response {
    let methods = get_available_reauth_methods(db, did).await;
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": "MfaVerificationRequired",
            "message": "This sensitive operation requires MFA verification. Your session was created via a legacy app that doesn't support MFA during login.",
            "reauthMethods": methods
        })),
    )
        .into_response()
}
