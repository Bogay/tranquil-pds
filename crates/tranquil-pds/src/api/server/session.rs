use crate::api::error::ApiError;
use crate::api::{EmptyResponse, SuccessResponse};
use crate::auth::{Active, Auth, Permissive};
use crate::state::{AppState, RateLimitKind};
use crate::types::{AccountState, Did, Handle, PlainPassword};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use bcrypt::verify;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{error, info, warn};
use tranquil_types::TokenId;

fn extract_client_ip(headers: &HeaderMap) -> String {
    if let Some(forwarded) = headers.get("x-forwarded-for")
        && let Ok(value) = forwarded.to_str()
        && let Some(first_ip) = value.split(',').next()
    {
        return first_ip.trim().to_string();
    }
    if let Some(real_ip) = headers.get("x-real-ip")
        && let Ok(value) = real_ip.to_str()
    {
        return value.trim().to_string();
    }
    "unknown".to_string()
}

fn normalize_handle(identifier: &str, pds_hostname: &str) -> String {
    let identifier = identifier.trim();
    if identifier.contains('@') || identifier.starts_with("did:") {
        identifier.to_string()
    } else if !identifier.contains('.') {
        format!("{}.{}", identifier.to_lowercase(), pds_hostname)
    } else {
        identifier.to_lowercase()
    }
}

fn full_handle(stored_handle: &str, _pds_hostname: &str) -> String {
    stored_handle.to_string()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionInput {
    pub identifier: String,
    pub password: PlainPassword,
    #[serde(default)]
    pub allow_takendown: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionOutput {
    pub access_jwt: String,
    pub refresh_jwt: String,
    pub handle: Handle,
    pub did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_doc: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_confirmed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

pub async fn create_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateSessionInput>,
) -> Response {
    info!(
        "create_session called with identifier: {}",
        input.identifier
    );
    let client_ip = extract_client_ip(&headers);
    if !state
        .check_rate_limit(RateLimitKind::Login, &client_ip)
        .await
    {
        warn!(ip = %client_ip, "Login rate limit exceeded");
        return ApiError::RateLimitExceeded(None).into_response();
    }
    let pds_hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let hostname_for_handles = pds_hostname.split(':').next().unwrap_or(&pds_hostname);
    let normalized_identifier = normalize_handle(&input.identifier, hostname_for_handles);
    info!(
        "Normalized identifier: {} -> {}",
        input.identifier, normalized_identifier
    );
    let row = match state
        .user_repo
        .get_login_full_by_identifier(&normalized_identifier)
        .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            let _ = verify(
                &input.password,
                "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.VTtYw1ZzQKZqmK",
            );
            warn!("User not found for login attempt");
            return ApiError::AuthenticationFailed(Some("Invalid identifier or password".into()))
                .into_response();
        }
        Err(e) => {
            error!("Database error fetching user: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let key_bytes = match crate::config::decrypt_key(&row.key_bytes, row.encryption_version) {
        Ok(k) => k,
        Err(e) => {
            error!("Failed to decrypt user key: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let (password_valid, app_password_name, app_password_scopes, app_password_controller) = if row
        .password_hash
        .as_ref()
        .map(|h| verify(&input.password, h).unwrap_or(false))
        .unwrap_or(false)
    {
        (true, None, None, None)
    } else {
        let app_passwords = state
            .session_repo
            .get_app_passwords_for_login(row.id)
            .await
            .unwrap_or_default();
        let matched = app_passwords
            .iter()
            .find(|app| verify(&input.password, &app.password_hash).unwrap_or(false));
        match matched {
            Some(app) => (
                true,
                Some(app.name.clone()),
                app.scopes.clone(),
                app.created_by_controller_did.clone(),
            ),
            None => (false, None, None, None),
        }
    };
    if !password_valid {
        warn!("Password verification failed for login attempt");
        return ApiError::AuthenticationFailed(Some("Invalid identifier or password".into()))
            .into_response();
    }
    let account_state = AccountState::from_db_fields(
        row.deactivated_at,
        row.takedown_ref.clone(),
        row.migrated_to_pds.clone(),
        None,
    );
    if account_state.is_takendown() && !input.allow_takendown {
        warn!("Login attempt for takendown account: {}", row.did);
        return ApiError::AccountTakedown.into_response();
    }
    let is_verified =
        row.email_verified || row.discord_verified || row.telegram_verified || row.signal_verified;
    let is_delegated = state
        .delegation_repo
        .is_delegated_account(&row.did)
        .await
        .unwrap_or(false);
    if !is_verified && !is_delegated {
        warn!("Login attempt for unverified account: {}", row.did);
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "AccountNotVerified",
                "message": "Please verify your account before logging in",
                "did": row.did
            })),
        )
            .into_response();
    }
    let has_totp = row.totp_enabled;
    let is_legacy_login = has_totp;
    if has_totp && !row.allow_legacy_login {
        warn!("Legacy login blocked for TOTP-enabled account: {}", row.did);
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "MfaRequired",
                "message": "This account requires MFA. Please use an OAuth client that supports TOTP verification.",
                "did": row.did
            })),
        )
            .into_response();
    }
    let access_meta = match crate::auth::create_access_token_with_delegation(
        &row.did,
        &key_bytes,
        app_password_scopes.as_deref(),
        app_password_controller.as_deref(),
        None,
    ) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to create access token: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let refresh_meta = match crate::auth::create_refresh_token_with_metadata(&row.did, &key_bytes) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to create refresh token: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let did_for_doc = row.did.clone();
    let did_resolver = state.did_resolver.clone();
    let session_data = tranquil_db_traits::SessionTokenCreate {
        did: row.did.clone(),
        access_jti: access_meta.jti.clone(),
        refresh_jti: refresh_meta.jti.clone(),
        access_expires_at: access_meta.expires_at,
        refresh_expires_at: refresh_meta.expires_at,
        legacy_login: is_legacy_login,
        mfa_verified: false,
        scope: app_password_scopes.clone(),
        controller_did: app_password_controller.clone(),
        app_password_name: app_password_name.clone(),
    };
    let (insert_result, did_doc) = tokio::join!(
        state.session_repo.create_session(&session_data),
        did_resolver.resolve_did_document(&did_for_doc)
    );
    if let Err(e) = insert_result {
        error!("Failed to insert session: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }
    if is_legacy_login {
        warn!(
            did = %row.did,
            ip = %client_ip,
            "Legacy login on TOTP-enabled account - sending notification"
        );
        let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
        if let Err(e) = crate::comms::comms_repo::enqueue_legacy_login(
            state.user_repo.as_ref(),
            state.infra_repo.as_ref(),
            row.id,
            &hostname,
            &client_ip,
            row.preferred_comms_channel,
        )
        .await
        {
            error!("Failed to queue legacy login notification: {:?}", e);
        }
    }
    let handle = full_handle(&row.handle, &pds_hostname);
    let is_active = account_state.is_active();
    let status = account_state.status_for_session().map(String::from);
    Json(CreateSessionOutput {
        access_jwt: access_meta.token,
        refresh_jwt: refresh_meta.token,
        handle: handle.into(),
        did: row.did,
        did_doc,
        email: row.email,
        email_confirmed: Some(row.email_verified),
        active: Some(is_active),
        status,
    })
    .into_response()
}

pub async fn get_session(
    State(state): State<AppState>,
    auth: Auth<Permissive>,
) -> Result<Response, ApiError> {
    let permissions = auth.permissions();
    let can_read_email = permissions.allows_email_read();

    let did_for_doc = auth.did.clone();
    let did_resolver = state.did_resolver.clone();
    let (db_result, did_doc) = tokio::join!(
        state.user_repo.get_session_info_by_did(&auth.did),
        did_resolver.resolve_did_document(&did_for_doc)
    );
    match db_result {
        Ok(Some(row)) => {
            let (preferred_channel, preferred_channel_verified) = match row.preferred_comms_channel
            {
                tranquil_db_traits::CommsChannel::Email => ("email", row.email_verified),
                tranquil_db_traits::CommsChannel::Discord => ("discord", row.discord_verified),
                tranquil_db_traits::CommsChannel::Telegram => ("telegram", row.telegram_verified),
                tranquil_db_traits::CommsChannel::Signal => ("signal", row.signal_verified),
            };
            let pds_hostname =
                std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
            let handle = full_handle(&row.handle, &pds_hostname);
            let account_state = AccountState::from_db_fields(
                row.deactivated_at,
                row.takedown_ref.clone(),
                row.migrated_to_pds.clone(),
                row.migrated_at,
            );
            let email_value = if can_read_email {
                row.email.clone()
            } else {
                None
            };
            let email_confirmed_value = can_read_email && row.email_verified;
            let mut response = json!({
                "handle": handle,
                "did": &auth.did,
                "active": account_state.is_active(),
                "preferredChannel": preferred_channel,
                "preferredChannelVerified": preferred_channel_verified,
                "preferredLocale": row.preferred_locale,
                "isAdmin": row.is_admin
            });
            if can_read_email {
                response["email"] = json!(email_value);
                response["emailConfirmed"] = json!(email_confirmed_value);
            }
            if let Some(status) = account_state.status_for_session() {
                response["status"] = json!(status);
            }
            if let AccountState::Migrated { to_pds, at } = &account_state {
                response["migratedToPds"] = json!(to_pds);
                response["migratedAt"] = json!(at);
            }
            if let Some(doc) = did_doc {
                response["didDoc"] = doc;
            }
            Ok(Json(response).into_response())
        }
        Ok(None) => Err(ApiError::AuthenticationFailed(None)),
        Err(e) => {
            error!("Database error in get_session: {:?}", e);
            Err(ApiError::InternalError(None))
        }
    }
}

pub async fn delete_session(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    _auth: Auth<Active>,
) -> Result<Response, ApiError> {
    let extracted = crate::auth::extract_auth_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    )
    .ok_or(ApiError::AuthenticationRequired)?;
    let jti = crate::auth::get_jti_from_token(&extracted.token)
        .map_err(|_| ApiError::AuthenticationFailed(None))?;
    let did = crate::auth::get_did_from_token(&extracted.token).ok();
    match state.session_repo.delete_session_by_access_jti(&jti).await {
        Ok(rows) if rows > 0 => {
            if let Some(did) = did {
                let session_cache_key = format!("auth:session:{}:{}", did, jti);
                let _ = state.cache.delete(&session_cache_key).await;
            }
            Ok(EmptyResponse::ok().into_response())
        }
        Ok(_) => Err(ApiError::AuthenticationFailed(None)),
        Err(_) => Err(ApiError::AuthenticationFailed(None)),
    }
}

pub async fn refresh_session(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let client_ip = crate::rate_limit::extract_client_ip(&headers, None);
    if !state
        .check_rate_limit(RateLimitKind::RefreshSession, &client_ip)
        .await
    {
        tracing::warn!(ip = %client_ip, "Refresh session rate limit exceeded");
        return ApiError::RateLimitExceeded(None).into_response();
    }
    let extracted = match crate::auth::extract_auth_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };
    let refresh_token = extracted.token;
    let refresh_jti = match crate::auth::get_jti_from_token(&refresh_token) {
        Ok(jti) => jti,
        Err(_) => {
            return ApiError::AuthenticationFailed(Some("Invalid token format".into()))
                .into_response();
        }
    };
    if let Ok(Some(_)) = state
        .session_repo
        .check_refresh_token_used(&refresh_jti)
        .await
    {
        warn!("Refresh token reuse detected for jti: {}", refresh_jti);
        return ApiError::AuthenticationFailed(Some(
            "Refresh token has been revoked due to suspected compromise".into(),
        ))
        .into_response();
    }
    let session_row = match state
        .session_repo
        .get_session_for_refresh(&refresh_jti)
        .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return ApiError::AuthenticationFailed(Some("Invalid refresh token".into()))
                .into_response();
        }
        Err(e) => {
            error!("Database error fetching session: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let key_bytes = match crate::config::decrypt_key(
        &session_row.key_bytes,
        Some(session_row.encryption_version),
    ) {
        Ok(k) => k,
        Err(e) => {
            error!("Failed to decrypt user key: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    if crate::auth::verify_refresh_token(&refresh_token, &key_bytes).is_err() {
        return ApiError::AuthenticationFailed(Some("Invalid refresh token".into()))
            .into_response();
    }
    let new_access_meta = match crate::auth::create_access_token_with_delegation(
        &session_row.did,
        &key_bytes,
        session_row.scope.as_deref(),
        session_row.controller_did.as_deref(),
        None,
    ) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to create access token: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let new_refresh_meta =
        match crate::auth::create_refresh_token_with_metadata(&session_row.did, &key_bytes) {
            Ok(m) => m,
            Err(e) => {
                error!("Failed to create refresh token: {:?}", e);
                return ApiError::InternalError(None).into_response();
            }
        };
    let refresh_data = tranquil_db_traits::SessionRefreshData {
        old_refresh_jti: refresh_jti.clone(),
        session_id: session_row.id,
        new_access_jti: new_access_meta.jti.clone(),
        new_refresh_jti: new_refresh_meta.jti.clone(),
        new_access_expires_at: new_access_meta.expires_at,
        new_refresh_expires_at: new_refresh_meta.expires_at,
    };
    match state
        .session_repo
        .refresh_session_atomic(&refresh_data)
        .await
    {
        Ok(tranquil_db_traits::RefreshSessionResult::Success) => {}
        Ok(tranquil_db_traits::RefreshSessionResult::TokenAlreadyUsed) => {
            warn!("Refresh token reuse detected during atomic operation");
            return ApiError::AuthenticationFailed(Some(
                "Refresh token has been revoked due to suspected compromise".into(),
            ))
            .into_response();
        }
        Ok(tranquil_db_traits::RefreshSessionResult::ConcurrentRefresh) => {
            warn!(
                "Concurrent refresh detected for session_id: {}",
                session_row.id
            );
            return ApiError::AuthenticationFailed(Some(
                "Refresh token has been revoked due to suspected compromise".into(),
            ))
            .into_response();
        }
        Err(e) => {
            error!("Database error during session refresh: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    }
    let did_for_doc = session_row.did.clone();
    let did_resolver = state.did_resolver.clone();
    let (db_result, did_doc) = tokio::join!(
        state.user_repo.get_session_info_by_did(&session_row.did),
        did_resolver.resolve_did_document(&did_for_doc)
    );
    match db_result {
        Ok(Some(u)) => {
            let (preferred_channel, preferred_channel_verified) = match u.preferred_comms_channel {
                tranquil_db_traits::CommsChannel::Email => ("email", u.email_verified),
                tranquil_db_traits::CommsChannel::Discord => ("discord", u.discord_verified),
                tranquil_db_traits::CommsChannel::Telegram => ("telegram", u.telegram_verified),
                tranquil_db_traits::CommsChannel::Signal => ("signal", u.signal_verified),
            };
            let pds_hostname =
                std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
            let handle = full_handle(&u.handle, &pds_hostname);
            let account_state =
                AccountState::from_db_fields(u.deactivated_at, u.takedown_ref.clone(), None, None);
            let mut response = json!({
                "accessJwt": new_access_meta.token,
                "refreshJwt": new_refresh_meta.token,
                "handle": handle,
                "did": session_row.did,
                "email": u.email,
                "emailConfirmed": u.email_verified,
                "preferredChannel": preferred_channel,
                "preferredChannelVerified": preferred_channel_verified,
                "preferredLocale": u.preferred_locale,
                "isAdmin": u.is_admin,
                "active": account_state.is_active()
            });
            if let Some(doc) = did_doc {
                response["didDoc"] = doc;
            }
            if let Some(status) = account_state.status_for_session() {
                response["status"] = json!(status);
            }
            Json(response).into_response()
        }
        Ok(None) => {
            error!("User not found for existing session: {}", session_row.did);
            ApiError::InternalError(None).into_response()
        }
        Err(e) => {
            error!("Database error fetching user: {:?}", e);
            ApiError::InternalError(None).into_response()
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmSignupInput {
    pub did: Did,
    pub verification_code: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmSignupOutput {
    pub access_jwt: String,
    pub refresh_jwt: String,
    pub handle: Handle,
    pub did: Did,
    pub email: Option<String>,
    pub email_verified: bool,
    pub preferred_channel: String,
    pub preferred_channel_verified: bool,
}

pub async fn confirm_signup(
    State(state): State<AppState>,
    Json(input): Json<ConfirmSignupInput>,
) -> Response {
    info!("confirm_signup called for DID: {}", input.did);
    let row = match state.user_repo.get_confirm_signup_by_did(&input.did).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            warn!("User not found for confirm_signup: {}", input.did);
            return ApiError::InvalidRequest("Invalid DID or verification code".into())
                .into_response();
        }
        Err(e) => {
            error!("Database error in confirm_signup: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let (channel_str, identifier) = match row.channel {
        tranquil_db_traits::CommsChannel::Email => ("email", row.email.clone().unwrap_or_default()),
        tranquil_db_traits::CommsChannel::Discord => {
            ("discord", row.discord_id.clone().unwrap_or_default())
        }
        tranquil_db_traits::CommsChannel::Telegram => (
            "telegram",
            row.telegram_username.clone().unwrap_or_default(),
        ),
        tranquil_db_traits::CommsChannel::Signal => {
            ("signal", row.signal_number.clone().unwrap_or_default())
        }
    };

    let normalized_token =
        crate::auth::verification_token::normalize_token_input(&input.verification_code);
    match crate::auth::verification_token::verify_signup_token(
        &normalized_token,
        channel_str,
        &identifier,
    ) {
        Ok(token_data) => {
            if token_data.did != input.did.as_str() {
                warn!(
                    "Token DID mismatch for confirm_signup: expected {}, got {}",
                    input.did, token_data.did
                );
                return ApiError::InvalidRequest("Invalid verification code".into())
                    .into_response();
            }
        }
        Err(crate::auth::verification_token::VerifyError::Expired) => {
            warn!("Verification code expired for user: {}", input.did);
            return ApiError::ExpiredToken(Some("Verification code has expired".into()))
                .into_response();
        }
        Err(e) => {
            warn!("Invalid verification code for user {}: {:?}", input.did, e);
            return ApiError::InvalidRequest("Invalid verification code".into()).into_response();
        }
    }

    let key_bytes = match crate::config::decrypt_key(&row.key_bytes, row.encryption_version) {
        Ok(k) => k,
        Err(e) => {
            error!("Failed to decrypt user key: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let access_meta = match crate::auth::create_access_token_with_metadata(&row.did, &key_bytes) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to create access token: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let refresh_meta = match crate::auth::create_refresh_token_with_metadata(&row.did, &key_bytes) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to create refresh token: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    if let Err(e) = state
        .user_repo
        .set_channel_verified(&input.did, row.channel)
        .await
    {
        error!("Failed to update verification status: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }

    let session_data = tranquil_db_traits::SessionTokenCreate {
        did: row.did.clone(),
        access_jti: access_meta.jti.clone(),
        refresh_jti: refresh_meta.jti.clone(),
        access_expires_at: access_meta.expires_at,
        refresh_expires_at: refresh_meta.expires_at,
        legacy_login: false,
        mfa_verified: false,
        scope: None,
        controller_did: None,
        app_password_name: None,
    };
    if let Err(e) = state.session_repo.create_session(&session_data).await {
        error!("Failed to insert session: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }

    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    if let Err(e) = crate::comms::comms_repo::enqueue_welcome(
        state.user_repo.as_ref(),
        state.infra_repo.as_ref(),
        row.id,
        &hostname,
    )
    .await
    {
        warn!("Failed to enqueue welcome notification: {:?}", e);
    }
    let email_verified = matches!(row.channel, tranquil_db_traits::CommsChannel::Email);
    let preferred_channel = match row.channel {
        tranquil_db_traits::CommsChannel::Email => "email",
        tranquil_db_traits::CommsChannel::Discord => "discord",
        tranquil_db_traits::CommsChannel::Telegram => "telegram",
        tranquil_db_traits::CommsChannel::Signal => "signal",
    };
    Json(ConfirmSignupOutput {
        access_jwt: access_meta.token,
        refresh_jwt: refresh_meta.token,
        handle: row.handle,
        did: row.did,
        email: row.email,
        email_verified,
        preferred_channel: preferred_channel.to_string(),
        preferred_channel_verified: true,
    })
    .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResendVerificationInput {
    pub did: Did,
}

pub async fn resend_verification(
    State(state): State<AppState>,
    Json(input): Json<ResendVerificationInput>,
) -> Response {
    info!("resend_verification called for DID: {}", input.did);
    let row = match state
        .user_repo
        .get_resend_verification_by_did(&input.did)
        .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return ApiError::InvalidRequest("User not found".into()).into_response();
        }
        Err(e) => {
            error!("Database error in resend_verification: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let is_verified =
        row.email_verified || row.discord_verified || row.telegram_verified || row.signal_verified;
    if is_verified {
        return ApiError::InvalidRequest("Account is already verified".into()).into_response();
    }

    let (channel_str, recipient) = match row.channel {
        tranquil_db_traits::CommsChannel::Email => ("email", row.email.clone().unwrap_or_default()),
        tranquil_db_traits::CommsChannel::Discord => {
            ("discord", row.discord_id.clone().unwrap_or_default())
        }
        tranquil_db_traits::CommsChannel::Telegram => (
            "telegram",
            row.telegram_username.clone().unwrap_or_default(),
        ),
        tranquil_db_traits::CommsChannel::Signal => {
            ("signal", row.signal_number.clone().unwrap_or_default())
        }
    };

    let verification_token =
        crate::auth::verification_token::generate_signup_token(&input.did, channel_str, &recipient);
    let formatted_token =
        crate::auth::verification_token::format_token_for_display(&verification_token);

    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    if let Err(e) = crate::comms::comms_repo::enqueue_signup_verification(
        state.infra_repo.as_ref(),
        row.id,
        channel_str,
        &recipient,
        &formatted_token,
        &hostname,
    )
    .await
    {
        warn!("Failed to enqueue verification notification: {:?}", e);
    }
    SuccessResponse::ok().into_response()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub id: String,
    pub session_type: String,
    pub client_name: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    pub is_current: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListSessionsOutput {
    pub sessions: Vec<SessionInfo>,
}

pub async fn list_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: Auth<Active>,
) -> Result<Response, ApiError> {
    let current_jti = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .and_then(|token| crate::auth::get_jti_from_token(token).ok());

    let jwt_rows = state
        .session_repo
        .list_sessions_by_did(&auth.did)
        .await
        .map_err(|e| {
            error!("DB error fetching JWT sessions: {:?}", e);
            ApiError::InternalError(None)
        })?;

    let oauth_rows = state
        .oauth_repo
        .list_sessions_by_did(&auth.did)
        .await
        .map_err(|e| {
            error!("DB error fetching OAuth sessions: {:?}", e);
            ApiError::InternalError(None)
        })?;

    let jwt_sessions = jwt_rows.into_iter().map(|row| SessionInfo {
        id: format!("jwt:{}", row.id),
        session_type: "legacy".to_string(),
        client_name: None,
        created_at: row.created_at.to_rfc3339(),
        expires_at: row.refresh_expires_at.to_rfc3339(),
        is_current: current_jti.as_ref() == Some(&row.access_jti),
    });

    let is_oauth = auth.is_oauth();
    let oauth_sessions = oauth_rows.into_iter().map(|row| {
        let client_name = extract_client_name(&row.client_id);
        let is_current_oauth = is_oauth && current_jti.as_deref() == Some(row.token_id.as_str());
        SessionInfo {
            id: format!("oauth:{}", row.id),
            session_type: "oauth".to_string(),
            client_name: Some(client_name),
            created_at: row.created_at.to_rfc3339(),
            expires_at: row.expires_at.to_rfc3339(),
            is_current: is_current_oauth,
        }
    });

    let mut sessions: Vec<SessionInfo> = jwt_sessions.chain(oauth_sessions).collect();
    sessions.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    Ok((StatusCode::OK, Json(ListSessionsOutput { sessions })).into_response())
}

fn extract_client_name(client_id: &str) -> String {
    if client_id.starts_with("http://localhost") || client_id.starts_with("http://127.0.0.1") {
        "Localhost App".to_string()
    } else if let Ok(parsed) = reqwest::Url::parse(client_id) {
        parsed.host_str().unwrap_or("Unknown App").to_string()
    } else {
        client_id.to_string()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeSessionInput {
    pub session_id: String,
}

pub async fn revoke_session(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<RevokeSessionInput>,
) -> Result<Response, ApiError> {
    if let Some(jwt_id) = input.session_id.strip_prefix("jwt:") {
        let session_id: i32 = jwt_id
            .parse()
            .map_err(|_| ApiError::InvalidRequest("Invalid session ID".into()))?;
        let access_jti = state
            .session_repo
            .get_session_access_jti_by_id(session_id, &auth.did)
            .await
            .map_err(|e| {
                error!("DB error in revoke_session: {:?}", e);
                ApiError::InternalError(None)
            })?
            .ok_or(ApiError::SessionNotFound)?;
        state
            .session_repo
            .delete_session_by_id(session_id)
            .await
            .map_err(|e| {
                error!("DB error deleting session: {:?}", e);
                ApiError::InternalError(None)
            })?;
        let cache_key = format!("auth:session:{}:{}", &auth.did, access_jti);
        if let Err(e) = state.cache.delete(&cache_key).await {
            warn!("Failed to invalidate session cache: {:?}", e);
        }
        info!(did = %&auth.did, session_id = %session_id, "JWT session revoked");
    } else if let Some(oauth_id) = input.session_id.strip_prefix("oauth:") {
        let session_id: i32 = oauth_id
            .parse()
            .map_err(|_| ApiError::InvalidRequest("Invalid session ID".into()))?;
        let deleted = state
            .oauth_repo
            .delete_session_by_id(session_id, &auth.did)
            .await
            .map_err(|e| {
                error!("DB error deleting OAuth session: {:?}", e);
                ApiError::InternalError(None)
            })?;
        if deleted == 0 {
            return Err(ApiError::SessionNotFound);
        }
        info!(did = %&auth.did, session_id = %session_id, "OAuth session revoked");
    } else {
        return Err(ApiError::InvalidRequest("Invalid session ID format".into()));
    }
    Ok(EmptyResponse::ok().into_response())
}

pub async fn revoke_all_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: Auth<Active>,
) -> Result<Response, ApiError> {
    let jti = crate::auth::extract_auth_token_from_header(
        headers.get("authorization").and_then(|v| v.to_str().ok()),
    )
    .and_then(|extracted| crate::auth::get_jti_from_token(&extracted.token).ok())
    .ok_or(ApiError::InvalidToken(None))?;

    if auth.is_oauth() {
        state
            .session_repo
            .delete_sessions_by_did(&auth.did)
            .await
            .map_err(|e| {
                error!("DB error revoking JWT sessions: {:?}", e);
                ApiError::InternalError(None)
            })?;
        let jti_typed = TokenId::from(jti.clone());
        state
            .oauth_repo
            .delete_sessions_by_did_except(&auth.did, &jti_typed)
            .await
            .map_err(|e| {
                error!("DB error revoking OAuth sessions: {:?}", e);
                ApiError::InternalError(None)
            })?;
    } else {
        state
            .session_repo
            .delete_sessions_by_did_except_jti(&auth.did, &jti)
            .await
            .map_err(|e| {
                error!("DB error revoking JWT sessions: {:?}", e);
                ApiError::InternalError(None)
            })?;
        state
            .oauth_repo
            .delete_sessions_by_did(&auth.did)
            .await
            .map_err(|e| {
                error!("DB error revoking OAuth sessions: {:?}", e);
                ApiError::InternalError(None)
            })?;
    }

    info!(did = %&auth.did, "All other sessions revoked");
    Ok(SuccessResponse::ok().into_response())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyLoginPreferenceOutput {
    pub allow_legacy_login: bool,
    pub has_mfa: bool,
}

pub async fn get_legacy_login_preference(
    State(state): State<AppState>,
    auth: Auth<Active>,
) -> Result<Response, ApiError> {
    let pref = state
        .user_repo
        .get_legacy_login_pref(&auth.did)
        .await
        .map_err(|e| {
            error!("DB error: {:?}", e);
            ApiError::InternalError(None)
        })?
        .ok_or(ApiError::AccountNotFound)?;
    Ok(Json(LegacyLoginPreferenceOutput {
        allow_legacy_login: pref.allow_legacy_login,
        has_mfa: pref.has_mfa,
    })
    .into_response())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateLegacyLoginInput {
    pub allow_legacy_login: bool,
}

pub async fn update_legacy_login_preference(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<UpdateLegacyLoginInput>,
) -> Result<Response, ApiError> {
    if !crate::api::server::reauth::check_legacy_session_mfa(&*state.session_repo, &auth.did).await
    {
        return Ok(crate::api::server::reauth::legacy_mfa_required_response(
            &*state.user_repo,
            &*state.session_repo,
            &auth.did,
        )
        .await);
    }

    if crate::api::server::reauth::check_reauth_required(&*state.session_repo, &auth.did).await {
        return Ok(crate::api::server::reauth::reauth_required_response(
            &*state.user_repo,
            &*state.session_repo,
            &auth.did,
        )
        .await);
    }

    let updated = state
        .user_repo
        .update_legacy_login(&auth.did, input.allow_legacy_login)
        .await
        .map_err(|e| {
            error!("DB error: {:?}", e);
            ApiError::InternalError(None)
        })?;
    if !updated {
        return Err(ApiError::AccountNotFound);
    }
    info!(
        did = %&auth.did,
        allow_legacy_login = input.allow_legacy_login,
        "Legacy login preference updated"
    );
    Ok(Json(json!({
        "allowLegacyLogin": input.allow_legacy_login
    }))
    .into_response())
}

use crate::comms::VALID_LOCALES;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateLocaleInput {
    pub preferred_locale: String,
}

pub async fn update_locale(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<UpdateLocaleInput>,
) -> Result<Response, ApiError> {
    if !VALID_LOCALES.contains(&input.preferred_locale.as_str()) {
        return Err(ApiError::InvalidRequest(format!(
            "Invalid locale. Valid options: {}",
            VALID_LOCALES.join(", ")
        )));
    }

    let updated = state
        .user_repo
        .update_locale(&auth.did, &input.preferred_locale)
        .await
        .map_err(|e| {
            error!("DB error updating locale: {:?}", e);
            ApiError::InternalError(None)
        })?;
    if !updated {
        return Err(ApiError::AccountNotFound);
    }
    info!(
        did = %&auth.did,
        locale = %input.preferred_locale,
        "User locale preference updated"
    );
    Ok(Json(json!({
        "preferredLocale": input.preferred_locale
    }))
    .into_response())
}
