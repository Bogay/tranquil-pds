use crate::api::error::{ApiError, DbResultExt};
use crate::api::{EmptyResponse, SuccessResponse};
use crate::auth::{
    Active, Auth, NormalizedLoginIdentifier, Permissive, require_legacy_session_mfa,
    require_reauth_window,
};
use crate::rate_limit::{LoginLimit, RateLimited, RefreshSessionLimit};
use crate::state::AppState;
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
use tranquil_db_traits::{SessionId, TokenFamilyId};
use tranquil_types::TokenId;

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
    pub auth_factor_token: Option<String>,
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
    pub email_auth_factor: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

pub async fn create_session(
    State(state): State<AppState>,
    rate_limit: RateLimited<LoginLimit>,
    Json(input): Json<CreateSessionInput>,
) -> Response {
    let client_ip = rate_limit.client_ip();
    info!(
        "create_session called with identifier: {}",
        input.identifier
    );
    let pds_host = &tranquil_config::get().server.hostname;
    let hostname_for_handles = tranquil_config::get().server.hostname_without_port();
    let normalized_identifier =
        NormalizedLoginIdentifier::normalize(&input.identifier, hostname_for_handles);
    info!(
        "Normalized identifier: {} -> {}",
        input.identifier, normalized_identifier
    );
    let row = match state
        .user_repo
        .get_login_full_by_identifier(normalized_identifier.as_str())
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
    let is_verified = row.channel_verification.has_any_verified();
    let is_delegated = state
        .delegation_repo
        .is_delegated_account(&row.did)
        .await
        .unwrap_or(false);
    if !is_verified && !is_delegated {
        warn!("Login attempt for unverified account: {}", row.did);
        let resend_info = auto_resend_verification(&state, &row.did).await;
        let handle = resend_info
            .as_ref()
            .map(|r| r.handle.to_string())
            .unwrap_or_else(|| row.handle.to_string());
        let channel = resend_info
            .as_ref()
            .map(|r| r.channel.as_str())
            .unwrap_or(row.preferred_comms_channel.as_str());
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "account_not_verified",
                "message": "Please verify your account before logging in",
                "did": row.did,
                "handle": handle,
                "channel": channel
            })),
        )
            .into_response();
    }
    let has_totp = row.totp_enabled;
    let email_2fa_enabled = row.email_2fa_enabled;
    let is_legacy_login = has_totp || email_2fa_enabled;
    let twofa_ctx = crate::auth::legacy_2fa::Legacy2faContext {
        email_2fa_enabled,
        has_totp,
        allow_legacy_login: row.allow_legacy_login,
    };
    match crate::auth::legacy_2fa::process_legacy_2fa(
        state.cache.as_ref(),
        &row.did,
        &twofa_ctx,
        input.auth_factor_token.as_deref(),
    )
    .await
    {
        Ok(crate::auth::legacy_2fa::Legacy2faOutcome::NotRequired) => {}
        Ok(crate::auth::legacy_2fa::Legacy2faOutcome::Blocked) => {
            warn!("Legacy login blocked for TOTP-enabled account: {}", row.did);
            return ApiError::LegacyLoginBlocked.into_response();
        }
        Ok(crate::auth::legacy_2fa::Legacy2faOutcome::ChallengeSent(code)) => {
            let hostname = &tranquil_config::get().server.hostname;
            if let Err(e) = crate::comms::comms_repo::enqueue_2fa_code(
                state.user_repo.as_ref(),
                state.infra_repo.as_ref(),
                row.id,
                code.as_str(),
                hostname,
            )
            .await
            {
                error!("Failed to send 2FA code: {:?}", e);
                crate::auth::legacy_2fa::clear_challenge(state.cache.as_ref(), &row.did).await;
                return ApiError::InternalError(Some(
                    "Failed to send verification code. Please try again.".into(),
                ))
                .into_response();
            }
            return ApiError::AuthFactorTokenRequired.into_response();
        }
        Ok(crate::auth::legacy_2fa::Legacy2faOutcome::Verified) => {}
        Err(crate::auth::legacy_2fa::Legacy2faFlowError::Challenge(e)) => {
            use crate::auth::legacy_2fa::ChallengeError;
            return match e {
                ChallengeError::CacheUnavailable => {
                    error!("Cache unavailable for 2FA, blocking legacy login");
                    ApiError::ServiceUnavailable(Some(
                        "2FA service temporarily unavailable. Please try again later or use an OAuth client.".into(),
                    ))
                    .into_response()
                }
                ChallengeError::RateLimited => ApiError::RateLimitExceeded(Some(
                    "Please wait before requesting a new verification code.".into(),
                ))
                .into_response(),
                ChallengeError::CacheError => {
                    error!("Cache error during 2FA challenge creation");
                    ApiError::InternalError(None).into_response()
                }
            };
        }
        Err(crate::auth::legacy_2fa::Legacy2faFlowError::Validation(e)) => {
            use crate::auth::legacy_2fa::ValidationError;
            warn!("Invalid 2FA code for {}: {:?}", row.did, e);
            let msg = match e {
                ValidationError::TooManyAttempts => "Too many attempts. Please request a new code.",
                ValidationError::ChallengeExpired => "Code has expired. Please request a new code.",
                ValidationError::CacheUnavailable => {
                    "2FA service temporarily unavailable. Please try again later."
                }
                ValidationError::ChallengeNotFound
                | ValidationError::InvalidCode
                | ValidationError::CacheError => "Invalid verification code",
            };
            return ApiError::InvalidCode(Some(msg.into())).into_response();
        }
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
        login_type: tranquil_db_traits::LoginType::from_legacy_flag(is_legacy_login),
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
        let hostname = &tranquil_config::get().server.hostname;
        if let Err(e) = crate::comms::comms_repo::enqueue_legacy_login(
            state.user_repo.as_ref(),
            state.infra_repo.as_ref(),
            row.id,
            hostname,
            client_ip,
            row.preferred_comms_channel,
        )
        .await
        {
            error!("Failed to queue legacy login notification: {:?}", e);
        }
    }
    let handle = full_handle(&row.handle, pds_host);
    let is_active = account_state.is_active();
    let status = account_state.status_for_session().map(String::from);
    let email_auth_factor_out = if email_2fa_enabled || has_totp {
        Some(true)
    } else {
        None
    };
    Json(CreateSessionOutput {
        access_jwt: access_meta.token,
        refresh_jwt: refresh_meta.token,
        handle: handle.into(),
        did: row.did,
        did_doc,
        email: row.email,
        email_confirmed: Some(row.channel_verification.email),
        email_auth_factor: email_auth_factor_out,
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
            let preferred_channel_verified = row
                .channel_verification
                .is_verified(row.preferred_comms_channel);
            let pds_hostname = &tranquil_config::get().server.hostname;
            let handle = full_handle(&row.handle, pds_hostname);
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
            let email_confirmed_value = can_read_email && row.channel_verification.email;
            let mut response = json!({
                "handle": handle,
                "did": &auth.did,
                "active": account_state.is_active(),
                "preferredChannel": row.preferred_comms_channel.as_str(),
                "preferredChannelVerified": preferred_channel_verified,
                "preferredLocale": row.preferred_locale,
                "isAdmin": row.is_admin
            });
            if can_read_email {
                response["email"] = json!(email_value);
                response["emailConfirmed"] = json!(email_confirmed_value);
            }
            if row.email_2fa_enabled || row.totp_enabled {
                response["emailAuthFactor"] = json!(true);
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
    let extracted = crate::auth::extract_auth_token_from_header(crate::util::get_header_str(
        &headers,
        http::header::AUTHORIZATION,
    ))
    .ok_or(ApiError::AuthenticationRequired)?;
    let jti = crate::auth::get_jti_from_token(&extracted.token)
        .map_err(|_| ApiError::AuthenticationFailed(None))?;
    let did = crate::auth::get_did_from_token(&extracted.token).ok();
    match state.session_repo.delete_session_by_access_jti(&jti).await {
        Ok(rows) if rows > 0 => {
            if let Some(did) = did {
                let session_cache_key = crate::cache_keys::session_key(&did, &jti);
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
    _rate_limit: RateLimited<RefreshSessionLimit>,
    headers: axum::http::HeaderMap,
) -> Response {
    let extracted = match crate::auth::extract_auth_token_from_header(crate::util::get_header_str(
        &headers,
        http::header::AUTHORIZATION,
    )) {
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
            let preferred_channel_verified = u
                .channel_verification
                .is_verified(u.preferred_comms_channel);
            let pds_hostname = &tranquil_config::get().server.hostname;
            let handle = full_handle(&u.handle, pds_hostname);
            let account_state =
                AccountState::from_db_fields(u.deactivated_at, u.takedown_ref.clone(), None, None);
            let mut response = json!({
                "accessJwt": new_access_meta.token,
                "refreshJwt": new_refresh_meta.token,
                "handle": handle,
                "did": session_row.did,
                "email": u.email,
                "emailConfirmed": u.channel_verification.email,
                "preferredChannel": u.preferred_comms_channel.as_str(),
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
    pub preferred_channel: tranquil_db_traits::CommsChannel,
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

    let identifier = match row.channel {
        tranquil_db_traits::CommsChannel::Email => row.email.clone().unwrap_or_default(),
        tranquil_db_traits::CommsChannel::Discord => {
            row.discord_username.clone().unwrap_or_default()
        }
        tranquil_db_traits::CommsChannel::Telegram => {
            row.telegram_username.clone().unwrap_or_default()
        }
        tranquil_db_traits::CommsChannel::Signal => row.signal_username.clone().unwrap_or_default(),
    };

    let normalized_token =
        crate::auth::verification_token::normalize_token_input(&input.verification_code);
    match crate::auth::verification_token::verify_signup_token(
        &normalized_token,
        row.channel,
        &identifier,
    ) {
        Ok(token_data) => {
            if token_data.did != input.did {
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
        login_type: tranquil_db_traits::LoginType::Modern,
        mfa_verified: false,
        scope: None,
        controller_did: None,
        app_password_name: None,
    };
    if let Err(e) = state.session_repo.create_session(&session_data).await {
        error!("Failed to insert session: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }

    let hostname = &tranquil_config::get().server.hostname;
    if let Err(e) = crate::comms::comms_repo::enqueue_welcome(
        state.user_repo.as_ref(),
        state.infra_repo.as_ref(),
        row.id,
        hostname,
    )
    .await
    {
        warn!("Failed to enqueue welcome notification: {:?}", e);
    }
    Json(ConfirmSignupOutput {
        access_jwt: access_meta.token,
        refresh_jwt: refresh_meta.token,
        handle: row.handle,
        did: row.did,
        email: row.email,
        email_verified: matches!(row.channel, tranquil_db_traits::CommsChannel::Email),
        preferred_channel: row.channel,
        preferred_channel_verified: true,
    })
    .into_response()
}

const AUTO_VERIFY_DEBOUNCE: std::time::Duration = std::time::Duration::from_secs(120);

pub struct AutoResendResult {
    pub handle: tranquil_types::Handle,
    pub channel: tranquil_db_traits::CommsChannel,
}

pub async fn auto_resend_verification(state: &AppState, did: &Did) -> Option<AutoResendResult> {
    let debounce_key = crate::cache_keys::auto_verify_sent_key(did.as_str());
    let debounced = state.cache.get(&debounce_key).await.is_some();
    let row = match state.user_repo.get_resend_verification_by_did(did).await {
        Ok(Some(row)) => row,
        Ok(None) => return None,
        Err(e) => {
            warn!(
                "Failed to fetch resend verification info for {}: {:?}",
                did, e
            );
            return None;
        }
    };
    if row.channel_verification.has_any_verified() {
        return None;
    }
    let result = AutoResendResult {
        handle: row.handle.clone(),
        channel: row.channel,
    };
    let is_bot_channel = matches!(
        row.channel,
        tranquil_db_traits::CommsChannel::Telegram | tranquil_db_traits::CommsChannel::Discord
    );
    if is_bot_channel || debounced {
        return Some(result);
    }
    let recipient = match row.channel {
        tranquil_db_traits::CommsChannel::Email => row.email.clone().unwrap_or_default(),
        tranquil_db_traits::CommsChannel::Signal => row.signal_username.clone().unwrap_or_default(),
        _ => return Some(result),
    };
    if recipient.is_empty() {
        warn!(
            "No recipient configured for auto-resend verification: {}",
            did
        );
        return Some(result);
    }
    let verification_token =
        crate::auth::verification_token::generate_signup_token(did, row.channel, &recipient);
    let formatted_token =
        crate::auth::verification_token::format_token_for_display(&verification_token);
    let hostname = &tranquil_config::get().server.hostname;
    if let Err(e) = crate::comms::comms_repo::enqueue_signup_verification(
        state.user_repo.as_ref(),
        state.infra_repo.as_ref(),
        row.id,
        row.channel,
        &recipient,
        &formatted_token,
        hostname,
    )
    .await
    {
        warn!("Failed to auto-resend verification for {}: {:?}", did, e);
        return Some(result);
    }
    let _ = state
        .cache
        .set(&debounce_key, "1", AUTO_VERIFY_DEBOUNCE)
        .await;
    Some(result)
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
    let is_verified = row.channel_verification.has_any_verified();
    if is_verified {
        return ApiError::InvalidRequest("Account is already verified".into()).into_response();
    }

    let recipient = match row.channel {
        tranquil_db_traits::CommsChannel::Email => row.email.clone().unwrap_or_default(),
        tranquil_db_traits::CommsChannel::Discord => {
            row.discord_username.clone().unwrap_or_default()
        }
        tranquil_db_traits::CommsChannel::Telegram => {
            row.telegram_username.clone().unwrap_or_default()
        }
        tranquil_db_traits::CommsChannel::Signal => row.signal_username.clone().unwrap_or_default(),
    };

    let verification_token =
        crate::auth::verification_token::generate_signup_token(&input.did, row.channel, &recipient);
    let formatted_token =
        crate::auth::verification_token::format_token_for_display(&verification_token);

    let hostname = &tranquil_config::get().server.hostname;
    if let Err(e) = crate::comms::comms_repo::enqueue_signup_verification(
        state.user_repo.as_ref(),
        state.infra_repo.as_ref(),
        row.id,
        row.channel,
        &recipient,
        &formatted_token,
        hostname,
    )
    .await
    {
        warn!("Failed to enqueue verification notification: {:?}", e);
    }
    SuccessResponse::ok().into_response()
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionType {
    Legacy,
    OAuth,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub id: String,
    pub session_type: SessionType,
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
        .log_db_err("fetching JWT sessions")?;

    let oauth_rows = state
        .oauth_repo
        .list_sessions_by_did(&auth.did)
        .await
        .log_db_err("fetching OAuth sessions")?;

    let jwt_sessions = jwt_rows.into_iter().map(|row| SessionInfo {
        id: format!("jwt:{}", row.id),
        session_type: SessionType::Legacy,
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
            session_type: SessionType::OAuth,
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
        let session_id = jwt_id
            .parse::<i32>()
            .map(SessionId::new)
            .map_err(|_| ApiError::InvalidRequest("Invalid session ID".into()))?;
        let access_jti = state
            .session_repo
            .get_session_access_jti_by_id(session_id, &auth.did)
            .await
            .log_db_err("in revoke_session")?
            .ok_or(ApiError::SessionNotFound)?;
        state
            .session_repo
            .delete_session_by_id(session_id)
            .await
            .log_db_err("deleting session")?;
        let cache_key = crate::cache_keys::session_key(&auth.did, &access_jti);
        if let Err(e) = state.cache.delete(&cache_key).await {
            warn!("Failed to invalidate session cache: {:?}", e);
        }
        info!(did = %&auth.did, session_id = %session_id, "JWT session revoked");
    } else if let Some(oauth_id) = input.session_id.strip_prefix("oauth:") {
        let session_id = oauth_id
            .parse::<i32>()
            .map(TokenFamilyId::new)
            .map_err(|_| ApiError::InvalidRequest("Invalid session ID".into()))?;
        let deleted = state
            .oauth_repo
            .delete_session_by_id(session_id, &auth.did)
            .await
            .log_db_err("deleting OAuth session")?;
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
            .log_db_err("revoking JWT sessions")?;
        let jti_typed = TokenId::from(jti.clone());
        state
            .oauth_repo
            .delete_sessions_by_did_except(&auth.did, &jti_typed)
            .await
            .log_db_err("revoking OAuth sessions")?;
    } else {
        state
            .session_repo
            .delete_sessions_by_did_except_jti(&auth.did, &jti)
            .await
            .log_db_err("revoking JWT sessions")?;
        state
            .oauth_repo
            .delete_sessions_by_did(&auth.did)
            .await
            .log_db_err("revoking OAuth sessions")?;
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
        .log_db_err("getting legacy login pref")?
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
    let session_mfa = match require_legacy_session_mfa(&state, &auth).await {
        Ok(proof) => proof,
        Err(response) => return Ok(response),
    };

    let reauth_mfa = match require_reauth_window(&state, &auth).await {
        Ok(proof) => proof,
        Err(response) => return Ok(response),
    };

    let updated = state
        .user_repo
        .update_legacy_login(reauth_mfa.did(), input.allow_legacy_login)
        .await
        .log_db_err("updating legacy login")?;
    if !updated {
        return Err(ApiError::AccountNotFound);
    }
    info!(
        did = %session_mfa.did(),
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
        .log_db_err("updating locale")?;
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
