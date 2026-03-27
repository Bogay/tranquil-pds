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
use tranquil_pds::api::error::{ApiError, DbResultExt};
use tranquil_pds::api::{EmptyResponse, PreferredLocaleOutput, SuccessResponse};
use tranquil_pds::auth::{
    Active, Auth, NormalizedLoginIdentifier, Permissive, require_legacy_session_mfa,
    require_reauth_window,
};
use tranquil_pds::rate_limit::{LoginLimit, RateLimited, RefreshSessionLimit};
use tranquil_pds::state::AppState;
use tranquil_pds::types::{AccountState, Did, Handle, PlainPassword};
use tranquil_types::TokenId;

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
) -> Result<Response, ApiError> {
    let client_ip = rate_limit.client_ip();
    info!(
        "create_session called with identifier: {}",
        input.identifier
    );
    let hostname_for_handles = tranquil_config::get().server.hostname_without_port();
    let normalized_identifier =
        NormalizedLoginIdentifier::normalize(&input.identifier, hostname_for_handles);
    info!(
        "Normalized identifier: {} -> {}",
        input.identifier, normalized_identifier
    );
    let row = match state
        .repos
        .user
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
            return Err(ApiError::AuthenticationFailed(Some(
                "Invalid identifier or password".into(),
            )));
        }
        Err(e) => {
            error!("Database error fetching user: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    };
    let key_bytes = match tranquil_pds::config::decrypt_key(&row.key_bytes, row.encryption_version)
    {
        Ok(k) => k,
        Err(e) => {
            error!("Failed to decrypt user key: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    };
    let credential = crate::common::verify_credential(
        state.repos.session.as_ref(),
        row.id,
        &input.password,
        row.password_hash.as_deref(),
    )
    .await;
    let (app_password_name, app_password_scopes, app_password_controller) = match credential {
        Some(crate::common::CredentialMatch::MainPassword) => (None, None, None),
        Some(crate::common::CredentialMatch::AppPassword {
            name,
            scopes,
            controller_did,
        }) => (Some(name), scopes, controller_did),
        None => {
            warn!("Password verification failed for login attempt");
            return Err(ApiError::AuthenticationFailed(Some(
                "Invalid identifier or password".into(),
            )));
        }
    };
    let account_state = AccountState::from_db_fields(
        row.deactivated_at,
        row.takedown_ref.clone(),
        row.migrated_to_pds.clone(),
        None,
    );
    if account_state.is_takendown() && !input.allow_takendown {
        warn!("Login attempt for takendown account: {}", row.did);
        return Err(ApiError::AccountTakedown);
    }
    let is_verified = row.channel_verification.has_any_verified();
    let is_delegated = state
        .repos
        .delegation
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
        return Ok((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "account_not_verified",
                "message": "Please verify your account before logging in",
                "did": row.did,
                "handle": handle,
                "channel": channel
            })),
        )
            .into_response());
    }
    let has_totp = row.totp_enabled;
    let email_2fa_enabled = row.email_2fa_enabled;
    let is_legacy_login = has_totp || email_2fa_enabled;
    let twofa_ctx = tranquil_pds::auth::legacy_2fa::Legacy2faContext {
        email_2fa_enabled,
        has_totp,
        allow_legacy_login: row.allow_legacy_login,
    };
    match tranquil_pds::auth::legacy_2fa::process_legacy_2fa(
        state.cache.as_ref(),
        &row.did,
        &twofa_ctx,
        input.auth_factor_token.as_deref(),
    )
    .await
    {
        Ok(tranquil_pds::auth::legacy_2fa::Legacy2faOutcome::NotRequired) => {}
        Ok(tranquil_pds::auth::legacy_2fa::Legacy2faOutcome::Blocked) => {
            warn!("Legacy login blocked for TOTP-enabled account: {}", row.did);
            return Err(ApiError::LegacyLoginBlocked);
        }
        Ok(tranquil_pds::auth::legacy_2fa::Legacy2faOutcome::ChallengeSent(code)) => {
            let hostname = &tranquil_config::get().server.hostname;
            if let Err(e) = tranquil_pds::comms::comms_repo::enqueue_2fa_code(
                state.repos.user.as_ref(),
                state.repos.infra.as_ref(),
                row.id,
                code.as_str(),
                hostname,
            )
            .await
            {
                error!("Failed to send 2FA code: {:?}", e);
                tranquil_pds::auth::legacy_2fa::clear_challenge(state.cache.as_ref(), &row.did)
                    .await;
                return Err(ApiError::InternalError(Some(
                    "Failed to send verification code. Please try again.".into(),
                )));
            }
            return Err(ApiError::AuthFactorTokenRequired);
        }
        Ok(tranquil_pds::auth::legacy_2fa::Legacy2faOutcome::Verified) => {}
        Err(tranquil_pds::auth::legacy_2fa::Legacy2faFlowError::Challenge(e)) => {
            use tranquil_pds::auth::legacy_2fa::ChallengeError;
            return match e {
                ChallengeError::CacheUnavailable => {
                    error!("Cache unavailable for 2FA, blocking legacy login");
                    Err(ApiError::ServiceUnavailable(Some(
                        "2FA service temporarily unavailable. Please try again later or use an OAuth client.".into(),
                    )))
                }
                ChallengeError::RateLimited => Err(ApiError::RateLimitExceeded(Some(
                    "Please wait before requesting a new verification code.".into(),
                ))),
                ChallengeError::CacheError => {
                    error!("Cache error during 2FA challenge creation");
                    Err(ApiError::InternalError(None))
                }
            };
        }
        Err(tranquil_pds::auth::legacy_2fa::Legacy2faFlowError::Validation(e)) => {
            use tranquil_pds::auth::legacy_2fa::ValidationError;
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
            return Err(ApiError::InvalidCode(Some(msg.into())));
        }
    }
    let access_meta = match tranquil_pds::auth::create_access_token_with_delegation(
        &row.did,
        &key_bytes,
        app_password_scopes.as_deref(),
        app_password_controller.as_deref(),
        None,
    ) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to create access token: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    };
    let refresh_meta =
        match tranquil_pds::auth::create_refresh_token_with_metadata(&row.did, &key_bytes) {
            Ok(m) => m,
            Err(e) => {
                error!("Failed to create refresh token: {:?}", e);
                return Err(ApiError::InternalError(None));
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
        state.repos.session.create_session(&session_data),
        did_resolver.fetch_did_document(&did_for_doc),
    );
    if let Err(e) = insert_result {
        error!("Failed to insert session: {:?}", e);
        return Err(ApiError::InternalError(None));
    }
    if is_legacy_login {
        warn!(
            did = %row.did,
            ip = %client_ip,
            "Legacy login on TOTP-enabled account - sending notification"
        );
        let hostname = &tranquil_config::get().server.hostname;
        if let Err(e) = tranquil_pds::comms::comms_repo::enqueue_legacy_login(
            state.repos.user.as_ref(),
            state.repos.infra.as_ref(),
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
    let handle = row.handle.clone();
    let is_active = account_state.is_active();
    let status = account_state.status_for_session().map(String::from);
    let email_auth_factor_out = if email_2fa_enabled || has_totp {
        Some(true)
    } else {
        None
    };
    Ok((
        StatusCode::OK,
        Json(CreateSessionOutput {
            access_jwt: access_meta.token,
            refresh_jwt: refresh_meta.token,
            handle,
            did: row.did,
            did_doc: did_doc.ok().map(|f| (*f).clone()),
            email: row.email,
            email_confirmed: Some(row.channel_verification.email),
            email_auth_factor: email_auth_factor_out,
            active: Some(is_active),
            status,
        }),
    )
        .into_response())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetSessionOutput {
    pub handle: Handle,
    pub did: Did,
    pub active: bool,
    pub preferred_channel: String,
    pub preferred_channel_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_locale: Option<String>,
    pub is_admin: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_confirmed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_auth_factor: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub migrated_to_pds: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub migrated_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_doc: Option<serde_json::Value>,
}

pub async fn get_session(
    State(state): State<AppState>,
    auth: Auth<Permissive>,
) -> Result<Json<GetSessionOutput>, ApiError> {
    let permissions = auth.permissions();
    let can_read_email = permissions.allows_email_read();

    let did_for_doc = auth.did.clone();
    let did_resolver = state.did_resolver.clone();
    let (db_result, did_doc) = tokio::join!(
        state.repos.user.get_session_info_by_did(&auth.did),
        did_resolver.fetch_did_document(&did_for_doc)
    );
    match db_result {
        Ok(Some(row)) => {
            let preferred_channel_verified = row
                .channel_verification
                .is_verified(row.preferred_comms_channel);
            let handle = row.handle.clone();
            let account_state = AccountState::from_db_fields(
                row.deactivated_at,
                row.takedown_ref.clone(),
                row.migrated_to_pds.clone(),
                row.migrated_at,
            );
            let email = match can_read_email {
                true => row.email.clone(),
                false => None,
            };
            let email_confirmed = match can_read_email {
                true => Some(row.channel_verification.email),
                false => None,
            };
            let email_auth_factor = match row.email_2fa_enabled || row.totp_enabled {
                true => Some(true),
                false => None,
            };
            let (migrated_to_pds, migrated_at) = match &account_state {
                AccountState::Migrated { to_pds, at } => (Some(to_pds.clone()), Some(*at)),
                _ => (None, None),
            };
            Ok(Json(GetSessionOutput {
                handle,
                did: auth.did.clone(),
                active: account_state.is_active(),
                preferred_channel: row.preferred_comms_channel.as_str().to_string(),
                preferred_channel_verified,
                preferred_locale: row.preferred_locale,
                is_admin: row.is_admin,
                email,
                email_confirmed,
                email_auth_factor,
                status: account_state.status_for_session().map(String::from),
                migrated_to_pds,
                migrated_at,
                did_doc: did_doc.ok().map(|f| (*f).clone()),
            }))
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
    auth: Auth<Active>,
) -> Result<Json<EmptyResponse>, ApiError> {
    let jti = tranquil_pds::auth::extract_jti_from_headers(&headers)
        .ok_or(ApiError::AuthenticationRequired)?;
    match state.repos.session.delete_session_by_access_jti(&jti).await {
        Ok(rows) if rows > 0 => {
            let session_cache_key = tranquil_pds::cache_keys::session_key(&auth.did, &jti);
            let _ = state.cache.delete(&session_cache_key).await;
            Ok(Json(EmptyResponse {}))
        }
        Ok(_) => Err(ApiError::AuthenticationFailed(None)),
        Err(_) => Err(ApiError::AuthenticationFailed(None)),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshSessionOutput {
    pub access_jwt: String,
    pub refresh_jwt: String,
    pub handle: Handle,
    pub did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub email_confirmed: bool,
    pub preferred_channel: String,
    pub preferred_channel_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_locale: Option<String>,
    pub is_admin: bool,
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_doc: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

pub async fn refresh_session(
    State(state): State<AppState>,
    _rate_limit: RateLimited<RefreshSessionLimit>,
    headers: axum::http::HeaderMap,
) -> Result<Json<RefreshSessionOutput>, ApiError> {
    let extracted = match tranquil_pds::auth::extract_auth_token_from_header(
        tranquil_pds::util::get_header_str(&headers, http::header::AUTHORIZATION),
    ) {
        Some(t) => t,
        None => return Err(ApiError::AuthenticationRequired),
    };
    let refresh_token = extracted.token;
    let refresh_jti = match tranquil_pds::auth::get_jti_from_token(&refresh_token) {
        Ok(jti) => jti,
        Err(_) => {
            return Err(ApiError::AuthenticationFailed(Some(
                "Invalid token format".into(),
            )));
        }
    };
    if let Ok(Some(_)) = state
        .repos
        .session
        .check_refresh_token_used(&refresh_jti)
        .await
    {
        warn!("Refresh token reuse detected for jti: {}", refresh_jti);
        return Err(ApiError::AuthenticationFailed(Some(
            "Refresh token has been revoked due to suspected compromise".into(),
        )));
    }
    let session_row = match state
        .repos
        .session
        .get_session_for_refresh(&refresh_jti)
        .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return Err(ApiError::AuthenticationFailed(Some(
                "Invalid refresh token".into(),
            )));
        }
        Err(e) => {
            error!("Database error fetching session: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    };
    let key_bytes = match tranquil_pds::config::decrypt_key(
        &session_row.key_bytes,
        Some(session_row.encryption_version),
    ) {
        Ok(k) => k,
        Err(e) => {
            error!("Failed to decrypt user key: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    };
    if tranquil_pds::auth::verify_refresh_token(&refresh_token, &key_bytes).is_err() {
        return Err(ApiError::AuthenticationFailed(Some(
            "Invalid refresh token".into(),
        )));
    }
    let new_access_meta = match tranquil_pds::auth::create_access_token_with_delegation(
        &session_row.did,
        &key_bytes,
        session_row.scope.as_deref(),
        session_row.controller_did.as_deref(),
        None,
    ) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to create access token: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    };
    let new_refresh_meta = match tranquil_pds::auth::create_refresh_token_with_metadata(
        &session_row.did,
        &key_bytes,
    ) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to create refresh token: {:?}", e);
            return Err(ApiError::InternalError(None));
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
        .repos
        .session
        .refresh_session_atomic(&refresh_data)
        .await
    {
        Ok(tranquil_db_traits::RefreshSessionResult::Success) => {}
        Ok(tranquil_db_traits::RefreshSessionResult::TokenAlreadyUsed) => {
            warn!("Refresh token reuse detected during atomic operation");
            return Err(ApiError::AuthenticationFailed(Some(
                "Refresh token has been revoked due to suspected compromise".into(),
            )));
        }
        Ok(tranquil_db_traits::RefreshSessionResult::ConcurrentRefresh) => {
            warn!(
                "Concurrent refresh detected for session_id: {}",
                session_row.id
            );
            return Err(ApiError::AuthenticationFailed(Some(
                "Refresh token has been revoked due to suspected compromise".into(),
            )));
        }
        Err(e) => {
            error!("Database error during session refresh: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    }
    let did_for_doc = session_row.did.clone();
    let did_resolver = state.did_resolver.clone();
    let (db_result, did_doc) = tokio::join!(
        state.repos.user.get_session_info_by_did(&session_row.did),
        did_resolver.fetch_did_document(&did_for_doc)
    );
    match db_result {
        Ok(Some(u)) => {
            let preferred_channel_verified = u
                .channel_verification
                .is_verified(u.preferred_comms_channel);
            let handle = u.handle.clone();
            let account_state =
                AccountState::from_db_fields(u.deactivated_at, u.takedown_ref.clone(), None, None);
            Ok(Json(RefreshSessionOutput {
                access_jwt: new_access_meta.token,
                refresh_jwt: new_refresh_meta.token,
                handle,
                did: session_row.did,
                email: u.email,
                email_confirmed: u.channel_verification.email,
                preferred_channel: u.preferred_comms_channel.as_str().to_string(),
                preferred_channel_verified,
                preferred_locale: u.preferred_locale,
                is_admin: u.is_admin,
                active: account_state.is_active(),
                did_doc: did_doc.ok().map(|f| (*f).clone()),
                status: account_state.status_for_session().map(String::from),
            }))
        }
        Ok(None) => {
            error!("User not found for existing session: {}", session_row.did);
            Err(ApiError::InternalError(None))
        }
        Err(e) => {
            error!("Database error fetching user: {:?}", e);
            Err(ApiError::InternalError(None))
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
) -> Result<Json<ConfirmSignupOutput>, ApiError> {
    info!("confirm_signup called for DID: {}", input.did);
    let row = match state.repos.user.get_confirm_signup_by_did(&input.did).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            warn!("User not found for confirm_signup: {}", input.did);
            return Err(ApiError::InvalidRequest(
                "Invalid DID or verification code".into(),
            ));
        }
        Err(e) => {
            error!("Database error in confirm_signup: {:?}", e);
            return Err(ApiError::InternalError(None));
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
        tranquil_pds::auth::verification_token::normalize_token_input(&input.verification_code);
    match tranquil_pds::auth::verification_token::verify_signup_token(
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
                return Err(ApiError::InvalidRequest("Invalid verification code".into()));
            }
        }
        Err(tranquil_pds::auth::verification_token::VerifyError::Expired) => {
            warn!("Verification code expired for user: {}", input.did);
            return Err(ApiError::ExpiredToken(Some(
                "Verification code has expired".into(),
            )));
        }
        Err(e) => {
            warn!("Invalid verification code for user {}: {:?}", input.did, e);
            return Err(ApiError::InvalidRequest("Invalid verification code".into()));
        }
    }

    let key_bytes = match tranquil_pds::config::decrypt_key(&row.key_bytes, row.encryption_version)
    {
        Ok(k) => k,
        Err(e) => {
            error!("Failed to decrypt user key: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    };

    if let Err(e) = state
        .repos
        .user
        .set_channel_verified(&input.did, row.channel)
        .await
    {
        error!("Failed to update verification status: {:?}", e);
        return Err(ApiError::InternalError(None));
    }

    let session = match crate::identity::provision::create_and_store_session(
        &state,
        &row.did,
        &row.did,
        &key_bytes,
        "transition:generic transition:chat.bsky",
        None,
    )
    .await
    {
        Ok(s) => s,
        Err(_) => return Err(ApiError::InternalError(None)),
    };

    let hostname = &tranquil_config::get().server.hostname;
    if let Err(e) = tranquil_pds::comms::comms_repo::enqueue_welcome(
        state.repos.user.as_ref(),
        state.repos.infra.as_ref(),
        row.id,
        hostname,
    )
    .await
    {
        warn!("Failed to enqueue welcome notification: {:?}", e);
    }
    Ok(Json(ConfirmSignupOutput {
        access_jwt: session.access_jwt,
        refresh_jwt: session.refresh_jwt,
        handle: row.handle,
        did: row.did,
        email: row.email,
        email_verified: matches!(row.channel, tranquil_db_traits::CommsChannel::Email),
        preferred_channel: row.channel,
        preferred_channel_verified: true,
    }))
}

const AUTO_VERIFY_DEBOUNCE: std::time::Duration = std::time::Duration::from_secs(120);

pub struct AutoResendResult {
    pub handle: tranquil_types::Handle,
    pub channel: tranquil_db_traits::CommsChannel,
}

pub async fn auto_resend_verification(state: &AppState, did: &Did) -> Option<AutoResendResult> {
    let debounce_key = tranquil_pds::cache_keys::auto_verify_sent_key(did.as_str());
    let debounced = state.cache.get(&debounce_key).await.is_some();
    let row = match state.repos.user.get_resend_verification_by_did(did).await {
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
    crate::identity::provision::enqueue_signup_verification(
        state,
        row.id,
        did,
        row.channel,
        &recipient,
    )
    .await;
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
) -> Result<Json<SuccessResponse>, ApiError> {
    info!("resend_verification called for DID: {}", input.did);
    let row = match state
        .repos
        .user
        .get_resend_verification_by_did(&input.did)
        .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return Err(ApiError::InvalidRequest("User not found".into()));
        }
        Err(e) => {
            error!("Database error in resend_verification: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    };
    let is_verified = row.channel_verification.has_any_verified();
    if is_verified {
        return Err(ApiError::InvalidRequest(
            "Account is already verified".into(),
        ));
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

    crate::identity::provision::enqueue_signup_verification(
        &state,
        row.id,
        &input.did,
        row.channel,
        &recipient,
    )
    .await;
    Ok(Json(SuccessResponse { success: true }))
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
) -> Result<Json<ListSessionsOutput>, ApiError> {
    let current_jti = tranquil_pds::auth::extract_jti_from_headers(&headers);

    let jwt_rows = state
        .repos
        .session
        .list_sessions_by_did(&auth.did)
        .await
        .log_db_err("fetching JWT sessions")?;

    let oauth_rows = state
        .repos
        .oauth
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

    Ok(Json(ListSessionsOutput { sessions }))
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
) -> Result<Json<EmptyResponse>, ApiError> {
    if let Some(jwt_id) = input.session_id.strip_prefix("jwt:") {
        let session_id = jwt_id
            .parse::<i32>()
            .map(SessionId::new)
            .map_err(|_| ApiError::InvalidRequest("Invalid session ID".into()))?;
        let access_jti = state
            .repos
            .session
            .get_session_access_jti_by_id(session_id, &auth.did)
            .await
            .log_db_err("in revoke_session")?
            .ok_or(ApiError::SessionNotFound)?;
        state
            .repos
            .session
            .delete_session_by_id(session_id)
            .await
            .log_db_err("deleting session")?;
        let cache_key = tranquil_pds::cache_keys::session_key(&auth.did, &access_jti);
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
            .repos
            .oauth
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
    Ok(Json(EmptyResponse {}))
}

pub async fn revoke_all_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: Auth<Active>,
) -> Result<Json<SuccessResponse>, ApiError> {
    let jti = tranquil_pds::auth::extract_jti_from_headers(&headers)
        .ok_or(ApiError::InvalidToken(None))?;

    if auth.is_oauth() {
        state
            .repos
            .session
            .delete_sessions_by_did(&auth.did)
            .await
            .log_db_err("revoking JWT sessions")?;
        let jti_typed = TokenId::from(jti.clone());
        state
            .repos
            .oauth
            .delete_sessions_by_did_except(&auth.did, &jti_typed)
            .await
            .log_db_err("revoking OAuth sessions")?;
    } else {
        state
            .repos
            .session
            .delete_sessions_by_did_except_jti(&auth.did, &jti)
            .await
            .log_db_err("revoking JWT sessions")?;
        state
            .repos
            .oauth
            .delete_sessions_by_did(&auth.did)
            .await
            .log_db_err("revoking OAuth sessions")?;
    }

    info!(did = %&auth.did, "All other sessions revoked");
    Ok(Json(SuccessResponse { success: true }))
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
) -> Result<Json<LegacyLoginPreferenceOutput>, ApiError> {
    let pref = state
        .repos
        .user
        .get_legacy_login_pref(&auth.did)
        .await
        .log_db_err("getting legacy login pref")?
        .ok_or(ApiError::AccountNotFound)?;
    Ok(Json(LegacyLoginPreferenceOutput {
        allow_legacy_login: pref.allow_legacy_login,
        has_mfa: pref.has_mfa,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateLegacyLoginInput {
    pub allow_legacy_login: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateLegacyLoginOutput {
    pub allow_legacy_login: bool,
}

pub async fn update_legacy_login_preference(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<UpdateLegacyLoginInput>,
) -> Result<Json<UpdateLegacyLoginOutput>, ApiError> {
    let session_mfa = require_legacy_session_mfa(&state, &auth).await?;

    let reauth_mfa = require_reauth_window(&state, &auth).await?;

    let updated = state
        .repos
        .user
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
    Ok(Json(UpdateLegacyLoginOutput {
        allow_legacy_login: input.allow_legacy_login,
    }))
}

use tranquil_pds::comms::VALID_LOCALES;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateLocaleInput {
    pub preferred_locale: String,
}

pub async fn update_locale(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<UpdateLocaleInput>,
) -> Result<Json<PreferredLocaleOutput>, ApiError> {
    if !VALID_LOCALES.contains(&input.preferred_locale.as_str()) {
        return Err(ApiError::InvalidRequest(format!(
            "Invalid locale. Valid options: {}",
            VALID_LOCALES.join(", ")
        )));
    }

    let updated = state
        .repos
        .user
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
    Ok(Json(PreferredLocaleOutput {
        preferred_locale: Some(input.preferred_locale),
    }))
}
