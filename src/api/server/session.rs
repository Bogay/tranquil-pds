use crate::api::ApiError;
use crate::auth::{BearerAuth, BearerAuthAllowDeactivated};
use crate::state::{AppState, RateLimitKind};
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
pub struct CreateSessionInput {
    pub identifier: String,
    pub password: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionOutput {
    pub access_jwt: String,
    pub refresh_jwt: String,
    pub handle: String,
    pub did: String,
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
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "RateLimitExceeded",
                "message": "Too many login attempts. Please try again later."
            })),
        )
            .into_response();
    }
    let pds_hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let normalized_identifier = normalize_handle(&input.identifier, &pds_hostname);
    info!(
        "Normalized identifier: {} -> {}",
        input.identifier, normalized_identifier
    );
    let row = match sqlx::query!(
        r#"SELECT
            u.id, u.did, u.handle, u.password_hash,
            u.email_verified, u.discord_verified, u.telegram_verified, u.signal_verified,
            u.allow_legacy_login,
            u.preferred_comms_channel as "preferred_comms_channel: crate::comms::CommsChannel",
            k.key_bytes, k.encryption_version,
            (SELECT verified FROM user_totp WHERE did = u.did) as totp_enabled
        FROM users u
        JOIN user_keys k ON u.id = k.user_id
        WHERE u.handle = $1 OR u.email = $1 OR u.did = $1"#,
        normalized_identifier
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            let _ = verify(
                &input.password,
                "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.VTtYw1ZzQKZqmK",
            );
            warn!("User not found for login attempt");
            return ApiError::AuthenticationFailedMsg("Invalid identifier or password".into())
                .into_response();
        }
        Err(e) => {
            error!("Database error fetching user: {:?}", e);
            return ApiError::InternalError.into_response();
        }
    };
    let key_bytes = match crate::config::decrypt_key(&row.key_bytes, row.encryption_version) {
        Ok(k) => k,
        Err(e) => {
            error!("Failed to decrypt user key: {:?}", e);
            return ApiError::InternalError.into_response();
        }
    };
    let (password_valid, app_password_scopes) = if row
        .password_hash
        .as_ref()
        .map(|h| verify(&input.password, h).unwrap_or(false))
        .unwrap_or(false)
    {
        (true, None)
    } else {
        let app_passwords = sqlx::query!(
            "SELECT password_hash, scopes FROM app_passwords WHERE user_id = $1 ORDER BY created_at DESC LIMIT 20",
            row.id
        )
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();
        let matched = app_passwords
            .iter()
            .find(|app| verify(&input.password, &app.password_hash).unwrap_or(false));
        match matched {
            Some(app) => (true, app.scopes.clone()),
            None => (false, None),
        }
    };
    if !password_valid {
        warn!("Password verification failed for login attempt");
        return ApiError::AuthenticationFailedMsg("Invalid identifier or password".into())
            .into_response();
    }
    let is_verified =
        row.email_verified || row.discord_verified || row.telegram_verified || row.signal_verified;
    if !is_verified {
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
    let has_totp = row.totp_enabled.unwrap_or(false);
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
    let access_meta = match crate::auth::create_access_token_with_scope_metadata(
        &row.did,
        &key_bytes,
        app_password_scopes.as_deref(),
    ) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to create access token: {:?}", e);
            return ApiError::InternalError.into_response();
        }
    };
    let refresh_meta = match crate::auth::create_refresh_token_with_metadata(&row.did, &key_bytes) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to create refresh token: {:?}", e);
            return ApiError::InternalError.into_response();
        }
    };
    if let Err(e) = sqlx::query!(
        "INSERT INTO session_tokens (did, access_jti, refresh_jti, access_expires_at, refresh_expires_at, legacy_login, mfa_verified, scope) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        row.did,
        access_meta.jti,
        refresh_meta.jti,
        access_meta.expires_at,
        refresh_meta.expires_at,
        is_legacy_login,
        false,
        app_password_scopes
    )
    .execute(&state.db)
    .await
    {
        error!("Failed to insert session: {:?}", e);
        return ApiError::InternalError.into_response();
    }
    if is_legacy_login {
        warn!(
            did = %row.did,
            ip = %client_ip,
            "Legacy login on TOTP-enabled account - sending notification"
        );
        let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
        if let Err(e) = crate::comms::queue_legacy_login_notification(
            &state.db,
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
    Json(CreateSessionOutput {
        access_jwt: access_meta.token,
        refresh_jwt: refresh_meta.token,
        handle,
        did: row.did,
    })
    .into_response()
}

pub async fn get_session(
    State(state): State<AppState>,
    BearerAuthAllowDeactivated(auth_user): BearerAuthAllowDeactivated,
) -> Response {
    let permissions = auth_user.permissions();
    let can_read_email = permissions.allows_email_read();

    match sqlx::query!(
        r#"SELECT
            handle, email, email_verified, is_admin, deactivated_at, preferred_locale,
            preferred_comms_channel as "preferred_channel: crate::comms::CommsChannel",
            discord_verified, telegram_verified, signal_verified
        FROM users WHERE did = $1"#,
        auth_user.did
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => {
            let (preferred_channel, preferred_channel_verified) = match row.preferred_channel {
                crate::comms::CommsChannel::Email => ("email", row.email_verified),
                crate::comms::CommsChannel::Discord => ("discord", row.discord_verified),
                crate::comms::CommsChannel::Telegram => ("telegram", row.telegram_verified),
                crate::comms::CommsChannel::Signal => ("signal", row.signal_verified),
            };
            let pds_hostname =
                std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
            let handle = full_handle(&row.handle, &pds_hostname);
            let is_active = row.deactivated_at.is_none();
            let email_value = if can_read_email {
                row.email.clone()
            } else {
                None
            };
            let email_verified_value = can_read_email && row.email_verified;
            Json(json!({
                "handle": handle,
                "did": auth_user.did,
                "email": email_value,
                "emailVerified": email_verified_value,
                "preferredChannel": preferred_channel,
                "preferredChannelVerified": preferred_channel_verified,
                "preferredLocale": row.preferred_locale,
                "isAdmin": row.is_admin,
                "active": is_active,
                "status": if is_active { "active" } else { "deactivated" },
                "didDoc": {}
            }))
            .into_response()
        }
        Ok(None) => ApiError::AuthenticationFailed.into_response(),
        Err(e) => {
            error!("Database error in get_session: {:?}", e);
            ApiError::InternalError.into_response()
        }
    }
}

pub async fn delete_session(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };
    let jti = match crate::auth::get_jti_from_token(&token) {
        Ok(jti) => jti,
        Err(_) => return ApiError::AuthenticationFailed.into_response(),
    };
    let did = crate::auth::get_did_from_token(&token).ok();
    match sqlx::query!("DELETE FROM session_tokens WHERE access_jti = $1", jti)
        .execute(&state.db)
        .await
    {
        Ok(res) if res.rows_affected() > 0 => {
            if let Some(did) = did {
                let session_cache_key = format!("auth:session:{}:{}", did, jti);
                let _ = state.cache.delete(&session_cache_key).await;
            }
            Json(json!({})).into_response()
        }
        Ok(_) => ApiError::AuthenticationFailed.into_response(),
        Err(e) => {
            error!("Database error in delete_session: {:?}", e);
            ApiError::AuthenticationFailed.into_response()
        }
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
        return (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            axum::Json(serde_json::json!({
                "error": "RateLimitExceeded",
                "message": "Too many requests. Please try again later."
            })),
        )
            .into_response();
    }
    let refresh_token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };
    let refresh_jti = match crate::auth::get_jti_from_token(&refresh_token) {
        Ok(jti) => jti,
        Err(_) => {
            return ApiError::AuthenticationFailedMsg("Invalid token format".into())
                .into_response();
        }
    };
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            error!("Failed to begin transaction: {:?}", e);
            return ApiError::InternalError.into_response();
        }
    };
    if let Ok(Some(session_id)) = sqlx::query_scalar!(
        "SELECT session_id FROM used_refresh_tokens WHERE refresh_jti = $1 FOR UPDATE",
        refresh_jti
    )
    .fetch_optional(&mut *tx)
    .await
    {
        warn!(
            "Refresh token reuse detected! Revoking token family for session_id: {}",
            session_id
        );
        let _ = sqlx::query!("DELETE FROM session_tokens WHERE id = $1", session_id)
            .execute(&mut *tx)
            .await;
        let _ = tx.commit().await;
        return ApiError::ExpiredTokenMsg(
            "Refresh token has been revoked due to suspected compromise".into(),
        )
        .into_response();
    }
    let session_row = match sqlx::query!(
        r#"SELECT st.id, st.did, st.scope, k.key_bytes, k.encryption_version
           FROM session_tokens st
           JOIN users u ON st.did = u.did
           JOIN user_keys k ON u.id = k.user_id
           WHERE st.refresh_jti = $1 AND st.refresh_expires_at > NOW()
           FOR UPDATE OF st"#,
        refresh_jti
    )
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return ApiError::AuthenticationFailedMsg("Invalid refresh token".into())
                .into_response();
        }
        Err(e) => {
            error!("Database error fetching session: {:?}", e);
            return ApiError::InternalError.into_response();
        }
    };
    let key_bytes =
        match crate::config::decrypt_key(&session_row.key_bytes, session_row.encryption_version) {
            Ok(k) => k,
            Err(e) => {
                error!("Failed to decrypt user key: {:?}", e);
                return ApiError::InternalError.into_response();
            }
        };
    if crate::auth::verify_refresh_token(&refresh_token, &key_bytes).is_err() {
        return ApiError::AuthenticationFailedMsg("Invalid refresh token".into()).into_response();
    }
    let new_access_meta = match crate::auth::create_access_token_with_scope_metadata(
        &session_row.did,
        &key_bytes,
        session_row.scope.as_deref(),
    ) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to create access token: {:?}", e);
            return ApiError::InternalError.into_response();
        }
    };
    let new_refresh_meta =
        match crate::auth::create_refresh_token_with_metadata(&session_row.did, &key_bytes) {
            Ok(m) => m,
            Err(e) => {
                error!("Failed to create refresh token: {:?}", e);
                return ApiError::InternalError.into_response();
            }
        };
    match sqlx::query!(
        "INSERT INTO used_refresh_tokens (refresh_jti, session_id) VALUES ($1, $2) ON CONFLICT (refresh_jti) DO NOTHING",
        refresh_jti,
        session_row.id
    )
    .execute(&mut *tx)
    .await
    {
        Ok(result) if result.rows_affected() == 0 => {
            warn!("Concurrent refresh token reuse detected for session_id: {}", session_row.id);
            let _ = sqlx::query!("DELETE FROM session_tokens WHERE id = $1", session_row.id)
                .execute(&mut *tx)
                .await;
            let _ = tx.commit().await;
            return ApiError::ExpiredTokenMsg("Refresh token has been revoked due to suspected compromise".into()).into_response();
        }
        Err(e) => {
            error!("Failed to record used refresh token: {:?}", e);
            return ApiError::InternalError.into_response();
        }
        Ok(_) => {}
    }
    if let Err(e) = sqlx::query!(
        "UPDATE session_tokens SET access_jti = $1, refresh_jti = $2, access_expires_at = $3, refresh_expires_at = $4, updated_at = NOW() WHERE id = $5",
        new_access_meta.jti,
        new_refresh_meta.jti,
        new_access_meta.expires_at,
        new_refresh_meta.expires_at,
        session_row.id
    )
    .execute(&mut *tx)
    .await
    {
        error!("Database error updating session: {:?}", e);
        return ApiError::InternalError.into_response();
    }
    if let Err(e) = tx.commit().await {
        error!("Failed to commit transaction: {:?}", e);
        return ApiError::InternalError.into_response();
    }
    match sqlx::query!(
        r#"SELECT
            handle, email, email_verified, is_admin, preferred_locale,
            preferred_comms_channel as "preferred_channel: crate::comms::CommsChannel",
            discord_verified, telegram_verified, signal_verified
        FROM users WHERE did = $1"#,
        session_row.did
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(u)) => {
            let (preferred_channel, preferred_channel_verified) = match u.preferred_channel {
                crate::comms::CommsChannel::Email => ("email", u.email_verified),
                crate::comms::CommsChannel::Discord => ("discord", u.discord_verified),
                crate::comms::CommsChannel::Telegram => ("telegram", u.telegram_verified),
                crate::comms::CommsChannel::Signal => ("signal", u.signal_verified),
            };
            let pds_hostname =
                std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
            let handle = full_handle(&u.handle, &pds_hostname);
            Json(json!({
                "accessJwt": new_access_meta.token,
                "refreshJwt": new_refresh_meta.token,
                "handle": handle,
                "did": session_row.did,
                "email": u.email,
                "emailVerified": u.email_verified,
                "preferredChannel": preferred_channel,
                "preferredChannelVerified": preferred_channel_verified,
                "preferredLocale": u.preferred_locale,
                "isAdmin": u.is_admin,
                "active": true
            }))
            .into_response()
        }
        Ok(None) => {
            error!("User not found for existing session: {}", session_row.did);
            ApiError::InternalError.into_response()
        }
        Err(e) => {
            error!("Database error fetching user: {:?}", e);
            ApiError::InternalError.into_response()
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmSignupInput {
    pub did: String,
    pub verification_code: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmSignupOutput {
    pub access_jwt: String,
    pub refresh_jwt: String,
    pub handle: String,
    pub did: String,
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
    let row = match sqlx::query!(
        r#"SELECT
            u.id, u.did, u.handle, u.email,
            u.preferred_comms_channel as "channel: crate::comms::CommsChannel",
            u.discord_id, u.telegram_username, u.signal_number,
            k.key_bytes, k.encryption_version
        FROM users u
        JOIN user_keys k ON u.id = k.user_id
        WHERE u.did = $1"#,
        input.did
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            warn!("User not found for confirm_signup: {}", input.did);
            return ApiError::InvalidRequest("Invalid DID or verification code".into())
                .into_response();
        }
        Err(e) => {
            error!("Database error in confirm_signup: {:?}", e);
            return ApiError::InternalError.into_response();
        }
    };

    let (channel_str, identifier) = match row.channel {
        crate::comms::CommsChannel::Email => ("email", row.email.clone().unwrap_or_default()),
        crate::comms::CommsChannel::Discord => {
            ("discord", row.discord_id.clone().unwrap_or_default())
        }
        crate::comms::CommsChannel::Telegram => (
            "telegram",
            row.telegram_username.clone().unwrap_or_default(),
        ),
        crate::comms::CommsChannel::Signal => {
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
            return ApiError::ExpiredTokenMsg("Verification code has expired".into())
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
            return ApiError::InternalError.into_response();
        }
    };
    let verified_column = match row.channel {
        crate::comms::CommsChannel::Email => "email_verified",
        crate::comms::CommsChannel::Discord => "discord_verified",
        crate::comms::CommsChannel::Telegram => "telegram_verified",
        crate::comms::CommsChannel::Signal => "signal_verified",
    };
    let update_query = format!("UPDATE users SET {} = TRUE WHERE did = $1", verified_column);
    if let Err(e) = sqlx::query(&update_query)
        .bind(&input.did)
        .execute(&state.db)
        .await
    {
        error!("Failed to update verification status: {:?}", e);
        return ApiError::InternalError.into_response();
    }

    let access_meta = match crate::auth::create_access_token_with_metadata(&row.did, &key_bytes) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to create access token: {:?}", e);
            return ApiError::InternalError.into_response();
        }
    };
    let refresh_meta = match crate::auth::create_refresh_token_with_metadata(&row.did, &key_bytes) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to create refresh token: {:?}", e);
            return ApiError::InternalError.into_response();
        }
    };
    let no_scope: Option<String> = None;
    if let Err(e) = sqlx::query!(
        "INSERT INTO session_tokens (did, access_jti, refresh_jti, access_expires_at, refresh_expires_at, legacy_login, mfa_verified, scope) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        row.did,
        access_meta.jti,
        refresh_meta.jti,
        access_meta.expires_at,
        refresh_meta.expires_at,
        false,
        false,
        no_scope
    )
    .execute(&state.db)
    .await
    {
        error!("Failed to insert session: {:?}", e);
        return ApiError::InternalError.into_response();
    }
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    if let Err(e) = crate::comms::enqueue_welcome(&state.db, row.id, &hostname).await {
        warn!("Failed to enqueue welcome notification: {:?}", e);
    }
    let email_verified = matches!(row.channel, crate::comms::CommsChannel::Email);
    let preferred_channel = match row.channel {
        crate::comms::CommsChannel::Email => "email",
        crate::comms::CommsChannel::Discord => "discord",
        crate::comms::CommsChannel::Telegram => "telegram",
        crate::comms::CommsChannel::Signal => "signal",
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
    pub did: String,
}

pub async fn resend_verification(
    State(state): State<AppState>,
    Json(input): Json<ResendVerificationInput>,
) -> Response {
    info!("resend_verification called for DID: {}", input.did);
    let row = match sqlx::query!(
        r#"SELECT
            id, handle, email,
            preferred_comms_channel as "channel: crate::comms::CommsChannel",
            discord_id, telegram_username, signal_number,
            email_verified, discord_verified, telegram_verified, signal_verified
        FROM users
        WHERE did = $1"#,
        input.did
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return ApiError::InvalidRequest("User not found".into()).into_response();
        }
        Err(e) => {
            error!("Database error in resend_verification: {:?}", e);
            return ApiError::InternalError.into_response();
        }
    };
    let is_verified =
        row.email_verified || row.discord_verified || row.telegram_verified || row.signal_verified;
    if is_verified {
        return ApiError::InvalidRequest("Account is already verified".into()).into_response();
    }

    let (channel_str, recipient) = match row.channel {
        crate::comms::CommsChannel::Email => ("email", row.email.clone().unwrap_or_default()),
        crate::comms::CommsChannel::Discord => {
            ("discord", row.discord_id.clone().unwrap_or_default())
        }
        crate::comms::CommsChannel::Telegram => (
            "telegram",
            row.telegram_username.clone().unwrap_or_default(),
        ),
        crate::comms::CommsChannel::Signal => {
            ("signal", row.signal_number.clone().unwrap_or_default())
        }
    };

    let verification_token =
        crate::auth::verification_token::generate_signup_token(&input.did, channel_str, &recipient);
    let formatted_token =
        crate::auth::verification_token::format_token_for_display(&verification_token);

    if let Err(e) = crate::comms::enqueue_signup_verification(
        &state.db,
        row.id,
        channel_str,
        &recipient,
        &formatted_token,
        None,
    )
    .await
    {
        warn!("Failed to enqueue verification notification: {:?}", e);
    }
    Json(json!({"success": true})).into_response()
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
    auth: BearerAuth,
) -> Response {
    let current_jti = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .and_then(|token| crate::auth::get_jti_from_token(token).ok());

    let mut sessions: Vec<SessionInfo> = Vec::new();

    let jwt_result = sqlx::query_as::<
        _,
        (
            i32,
            String,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        ),
    >(
        r#"
        SELECT id, access_jti, created_at, refresh_expires_at
        FROM session_tokens
        WHERE did = $1 AND refresh_expires_at > NOW()
        ORDER BY created_at DESC
        "#,
    )
    .bind(&auth.0.did)
    .fetch_all(&state.db)
    .await;

    match jwt_result {
        Ok(rows) => {
            for (id, access_jti, created_at, expires_at) in rows {
                sessions.push(SessionInfo {
                    id: format!("jwt:{}", id),
                    session_type: "legacy".to_string(),
                    client_name: None,
                    created_at: created_at.to_rfc3339(),
                    expires_at: expires_at.to_rfc3339(),
                    is_current: current_jti.as_ref() == Some(&access_jti),
                });
            }
        }
        Err(e) => {
            error!("DB error fetching JWT sessions: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    }

    let oauth_result = sqlx::query_as::<
        _,
        (
            i32,
            String,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
            String,
        ),
    >(
        r#"
        SELECT id, token_id, created_at, expires_at, client_id
        FROM oauth_token
        WHERE did = $1 AND expires_at > NOW()
        ORDER BY created_at DESC
        "#,
    )
    .bind(&auth.0.did)
    .fetch_all(&state.db)
    .await;

    match oauth_result {
        Ok(rows) => {
            for (id, token_id, created_at, expires_at, client_id) in rows {
                let client_name = extract_client_name(&client_id);
                let is_current_oauth = auth.0.is_oauth && current_jti.as_ref() == Some(&token_id);
                sessions.push(SessionInfo {
                    id: format!("oauth:{}", id),
                    session_type: "oauth".to_string(),
                    client_name: Some(client_name),
                    created_at: created_at.to_rfc3339(),
                    expires_at: expires_at.to_rfc3339(),
                    is_current: is_current_oauth,
                });
            }
        }
        Err(e) => {
            error!("DB error fetching OAuth sessions: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    }

    sessions.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    (StatusCode::OK, Json(ListSessionsOutput { sessions })).into_response()
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
    auth: BearerAuth,
    Json(input): Json<RevokeSessionInput>,
) -> Response {
    if let Some(jwt_id) = input.session_id.strip_prefix("jwt:") {
        let session_id: i32 = match jwt_id.parse() {
            Ok(id) => id,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "InvalidRequest", "message": "Invalid session ID"})),
                )
                    .into_response();
            }
        };
        let session = sqlx::query_as::<_, (String,)>(
            "SELECT access_jti FROM session_tokens WHERE id = $1 AND did = $2",
        )
        .bind(session_id)
        .bind(&auth.0.did)
        .fetch_optional(&state.db)
        .await;
        let access_jti = match session {
            Ok(Some((jti,))) => jti,
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "SessionNotFound", "message": "Session not found"})),
                )
                    .into_response();
            }
            Err(e) => {
                error!("DB error in revoke_session: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }
        };
        if let Err(e) = sqlx::query("DELETE FROM session_tokens WHERE id = $1")
            .bind(session_id)
            .execute(&state.db)
            .await
        {
            error!("DB error deleting session: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
        let cache_key = format!("auth:session:{}:{}", auth.0.did, access_jti);
        if let Err(e) = state.cache.delete(&cache_key).await {
            warn!("Failed to invalidate session cache: {:?}", e);
        }
        info!(did = %auth.0.did, session_id = %session_id, "JWT session revoked");
    } else if let Some(oauth_id) = input.session_id.strip_prefix("oauth:") {
        let session_id: i32 = match oauth_id.parse() {
            Ok(id) => id,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "InvalidRequest", "message": "Invalid session ID"})),
                )
                    .into_response();
            }
        };
        let result = sqlx::query("DELETE FROM oauth_token WHERE id = $1 AND did = $2")
            .bind(session_id)
            .bind(&auth.0.did)
            .execute(&state.db)
            .await;
        match result {
            Ok(r) if r.rows_affected() == 0 => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "SessionNotFound", "message": "Session not found"})),
                )
                    .into_response();
            }
            Err(e) => {
                error!("DB error deleting OAuth session: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }
            _ => {}
        }
        info!(did = %auth.0.did, session_id = %session_id, "OAuth session revoked");
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "Invalid session ID format"})),
        )
            .into_response();
    }
    (StatusCode::OK, Json(json!({}))).into_response()
}

pub async fn revoke_all_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: BearerAuth,
) -> Response {
    let current_jti = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .and_then(|token| crate::auth::get_jti_from_token(token).ok());

    if let Some(ref jti) = current_jti {
        if auth.0.is_oauth {
            if let Err(e) = sqlx::query("DELETE FROM session_tokens WHERE did = $1")
                .bind(&auth.0.did)
                .execute(&state.db)
                .await
            {
                error!("DB error revoking JWT sessions: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }
            if let Err(e) = sqlx::query("DELETE FROM oauth_token WHERE did = $1 AND token_id != $2")
                .bind(&auth.0.did)
                .bind(jti)
                .execute(&state.db)
                .await
            {
                error!("DB error revoking OAuth sessions: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }
        } else {
            if let Err(e) =
                sqlx::query("DELETE FROM session_tokens WHERE did = $1 AND access_jti != $2")
                    .bind(&auth.0.did)
                    .bind(jti)
                    .execute(&state.db)
                    .await
            {
                error!("DB error revoking JWT sessions: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }
            if let Err(e) = sqlx::query("DELETE FROM oauth_token WHERE did = $1")
                .bind(&auth.0.did)
                .execute(&state.db)
                .await
            {
                error!("DB error revoking OAuth sessions: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }
        }
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidToken", "message": "Could not identify current session"})),
        )
            .into_response();
    }

    info!(did = %auth.0.did, "All other sessions revoked");
    (StatusCode::OK, Json(json!({"success": true}))).into_response()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyLoginPreferenceOutput {
    pub allow_legacy_login: bool,
    pub has_mfa: bool,
}

pub async fn get_legacy_login_preference(
    State(state): State<AppState>,
    auth: BearerAuth,
) -> Response {
    let result = sqlx::query!(
        r#"SELECT
            u.allow_legacy_login,
            (EXISTS(SELECT 1 FROM user_totp t WHERE t.did = u.did AND t.verified = TRUE) OR
             EXISTS(SELECT 1 FROM passkeys p WHERE p.did = u.did)) as "has_mfa!"
        FROM users u WHERE u.did = $1"#,
        auth.0.did
    )
    .fetch_optional(&state.db)
    .await;

    match result {
        Ok(Some(row)) => Json(LegacyLoginPreferenceOutput {
            allow_legacy_login: row.allow_legacy_login,
            has_mfa: row.has_mfa,
        })
        .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "AccountNotFound"})),
        )
            .into_response(),
        Err(e) => {
            error!("DB error: {:?}", e);
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
pub struct UpdateLegacyLoginInput {
    pub allow_legacy_login: bool,
}

pub async fn update_legacy_login_preference(
    State(state): State<AppState>,
    auth: BearerAuth,
    Json(input): Json<UpdateLegacyLoginInput>,
) -> Response {
    if !crate::api::server::reauth::check_legacy_session_mfa(&state.db, &auth.0.did).await {
        return crate::api::server::reauth::legacy_mfa_required_response(&state.db, &auth.0.did)
            .await;
    }

    if crate::api::server::reauth::check_reauth_required(&state.db, &auth.0.did).await {
        return crate::api::server::reauth::reauth_required_response(&state.db, &auth.0.did).await;
    }

    let result = sqlx::query!(
        "UPDATE users SET allow_legacy_login = $1 WHERE did = $2 RETURNING did",
        input.allow_legacy_login,
        auth.0.did
    )
    .fetch_optional(&state.db)
    .await;

    match result {
        Ok(Some(_)) => {
            info!(
                did = %auth.0.did,
                allow_legacy_login = input.allow_legacy_login,
                "Legacy login preference updated"
            );
            Json(json!({
                "allowLegacyLogin": input.allow_legacy_login
            }))
            .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "AccountNotFound"})),
        )
            .into_response(),
        Err(e) => {
            error!("DB error: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

use crate::comms::locale::VALID_LOCALES;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateLocaleInput {
    pub preferred_locale: String,
}

pub async fn update_locale(
    State(state): State<AppState>,
    auth: BearerAuth,
    Json(input): Json<UpdateLocaleInput>,
) -> Response {
    if !VALID_LOCALES.contains(&input.preferred_locale.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "InvalidRequest",
                "message": format!("Invalid locale. Valid options: {}", VALID_LOCALES.join(", "))
            })),
        )
            .into_response();
    }

    let result = sqlx::query!(
        "UPDATE users SET preferred_locale = $1 WHERE did = $2 RETURNING did",
        input.preferred_locale,
        auth.0.did
    )
    .fetch_optional(&state.db)
    .await;

    match result {
        Ok(Some(_)) => {
            info!(
                did = %auth.0.did,
                locale = %input.preferred_locale,
                "User locale preference updated"
            );
            Json(json!({
                "preferredLocale": input.preferred_locale
            }))
            .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "AccountNotFound"})),
        )
            .into_response(),
        Err(e) => {
            error!("DB error updating locale: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}
