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
use chrono::Utc;
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
    info!("create_session called with identifier: {}", input.identifier);
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
    info!("Normalized identifier: {} -> {}", input.identifier, normalized_identifier);
    let row = match sqlx::query!(
        r#"SELECT
            u.id, u.did, u.handle, u.password_hash,
            u.email_verified, u.discord_verified, u.telegram_verified, u.signal_verified,
            k.key_bytes, k.encryption_version
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
    let password_valid = if verify(&input.password, &row.password_hash).unwrap_or(false) {
        true
    } else {
        let app_passwords = sqlx::query!(
            "SELECT password_hash FROM app_passwords WHERE user_id = $1 ORDER BY created_at DESC LIMIT 20",
            row.id
        )
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();
        app_passwords
            .iter()
            .any(|app| verify(&input.password, &app.password_hash).unwrap_or(false))
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
    if let Err(e) = sqlx::query!(
        "INSERT INTO session_tokens (did, access_jti, refresh_jti, access_expires_at, refresh_expires_at) VALUES ($1, $2, $3, $4, $5)",
        row.did,
        access_meta.jti,
        refresh_meta.jti,
        access_meta.expires_at,
        refresh_meta.expires_at
    )
    .execute(&state.db)
    .await
    {
        error!("Failed to insert session: {:?}", e);
        return ApiError::InternalError.into_response();
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
            handle, email, email_verified, is_admin, deactivated_at,
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
        r#"SELECT st.id, st.did, k.key_bytes, k.encryption_version
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
    let new_access_meta =
        match crate::auth::create_access_token_with_metadata(&session_row.did, &key_bytes) {
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
            handle, email, email_verified, is_admin,
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

    let verification = match sqlx::query!(
        "SELECT code, expires_at FROM channel_verifications WHERE user_id = $1 AND channel = 'email'",
        row.id
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(v)) => v,
        Ok(None) => {
            warn!("No verification code found for user: {}", input.did);
            return ApiError::InvalidRequest("No pending verification".into()).into_response();
        }
        Err(e) => {
            error!("Database error fetching verification: {:?}", e);
            return ApiError::InternalError.into_response();
        }
    };

    if verification.code != input.verification_code {
        warn!("Invalid verification code for user: {}", input.did);
        return ApiError::InvalidRequest("Invalid verification code".into()).into_response();
    }
    if verification.expires_at < Utc::now() {
        warn!("Verification code expired for user: {}", input.did);
        return ApiError::ExpiredTokenMsg("Verification code has expired".into()).into_response();
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

    if let Err(e) = sqlx::query!(
        "DELETE FROM channel_verifications WHERE user_id = $1 AND channel = 'email'",
        row.id
    )
    .execute(&state.db)
    .await
    {
        error!("Failed to delete verification record: {:?}", e);
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
    if let Err(e) = sqlx::query!(
        "INSERT INTO session_tokens (did, access_jti, refresh_jti, access_expires_at, refresh_expires_at) VALUES ($1, $2, $3, $4, $5)",
        row.did,
        access_meta.jti,
        refresh_meta.jti,
        access_meta.expires_at,
        refresh_meta.expires_at
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
    let verification_code = format!("{:06}", rand::random::<u32>() % 1_000_000);
    let code_expires_at = Utc::now() + chrono::Duration::minutes(30);

    let email = row.email.clone();

    if let Err(e) = sqlx::query!(
        r#"
        INSERT INTO channel_verifications (user_id, channel, code, pending_identifier, expires_at)
        VALUES ($1, 'email', $2, $3, $4)
        ON CONFLICT (user_id, channel) DO UPDATE
        SET code = $2, pending_identifier = $3, expires_at = $4, created_at = NOW()
        "#,
        row.id,
        verification_code,
        email,
        code_expires_at
    )
    .execute(&state.db)
    .await
    {
        error!("Failed to update verification code: {:?}", e);
        return ApiError::InternalError.into_response();
    }
    let (channel_str, recipient) = match row.channel {
        crate::comms::CommsChannel::Email => ("email", row.email.unwrap_or_default()),
        crate::comms::CommsChannel::Discord => ("discord", row.discord_id.unwrap_or_default()),
        crate::comms::CommsChannel::Telegram => {
            ("telegram", row.telegram_username.unwrap_or_default())
        }
        crate::comms::CommsChannel::Signal => ("signal", row.signal_number.unwrap_or_default()),
    };
    if let Err(e) = crate::comms::enqueue_signup_verification(
        &state.db,
        row.id,
        channel_str,
        &recipient,
        &verification_code,
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
    let result = sqlx::query_as::<
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
    match result {
        Ok(rows) => {
            let sessions: Vec<SessionInfo> = rows
                .into_iter()
                .map(|(id, access_jti, created_at, expires_at)| SessionInfo {
                    id: id.to_string(),
                    created_at: created_at.to_rfc3339(),
                    expires_at: expires_at.to_rfc3339(),
                    is_current: current_jti.as_ref() == Some(&access_jti),
                })
                .collect();
            (StatusCode::OK, Json(ListSessionsOutput { sessions })).into_response()
        }
        Err(e) => {
            error!("DB error in list_sessions: {:?}", e);
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
pub struct RevokeSessionInput {
    pub session_id: String,
}

pub async fn revoke_session(
    State(state): State<AppState>,
    auth: BearerAuth,
    Json(input): Json<RevokeSessionInput>,
) -> Response {
    let session_id: i32 = match input.session_id.parse() {
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
    info!(did = %auth.0.did, session_id = %session_id, "Session revoked");
    (StatusCode::OK, Json(json!({}))).into_response()
}
