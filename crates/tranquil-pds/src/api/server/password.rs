use crate::api::error::ApiError;
use crate::api::{EmptyResponse, HasPasswordResponse, SuccessResponse};
use crate::auth::BearerAuth;
use crate::state::{AppState, RateLimitKind};
use crate::types::PlainPassword;
use crate::validation::validate_password;
use axum::{
    Json,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use bcrypt::{DEFAULT_COST, hash, verify};
use chrono::{Duration, Utc};
use serde::Deserialize;
use tracing::{error, info, warn};

fn generate_reset_code() -> String {
    crate::util::generate_token_code()
}
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

#[derive(Deserialize)]
pub struct RequestPasswordResetInput {
    #[serde(alias = "identifier")]
    pub email: String,
}

pub async fn request_password_reset(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<RequestPasswordResetInput>,
) -> Response {
    let client_ip = extract_client_ip(&headers);
    if !state
        .check_rate_limit(RateLimitKind::PasswordReset, &client_ip)
        .await
    {
        warn!(ip = %client_ip, "Password reset rate limit exceeded");
        return ApiError::RateLimitExceeded(None).into_response();
    }
    let identifier = input.email.trim();
    if identifier.is_empty() {
        return ApiError::InvalidRequest("email or handle is required".into()).into_response();
    }
    let pds_hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let hostname_for_handles = pds_hostname.split(':').next().unwrap_or(&pds_hostname);
    let normalized = identifier.to_lowercase();
    let normalized = normalized.strip_prefix('@').unwrap_or(&normalized);
    let normalized_handle = if normalized.contains('@') || normalized.contains('.') {
        normalized.to_string()
    } else {
        format!("{}.{}", normalized, hostname_for_handles)
    };
    let user_id = match state
        .user_repo
        .get_id_by_email_or_handle(normalized, &normalized_handle)
        .await
    {
        Ok(Some(id)) => id,
        Ok(None) => {
            info!("Password reset requested for unknown identifier");
            return EmptyResponse::ok().into_response();
        }
        Err(e) => {
            error!("DB error in request_password_reset: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let code = generate_reset_code();
    let expires_at = Utc::now() + Duration::minutes(10);
    if let Err(e) = state
        .user_repo
        .set_password_reset_code(user_id, &code, expires_at)
        .await
    {
        error!("DB error setting reset code: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    if let Err(e) = crate::comms::comms_repo::enqueue_password_reset(
        state.user_repo.as_ref(),
        state.infra_repo.as_ref(),
        user_id,
        &code,
        &hostname,
    )
    .await
    {
        warn!("Failed to enqueue password reset notification: {:?}", e);
    }
    info!("Password reset requested for user {}", user_id);
    EmptyResponse::ok().into_response()
}

#[derive(Deserialize)]
pub struct ResetPasswordInput {
    pub token: String,
    pub password: PlainPassword,
}

pub async fn reset_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ResetPasswordInput>,
) -> Response {
    let client_ip = extract_client_ip(&headers);
    if !state
        .check_rate_limit(RateLimitKind::ResetPassword, &client_ip)
        .await
    {
        warn!(ip = %client_ip, "Reset password rate limit exceeded");
        return ApiError::RateLimitExceeded(None).into_response();
    }
    let token = input.token.trim();
    let password = &input.password;
    if token.is_empty() {
        return ApiError::InvalidToken(None).into_response();
    }
    if password.is_empty() {
        return ApiError::InvalidRequest("password is required".into()).into_response();
    }
    if let Err(e) = validate_password(password) {
        return ApiError::InvalidRequest(e.to_string()).into_response();
    }
    let user = match state.user_repo.get_user_by_reset_code(token).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return ApiError::InvalidToken(None).into_response();
        }
        Err(e) => {
            error!("DB error in reset_password: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let user_id = user.id;
    let Some(exp) = user.expires_at else {
        return ApiError::InvalidToken(None).into_response();
    };
    if Utc::now() > exp {
        if let Err(e) = state.user_repo.clear_password_reset_code(user_id).await {
            error!("Failed to clear expired reset code: {:?}", e);
        }
        return ApiError::ExpiredToken(None).into_response();
    }
    let password_clone = password.to_string();
    let password_hash =
        match tokio::task::spawn_blocking(move || hash(password_clone, DEFAULT_COST)).await {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                error!("Failed to hash password: {:?}", e);
                return ApiError::InternalError(None).into_response();
            }
            Err(e) => {
                error!("Failed to spawn blocking task: {:?}", e);
                return ApiError::InternalError(None).into_response();
            }
        };
    let result = match state
        .user_repo
        .reset_password_with_sessions(user_id, &password_hash)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to reset password: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    futures::future::join_all(result.session_jtis.iter().map(|jti| {
        let cache_key = format!("auth:session:{}:{}", result.did, jti);
        let cache = state.cache.clone();
        async move {
            if let Err(e) = cache.delete(&cache_key).await {
                warn!(
                    "Failed to invalidate session cache for {}: {:?}",
                    cache_key, e
                );
            }
        }
    }))
    .await;
    info!("Password reset completed for user {}", user_id);
    EmptyResponse::ok().into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordInput {
    pub current_password: PlainPassword,
    pub new_password: PlainPassword,
}

pub async fn change_password(
    State(state): State<AppState>,
    auth: BearerAuth,
    Json(input): Json<ChangePasswordInput>,
) -> Response {
    if !crate::api::server::reauth::check_legacy_session_mfa(&*state.session_repo, &auth.0.did)
        .await
    {
        return crate::api::server::reauth::legacy_mfa_required_response(
            &*state.user_repo,
            &*state.session_repo,
            &auth.0.did,
        )
        .await;
    }

    let current_password = &input.current_password;
    let new_password = &input.new_password;
    if current_password.is_empty() {
        return ApiError::InvalidRequest("currentPassword is required".into()).into_response();
    }
    if new_password.is_empty() {
        return ApiError::InvalidRequest("newPassword is required".into()).into_response();
    }
    if let Err(e) = validate_password(new_password) {
        return ApiError::InvalidRequest(e.to_string()).into_response();
    }
    let user = match state
        .user_repo
        .get_id_and_password_hash_by_did(&auth.0.did)
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            return ApiError::AccountNotFound.into_response();
        }
        Err(e) => {
            error!("DB error in change_password: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let (user_id, password_hash) = (user.id, user.password_hash);
    let valid = match verify(current_password, &password_hash) {
        Ok(v) => v,
        Err(e) => {
            error!("Password verification error: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    if !valid {
        return ApiError::InvalidPassword("Current password is incorrect".into()).into_response();
    }
    let new_password_clone = new_password.to_string();
    let new_hash =
        match tokio::task::spawn_blocking(move || hash(new_password_clone, DEFAULT_COST)).await {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                error!("Failed to hash password: {:?}", e);
                return ApiError::InternalError(None).into_response();
            }
            Err(e) => {
                error!("Failed to spawn blocking task: {:?}", e);
                return ApiError::InternalError(None).into_response();
            }
        };
    if let Err(e) = state
        .user_repo
        .update_password_hash(user_id, &new_hash)
        .await
    {
        error!("DB error updating password: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }
    info!(did = %&auth.0.did, "Password changed successfully");
    EmptyResponse::ok().into_response()
}

pub async fn get_password_status(State(state): State<AppState>, auth: BearerAuth) -> Response {
    match state.user_repo.has_password_by_did(&auth.0.did).await {
        Ok(Some(has)) => HasPasswordResponse::response(has).into_response(),
        Ok(None) => ApiError::AccountNotFound.into_response(),
        Err(e) => {
            error!("DB error: {:?}", e);
            ApiError::InternalError(None).into_response()
        }
    }
}

pub async fn remove_password(State(state): State<AppState>, auth: BearerAuth) -> Response {
    if !crate::api::server::reauth::check_legacy_session_mfa(&*state.session_repo, &auth.0.did)
        .await
    {
        return crate::api::server::reauth::legacy_mfa_required_response(
            &*state.user_repo,
            &*state.session_repo,
            &auth.0.did,
        )
        .await;
    }

    if crate::api::server::reauth::check_reauth_required_cached(
        &*state.session_repo,
        &state.cache,
        &auth.0.did,
    )
    .await
    {
        return crate::api::server::reauth::reauth_required_response(
            &*state.user_repo,
            &*state.session_repo,
            &auth.0.did,
        )
        .await;
    }

    let has_passkeys = state
        .user_repo
        .has_passkeys(&auth.0.did)
        .await
        .unwrap_or(false);
    if !has_passkeys {
        return ApiError::InvalidRequest(
            "You must have at least one passkey registered before removing your password".into(),
        )
        .into_response();
    }

    let user = match state.user_repo.get_password_info_by_did(&auth.0.did).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return ApiError::AccountNotFound.into_response();
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    if user.password_hash.is_none() {
        return ApiError::InvalidRequest("Account already has no password".into()).into_response();
    }

    if let Err(e) = state.user_repo.remove_user_password(user.id).await {
        error!("DB error removing password: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }

    info!(did = %&auth.0.did, "Password removed - account is now passkey-only");
    SuccessResponse::ok().into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetPasswordInput {
    pub new_password: PlainPassword,
}

pub async fn set_password(
    State(state): State<AppState>,
    auth: BearerAuth,
    Json(input): Json<SetPasswordInput>,
) -> Response {
    if crate::api::server::reauth::check_reauth_required_cached(
        &*state.session_repo,
        &state.cache,
        &auth.0.did,
    )
    .await
    {
        return crate::api::server::reauth::reauth_required_response(
            &*state.user_repo,
            &*state.session_repo,
            &auth.0.did,
        )
        .await;
    }

    let new_password = &input.new_password;
    if new_password.is_empty() {
        return ApiError::InvalidRequest("newPassword is required".into()).into_response();
    }
    if let Err(e) = validate_password(new_password) {
        return ApiError::InvalidRequest(e.to_string()).into_response();
    }

    let user = match state.user_repo.get_password_info_by_did(&auth.0.did).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return ApiError::AccountNotFound.into_response();
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    if user.password_hash.is_some() {
        return ApiError::InvalidRequest(
            "Account already has a password. Use changePassword instead.".into(),
        )
        .into_response();
    }

    let new_password_clone = new_password.to_string();
    let new_hash =
        match tokio::task::spawn_blocking(move || hash(new_password_clone, DEFAULT_COST)).await {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                error!("Failed to hash password: {:?}", e);
                return ApiError::InternalError(None).into_response();
            }
            Err(e) => {
                error!("Failed to spawn blocking task: {:?}", e);
                return ApiError::InternalError(None).into_response();
            }
        };

    if let Err(e) = state
        .user_repo
        .set_new_user_password(user.id, &new_hash)
        .await
    {
        error!("DB error setting password: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }

    info!(did = %&auth.0.did, "Password set for passkey-only account");
    SuccessResponse::ok().into_response()
}
