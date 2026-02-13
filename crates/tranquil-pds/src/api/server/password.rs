use crate::api::error::{ApiError, DbResultExt};
use crate::api::{EmptyResponse, HasPasswordResponse, SuccessResponse};
use crate::auth::{
    Active, Auth, NormalizedLoginIdentifier, require_legacy_session_mfa, require_reauth_window,
    require_reauth_window_if_available,
};
use crate::rate_limit::{PasswordResetLimit, RateLimited, ResetPasswordLimit};
use crate::state::AppState;
use crate::types::PlainPassword;
use crate::validation::validate_password;
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use bcrypt::{DEFAULT_COST, hash};
use chrono::{Duration, Utc};
use serde::Deserialize;
use tracing::{error, info, warn};

fn generate_reset_code() -> String {
    crate::util::generate_token_code()
}

#[derive(Deserialize)]
pub struct RequestPasswordResetInput {
    #[serde(alias = "identifier")]
    pub email: String,
}

pub async fn request_password_reset(
    State(state): State<AppState>,
    _rate_limit: RateLimited<PasswordResetLimit>,
    Json(input): Json<RequestPasswordResetInput>,
) -> Response {
    let identifier = input.email.trim();
    if identifier.is_empty() {
        return ApiError::InvalidRequest("email or handle is required".into()).into_response();
    }
    let hostname_for_handles = tranquil_config::get().server.hostname_without_port();
    let normalized = identifier.to_lowercase();
    let normalized = normalized.strip_prefix('@').unwrap_or(&normalized);
    let is_email_lookup = normalized.contains('@');
    let normalized_handle = NormalizedLoginIdentifier::normalize(identifier, hostname_for_handles);

    let multiple_accounts_warning = if is_email_lookup {
        match state.user_repo.count_accounts_by_email(normalized).await {
            Ok(count) if count > 1 => Some(count),
            _ => None,
        }
    } else {
        None
    };

    let user_id = match state
        .user_repo
        .get_id_by_email_or_handle(normalized, normalized_handle.as_str())
        .await
    {
        Ok(Some(id)) => id,
        Ok(None) => {
            info!("Password reset requested for unknown identifier");
            return Json(serde_json::json!({ "success": true })).into_response();
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
    let hostname = &tranquil_config::get().server.hostname;
    if let Err(e) = crate::comms::comms_repo::enqueue_password_reset(
        state.user_repo.as_ref(),
        state.infra_repo.as_ref(),
        user_id,
        &code,
        hostname,
    )
    .await
    {
        warn!("Failed to enqueue password reset notification: {:?}", e);
    }
    info!("Password reset requested for user {}", user_id);

    match multiple_accounts_warning {
        Some(count) => Json(serde_json::json!({
            "success": true,
            "multipleAccounts": true,
            "accountCount": count,
            "message": "Multiple accounts share this email. Reset link sent to the most recent account. Use your handle for a specific account."
        }))
        .into_response(),
        None => Json(serde_json::json!({ "success": true })).into_response(),
    }
}

#[derive(Deserialize)]
pub struct ResetPasswordInput {
    pub token: String,
    pub password: PlainPassword,
}

pub async fn reset_password(
    State(state): State<AppState>,
    _rate_limit: RateLimited<ResetPasswordLimit>,
    Json(input): Json<ResetPasswordInput>,
) -> Response {
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
        let cache_key = crate::cache_keys::session_key(&result.did, jti);
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
    auth: Auth<Active>,
    Json(input): Json<ChangePasswordInput>,
) -> Result<Response, ApiError> {
    use crate::auth::verify_password_mfa;

    let session_mfa = match require_legacy_session_mfa(&state, &auth).await {
        Ok(proof) => proof,
        Err(response) => return Ok(response),
    };

    if input.current_password.is_empty() {
        return Err(ApiError::InvalidRequest(
            "currentPassword is required".into(),
        ));
    }
    if input.new_password.is_empty() {
        return Err(ApiError::InvalidRequest("newPassword is required".into()));
    }
    if let Err(e) = validate_password(&input.new_password) {
        return Err(ApiError::InvalidRequest(e.to_string()));
    }

    let password_mfa = verify_password_mfa(&state, &auth, &input.current_password).await?;

    let user = state
        .user_repo
        .get_id_and_password_hash_by_did(password_mfa.did())
        .await
        .log_db_err("in change_password")?
        .ok_or(ApiError::AccountNotFound)?;

    let new_password_clone = input.new_password.to_string();
    let new_hash = tokio::task::spawn_blocking(move || hash(new_password_clone, DEFAULT_COST))
        .await
        .map_err(|e| {
            error!("Failed to spawn blocking task: {:?}", e);
            ApiError::InternalError(None)
        })?
        .map_err(|e| {
            error!("Failed to hash password: {:?}", e);
            ApiError::InternalError(None)
        })?;

    state
        .user_repo
        .update_password_hash(user.id, &new_hash)
        .await
        .log_db_err("updating password")?;

    info!(did = %session_mfa.did(), "Password changed successfully");
    Ok(EmptyResponse::ok().into_response())
}

pub async fn get_password_status(
    State(state): State<AppState>,
    auth: Auth<Active>,
) -> Result<Response, ApiError> {
    let has = state
        .user_repo
        .has_password_by_did(&auth.did)
        .await
        .log_db_err("checking password status")?
        .ok_or(ApiError::AccountNotFound)?;
    Ok(HasPasswordResponse::response(has).into_response())
}

pub async fn remove_password(
    State(state): State<AppState>,
    auth: Auth<Active>,
) -> Result<Response, ApiError> {
    let session_mfa = match require_legacy_session_mfa(&state, &auth).await {
        Ok(proof) => proof,
        Err(response) => return Ok(response),
    };

    let reauth_mfa = match require_reauth_window(&state, &auth).await {
        Ok(proof) => proof,
        Err(response) => return Ok(response),
    };

    let has_passkeys = state
        .user_repo
        .has_passkeys(reauth_mfa.did())
        .await
        .unwrap_or(false);
    if !has_passkeys {
        return Err(ApiError::InvalidRequest(
            "You must have at least one passkey registered before removing your password".into(),
        ));
    }

    let user = state
        .user_repo
        .get_password_info_by_did(reauth_mfa.did())
        .await
        .log_db_err("getting password info")?
        .ok_or(ApiError::AccountNotFound)?;

    if user.password_hash.is_none() {
        return Err(ApiError::InvalidRequest(
            "Account already has no password".into(),
        ));
    }

    state
        .user_repo
        .remove_user_password(user.id)
        .await
        .log_db_err("removing password")?;

    info!(did = %session_mfa.did(), "Password removed - account is now passkey-only");
    Ok(SuccessResponse::ok().into_response())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetPasswordInput {
    pub new_password: PlainPassword,
}

pub async fn set_password(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<SetPasswordInput>,
) -> Result<Response, ApiError> {
    let reauth_mfa = match require_reauth_window_if_available(&state, &auth).await {
        Ok(proof) => proof,
        Err(response) => return Ok(response),
    };

    let new_password = &input.new_password;
    if new_password.is_empty() {
        return Err(ApiError::InvalidRequest("newPassword is required".into()));
    }
    if let Err(e) = validate_password(new_password) {
        return Err(ApiError::InvalidRequest(e.to_string()));
    }

    let did = reauth_mfa.as_ref().map(|m| m.did()).unwrap_or(&auth.did);

    let user = state
        .user_repo
        .get_password_info_by_did(did)
        .await
        .log_db_err("getting password info")?
        .ok_or(ApiError::AccountNotFound)?;

    if user.password_hash.is_some() {
        return Err(ApiError::InvalidRequest(
            "Account already has a password. Use changePassword instead.".into(),
        ));
    }

    let new_password_clone = new_password.to_string();
    let new_hash = tokio::task::spawn_blocking(move || hash(new_password_clone, DEFAULT_COST))
        .await
        .map_err(|e| {
            error!("Failed to spawn blocking task: {:?}", e);
            ApiError::InternalError(None)
        })?
        .map_err(|e| {
            error!("Failed to hash password: {:?}", e);
            ApiError::InternalError(None)
        })?;

    state
        .user_repo
        .set_new_user_password(user.id, &new_hash)
        .await
        .log_db_err("setting password")?;

    info!(did = %did, "Password set for passkey-only account");
    Ok(SuccessResponse::ok().into_response())
}
