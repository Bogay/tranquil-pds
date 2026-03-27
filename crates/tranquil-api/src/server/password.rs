use axum::{Json, extract::State};
use chrono::{Duration, Utc};
use serde::Deserialize;
use tracing::{error, info, warn};
use tranquil_pds::api::error::{ApiError, DbResultExt};
use tranquil_pds::api::{EmptyResponse, HasPasswordResponse, PasswordResetOutput, SuccessResponse};
use tranquil_pds::auth::{
    Active, Auth, NormalizedLoginIdentifier, require_legacy_session_mfa, require_reauth_window,
    require_reauth_window_if_available,
};
use tranquil_pds::rate_limit::{PasswordResetLimit, RateLimited, ResetPasswordLimit};
use tranquil_pds::state::AppState;
use tranquil_pds::types::PlainPassword;
use tranquil_pds::validation::validate_password;

fn generate_reset_code() -> String {
    tranquil_pds::util::generate_token_code()
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
) -> Result<Json<PasswordResetOutput>, ApiError> {
    let identifier = input.email.trim();
    if identifier.is_empty() {
        return Err(ApiError::InvalidRequest(
            "email or handle is required".into(),
        ));
    }
    let hostname_for_handles = tranquil_config::get().server.hostname_without_port();
    let normalized = identifier.to_lowercase();
    let normalized = normalized.strip_prefix('@').unwrap_or(&normalized);
    let is_email_lookup = normalized.contains('@');
    let normalized_handle = NormalizedLoginIdentifier::normalize(identifier, hostname_for_handles);

    let multiple_accounts_warning = if is_email_lookup {
        match state.repos.user.count_accounts_by_email(normalized).await {
            Ok(count) if count > 1 => Some(count),
            _ => None,
        }
    } else {
        None
    };

    let user_id = match state
        .repos
        .user
        .get_id_by_email_or_handle(normalized, normalized_handle.as_str())
        .await
    {
        Ok(Some(id)) => id,
        Ok(None) => {
            info!("Password reset requested for unknown identifier");
            return Ok(Json(PasswordResetOutput {
                success: true,
                multiple_accounts: None,
                account_count: None,
                message: None,
            }));
        }
        Err(e) => {
            error!("DB error in request_password_reset: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    };
    let code = generate_reset_code();
    let expires_at = Utc::now() + Duration::minutes(10);
    if let Err(e) = state
        .repos
        .user
        .set_password_reset_code(user_id, &code, expires_at)
        .await
    {
        error!("DB error setting reset code: {:?}", e);
        return Err(ApiError::InternalError(None));
    }
    let hostname = &tranquil_config::get().server.hostname;
    if let Err(e) = tranquil_pds::comms::comms_repo::enqueue_password_reset(
        state.repos.user.as_ref(),
        state.repos.infra.as_ref(),
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
        Some(count) => Ok(Json(PasswordResetOutput {
            success: true,
            multiple_accounts: Some(true),
            account_count: Some(count),
            message: Some("Multiple accounts share this email. Reset link sent to the most recent account. Use your handle for a specific account.".into()),
        })),
        None => Ok(Json(PasswordResetOutput {
            success: true,
            multiple_accounts: None,
            account_count: None,
            message: None,
        })),
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
) -> Result<Json<EmptyResponse>, ApiError> {
    let token = input.token.trim();
    let password = &input.password;
    if token.is_empty() {
        return Err(ApiError::InvalidToken(None));
    }
    if password.is_empty() {
        return Err(ApiError::InvalidRequest("password is required".into()));
    }
    if let Err(e) = validate_password(password) {
        return Err(ApiError::InvalidRequest(e.to_string()));
    }
    let user = match state.repos.user.get_user_by_reset_code(token).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return Err(ApiError::InvalidToken(None));
        }
        Err(e) => {
            error!("DB error in reset_password: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    };
    let user_id = user.id;
    let Some(exp) = user.expires_at else {
        return Err(ApiError::InvalidToken(None));
    };
    if Utc::now() > exp {
        if let Err(e) = state.repos.user.clear_password_reset_code(user_id).await {
            error!("Failed to clear expired reset code: {:?}", e);
        }
        return Err(ApiError::ExpiredToken(None));
    }
    let password_hash = crate::common::hash_password_async(password).await?;
    let result = match state
        .repos
        .user
        .reset_password_with_sessions(user_id, &password_hash)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to reset password: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    };
    futures::future::join_all(result.session_jtis.iter().map(|jti| {
        let cache_key = tranquil_pds::cache_keys::session_key(&result.did, jti);
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
    if let Ok(Some(prefs)) = state.repos.user.get_comms_prefs(user_id).await {
        let actual_channel =
            tranquil_pds::comms::resolve_delivery_channel(&prefs, user.preferred_comms_channel);
        if let Err(e) = state
            .repos
            .user
            .set_channel_verified(&user.did, actual_channel)
            .await
        {
            warn!(
                "Failed to implicitly verify channel on password reset: {:?}",
                e
            );
        }
    }
    info!("Password reset completed for user {}", user_id);
    Ok(Json(EmptyResponse {}))
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
) -> Result<Json<EmptyResponse>, ApiError> {
    use tranquil_pds::auth::verify_password_mfa;

    let session_mfa = require_legacy_session_mfa(&state, &auth).await?;

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
        .repos
        .user
        .get_id_and_password_hash_by_did(password_mfa.did())
        .await
        .log_db_err("in change_password")?
        .ok_or(ApiError::AccountNotFound)?;

    let new_hash = crate::common::hash_password_async(&input.new_password).await?;

    state
        .repos
        .user
        .update_password_hash(user.id, &new_hash)
        .await
        .log_db_err("updating password")?;

    info!(did = %session_mfa.did(), "Password changed successfully");
    Ok(Json(EmptyResponse {}))
}

pub async fn get_password_status(
    State(state): State<AppState>,
    auth: Auth<Active>,
) -> Result<Json<HasPasswordResponse>, ApiError> {
    let has = state
        .repos
        .user
        .has_password_by_did(&auth.did)
        .await
        .log_db_err("checking password status")?
        .ok_or(ApiError::AccountNotFound)?;
    Ok(Json(HasPasswordResponse { has_password: has }))
}

pub async fn remove_password(
    State(state): State<AppState>,
    auth: Auth<Active>,
) -> Result<Json<SuccessResponse>, ApiError> {
    let session_mfa = require_legacy_session_mfa(&state, &auth).await?;

    let reauth_mfa = require_reauth_window(&state, &auth).await?;

    let has_passkeys = state
        .repos
        .user
        .has_passkeys(reauth_mfa.did())
        .await
        .unwrap_or(false);
    if !has_passkeys {
        return Err(ApiError::InvalidRequest(
            "You must have at least one passkey registered before removing your password".into(),
        ));
    }

    let user = state
        .repos
        .user
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
        .repos
        .user
        .remove_user_password(user.id)
        .await
        .log_db_err("removing password")?;

    info!(did = %session_mfa.did(), "Password removed - account is now passkey-only");
    Ok(Json(SuccessResponse { success: true }))
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
) -> Result<Json<SuccessResponse>, ApiError> {
    let reauth_mfa = require_reauth_window_if_available(&state, &auth).await?;

    let new_password = &input.new_password;
    if new_password.is_empty() {
        return Err(ApiError::InvalidRequest("newPassword is required".into()));
    }
    if let Err(e) = validate_password(new_password) {
        return Err(ApiError::InvalidRequest(e.to_string()));
    }

    let did = reauth_mfa.as_ref().map(|m| m.did()).unwrap_or(&auth.did);

    let user = state
        .repos
        .user
        .get_password_info_by_did(did)
        .await
        .log_db_err("getting password info")?
        .ok_or(ApiError::AccountNotFound)?;

    if user.password_hash.is_some() {
        return Err(ApiError::InvalidRequest(
            "Account already has a password. Use changePassword instead.".into(),
        ));
    }

    let new_hash = crate::common::hash_password_async(new_password).await?;

    state
        .repos
        .user
        .set_new_user_password(user.id, &new_hash)
        .await
        .log_db_err("setting password")?;

    info!(did = %did, "Password set for passkey-only account");
    Ok(Json(SuccessResponse { success: true }))
}
