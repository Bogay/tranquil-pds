use crate::api::error::ApiError;
use crate::api::{EmptyResponse, TokenRequiredResponse, VerifiedResponse};
use crate::auth::BearerAuth;
use crate::state::{AppState, RateLimitKind};
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use tracing::{error, info, warn};

pub async fn request_email_update(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    auth: BearerAuth,
) -> Response {
    let client_ip = crate::rate_limit::extract_client_ip(&headers, None);
    if !state
        .check_rate_limit(RateLimitKind::EmailUpdate, &client_ip)
        .await
    {
        warn!(ip = %client_ip, "Email update rate limit exceeded");
        return ApiError::RateLimitExceeded(None).into_response();
    }

    if let Err(e) = crate::auth::scope_check::check_account_scope(
        auth.0.is_oauth,
        auth.0.scope.as_deref(),
        crate::oauth::scopes::AccountAttr::Email,
        crate::oauth::scopes::AccountAction::Manage,
    ) {
        return e;
    }

    let user = match state.user_repo.get_email_info_by_did(&auth.0.did).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return ApiError::AccountNotFound.into_response();
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let Some(current_email) = user.email else {
        return ApiError::InvalidRequest("account does not have an email address".into())
            .into_response();
    };

    let token_required = user.email_verified;

    if token_required {
        let code = crate::auth::verification_token::generate_channel_update_token(
            &auth.0.did,
            "email_update",
            &current_email.to_lowercase(),
        );
        let formatted_code = crate::auth::verification_token::format_token_for_display(&code);

        let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
        if let Err(e) = crate::comms::comms_repo::enqueue_email_update_token(
            state.user_repo.as_ref(),
            state.infra_repo.as_ref(),
            user.id,
            &formatted_code,
            &hostname,
        )
        .await
        {
            warn!("Failed to enqueue email update notification: {:?}", e);
        }
    }

    info!("Email update requested for user {}", user.id);
    TokenRequiredResponse::response(token_required).into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmEmailInput {
    pub email: String,
    pub token: String,
}

pub async fn confirm_email(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    auth: BearerAuth,
    Json(input): Json<ConfirmEmailInput>,
) -> Response {
    let client_ip = crate::rate_limit::extract_client_ip(&headers, None);
    if !state
        .check_rate_limit(RateLimitKind::EmailUpdate, &client_ip)
        .await
    {
        warn!(ip = %client_ip, "Confirm email rate limit exceeded");
        return ApiError::RateLimitExceeded(None).into_response();
    }

    if let Err(e) = crate::auth::scope_check::check_account_scope(
        auth.0.is_oauth,
        auth.0.scope.as_deref(),
        crate::oauth::scopes::AccountAttr::Email,
        crate::oauth::scopes::AccountAction::Manage,
    ) {
        return e;
    }

    let did = &auth.0.did;
    let user = match state.user_repo.get_email_info_by_did(did).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return ApiError::AccountNotFound.into_response();
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let Some(ref email) = user.email else {
        return ApiError::InvalidEmail.into_response();
    };
    let current_email = email.to_lowercase();

    let provided_email = input.email.trim().to_lowercase();
    if provided_email != current_email {
        return ApiError::InvalidEmail.into_response();
    }

    if user.email_verified {
        return EmptyResponse::ok().into_response();
    }

    let confirmation_code =
        crate::auth::verification_token::normalize_token_input(input.token.trim());

    let verified = crate::auth::verification_token::verify_signup_token(
        &confirmation_code,
        "email",
        &provided_email,
    );

    match verified {
        Ok(token_data) => {
            if token_data.did != did.as_str() {
                return ApiError::InvalidToken(None).into_response();
            }
        }
        Err(crate::auth::verification_token::VerifyError::Expired) => {
            return ApiError::ExpiredToken(None).into_response();
        }
        Err(_) => {
            return ApiError::InvalidToken(None).into_response();
        }
    }

    if let Err(e) = state.user_repo.set_email_verified(user.id, true).await {
        error!("DB error confirming email: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }

    info!("Email confirmed for user {}", user.id);
    EmptyResponse::ok().into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateEmailInput {
    pub email: String,
    #[serde(default)]
    pub email_auth_factor: Option<bool>,
    pub token: Option<String>,
}

pub async fn update_email(
    State(state): State<AppState>,
    auth: BearerAuth,
    Json(input): Json<UpdateEmailInput>,
) -> Response {
    let auth_user = auth.0;

    if let Err(e) = crate::auth::scope_check::check_account_scope(
        auth_user.is_oauth,
        auth_user.scope.as_deref(),
        crate::oauth::scopes::AccountAttr::Email,
        crate::oauth::scopes::AccountAction::Manage,
    ) {
        return e;
    }

    let did = &auth_user.did;
    let user = match state.user_repo.get_email_info_by_did(did).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return ApiError::AccountNotFound.into_response();
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let user_id = user.id;
    let current_email = user.email.clone();
    let email_verified = user.email_verified;
    let new_email = input.email.trim().to_lowercase();

    if !crate::api::validation::is_valid_email(&new_email) {
        return ApiError::InvalidRequest(
            "This email address is not supported, please use a different email.".into(),
        )
        .into_response();
    }

    if let Some(ref current) = current_email
        && new_email == current.to_lowercase()
    {
        return EmptyResponse::ok().into_response();
    }

    if email_verified {
        let Some(ref t) = input.token else {
            return ApiError::TokenRequired.into_response();
        };
        let confirmation_token = crate::auth::verification_token::normalize_token_input(t.trim());

        let current_email_lower = current_email
            .as_ref()
            .map(|e| e.to_lowercase())
            .unwrap_or_default();

        let verified = crate::auth::verification_token::verify_channel_update_token(
            &confirmation_token,
            "email_update",
            &current_email_lower,
        );

        match verified {
            Ok(token_data) => {
                if token_data.did != did.as_str() {
                    return ApiError::InvalidToken(None).into_response();
                }
            }
            Err(crate::auth::verification_token::VerifyError::Expired) => {
                return ApiError::ExpiredToken(None).into_response();
            }
            Err(_) => {
                return ApiError::InvalidToken(None).into_response();
            }
        }
    }

    if let Ok(true) = state.user_repo.check_email_exists(&new_email, user_id).await {
        return ApiError::InvalidRequest("Email is already in use".into()).into_response();
    }

    if let Err(e) = state.user_repo.update_email(user_id, &new_email).await {
        error!("DB error updating email: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }

    let verification_token =
        crate::auth::verification_token::generate_signup_token(&did, "email", &new_email);
    let formatted_token =
        crate::auth::verification_token::format_token_for_display(&verification_token);
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    if let Err(e) = crate::comms::comms_repo::enqueue_signup_verification(
        state.infra_repo.as_ref(),
        user_id,
        "email",
        &new_email,
        &formatted_token,
        &hostname,
    )
    .await
    {
        warn!("Failed to send verification email to new address: {:?}", e);
    }

    if let Err(e) = state
        .infra_repo
        .upsert_account_preference(
            user_id,
            "email_auth_factor",
            json!(input.email_auth_factor.unwrap_or(false)),
        )
        .await
    {
        warn!("Failed to update email_auth_factor preference: {}", e);
    }

    info!("Email updated for user {}", user_id);
    EmptyResponse::ok().into_response()
}

#[derive(Deserialize)]
pub struct CheckEmailVerifiedInput {
    pub identifier: String,
}

pub async fn check_email_verified(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<CheckEmailVerifiedInput>,
) -> Response {
    let client_ip = crate::rate_limit::extract_client_ip(&headers, None);
    if !state
        .check_rate_limit(RateLimitKind::VerificationCheck, &client_ip)
        .await
    {
        return ApiError::RateLimitExceeded(None).into_response();
    }

    match state
        .user_repo
        .check_email_verified_by_identifier(&input.identifier)
        .await
    {
        Ok(Some(verified)) => VerifiedResponse::response(verified).into_response(),
        Ok(None) => ApiError::AccountNotFound.into_response(),
        Err(e) => {
            error!("DB error checking email verified: {:?}", e);
            ApiError::InternalError(None).into_response()
        }
    }
}
