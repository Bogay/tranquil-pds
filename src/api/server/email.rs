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

    let did = auth.0.did.to_string();
    let user = match sqlx::query!(
        "SELECT id, handle, email, email_verified FROM users WHERE did = $1",
        did
    )
    .fetch_optional(&state.db)
    .await
    {
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
            &did,
            "email_update",
            &current_email.to_lowercase(),
        );
        let formatted_code = crate::auth::verification_token::format_token_for_display(&code);

        let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
        if let Err(e) =
            crate::comms::enqueue_email_update_token(&state.db, user.id, &formatted_code, &hostname)
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

    let did = auth.0.did.to_string();
    let user = match sqlx::query!(
        "SELECT id, email, email_verified FROM users WHERE did = $1",
        did
    )
    .fetch_optional(&state.db)
    .await
    {
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
            if token_data.did != did {
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

    let update = sqlx::query!(
        "UPDATE users SET email_verified = TRUE, updated_at = NOW() WHERE id = $1",
        user.id
    )
    .execute(&state.db)
    .await;

    if let Err(e) = update {
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

    let did = auth_user.did.to_string();
    let user = match sqlx::query!(
        "SELECT id, email, email_verified FROM users WHERE did = $1",
        did
    )
    .fetch_optional(&state.db)
    .await
    {
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
                if token_data.did != did {
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

    let exists = sqlx::query!(
        "SELECT 1 as one FROM users WHERE LOWER(email) = $1 AND id != $2",
        new_email,
        user_id
    )
    .fetch_optional(&state.db)
    .await;

    if let Ok(Some(_)) = exists {
        return ApiError::InvalidRequest("Email is already in use".into()).into_response();
    }

    let update: Result<sqlx::postgres::PgQueryResult, sqlx::Error> = sqlx::query!(
        "UPDATE users SET email = $1, email_verified = FALSE, updated_at = NOW() WHERE id = $2",
        new_email,
        user_id
    )
    .execute(&state.db)
    .await;

    if let Err(e) = update {
        error!("DB error updating email: {:?}", e);
        if e.as_database_error()
            .map(|db_err: &dyn sqlx::error::DatabaseError| db_err.is_unique_violation())
            .unwrap_or(false)
        {
            return ApiError::EmailTaken.into_response();
        }
        return ApiError::InternalError(None).into_response();
    }

    let verification_token =
        crate::auth::verification_token::generate_signup_token(&did, "email", &new_email);
    let formatted_token =
        crate::auth::verification_token::format_token_for_display(&verification_token);
    if let Err(e) = crate::comms::enqueue_signup_verification(
        &state.db,
        user_id,
        "email",
        &new_email,
        &formatted_token,
        None,
    )
    .await
    {
        warn!("Failed to send verification email to new address: {:?}", e);
    }

    match sqlx::query!(
        "INSERT INTO account_preferences (user_id, name, value_json) VALUES ($1, 'email_auth_factor', $2) ON CONFLICT (user_id, name) DO UPDATE SET value_json = $2",
        user_id,
        json!(input.email_auth_factor.unwrap_or(false))
    )
    .execute(&state.db)
    .await
    {
        Ok(_) => {}
        Err(e) => warn!("Failed to update email_auth_factor preference: {}", e),
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

    let user = sqlx::query!(
        "SELECT email_verified FROM users WHERE email = $1 OR handle = $1",
        input.identifier
    )
    .fetch_optional(&state.db)
    .await;

    match user {
        Ok(Some(row)) => VerifiedResponse::response(row.email_verified).into_response(),
        Ok(None) => ApiError::AccountNotFound.into_response(),
        Err(e) => {
            error!("DB error checking email verified: {:?}", e);
            ApiError::InternalError(None).into_response()
        }
    }
}
