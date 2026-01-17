use crate::api::error::ApiError;
use crate::api::{EmptyResponse, TokenRequiredResponse, VerifiedResponse};
use crate::auth::BearerAuth;
use crate::state::{AppState, RateLimitKind};
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::Duration;
use subtle::ConstantTimeEq;
use tracing::{error, info, warn};

const EMAIL_UPDATE_TTL: Duration = Duration::from_secs(30 * 60);

fn email_update_cache_key(did: &str) -> String {
    format!("email_update:{}", did)
}

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

#[derive(Serialize, Deserialize)]
struct PendingEmailUpdate {
    new_email: String,
    token_hash: String,
    authorized: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestEmailUpdateInput {
    #[serde(default)]
    pub new_email: Option<String>,
}

pub async fn request_email_update(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    auth: BearerAuth,
    input: Option<Json<RequestEmailUpdateInput>>,
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

        if let Some(Json(ref inp)) = input
            && let Some(ref new_email) = inp.new_email {
                let new_email = new_email.trim().to_lowercase();
                if !new_email.is_empty() && crate::api::validation::is_valid_email(&new_email) {
                    let pending = PendingEmailUpdate {
                        new_email,
                        token_hash: hash_token(&code),
                        authorized: false,
                    };
                    if let Ok(json) = serde_json::to_string(&pending) {
                        let cache_key = email_update_cache_key(&auth.0.did);
                        if let Err(e) = state.cache.set(&cache_key, &json, EMAIL_UPDATE_TTL).await {
                            warn!("Failed to cache pending email update: {:?}", e);
                        }
                    }
                }
            }

        let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
        if let Err(e) = crate::comms::comms_repo::enqueue_email_update_token(
            state.user_repo.as_ref(),
            state.infra_repo.as_ref(),
            user.id,
            &code,
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
        let mut authorized_via_link = false;

        let cache_key = email_update_cache_key(did);
        if let Some(pending_json) = state.cache.get(&cache_key).await
            && let Ok(pending) = serde_json::from_str::<PendingEmailUpdate>(&pending_json)
                && pending.authorized && pending.new_email == new_email {
                    authorized_via_link = true;
                    let _ = state.cache.delete(&cache_key).await;
                    info!(did = %did, "Email update completed via link authorization");
                }

        if !authorized_via_link {
            let Some(ref t) = input.token else {
                return ApiError::TokenRequired.into_response();
            };
            let confirmation_token =
                crate::auth::verification_token::normalize_token_input(t.trim());

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
    }

    if let Ok(true) = state
        .user_repo
        .check_email_exists(&new_email, user_id)
        .await
    {
        return ApiError::InvalidRequest("Email is already in use".into()).into_response();
    }

    if let Err(e) = state.user_repo.update_email(user_id, &new_email).await {
        error!("DB error updating email: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }

    let verification_token =
        crate::auth::verification_token::generate_signup_token(did, "email", &new_email);
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

#[derive(Deserialize)]
pub struct AuthorizeEmailUpdateQuery {
    pub token: String,
}

pub async fn authorize_email_update(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(query): axum::extract::Query<AuthorizeEmailUpdateQuery>,
) -> Response {
    let client_ip = crate::rate_limit::extract_client_ip(&headers, None);
    if !state
        .check_rate_limit(RateLimitKind::VerificationCheck, &client_ip)
        .await
    {
        return ApiError::RateLimitExceeded(None).into_response();
    }

    let verified = crate::auth::verification_token::verify_token_signature(&query.token);

    let token_data = match verified {
        Ok(data) => data,
        Err(crate::auth::verification_token::VerifyError::Expired) => {
            warn!("authorize_email_update: token expired");
            return ApiError::ExpiredToken(None).into_response();
        }
        Err(e) => {
            warn!("authorize_email_update: token verification failed: {:?}", e);
            return ApiError::InvalidToken(None).into_response();
        }
    };

    if token_data.purpose != crate::auth::verification_token::VerificationPurpose::ChannelUpdate {
        warn!(
            "authorize_email_update: wrong purpose: {:?}",
            token_data.purpose
        );
        return ApiError::InvalidToken(None).into_response();
    }
    if token_data.channel != "email_update" {
        warn!(
            "authorize_email_update: wrong channel: {}",
            token_data.channel
        );
        return ApiError::InvalidToken(None).into_response();
    }

    let did = token_data.did;
    info!("authorize_email_update: token valid for did={}", did);

    let cache_key = email_update_cache_key(&did);
    let pending_json = match state.cache.get(&cache_key).await {
        Some(json) => json,
        None => {
            warn!(
                "authorize_email_update: no pending email update in cache for did={}",
                did
            );
            return ApiError::InvalidRequest("No pending email update found".into())
                .into_response();
        }
    };

    let mut pending: PendingEmailUpdate = match serde_json::from_str(&pending_json) {
        Ok(p) => p,
        Err(_) => {
            return ApiError::InternalError(None).into_response();
        }
    };

    let token_hash = hash_token(&query.token);
    if pending
        .token_hash
        .as_bytes()
        .ct_eq(token_hash.as_bytes())
        .unwrap_u8()
        != 1
    {
        warn!("authorize_email_update: token hash mismatch");
        return ApiError::InvalidToken(None).into_response();
    }

    pending.authorized = true;
    if let Ok(json) = serde_json::to_string(&pending)
        && let Err(e) = state.cache.set(&cache_key, &json, EMAIL_UPDATE_TTL).await {
            warn!("Failed to update pending email authorization: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }

    info!(did = %did, "Email update authorized via link click");

    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let redirect_url = format!(
        "https://{}/app/verify?type=email-authorize-success",
        hostname
    );

    axum::response::Redirect::to(&redirect_url).into_response()
}

pub async fn check_email_update_status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    auth: BearerAuth,
) -> Response {
    let client_ip = crate::rate_limit::extract_client_ip(&headers, None);
    if !state
        .check_rate_limit(RateLimitKind::VerificationCheck, &client_ip)
        .await
    {
        return ApiError::RateLimitExceeded(None).into_response();
    }

    if let Err(e) = crate::auth::scope_check::check_account_scope(
        auth.0.is_oauth,
        auth.0.scope.as_deref(),
        crate::oauth::scopes::AccountAttr::Email,
        crate::oauth::scopes::AccountAction::Read,
    ) {
        return e;
    }

    let cache_key = email_update_cache_key(&auth.0.did);
    let pending_json = match state.cache.get(&cache_key).await {
        Some(json) => json,
        None => {
            return Json(json!({ "pending": false, "authorized": false })).into_response();
        }
    };

    let pending: PendingEmailUpdate = match serde_json::from_str(&pending_json) {
        Ok(p) => p,
        Err(_) => {
            return Json(json!({ "pending": false, "authorized": false })).into_response();
        }
    };

    Json(json!({
        "pending": true,
        "authorized": pending.authorized,
        "newEmail": pending.new_email,
    }))
    .into_response()
}
