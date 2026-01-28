use crate::api::error::{ApiError, DbResultExt};
use crate::api::{EmptyResponse, TokenRequiredResponse, VerifiedResponse};
use crate::auth::{Auth, NotTakendown};
use crate::rate_limit::{EmailUpdateLimit, RateLimited, VerificationCheckLimit};
use crate::state::AppState;
use crate::util::pds_hostname;
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
use tranquil_db_traits::CommsChannel;

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
    _rate_limit: RateLimited<EmailUpdateLimit>,
    auth: Auth<NotTakendown>,
    input: Option<Json<RequestEmailUpdateInput>>,
) -> Result<Response, ApiError> {
    if let Err(e) = crate::auth::scope_check::check_account_scope(
        auth.is_oauth(),
        auth.scope.as_deref(),
        crate::oauth::scopes::AccountAttr::Email,
        crate::oauth::scopes::AccountAction::Manage,
    ) {
        return Ok(e);
    }

    let user = state
        .user_repo
        .get_email_info_by_did(&auth.did)
        .await
        .log_db_err("getting email info")?
        .ok_or(ApiError::AccountNotFound)?;

    let Some(_current_email) = user.email else {
        return Err(ApiError::InvalidRequest(
            "account does not have an email address".into(),
        ));
    };

    let token_required = user.email_verified;

    if token_required {
        let token = crate::auth::email_token::create_email_token(
            state.cache.as_ref(),
            auth.did.as_str(),
            crate::auth::email_token::EmailTokenPurpose::UpdateEmail,
        )
        .await
        .map_err(|e| {
            error!("Failed to create email update token: {:?}", e);
            ApiError::InternalError(Some("Failed to generate verification code".into()))
        })?;

        if let Some(Json(ref inp)) = input
            && let Some(ref new_email) = inp.new_email
        {
            let new_email = new_email.trim().to_lowercase();
            if !new_email.is_empty() && crate::api::validation::is_valid_email(&new_email) {
                let pending = PendingEmailUpdate {
                    new_email,
                    token_hash: hash_token(&token),
                    authorized: false,
                };
                if let Ok(json) = serde_json::to_string(&pending) {
                    let cache_key = email_update_cache_key(&auth.did);
                    if let Err(e) = state.cache.set(&cache_key, &json, EMAIL_UPDATE_TTL).await {
                        warn!("Failed to cache pending email update: {:?}", e);
                    }
                }
            }
        }

        let hostname = pds_hostname();
        if let Err(e) = crate::comms::comms_repo::enqueue_short_token_email(
            state.user_repo.as_ref(),
            state.infra_repo.as_ref(),
            user.id,
            &token,
            "email_update",
            hostname,
        )
        .await
        {
            warn!("Failed to enqueue email update notification: {:?}", e);
        }
    }

    info!("Email update requested for user {}", user.id);
    Ok(TokenRequiredResponse::response(token_required).into_response())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmEmailInput {
    pub email: String,
    pub token: String,
}

pub async fn confirm_email(
    State(state): State<AppState>,
    _rate_limit: RateLimited<EmailUpdateLimit>,
    auth: Auth<NotTakendown>,
    Json(input): Json<ConfirmEmailInput>,
) -> Result<Response, ApiError> {
    if let Err(e) = crate::auth::scope_check::check_account_scope(
        auth.is_oauth(),
        auth.scope.as_deref(),
        crate::oauth::scopes::AccountAttr::Email,
        crate::oauth::scopes::AccountAction::Manage,
    ) {
        return Ok(e);
    }

    let did = &auth.did;
    let user = state
        .user_repo
        .get_email_info_by_did(did)
        .await
        .log_db_err("getting email info")?
        .ok_or(ApiError::AccountNotFound)?;

    let Some(ref email) = user.email else {
        return Err(ApiError::InvalidEmail);
    };
    let current_email = email.to_lowercase();

    let provided_email = input.email.trim().to_lowercase();
    if provided_email != current_email {
        return Err(ApiError::InvalidEmail);
    }

    if user.email_verified {
        return Ok(EmptyResponse::ok().into_response());
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
                return Err(ApiError::InvalidToken(None));
            }
        }
        Err(crate::auth::verification_token::VerifyError::Expired) => {
            return Err(ApiError::ExpiredToken(None));
        }
        Err(_) => {
            return Err(ApiError::InvalidToken(None));
        }
    }

    state
        .user_repo
        .set_email_verified(user.id, true)
        .await
        .log_db_err("confirming email")?;

    info!("Email confirmed for user {}", user.id);
    Ok(EmptyResponse::ok().into_response())
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
    auth: Auth<NotTakendown>,
    Json(input): Json<UpdateEmailInput>,
) -> Result<Response, ApiError> {
    if let Err(e) = crate::auth::scope_check::check_account_scope(
        auth.is_oauth(),
        auth.scope.as_deref(),
        crate::oauth::scopes::AccountAttr::Email,
        crate::oauth::scopes::AccountAction::Manage,
    ) {
        return Ok(e);
    }

    let did = &auth.did;
    let user = state
        .user_repo
        .get_email_info_by_did(did)
        .await
        .log_db_err("getting email info")?
        .ok_or(ApiError::AccountNotFound)?;

    let user_id = user.id;
    let current_email = user.email.clone();
    let email_verified = user.email_verified;
    let new_email = input.email.trim().to_lowercase();

    if !crate::api::validation::is_valid_email(&new_email) {
        return Err(ApiError::InvalidRequest(
            "This email address is not supported, please use a different email.".into(),
        ));
    }

    let email_unchanged = current_email
        .as_ref()
        .map(|c| new_email == c.to_lowercase())
        .unwrap_or(false);

    if email_unchanged {
        if let Some(email_auth_factor) = input.email_auth_factor {
            if email_verified {
                let token = input
                    .token
                    .as_ref()
                    .filter(|t| !t.is_empty())
                    .ok_or(ApiError::TokenRequired)?;

                crate::auth::email_token::validate_email_token(
                    state.cache.as_ref(),
                    did.as_str(),
                    crate::auth::email_token::EmailTokenPurpose::UpdateEmail,
                    token,
                )
                .await
                .map_err(|e| match e {
                    crate::auth::email_token::TokenError::ExpiredToken => {
                        ApiError::ExpiredToken(None)
                    }
                    _ => ApiError::InvalidToken(None),
                })?;
            }

            state
                .infra_repo
                .upsert_account_preference(user_id, "email_auth_factor", json!(email_auth_factor))
                .await
                .map_err(|e| {
                    error!("Failed to update email_auth_factor preference: {}", e);
                    ApiError::InternalError(Some("Failed to update 2FA setting".into()))
                })?;
        }
        return Ok(EmptyResponse::ok().into_response());
    }

    if email_verified {
        let mut authorized_via_link = false;

        let cache_key = email_update_cache_key(did);
        if let Some(pending_json) = state.cache.get(&cache_key).await
            && let Ok(pending) = serde_json::from_str::<PendingEmailUpdate>(&pending_json)
            && pending.authorized
            && pending.new_email == new_email
        {
            authorized_via_link = true;
            let _ = state.cache.delete(&cache_key).await;
            info!(did = %did, "Email update completed via link authorization");
        }

        if !authorized_via_link {
            let token = input
                .token
                .as_ref()
                .filter(|t| !t.is_empty())
                .ok_or(ApiError::TokenRequired)?;

            let short_token_result = crate::auth::email_token::validate_email_token(
                state.cache.as_ref(),
                did.as_str(),
                crate::auth::email_token::EmailTokenPurpose::UpdateEmail,
                token,
            )
            .await;

            if let Err(e) = short_token_result {
                let confirmation_token =
                    crate::auth::verification_token::normalize_token_input(token.trim());

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
                            return Err(ApiError::InvalidToken(None));
                        }
                    }
                    Err(crate::auth::verification_token::VerifyError::Expired) => {
                        return Err(match e {
                            crate::auth::email_token::TokenError::ExpiredToken => {
                                ApiError::ExpiredToken(None)
                            }
                            _ => ApiError::InvalidToken(None),
                        });
                    }
                    Err(_) => {
                        return Err(match e {
                            crate::auth::email_token::TokenError::ExpiredToken => {
                                ApiError::ExpiredToken(None)
                            }
                            _ => ApiError::InvalidToken(None),
                        });
                    }
                }
            }
        }
    }

    state
        .user_repo
        .update_email(user_id, &new_email)
        .await
        .log_db_err("updating email")?;

    let verification_token =
        crate::auth::verification_token::generate_signup_token(did, "email", &new_email);
    let formatted_token =
        crate::auth::verification_token::format_token_for_display(&verification_token);
    let hostname = pds_hostname();
    if let Err(e) = crate::comms::comms_repo::enqueue_signup_verification(
        state.infra_repo.as_ref(),
        user_id,
        "email",
        &new_email,
        &formatted_token,
        hostname,
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
    Ok(EmptyResponse::ok().into_response())
}

#[derive(Deserialize)]
pub struct CheckEmailVerifiedInput {
    pub identifier: String,
}

pub async fn check_email_verified(
    State(state): State<AppState>,
    _rate_limit: RateLimited<VerificationCheckLimit>,
    Json(input): Json<CheckEmailVerifiedInput>,
) -> Response {
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
    _rate_limit: RateLimited<VerificationCheckLimit>,
    axum::extract::Query(query): axum::extract::Query<AuthorizeEmailUpdateQuery>,
) -> Response {
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
        && let Err(e) = state.cache.set(&cache_key, &json, EMAIL_UPDATE_TTL).await
    {
        warn!("Failed to update pending email authorization: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }

    info!(did = %did, "Email update authorized via link click");

    let hostname = pds_hostname();
    let redirect_url = format!(
        "https://{}/app/verify?type=email-authorize-success",
        hostname
    );

    axum::response::Redirect::to(&redirect_url).into_response()
}

pub async fn check_email_update_status(
    State(state): State<AppState>,
    _rate_limit: RateLimited<VerificationCheckLimit>,
    auth: Auth<NotTakendown>,
) -> Result<Response, ApiError> {
    if let Err(e) = crate::auth::scope_check::check_account_scope(
        auth.is_oauth(),
        auth.scope.as_deref(),
        crate::oauth::scopes::AccountAttr::Email,
        crate::oauth::scopes::AccountAction::Read,
    ) {
        return Ok(e);
    }

    let cache_key = email_update_cache_key(&auth.did);
    let pending_json = match state.cache.get(&cache_key).await {
        Some(json) => json,
        None => {
            return Ok(Json(json!({ "pending": false, "authorized": false })).into_response());
        }
    };

    let pending: PendingEmailUpdate = match serde_json::from_str(&pending_json) {
        Ok(p) => p,
        Err(_) => {
            return Ok(Json(json!({ "pending": false, "authorized": false })).into_response());
        }
    };

    Ok(Json(json!({
        "pending": true,
        "authorized": pending.authorized,
        "newEmail": pending.new_email,
    }))
    .into_response())
}

#[derive(Deserialize)]
pub struct CheckEmailInUseInput {
    pub email: String,
}

pub async fn check_email_in_use(
    State(state): State<AppState>,
    _rate_limit: RateLimited<VerificationCheckLimit>,
    Json(input): Json<CheckEmailInUseInput>,
) -> Response {
    let email = input.email.trim().to_lowercase();
    if email.is_empty() {
        return ApiError::InvalidRequest("email is required".into()).into_response();
    }

    let count = match state.user_repo.count_accounts_by_email(&email).await {
        Ok(c) => c,
        Err(e) => {
            error!("DB error checking email usage: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    Json(json!({
        "inUse": count > 0,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct CheckCommsChannelInUseInput {
    pub channel: String,
    pub identifier: String,
}

pub async fn check_comms_channel_in_use(
    State(state): State<AppState>,
    _rate_limit: RateLimited<VerificationCheckLimit>,
    Json(input): Json<CheckCommsChannelInUseInput>,
) -> Response {
    let channel = match input.channel.to_lowercase().as_str() {
        "email" => CommsChannel::Email,
        "discord" => CommsChannel::Discord,
        "telegram" => CommsChannel::Telegram,
        "signal" => CommsChannel::Signal,
        _ => {
            return ApiError::InvalidRequest("invalid channel".into()).into_response();
        }
    };

    let identifier = input.identifier.trim();
    if identifier.is_empty() {
        return ApiError::InvalidRequest("identifier is required".into()).into_response();
    }

    let count = match state
        .user_repo
        .count_accounts_by_comms_identifier(channel, identifier)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            error!("DB error checking comms channel usage: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    Json(json!({
        "inUse": count > 0,
    }))
    .into_response()
}
