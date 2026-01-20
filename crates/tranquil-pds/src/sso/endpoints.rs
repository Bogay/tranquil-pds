use axum::{
    Form, Json,
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use tranquil_db_traits::SsoProviderType;
use tranquil_types::RequestId;

use super::config::SsoConfig;
use crate::api::error::ApiError;
use crate::auth::extractor::extract_bearer_token_from_header;
use crate::auth::{generate_app_password, validate_bearer_token_cached};
use crate::rate_limit::extract_client_ip;
use crate::state::{AppState, RateLimitKind};

fn generate_state() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn generate_nonce() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Debug, Serialize)]
pub struct SsoProviderInfo {
    pub provider: String,
    pub name: String,
    pub icon: String,
}

#[derive(Debug, Serialize)]
pub struct SsoProvidersResponse {
    pub providers: Vec<SsoProviderInfo>,
}

pub async fn get_sso_providers(State(state): State<AppState>) -> Json<SsoProvidersResponse> {
    let providers = state
        .sso_manager
        .enabled_providers()
        .iter()
        .map(|(t, name, icon)| SsoProviderInfo {
            provider: t.as_str().to_string(),
            name: name.to_string(),
            icon: icon.to_string(),
        })
        .collect();

    Json(SsoProvidersResponse { providers })
}

#[derive(Debug, Deserialize)]
pub struct SsoInitiateRequest {
    pub provider: String,
    pub request_uri: Option<String>,
    pub action: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SsoInitiateResponse {
    pub redirect_url: String,
}

pub async fn sso_initiate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<SsoInitiateRequest>,
) -> Result<Json<SsoInitiateResponse>, ApiError> {
    let client_ip = extract_client_ip(&headers, None);
    if !state
        .check_rate_limit(RateLimitKind::SsoInitiate, &client_ip)
        .await
    {
        tracing::warn!(ip = %client_ip, "SSO initiate rate limit exceeded");
        return Err(ApiError::RateLimitExceeded(None));
    }

    if input.provider.len() > 20 {
        return Err(ApiError::SsoProviderNotFound);
    }
    if let Some(ref uri) = input.request_uri
        && uri.len() > 500
    {
        return Err(ApiError::InvalidRequest("Request URI too long".into()));
    }
    if let Some(ref action) = input.action
        && action.len() > 20
    {
        return Err(ApiError::SsoInvalidAction);
    }

    let provider_type =
        SsoProviderType::parse(&input.provider).ok_or(ApiError::SsoProviderNotFound)?;

    let provider = state
        .sso_manager
        .get_provider(provider_type)
        .ok_or(ApiError::SsoProviderNotEnabled)?;

    let action = input.action.as_deref().unwrap_or("login");
    if !["login", "link", "register"].contains(&action) {
        return Err(ApiError::SsoInvalidAction);
    }

    let is_standalone = action == "register" && input.request_uri.is_none();
    let request_uri = input
        .request_uri
        .clone()
        .unwrap_or_else(|| "standalone".to_string());

    let auth_did = match action {
        "link" => {
            let auth_header = headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok());
            let token = extract_bearer_token_from_header(auth_header)
                .ok_or(ApiError::SsoNotAuthenticated)?;
            let auth_user = validate_bearer_token_cached(
                state.user_repo.as_ref(),
                state.cache.as_ref(),
                &token,
            )
            .await
            .map_err(|_| ApiError::SsoNotAuthenticated)?;
            Some(auth_user.did)
        }
        "register" if is_standalone => None,
        _ => {
            let request_id = RequestId::new(request_uri.clone());
            let _request_data = state
                .oauth_repo
                .get_authorization_request(&request_id)
                .await?
                .ok_or(ApiError::InvalidRequest(
                    "Authorization request not found or expired".into(),
                ))?;
            None
        }
    };

    let sso_state = generate_state();
    let nonce = generate_nonce();
    let redirect_uri = SsoConfig::get_redirect_uri();

    let auth_result = provider
        .build_auth_url(&sso_state, redirect_uri, Some(&nonce))
        .await
        .map_err(|e| {
            tracing::error!("Failed to build auth URL: {:?}", e);
            ApiError::InternalError(Some("Failed to build authorization URL".into()))
        })?;

    state
        .sso_repo
        .create_sso_auth_state(
            &sso_state,
            &request_uri,
            provider_type,
            action,
            Some(&nonce),
            auth_result.code_verifier.as_deref(),
            auth_did.as_ref(),
        )
        .await?;

    tracing::debug!(
        provider = %provider_type.as_str(),
        action = %action,
        "SSO flow initiated"
    );

    Ok(Json(SsoInitiateResponse {
        redirect_url: auth_result.url,
    }))
}

#[derive(Debug, Deserialize)]
pub struct SsoCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SsoCallbackForm {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
}

fn redirect_to_error(message: &str) -> Response {
    let encoded = urlencoding::encode(message);
    Redirect::to(&format!("/app/oauth/error?error={}", encoded)).into_response()
}

fn redirect_to_login_with_error(request_uri: &str, message: &str) -> Response {
    let uri_encoded = urlencoding::encode(request_uri);
    let msg_encoded = urlencoding::encode(message);
    Redirect::to(&format!(
        "/app/oauth/login?request_uri={}&error={}",
        uri_encoded, msg_encoded
    ))
    .into_response()
}

pub async fn sso_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SsoCallbackQuery>,
) -> Response {
    tracing::debug!(
        has_code = query.code.is_some(),
        has_state = query.state.is_some(),
        has_error = query.error.is_some(),
        "SSO callback received"
    );

    let client_ip = extract_client_ip(&headers, None);
    if !state
        .check_rate_limit(RateLimitKind::SsoCallback, &client_ip)
        .await
    {
        tracing::warn!(ip = %client_ip, "SSO callback rate limit exceeded");
        return redirect_to_error("Too many requests. Please try again later.");
    }

    if let Some(ref error) = query.error {
        tracing::warn!(
            error = %error,
            error_description = ?query.error_description,
            "SSO provider returned error"
        );
        if error.len() > 100 {
            return redirect_to_error("Invalid error response");
        }
        let desc = query
            .error_description
            .as_ref()
            .map(|d| if d.len() > 500 { "Error" } else { d.as_str() })
            .unwrap_or_default();
        return redirect_to_error(&format!("{}: {}", error, desc));
    }

    let (code, sso_state) = match (&query.code, &query.state) {
        (Some(c), Some(s)) if c.len() <= 2000 && s.len() <= 100 => (c.clone(), s.clone()),
        (Some(_), Some(_)) => return redirect_to_error("Invalid callback parameters"),
        _ => return redirect_to_error("Missing code or state parameter"),
    };

    let auth_state = match state.sso_repo.consume_sso_auth_state(&sso_state).await {
        Ok(Some(s)) => s,
        Ok(None) => return redirect_to_error("SSO session expired or invalid"),
        Err(e) => {
            tracing::error!("SSO state lookup failed: {:?}", e);
            return redirect_to_error("Database error");
        }
    };

    tracing::debug!(
        provider = %auth_state.provider.as_str(),
        action = %auth_state.action,
        request_uri = %auth_state.request_uri,
        "SSO auth state retrieved"
    );

    let is_standalone = auth_state.request_uri == "standalone";

    let provider = match state.sso_manager.get_provider(auth_state.provider) {
        Some(p) => p,
        None => return redirect_to_error("Provider no longer available"),
    };

    let redirect_uri = SsoConfig::get_redirect_uri();

    let token_resp = match provider
        .exchange_code(&code, redirect_uri, auth_state.code_verifier.as_deref())
        .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("SSO token exchange failed: {:?}", e);
            if is_standalone {
                return redirect_to_error(
                    "Failed to exchange authorization code. Please try again.",
                );
            }
            return redirect_to_login_with_error(
                &auth_state.request_uri,
                "Failed to exchange authorization code",
            );
        }
    };

    let user_info = match provider
        .get_user_info(
            &token_resp.access_token,
            token_resp.id_token.as_deref(),
            auth_state.nonce.as_deref(),
        )
        .await
    {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("SSO user info fetch failed: {:?}", e);
            if is_standalone {
                return redirect_to_error(
                    "Failed to get user information from provider. Please try again.",
                );
            }
            return redirect_to_login_with_error(
                &auth_state.request_uri,
                "Failed to get user information from provider",
            );
        }
    };

    match auth_state.action.as_str() {
        "login" => {
            handle_sso_login(
                &state,
                &auth_state.request_uri,
                auth_state.provider,
                &user_info,
            )
            .await
        }
        "link" => {
            let did = match auth_state.did {
                Some(d) => d,
                None => return redirect_to_error("Not authenticated"),
            };
            handle_sso_link(&state, did, auth_state.provider, &user_info).await
        }
        "register" => {
            handle_sso_register(
                &state,
                &auth_state.request_uri,
                auth_state.provider,
                &user_info,
            )
            .await
        }
        _ => redirect_to_error("Unknown SSO action"),
    }
}

pub async fn sso_callback_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SsoCallbackForm>,
) -> Response {
    tracing::debug!(
        has_code = form.code.is_some(),
        has_state = form.state.is_some(),
        has_error = form.error.is_some(),
        has_user = form.user.is_some(),
        "SSO callback (POST/form_post) received"
    );

    let query = SsoCallbackQuery {
        code: form.code,
        state: form.state,
        error: form.error,
        error_description: form.error_description,
    };

    sso_callback(State(state), headers, Query(query)).await
}

fn generate_registration_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

async fn handle_sso_login(
    state: &AppState,
    request_uri: &str,
    provider: SsoProviderType,
    user_info: &crate::sso::providers::SsoUserInfo,
) -> Response {
    let identity = match state
        .sso_repo
        .get_external_identity_by_provider(provider, &user_info.provider_user_id)
        .await
    {
        Ok(Some(id)) => id,
        Ok(None) => {
            let token = generate_registration_token();
            if let Err(e) = state
                .sso_repo
                .create_pending_registration(
                    &token,
                    request_uri,
                    provider,
                    &user_info.provider_user_id,
                    user_info.username.as_deref(),
                    user_info.email.as_deref(),
                    user_info.email_verified.unwrap_or(false),
                )
                .await
            {
                tracing::error!("Failed to create pending registration: {:?}", e);
                return redirect_to_error("Database error");
            }
            return Redirect::to(&format!(
                "/app/oauth/sso-register?token={}",
                urlencoding::encode(&token),
            ))
            .into_response();
        }
        Err(e) => {
            tracing::error!("SSO identity lookup failed: {:?}", e);
            return redirect_to_error("Database error");
        }
    };

    let is_verified = match state.user_repo.get_session_info_by_did(&identity.did).await {
        Ok(Some(info)) => {
            info.email_verified
                || info.discord_verified
                || info.telegram_verified
                || info.signal_verified
        }
        Ok(None) => {
            tracing::error!("User not found for SSO login: {}", identity.did);
            return redirect_to_error("Account not found");
        }
        Err(e) => {
            tracing::error!("Database error checking verification status: {:?}", e);
            return redirect_to_error("Database error");
        }
    };

    if !is_verified {
        tracing::warn!(
            did = %identity.did,
            provider = %provider.as_str(),
            "SSO login attempt for unverified account"
        );
        return redirect_to_login_with_error(
            request_uri,
            "Please verify your account before logging in",
        );
    }

    if let Err(e) = state
        .sso_repo
        .update_external_identity_login(
            identity.id,
            user_info.username.as_deref(),
            user_info.email.as_deref(),
        )
        .await
    {
        tracing::warn!("Failed to update external identity last login: {:?}", e);
    }

    let request_id = RequestId::new(request_uri.to_string());
    if let Err(e) = state
        .oauth_repo
        .set_authorization_did(&request_id, &identity.did, None)
        .await
    {
        tracing::error!("Failed to set authorization DID: {:?}", e);
        return redirect_to_error("Failed to authenticate");
    }

    tracing::info!(
        did = %identity.did,
        provider = %provider.as_str(),
        provider_user_id = %user_info.provider_user_id,
        "SSO login successful"
    );

    let has_totp = match state.user_repo.get_totp_record(&identity.did).await {
        Ok(Some(record)) => record.verified,
        _ => false,
    };

    if has_totp {
        return Redirect::to(&format!(
            "/app/oauth/totp?request_uri={}",
            urlencoding::encode(request_uri)
        ))
        .into_response();
    }

    Redirect::to(&format!(
        "/app/oauth/consent?request_uri={}",
        urlencoding::encode(request_uri)
    ))
    .into_response()
}

async fn handle_sso_link(
    state: &AppState,
    did: tranquil_types::Did,
    provider: SsoProviderType,
    user_info: &crate::sso::providers::SsoUserInfo,
) -> Response {
    let existing = state
        .sso_repo
        .get_external_identity_by_provider(provider, &user_info.provider_user_id)
        .await;

    match existing {
        Ok(Some(existing_id)) => {
            if existing_id.did != did {
                tracing::warn!(
                    provider = %provider.as_str(),
                    provider_user_id = %user_info.provider_user_id,
                    existing_did = %existing_id.did,
                    requested_did = %did,
                    "SSO account already linked to different user"
                );
                return Redirect::to(&format!(
                    "/app/security?error={}",
                    urlencoding::encode("This SSO account is already linked to a different user")
                ))
                .into_response();
            }
            tracing::info!(
                did = %did,
                provider = %provider.as_str(),
                "SSO account already linked to this user"
            );
            return Redirect::to("/app/security?sso_linked=true").into_response();
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!("Failed to check existing identity: {:?}", e);
            return Redirect::to(&format!(
                "/app/security?error={}",
                urlencoding::encode("Database error")
            ))
            .into_response();
        }
    }

    if let Err(e) = state
        .sso_repo
        .create_external_identity(
            &did,
            provider,
            &user_info.provider_user_id,
            user_info.username.as_deref(),
            user_info.email.as_deref(),
        )
        .await
    {
        tracing::error!("Failed to create external identity: {:?}", e);
        return Redirect::to(&format!(
            "/app/security?error={}",
            urlencoding::encode("Failed to link account")
        ))
        .into_response();
    }

    tracing::info!(
        did = %did,
        provider = %provider.as_str(),
        provider_user_id = %user_info.provider_user_id,
        "Successfully linked SSO account"
    );
    Redirect::to("/app/security?sso_linked=true").into_response()
}

async fn handle_sso_register(
    state: &AppState,
    request_uri: &str,
    provider: SsoProviderType,
    user_info: &crate::sso::providers::SsoUserInfo,
) -> Response {
    match state
        .sso_repo
        .get_external_identity_by_provider(provider, &user_info.provider_user_id)
        .await
    {
        Ok(Some(_)) => {
            return redirect_to_error(
                "This account is already linked to an existing user. Please sign in instead.",
            );
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!("SSO identity lookup failed: {:?}", e);
            return redirect_to_error("Database error");
        }
    }

    let token = generate_registration_token();
    if let Err(e) = state
        .sso_repo
        .create_pending_registration(
            &token,
            request_uri,
            provider,
            &user_info.provider_user_id,
            user_info.username.as_deref(),
            user_info.email.as_deref(),
            user_info.email_verified.unwrap_or(false),
        )
        .await
    {
        tracing::error!("Failed to create pending registration: {:?}", e);
        return redirect_to_error("Database error");
    }
    Redirect::to(&format!(
        "/app/oauth/sso-register?token={}",
        urlencoding::encode(&token),
    ))
    .into_response()
}

#[derive(Debug, Serialize)]
pub struct LinkedAccountInfo {
    pub id: String,
    pub provider: String,
    pub provider_name: String,
    pub provider_username: Option<String>,
    pub provider_email: Option<String>,
    pub created_at: String,
    pub last_login_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LinkedAccountsResponse {
    pub accounts: Vec<LinkedAccountInfo>,
}

pub async fn get_linked_accounts(
    State(state): State<AppState>,
    crate::auth::extractor::BearerAuth(auth): crate::auth::extractor::BearerAuth,
) -> Result<Json<LinkedAccountsResponse>, ApiError> {
    let identities = state
        .sso_repo
        .get_external_identities_by_did(&auth.did)
        .await?;

    let accounts = identities
        .into_iter()
        .map(|id| LinkedAccountInfo {
            id: id.id.to_string(),
            provider: id.provider.as_str().to_string(),
            provider_name: id.provider.display_name().to_string(),
            provider_username: id.provider_username,
            provider_email: id.provider_email,
            created_at: id.created_at.to_rfc3339(),
            last_login_at: id.last_login_at.map(|t| t.to_rfc3339()),
        })
        .collect();

    Ok(Json(LinkedAccountsResponse { accounts }))
}

#[derive(Debug, Deserialize)]
pub struct UnlinkAccountRequest {
    pub id: String,
}

#[derive(Debug, Serialize)]
pub struct UnlinkAccountResponse {
    pub success: bool,
}

pub async fn unlink_account(
    State(state): State<AppState>,
    crate::auth::extractor::BearerAuth(auth): crate::auth::extractor::BearerAuth,
    Json(input): Json<UnlinkAccountRequest>,
) -> Result<Json<UnlinkAccountResponse>, ApiError> {
    if !state
        .check_rate_limit(RateLimitKind::SsoUnlink, auth.did.as_str())
        .await
    {
        tracing::warn!(did = %auth.did, "SSO unlink rate limit exceeded");
        return Err(ApiError::RateLimitExceeded(None));
    }

    let id = uuid::Uuid::parse_str(&input.id).map_err(|_| ApiError::InvalidId)?;

    let has_password = state
        .user_repo
        .has_password_by_did(&auth.did)
        .await?
        .unwrap_or(false);

    let passkeys = state.user_repo.get_passkeys_for_user(&auth.did).await?;
    let has_passkeys = !passkeys.is_empty();

    if !has_password && !has_passkeys {
        let identities = state
            .sso_repo
            .get_external_identities_by_did(&auth.did)
            .await?;

        if identities.len() <= 1 {
            return Err(ApiError::InvalidRequest(
                "Cannot unlink your only login method. Add a password or passkey first."
                    .to_string(),
            ));
        }
    }

    let deleted = state
        .sso_repo
        .delete_external_identity(id, &auth.did)
        .await?;

    if !deleted {
        return Err(ApiError::SsoLinkNotFound);
    }

    tracing::info!(did = %auth.did, identity_id = %id, "SSO account unlinked");

    Ok(Json(UnlinkAccountResponse { success: true }))
}

#[derive(Debug, Deserialize)]
pub struct PendingRegistrationQuery {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct PendingRegistrationResponse {
    pub request_uri: String,
    pub provider: String,
    pub provider_user_id: String,
    pub provider_username: Option<String>,
    pub provider_email: Option<String>,
    pub provider_email_verified: bool,
}

pub async fn get_pending_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PendingRegistrationQuery>,
) -> Result<Json<PendingRegistrationResponse>, ApiError> {
    let client_ip = extract_client_ip(&headers, None);
    if !state
        .check_rate_limit(RateLimitKind::SsoCallback, &client_ip)
        .await
    {
        tracing::warn!(ip = %client_ip, "SSO pending registration rate limit exceeded");
        return Err(ApiError::RateLimitExceeded(None));
    }

    if query.token.len() > 100 {
        return Err(ApiError::InvalidRequest("Invalid token".into()));
    }

    let pending = state
        .sso_repo
        .get_pending_registration(&query.token)
        .await?
        .ok_or(ApiError::SsoSessionExpired)?;

    Ok(Json(PendingRegistrationResponse {
        request_uri: pending.request_uri,
        provider: pending.provider.as_str().to_string(),
        provider_user_id: pending.provider_user_id,
        provider_username: pending.provider_username,
        provider_email: pending.provider_email,
        provider_email_verified: pending.provider_email_verified,
    }))
}

#[derive(Debug, Deserialize)]
pub struct CheckHandleQuery {
    pub handle: String,
}

#[derive(Debug, Serialize)]
pub struct CheckHandleResponse {
    pub available: bool,
    pub reason: Option<String>,
}

pub async fn check_handle_available(
    State(state): State<AppState>,
    Query(query): Query<CheckHandleQuery>,
) -> Result<Json<CheckHandleResponse>, ApiError> {
    if query.handle.len() > 100 {
        return Ok(Json(CheckHandleResponse {
            available: false,
            reason: Some("Handle too long".into()),
        }));
    }

    let validated = match crate::api::validation::validate_short_handle(&query.handle) {
        Ok(h) => h,
        Err(e) => {
            return Ok(Json(CheckHandleResponse {
                available: false,
                reason: Some(e.to_string()),
            }));
        }
    };

    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let hostname_for_handles = hostname.split(':').next().unwrap_or(&hostname);
    let full_handle = format!("{}.{}", validated, hostname_for_handles);
    let handle_typed = crate::types::Handle::new_unchecked(&full_handle);

    let db_available = state
        .user_repo
        .check_handle_available_for_new_account(&handle_typed)
        .await
        .unwrap_or(false);

    if !db_available {
        return Ok(Json(CheckHandleResponse {
            available: false,
            reason: Some("Handle is already taken".into()),
        }));
    }

    Ok(Json(CheckHandleResponse {
        available: true,
        reason: None,
    }))
}

#[derive(Debug, Deserialize)]
pub struct CompleteRegistrationInput {
    pub token: String,
    pub handle: String,
    pub email: Option<String>,
    pub invite_code: Option<String>,
    pub verification_channel: Option<String>,
    pub discord_id: Option<String>,
    pub telegram_username: Option<String>,
    pub signal_number: Option<String>,
    pub did_type: Option<String>,
    pub did: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompleteRegistrationResponse {
    pub did: String,
    pub handle: String,
    pub redirect_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_jwt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_jwt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_password_name: Option<String>,
}

pub async fn complete_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CompleteRegistrationInput>,
) -> Result<Json<CompleteRegistrationResponse>, ApiError> {
    use jacquard_common::types::{integer::LimitedU32, string::Tid};
    use jacquard_repo::{mst::Mst, storage::BlockStore};
    use k256::ecdsa::SigningKey;
    use rand::rngs::OsRng;
    use serde_json::json;
    use std::sync::Arc;

    let client_ip = extract_client_ip(&headers, None);
    if !state
        .check_rate_limit(RateLimitKind::AccountCreation, &client_ip)
        .await
    {
        tracing::warn!(ip = %client_ip, "SSO registration rate limit exceeded");
        return Err(ApiError::RateLimitExceeded(None));
    }

    if input.token.len() > 100 {
        return Err(ApiError::InvalidRequest("Invalid token".into()));
    }

    if input.handle.len() > 100 {
        return Err(ApiError::InvalidHandle(None));
    }

    let pending_preview = state
        .sso_repo
        .get_pending_registration(&input.token)
        .await?
        .ok_or(ApiError::SsoSessionExpired)?;

    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let hostname_for_handles = hostname.split(':').next().unwrap_or(&hostname);

    let handle = match crate::api::validation::validate_short_handle(&input.handle) {
        Ok(h) => format!("{}.{}", h, hostname_for_handles),
        Err(_) => return Err(ApiError::InvalidHandle(None)),
    };

    let verification_channel = input.verification_channel.as_deref().unwrap_or("email");
    let verification_recipient = match verification_channel {
        "email" => {
            let email = input
                .email
                .clone()
                .or_else(|| pending_preview.provider_email.clone())
                .map(|e| e.trim().to_string())
                .filter(|e| !e.is_empty());
            match email {
                Some(e) if !e.is_empty() => e,
                _ => return Err(ApiError::MissingEmail),
            }
        }
        "discord" => match &input.discord_id {
            Some(id) if !id.trim().is_empty() => id.trim().to_string(),
            _ => return Err(ApiError::MissingDiscordId),
        },
        "telegram" => match &input.telegram_username {
            Some(username) if !username.trim().is_empty() => username.trim().to_string(),
            _ => return Err(ApiError::MissingTelegramUsername),
        },
        "signal" => match &input.signal_number {
            Some(number) if !number.trim().is_empty() => number.trim().to_string(),
            _ => return Err(ApiError::MissingSignalNumber),
        },
        _ => return Err(ApiError::InvalidVerificationChannel),
    };

    let email = input
        .email
        .clone()
        .or_else(|| pending_preview.provider_email.clone())
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty());

    let email = match &email {
        Some(e) => {
            if e.len() > 254 {
                return Err(ApiError::InvalidEmail);
            }
            if !crate::api::validation::is_valid_email(e) {
                return Err(ApiError::InvalidEmail);
            }
            Some(e.clone())
        }
        None => None,
    };

    if let Some(ref code) = input.invite_code {
        let valid = state
            .infra_repo
            .is_invite_code_valid(code)
            .await
            .unwrap_or(false);
        if !valid {
            return Err(ApiError::InvalidInviteCode);
        }
    } else {
        let invite_required = std::env::var("INVITE_CODE_REQUIRED")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        if invite_required {
            return Err(ApiError::InviteCodeRequired);
        }
    }

    let handle_typed = crate::types::Handle::new_unchecked(&handle);
    let reserved = state
        .user_repo
        .reserve_handle(&handle_typed, &client_ip)
        .await
        .unwrap_or(false);

    if !reserved {
        return Err(ApiError::HandleNotAvailable(None));
    }

    let secret_key = k256::SecretKey::random(&mut OsRng);
    let secret_key_bytes = secret_key.to_bytes().to_vec();
    let signing_key = match SigningKey::from_slice(&secret_key_bytes) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("Error creating signing key: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    };

    let pds_endpoint = format!("https://{}", hostname);
    let did_type = input.did_type.as_deref().unwrap_or("plc");

    let did = match did_type {
        "web" => {
            let subdomain_host = format!("{}.{}", input.handle, hostname_for_handles);
            let encoded_subdomain = subdomain_host.replace(':', "%3A");
            let self_hosted_did = format!("did:web:{}", encoded_subdomain);
            tracing::info!(did = %self_hosted_did, "Creating self-hosted did:web SSO account");
            self_hosted_did
        }
        "web-external" => {
            let d = match &input.did {
                Some(d) if !d.trim().is_empty() => d.trim(),
                _ => {
                    return Err(ApiError::InvalidRequest(
                        "External did:web requires the 'did' field to be provided".into(),
                    ));
                }
            };
            if !d.starts_with("did:web:") {
                return Err(ApiError::InvalidDid(
                    "External DID must be a did:web".into(),
                ));
            }
            tracing::info!(did = %d, "Creating external did:web SSO account");
            d.to_string()
        }
        _ => {
            let rotation_key = std::env::var("PLC_ROTATION_KEY")
                .unwrap_or_else(|_| crate::plc::signing_key_to_did_key(&signing_key));

            let genesis_result = match crate::plc::create_genesis_operation(
                &signing_key,
                &rotation_key,
                &handle,
                &pds_endpoint,
            ) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("Error creating PLC genesis operation: {:?}", e);
                    return Err(ApiError::InternalError(Some(
                        "Failed to create PLC operation".into(),
                    )));
                }
            };

            let plc_client = crate::plc::PlcClient::with_cache(None, Some(state.cache.clone()));
            if let Err(e) = plc_client
                .send_operation(&genesis_result.did, &genesis_result.signed_operation)
                .await
            {
                tracing::error!("Failed to submit PLC genesis operation: {:?}", e);
                return Err(ApiError::UpstreamErrorMsg(format!(
                    "Failed to register DID with PLC directory: {}",
                    e
                )));
            }
            genesis_result.did
        }
    };
    tracing::info!(did = %did, handle = %handle, provider = %pending_preview.provider.as_str(), "Created DID for SSO account");

    let encrypted_key_bytes = match crate::config::encrypt_key(&secret_key_bytes) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!("Error encrypting signing key: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    };

    let mst = Mst::new(Arc::new(state.block_store.clone()));
    let mst_root = match mst.persist().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Error persisting MST: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    };

    let rev = Tid::now(LimitedU32::MIN);
    let did_typed = crate::types::Did::new_unchecked(&did);
    let (commit_bytes, _sig) = match crate::api::repo::record::utils::create_signed_commit(
        &did_typed,
        mst_root,
        rev.as_ref(),
        None,
        &signing_key,
    ) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Error creating genesis commit: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    };

    let commit_cid: cid::Cid = match state.block_store.put(&commit_bytes).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Error saving genesis commit: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    };

    let genesis_block_cids = vec![mst_root.to_bytes(), commit_cid.to_bytes()];

    let birthdate_pref = std::env::var("PDS_AGE_ASSURANCE_OVERRIDE").ok().map(|_| {
        json!({
            "$type": "app.bsky.actor.defs#personalDetailsPref",
            "birthDate": "1998-05-06T00:00:00.000Z"
        })
    });

    let preferred_comms_channel = match verification_channel {
        "email" => tranquil_db_traits::CommsChannel::Email,
        "discord" => tranquil_db_traits::CommsChannel::Discord,
        "telegram" => tranquil_db_traits::CommsChannel::Telegram,
        "signal" => tranquil_db_traits::CommsChannel::Signal,
        _ => tranquil_db_traits::CommsChannel::Email,
    };

    let create_input = tranquil_db_traits::CreateSsoAccountInput {
        handle: handle_typed.clone(),
        email: email.clone(),
        did: did_typed.clone(),
        preferred_comms_channel,
        discord_id: input
            .discord_id
            .clone()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        telegram_username: input
            .telegram_username
            .clone()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        signal_number: input
            .signal_number
            .clone()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        encrypted_key_bytes: encrypted_key_bytes.clone(),
        encryption_version: crate::config::ENCRYPTION_VERSION,
        commit_cid: commit_cid.to_string(),
        repo_rev: rev.as_ref().to_string(),
        genesis_block_cids,
        invite_code: input.invite_code.clone(),
        birthdate_pref,
        sso_provider: pending_preview.provider,
        sso_provider_user_id: pending_preview.provider_user_id.clone(),
        sso_provider_username: pending_preview.provider_username.clone(),
        sso_provider_email: pending_preview.provider_email.clone(),
        sso_provider_email_verified: pending_preview.provider_email_verified,
        pending_registration_token: input.token.clone(),
    };

    let create_result = match state.user_repo.create_sso_account(&create_input).await {
        Ok(r) => r,
        Err(tranquil_db_traits::CreateAccountError::HandleTaken) => {
            return Err(ApiError::HandleNotAvailable(None));
        }
        Err(tranquil_db_traits::CreateAccountError::EmailTaken) => {
            return Err(ApiError::EmailTaken);
        }
        Err(tranquil_db_traits::CreateAccountError::InvalidToken) => {
            return Err(ApiError::SsoSessionExpired);
        }
        Err(e) => {
            tracing::error!("Error creating SSO account: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    };

    let _ = state
        .user_repo
        .release_handle_reservation(&handle_typed)
        .await;

    if let Err(e) =
        crate::api::repo::record::sequence_identity_event(&state, &did_typed, Some(&handle_typed))
            .await
    {
        tracing::warn!("Failed to sequence identity event for {}: {}", did, e);
    }
    if let Err(e) =
        crate::api::repo::record::sequence_account_event(&state, &did_typed, true, None).await
    {
        tracing::warn!("Failed to sequence account event for {}: {}", did, e);
    }

    let profile_record = json!({
        "$type": "app.bsky.actor.profile",
        "displayName": handle_typed.as_str()
    });
    let profile_collection = crate::types::Nsid::new_unchecked("app.bsky.actor.profile");
    let profile_rkey = crate::types::Rkey::new_unchecked("self");
    if let Err(e) = crate::api::repo::record::create_record_internal(
        &state,
        &did_typed,
        &profile_collection,
        &profile_rkey,
        &profile_record,
    )
    .await
    {
        tracing::warn!("Failed to create default profile for {}: {}", did, e);
    }

    let app_password = generate_app_password();
    let app_password_name = "bsky.app".to_string();
    let app_password_hash = match bcrypt::hash(&app_password, bcrypt::DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("Failed to hash app password: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    };

    let app_password_data = tranquil_db_traits::AppPasswordCreate {
        user_id: create_result.user_id,
        name: app_password_name.clone(),
        password_hash: app_password_hash,
        privileged: false,
        scopes: None,
        created_by_controller_did: None,
    };
    if let Err(e) = state
        .session_repo
        .create_app_password(&app_password_data)
        .await
    {
        tracing::warn!("Failed to create initial app password: {:?}", e);
    }

    let is_standalone = pending_preview.request_uri == "standalone";

    if !is_standalone {
        let request_id = RequestId::new(pending_preview.request_uri.clone());
        if let Err(e) = state
            .oauth_repo
            .set_authorization_did(&request_id, &did_typed, None)
            .await
        {
            tracing::error!("Failed to set authorization DID: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    }

    tracing::info!(
        did = %did,
        handle = %handle,
        provider = %pending_preview.provider.as_str(),
        provider_user_id = %pending_preview.provider_user_id,
        standalone = %is_standalone,
        "SSO registration completed successfully"
    );

    let user_id = state
        .user_repo
        .get_id_by_did(&did_typed)
        .await
        .unwrap_or(None);

    let channel_auto_verified = verification_channel == "email"
        && pending_preview.provider_email_verified
        && pending_preview.provider_email.as_ref() == email.as_ref();

    if channel_auto_verified {
        let _ = state
            .user_repo
            .set_channel_verified(&did_typed, tranquil_db_traits::CommsChannel::Email)
            .await;
        tracing::info!(did = %did, "Auto-verified email from SSO provider");

        if is_standalone {
            let key_bytes = match crate::config::decrypt_key(
                &encrypted_key_bytes,
                Some(crate::config::ENCRYPTION_VERSION),
            ) {
                Ok(k) => k,
                Err(e) => {
                    tracing::error!("Failed to decrypt user key: {:?}", e);
                    return Err(ApiError::InternalError(None));
                }
            };

            let access_meta = match crate::auth::create_access_token_with_metadata(&did, &key_bytes)
            {
                Ok(m) => m,
                Err(e) => {
                    tracing::error!("Failed to create access token: {:?}", e);
                    return Err(ApiError::InternalError(None));
                }
            };
            let refresh_meta =
                match crate::auth::create_refresh_token_with_metadata(&did, &key_bytes) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::error!("Failed to create refresh token: {:?}", e);
                        return Err(ApiError::InternalError(None));
                    }
                };

            let session_data = tranquil_db_traits::SessionTokenCreate {
                did: did_typed.clone(),
                access_jti: access_meta.jti.clone(),
                refresh_jti: refresh_meta.jti.clone(),
                access_expires_at: access_meta.expires_at,
                refresh_expires_at: refresh_meta.expires_at,
                legacy_login: false,
                mfa_verified: false,
                scope: None,
                controller_did: None,
                app_password_name: None,
            };
            if let Err(e) = state.session_repo.create_session(&session_data).await {
                tracing::error!("Failed to insert session: {:?}", e);
                return Err(ApiError::InternalError(None));
            }

            let hostname =
                std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
            if let Err(e) = crate::comms::comms_repo::enqueue_welcome(
                state.user_repo.as_ref(),
                state.infra_repo.as_ref(),
                user_id.unwrap_or(uuid::Uuid::nil()),
                &hostname,
            )
            .await
            {
                tracing::warn!("Failed to enqueue welcome notification: {:?}", e);
            }

            return Ok(Json(CompleteRegistrationResponse {
                did,
                handle,
                redirect_url: "/app/dashboard".to_string(),
                access_jwt: Some(access_meta.token),
                refresh_jwt: Some(refresh_meta.token),
                app_password: Some(app_password),
                app_password_name: Some(app_password_name),
            }));
        }

        return Ok(Json(CompleteRegistrationResponse {
            did,
            handle,
            redirect_url: format!(
                "/app/oauth/consent?request_uri={}",
                urlencoding::encode(&pending_preview.request_uri)
            ),
            access_jwt: None,
            refresh_jwt: None,
            app_password: Some(app_password),
            app_password_name: Some(app_password_name),
        }));
    }

    if let Some(uid) = user_id {
        let verification_token = crate::auth::verification_token::generate_signup_token(
            &did,
            verification_channel,
            &verification_recipient,
        );
        let formatted_token =
            crate::auth::verification_token::format_token_for_display(&verification_token);
        if let Err(e) = crate::comms::comms_repo::enqueue_signup_verification(
            state.infra_repo.as_ref(),
            uid,
            verification_channel,
            &verification_recipient,
            &formatted_token,
            &hostname,
        )
        .await
        {
            tracing::warn!("Failed to enqueue signup verification: {:?}", e);
        }
    }

    let redirect_url = if is_standalone {
        format!("/app/verify?did={}", urlencoding::encode(&did))
    } else {
        format!(
            "/app/verify?did={}&request_uri={}",
            urlencoding::encode(&did),
            urlencoding::encode(&pending_preview.request_uri)
        )
    };

    Ok(Json(CompleteRegistrationResponse {
        did,
        handle,
        redirect_url,
        access_jwt: None,
        refresh_jwt: None,
        app_password: Some(app_password),
        app_password_name: Some(app_password_name),
    }))
}
