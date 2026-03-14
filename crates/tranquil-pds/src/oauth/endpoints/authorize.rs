use crate::auth::{BareLoginIdentifier, NormalizedLoginIdentifier};
use crate::comms::comms_repo::enqueue_2fa_code;
use crate::oauth::{
    AuthFlow, ClientMetadataCache, Code, DeviceData, DeviceId, OAuthError, Prompt, SessionId,
    db::should_show_consent, scopes::expand_include_scopes,
};
use crate::rate_limit::{
    OAuthAuthorizeLimit, OAuthRateLimited, OAuthRegisterCompleteLimit, TotpVerifyLimit,
    check_user_rate_limit,
};
use crate::state::AppState;
use crate::types::{Did, Handle, PlainPassword};
use crate::util::extract_client_ip;
use axum::{
    Json,
    extract::{Query, State},
    http::{
        HeaderMap, StatusCode,
        header::{LOCATION, SET_COOKIE},
    },
    response::{IntoResponse, Response},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tranquil_db_traits::{ScopePreference, WebauthnChallengeType};
use tranquil_types::{AuthorizationCode, ClientId, DeviceId as DeviceIdType, RequestId};
use urlencoding::encode as url_encode;

const DEVICE_COOKIE_NAME: &str = "oauth_device_id";
const RENEW_EXPIRY_SECONDS: i64 = 600;
const MAX_RENEWAL_STALENESS_SECONDS: i64 = 3600;

fn redirect_see_other(uri: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [
            (LOCATION, uri.to_string()),
            (axum::http::header::CACHE_CONTROL, "no-store".to_string()),
            (
                SET_COOKIE,
                "bfCacheBypass=foo; max-age=1; SameSite=Lax".to_string(),
            ),
        ],
    )
        .into_response()
}

fn redirect_to_frontend_error(error: &str, description: &str) -> Response {
    redirect_see_other(&format!(
        "/app/oauth/error?error={}&error_description={}",
        url_encode(error),
        url_encode(description)
    ))
}

fn json_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": error,
            "error_description": description
        })),
    )
        .into_response()
}

fn is_granular_scope(s: &str) -> bool {
    s.starts_with("repo:")
        || s.starts_with("repo?")
        || s == "repo"
        || s.starts_with("blob:")
        || s.starts_with("blob?")
        || s == "blob"
        || s.starts_with("rpc:")
        || s.starts_with("rpc?")
        || s.starts_with("account:")
        || s.starts_with("identity:")
}

fn is_valid_scope(s: &str) -> bool {
    s == "atproto"
        || s == "transition:generic"
        || s == "transition:chat.bsky"
        || s == "transition:email"
        || is_granular_scope(s)
        || s.starts_with("include:")
}

fn extract_device_cookie(headers: &HeaderMap) -> Option<tranquil_types::DeviceId> {
    headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookie_str| {
            cookie_str.split(';').map(|c| c.trim()).find_map(|cookie| {
                cookie
                    .strip_prefix(&format!("{}=", DEVICE_COOKIE_NAME))
                    .and_then(|value| crate::config::AuthConfig::get().verify_device_cookie(value))
                    .map(tranquil_types::DeviceId::new)
            })
        })
}

fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn make_device_cookie(device_id: &tranquil_types::DeviceId) -> String {
    let signed_value = crate::config::AuthConfig::get().sign_device_cookie(device_id.as_str());
    format!(
        "{}={}; Path=/oauth; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000",
        DEVICE_COOKIE_NAME, signed_value
    )
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub request_uri: Option<String>,
    pub client_id: Option<String>,
    pub new_account: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct AuthorizeResponse {
    pub client_id: String,
    pub client_name: Option<String>,
    pub scope: Option<String>,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub login_hint: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeSubmit {
    pub request_uri: String,
    pub username: String,
    pub password: PlainPassword,
    #[serde(default)]
    pub remember_device: bool,
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeSelectSubmit {
    pub request_uri: String,
    pub did: String,
}

fn wants_json(headers: &HeaderMap) -> bool {
    headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .map(|accept| accept.contains("application/json"))
        .unwrap_or(false)
}

pub async fn authorize_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuthorizeQuery>,
) -> Response {
    let request_uri = match query.request_uri {
        Some(uri) => uri,
        None => {
            if wants_json(&headers) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_request",
                        "error_description": "Missing request_uri parameter. Use PAR to initiate authorization."
                    })),
                ).into_response();
            }
            return redirect_to_frontend_error(
                "invalid_request",
                "Missing request_uri parameter. Use PAR to initiate authorization.",
            );
        }
    };
    let request_id = RequestId::from(request_uri.clone());
    let request_data = match state
        .oauth_repo
        .get_authorization_request(&request_id)
        .await
    {
        Ok(Some(data)) => data,
        Ok(None) => {
            if wants_json(&headers) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_request",
                        "error_description": "Invalid or expired request_uri. Please start a new authorization request."
                    })),
                ).into_response();
            }
            return redirect_to_frontend_error(
                "invalid_request",
                "Invalid or expired request_uri. Please start a new authorization request.",
            );
        }
        Err(e) => {
            if wants_json(&headers) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "server_error",
                        "error_description": format!("Database error: {:?}", e)
                    })),
                )
                    .into_response();
            }
            return redirect_to_frontend_error("server_error", "A database error occurred.");
        }
    };
    if request_data.expires_at < Utc::now() {
        let _ = state
            .oauth_repo
            .delete_authorization_request(&request_id)
            .await;
        if wants_json(&headers) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "Authorization request has expired. Please start a new request."
                })),
            ).into_response();
        }
        return redirect_to_frontend_error(
            "invalid_request",
            "Authorization request has expired. Please start a new request.",
        );
    }
    let client_cache = ClientMetadataCache::new(3600);
    let client_name = client_cache
        .get(&request_data.parameters.client_id)
        .await
        .ok()
        .and_then(|m| m.client_name);
    if wants_json(&headers) {
        return Json(AuthorizeResponse {
            client_id: request_data.parameters.client_id.clone(),
            client_name: client_name.clone(),
            scope: request_data.parameters.scope.clone(),
            redirect_uri: request_data.parameters.redirect_uri.clone(),
            state: request_data.parameters.state.clone(),
            login_hint: request_data.parameters.login_hint.clone(),
        })
        .into_response();
    }
    let force_new_account = query.new_account.unwrap_or(false);

    if let Some(ref login_hint) = request_data.parameters.login_hint {
        tracing::info!(login_hint = %login_hint, "Checking login_hint for delegation");
        let hostname_for_handles = tranquil_config::get().server.hostname_without_port();
        let normalized = NormalizedLoginIdentifier::normalize(login_hint, hostname_for_handles);
        tracing::info!(normalized = %normalized, "Normalized login_hint");

        match state
            .user_repo
            .get_login_check_by_handle_or_email(normalized.as_str())
            .await
        {
            Ok(Some(user)) => {
                tracing::info!(did = %user.did, has_password = user.password_hash.is_some(), "Found user for login_hint");
                let is_delegated = state
                    .delegation_repo
                    .is_delegated_account(&user.did)
                    .await
                    .unwrap_or(false);
                let has_password = user.password_hash.is_some();
                tracing::info!(is_delegated = %is_delegated, has_password = %has_password, "Delegation check");

                if is_delegated {
                    tracing::info!("Redirecting to delegation auth");
                    if let Err(e) = state
                        .oauth_repo
                        .set_request_did(&request_id, &user.did)
                        .await
                    {
                        tracing::error!(error = %e, "Failed to set delegated DID on authorization request");
                        return redirect_to_frontend_error(
                            "server_error",
                            "Failed to initialize delegation flow",
                        );
                    }
                    return redirect_see_other(&format!(
                        "/app/oauth/delegation?request_uri={}&delegated_did={}",
                        url_encode(&request_uri),
                        url_encode(&user.did)
                    ));
                }
            }
            Ok(None) => {
                tracing::info!(normalized = %normalized, "No user found for login_hint");
            }
            Err(e) => {
                tracing::error!(error = %e, "Error looking up user for login_hint");
            }
        }
    } else {
        tracing::info!("No login_hint in request");
    }

    if request_data.parameters.prompt == Some(Prompt::Create) {
        return redirect_see_other(&format!(
            "/app/oauth/register?request_uri={}",
            url_encode(&request_uri)
        ));
    }

    if !force_new_account
        && let Some(device_id) = extract_device_cookie(&headers)
        && let Ok(accounts) = state
            .oauth_repo
            .get_device_accounts(&device_id.clone())
            .await
        && !accounts.is_empty()
    {
        return redirect_see_other(&format!(
            "/app/oauth/accounts?request_uri={}",
            url_encode(&request_uri)
        ));
    }
    redirect_see_other(&format!(
        "/app/oauth/login?request_uri={}",
        url_encode(&request_uri)
    ))
}

pub async fn authorize_get_json(
    State(state): State<AppState>,
    Query(query): Query<AuthorizeQuery>,
) -> Result<Json<AuthorizeResponse>, OAuthError> {
    let request_uri = query
        .request_uri
        .ok_or_else(|| OAuthError::InvalidRequest("request_uri is required".to_string()))?;
    let request_id_json = RequestId::from(request_uri.clone());
    let request_data = state
        .oauth_repo
        .get_authorization_request(&request_id_json)
        .await
        .map_err(crate::oauth::db_err_to_oauth)?
        .ok_or_else(|| OAuthError::InvalidRequest("Invalid or expired request_uri".to_string()))?;
    if request_data.expires_at < Utc::now() {
        let _ = state
            .oauth_repo
            .delete_authorization_request(&request_id_json)
            .await;
        return Err(OAuthError::InvalidRequest(
            "request_uri has expired".to_string(),
        ));
    }
    Ok(Json(AuthorizeResponse {
        client_id: request_data.parameters.client_id.clone(),
        client_name: None,
        scope: request_data.parameters.scope.clone(),
        redirect_uri: request_data.parameters.redirect_uri.clone(),
        state: request_data.parameters.state.clone(),
        login_hint: request_data.parameters.login_hint.clone(),
    }))
}

#[derive(Debug, Serialize)]
pub struct AccountInfo {
    pub did: String,
    pub handle: Handle,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AccountsResponse {
    pub accounts: Vec<AccountInfo>,
    pub request_uri: String,
}

fn mask_email(email: &str) -> String {
    if let Some(at_pos) = email.find('@') {
        let local = &email[..at_pos];
        let domain = &email[at_pos..];
        if local.len() <= 2 {
            format!("{}***{}", local.chars().next().unwrap_or('*'), domain)
        } else {
            let first = local.chars().next().unwrap_or('*');
            let last = local.chars().last().unwrap_or('*');
            format!("{}***{}{}", first, last, domain)
        }
    } else {
        "***".to_string()
    }
}

pub async fn authorize_accounts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuthorizeQuery>,
) -> Response {
    let request_uri = match query.request_uri {
        Some(uri) => uri,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "Missing request_uri parameter"
                })),
            )
                .into_response();
        }
    };
    let device_id = match extract_device_cookie(&headers) {
        Some(id) => id,
        None => {
            return Json(AccountsResponse {
                accounts: vec![],
                request_uri,
            })
            .into_response();
        }
    };
    let accounts = match state.oauth_repo.get_device_accounts(&device_id).await {
        Ok(accts) => accts,
        Err(_) => {
            return Json(AccountsResponse {
                accounts: vec![],
                request_uri,
            })
            .into_response();
        }
    };
    let account_infos: Vec<AccountInfo> = accounts
        .into_iter()
        .map(|row| AccountInfo {
            did: row.did.to_string(),
            handle: row.handle,
            email: row.email.map(|e| mask_email(&e)),
        })
        .collect();
    Json(AccountsResponse {
        accounts: account_infos,
        request_uri,
    })
    .into_response()
}

pub async fn authorize_post(
    State(state): State<AppState>,
    _rate_limit: OAuthRateLimited<OAuthAuthorizeLimit>,
    headers: HeaderMap,
    Json(form): Json<AuthorizeSubmit>,
) -> Response {
    let json_response = wants_json(&headers);
    let form_request_id = RequestId::from(form.request_uri.clone());
    let request_data = match state
        .oauth_repo
        .get_authorization_request(&form_request_id)
        .await
    {
        Ok(Some(data)) => data,
        Ok(None) => {
            if json_response {
                return (
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_request",
                        "error_description": "Invalid or expired request_uri."
                    })),
                )
                    .into_response();
            }
            return redirect_to_frontend_error(
                "invalid_request",
                "Invalid or expired request_uri. Please start a new authorization request.",
            );
        }
        Err(e) => {
            if json_response {
                return (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "server_error",
                        "error_description": format!("Database error: {:?}", e)
                    })),
                )
                    .into_response();
            }
            return redirect_to_frontend_error("server_error", &format!("Database error: {:?}", e));
        }
    };
    if request_data.expires_at < Utc::now() {
        let _ = state
            .oauth_repo
            .delete_authorization_request(&form_request_id)
            .await;
        if json_response {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "Authorization request has expired."
                })),
            )
                .into_response();
        }
        return redirect_to_frontend_error(
            "invalid_request",
            "Authorization request has expired. Please start a new request.",
        );
    }
    let show_login_error = |error_msg: &str, json: bool| -> Response {
        if json {
            return (
                axum::http::StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "access_denied",
                    "error_description": error_msg
                })),
            )
                .into_response();
        }
        redirect_see_other(&format!(
            "/app/oauth/login?request_uri={}&error={}",
            url_encode(&form.request_uri),
            url_encode(error_msg)
        ))
    };
    let hostname_for_handles = tranquil_config::get().server.hostname_without_port();
    let normalized_username =
        NormalizedLoginIdentifier::normalize(&form.username, hostname_for_handles);
    tracing::debug!(
        original_username = %form.username,
        normalized_username = %normalized_username,
        pds_hostname = %tranquil_config::get().server.hostname,
        "Normalized username for lookup"
    );
    let user = match state
        .user_repo
        .get_login_info_by_handle_or_email(normalized_username.as_str())
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            let _ = bcrypt::verify(
                &form.password,
                "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.VTtYw1ZzQKZqmK",
            );
            return show_login_error("Invalid handle/email or password.", json_response);
        }
        Err(_) => return show_login_error("An error occurred. Please try again.", json_response),
    };
    if user.deactivated_at.is_some() {
        return show_login_error("This account has been deactivated.", json_response);
    }
    if user.takedown_ref.is_some() {
        return show_login_error("This account has been taken down.", json_response);
    }
    if user.account_type.is_delegated() {
        if state
            .oauth_repo
            .set_authorization_did(&form_request_id, &user.did, None)
            .await
            .is_err()
        {
            return show_login_error("An error occurred. Please try again.", json_response);
        }
        let redirect_url = format!(
            "/app/oauth/delegation?request_uri={}&delegated_did={}",
            url_encode(&form.request_uri),
            url_encode(&user.did)
        );
        if json_response {
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "next": "delegation",
                    "delegated_did": user.did,
                    "redirect": redirect_url
                })),
            )
                .into_response();
        }
        return redirect_see_other(&redirect_url);
    }

    if !user.password_required {
        if state
            .oauth_repo
            .set_authorization_did(&form_request_id, &user.did, None)
            .await
            .is_err()
        {
            return show_login_error("An error occurred. Please try again.", json_response);
        }
        let redirect_url = format!(
            "/app/oauth/passkey?request_uri={}",
            url_encode(&form.request_uri)
        );
        if json_response {
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "next": "passkey",
                    "redirect": redirect_url
                })),
            )
                .into_response();
        }
        return redirect_see_other(&redirect_url);
    }

    let password_valid = match &user.password_hash {
        Some(hash) => match bcrypt::verify(&form.password, hash) {
            Ok(valid) => valid,
            Err(_) => {
                return show_login_error("An error occurred. Please try again.", json_response);
            }
        },
        None => false,
    };
    if !password_valid {
        return show_login_error("Invalid handle/email or password.", json_response);
    }
    let is_verified = user.channel_verification.has_any_verified();
    if !is_verified {
        let resend_info = crate::api::server::auto_resend_verification(&state, &user.did).await;
        let handle = resend_info
            .as_ref()
            .map(|r| r.handle.to_string())
            .unwrap_or_else(|| form.username.clone());
        let channel = resend_info
            .map(|r| r.channel.as_str().to_owned())
            .unwrap_or_else(|| user.preferred_comms_channel.as_str().to_owned());
        if json_response {
            return (
                axum::http::StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "account_not_verified",
                    "error_description": "Please verify your account before logging in.",
                    "did": user.did,
                    "handle": handle,
                    "channel": channel
                })),
            )
                .into_response();
        }
        return redirect_see_other(&format!(
            "/app/oauth/login?request_uri={}&error={}",
            url_encode(&form.request_uri),
            url_encode("account_not_verified")
        ));
    }
    let has_totp = crate::api::server::has_totp_enabled(&state, &user.did).await;
    if has_totp {
        let device_cookie = extract_device_cookie(&headers);
        let device_is_trusted = if let Some(ref dev_id) = device_cookie {
            crate::api::server::is_device_trusted(state.oauth_repo.as_ref(), dev_id, &user.did)
                .await
        } else {
            false
        };

        if device_is_trusted {
            if let Some(ref dev_id) = device_cookie {
                let _ = crate::api::server::extend_device_trust(state.oauth_repo.as_ref(), dev_id)
                    .await;
            }
        } else {
            if state
                .oauth_repo
                .set_authorization_did(&form_request_id, &user.did, None)
                .await
                .is_err()
            {
                return show_login_error("An error occurred. Please try again.", json_response);
            }
            if json_response {
                return Json(serde_json::json!({
                    "needs_totp": true
                }))
                .into_response();
            }
            return redirect_see_other(&format!(
                "/app/oauth/totp?request_uri={}",
                url_encode(&form.request_uri)
            ));
        }
    }
    if user.two_factor_enabled {
        let _ = state
            .oauth_repo
            .delete_2fa_challenge_by_request_uri(&form_request_id)
            .await;
        match state
            .oauth_repo
            .create_2fa_challenge(&user.did, &form_request_id)
            .await
        {
            Ok(challenge) => {
                let hostname = &tranquil_config::get().server.hostname;
                if let Err(e) = enqueue_2fa_code(
                    state.user_repo.as_ref(),
                    state.infra_repo.as_ref(),
                    user.id,
                    &challenge.code,
                    hostname,
                )
                .await
                {
                    tracing::warn!(
                        did = %user.did,
                        error = %e,
                        "Failed to enqueue 2FA notification"
                    );
                }
                let channel_name = user.preferred_comms_channel.display_name();
                if json_response {
                    return Json(serde_json::json!({
                        "needs_2fa": true,
                        "channel": channel_name
                    }))
                    .into_response();
                }
                return redirect_see_other(&format!(
                    "/app/oauth/2fa?request_uri={}&channel={}",
                    url_encode(&form.request_uri),
                    url_encode(channel_name)
                ));
            }
            Err(_) => {
                return show_login_error("An error occurred. Please try again.", json_response);
            }
        }
    }
    let mut device_id: Option<DeviceIdType> = extract_device_cookie(&headers);
    let mut new_cookie: Option<String> = None;
    if form.remember_device {
        let final_device_id = if let Some(existing_id) = &device_id {
            existing_id.clone()
        } else {
            let new_id = DeviceId::generate();
            let new_device_id_typed = DeviceIdType::new(new_id.0.clone());
            let device_data = DeviceData {
                session_id: SessionId::generate(),
                user_agent: extract_user_agent(&headers),
                ip_address: extract_client_ip(&headers, None),
                last_seen_at: Utc::now(),
            };
            if state
                .oauth_repo
                .create_device(&new_device_id_typed, &device_data)
                .await
                .is_ok()
            {
                new_cookie = Some(make_device_cookie(&new_device_id_typed));
                device_id = Some(new_device_id_typed.clone());
            }
            new_device_id_typed
        };
        let _ = state
            .oauth_repo
            .upsert_account_device(&user.did, &final_device_id)
            .await;
    }
    let set_auth_device_id = device_id.clone();
    if state
        .oauth_repo
        .set_authorization_did(&form_request_id, &user.did, set_auth_device_id.as_ref())
        .await
        .is_err()
    {
        return show_login_error("An error occurred. Please try again.", json_response);
    }
    let requested_scope_str = request_data
        .parameters
        .scope
        .as_deref()
        .unwrap_or("atproto");
    let requested_scopes: Vec<String> = requested_scope_str
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    let client_id_typed = ClientId::from(request_data.parameters.client_id.clone());
    let needs_consent = should_show_consent(
        state.oauth_repo.as_ref(),
        &user.did,
        &client_id_typed,
        &requested_scopes,
    )
    .await
    .unwrap_or(true);
    if needs_consent {
        let consent_url = format!(
            "/app/oauth/consent?request_uri={}",
            url_encode(&form.request_uri)
        );
        if json_response {
            if let Some(cookie) = new_cookie {
                return (
                    StatusCode::OK,
                    [(SET_COOKIE, cookie)],
                    Json(serde_json::json!({"redirect_uri": consent_url})),
                )
                    .into_response();
            }
            return Json(serde_json::json!({"redirect_uri": consent_url})).into_response();
        }
        if let Some(cookie) = new_cookie {
            return (
                StatusCode::SEE_OTHER,
                [(SET_COOKIE, cookie), (LOCATION, consent_url)],
            )
                .into_response();
        }
        return redirect_see_other(&consent_url);
    }
    let code = Code::generate();
    let auth_post_device_id = device_id.clone();
    let auth_post_code = AuthorizationCode::from(code.0.clone());
    if state
        .oauth_repo
        .update_authorization_request(
            &form_request_id,
            &user.did,
            auth_post_device_id.as_ref(),
            &auth_post_code,
        )
        .await
        .is_err()
    {
        return show_login_error("An error occurred. Please try again.", json_response);
    }
    if json_response {
        let redirect_url = build_intermediate_redirect_url(
            &request_data.parameters.redirect_uri,
            &code.0,
            request_data.parameters.state.as_deref(),
            request_data.parameters.response_mode.map(|m| m.as_str()),
        );
        if let Some(cookie) = new_cookie {
            (
                StatusCode::OK,
                [(SET_COOKIE, cookie)],
                Json(serde_json::json!({"redirect_uri": redirect_url})),
            )
                .into_response()
        } else {
            Json(serde_json::json!({"redirect_uri": redirect_url})).into_response()
        }
    } else {
        let redirect_url = build_success_redirect(
            &request_data.parameters.redirect_uri,
            &code.0,
            request_data.parameters.state.as_deref(),
            request_data.parameters.response_mode.map(|m| m.as_str()),
        );
        if let Some(cookie) = new_cookie {
            (
                StatusCode::SEE_OTHER,
                [(SET_COOKIE, cookie), (LOCATION, redirect_url)],
            )
                .into_response()
        } else {
            redirect_see_other(&redirect_url)
        }
    }
}

pub async fn authorize_select(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(form): Json<AuthorizeSelectSubmit>,
) -> Response {
    let json_error = |status: StatusCode, error: &str, description: &str| -> Response {
        (
            status,
            Json(serde_json::json!({
                "error": error,
                "error_description": description
            })),
        )
            .into_response()
    };
    let select_request_id = RequestId::from(form.request_uri.clone());
    let request_data = match state
        .oauth_repo
        .get_authorization_request(&select_request_id)
        .await
    {
        Ok(Some(data)) => data,
        Ok(None) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid or expired request_uri. Please start a new authorization request.",
            );
        }
        Err(_) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "An error occurred. Please try again.",
            );
        }
    };
    if request_data.expires_at < Utc::now() {
        let _ = state
            .oauth_repo
            .delete_authorization_request(&select_request_id)
            .await;
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Authorization request has expired. Please start a new request.",
        );
    }
    let device_id = match extract_device_cookie(&headers) {
        Some(id) => id,
        None => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "No device session found. Please sign in.",
            );
        }
    };
    let did: Did = match form.did.parse() {
        Ok(d) => d,
        Err(_) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid DID format.",
            );
        }
    };
    let verify_device_id = device_id.clone();
    let account_valid = match state
        .oauth_repo
        .verify_account_on_device(&verify_device_id, &did)
        .await
    {
        Ok(valid) => valid,
        Err(_) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "An error occurred. Please try again.",
            );
        }
    };
    if !account_valid {
        return json_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "This account is not available on this device. Please sign in.",
        );
    }
    let user = match state.user_repo.get_2fa_status_by_did(&did).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return json_error(
                StatusCode::FORBIDDEN,
                "access_denied",
                "Account not found. Please sign in.",
            );
        }
        Err(_) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "An error occurred. Please try again.",
            );
        }
    };
    let is_verified = user.channel_verification.has_any_verified();
    if !is_verified {
        let resend_info = crate::api::server::auto_resend_verification(&state, &did).await;
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "account_not_verified",
                "error_description": "Please verify your account before logging in.",
                "did": did,
                "handle": resend_info.as_ref().map(|r| r.handle.to_string()),
                "channel": resend_info.as_ref().map(|r| r.channel.as_str())
            })),
        )
            .into_response();
    }
    let has_totp = crate::api::server::has_totp_enabled(&state, &did).await;
    let select_early_device_typed = device_id.clone();
    if has_totp {
        let device_is_trusted =
            crate::api::server::is_device_trusted(state.oauth_repo.as_ref(), &device_id, &did)
                .await;
        if !device_is_trusted {
            if state
                .oauth_repo
                .set_authorization_did(&select_request_id, &did, Some(&select_early_device_typed))
                .await
                .is_err()
            {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "An error occurred. Please try again.",
                );
            }
            return Json(serde_json::json!({
                "needs_totp": true
            }))
            .into_response();
        }
        let _ =
            crate::api::server::extend_device_trust(state.oauth_repo.as_ref(), &device_id).await;
    }
    if user.two_factor_enabled {
        let _ = state
            .oauth_repo
            .delete_2fa_challenge_by_request_uri(&select_request_id)
            .await;
        match state
            .oauth_repo
            .create_2fa_challenge(&did, &select_request_id)
            .await
        {
            Ok(challenge) => {
                let hostname = &tranquil_config::get().server.hostname;
                if let Err(e) = enqueue_2fa_code(
                    state.user_repo.as_ref(),
                    state.infra_repo.as_ref(),
                    user.id,
                    &challenge.code,
                    hostname,
                )
                .await
                {
                    tracing::warn!(
                        did = %form.did,
                        error = %e,
                        "Failed to enqueue 2FA notification"
                    );
                }
                let channel_name = user.preferred_comms_channel.display_name();
                return Json(serde_json::json!({
                    "needs_2fa": true,
                    "channel": channel_name
                }))
                .into_response();
            }
            Err(_) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "An error occurred. Please try again.",
                );
            }
        }
    }
    let select_device_typed = device_id.clone();
    let _ = state
        .oauth_repo
        .upsert_account_device(&did, &select_device_typed)
        .await;

    if state
        .oauth_repo
        .set_authorization_did(&select_request_id, &did, Some(&select_device_typed))
        .await
        .is_err()
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "An error occurred. Please try again.",
        );
    }
    let consent_url = format!(
        "/app/oauth/consent?request_uri={}",
        url_encode(&form.request_uri)
    );
    Json(serde_json::json!({"redirect_uri": consent_url})).into_response()
}

fn build_success_redirect(
    redirect_uri: &str,
    code: &str,
    state: Option<&str>,
    response_mode: Option<&str>,
) -> String {
    let mut redirect_url = redirect_uri.to_string();
    let use_fragment = response_mode == Some("fragment");
    let separator = if use_fragment {
        '#'
    } else if redirect_url.contains('?') {
        '&'
    } else {
        '?'
    };
    redirect_url.push(separator);
    let pds_host = &tranquil_config::get().server.hostname;
    redirect_url.push_str(&format!(
        "iss={}",
        url_encode(&format!("https://{}", pds_host))
    ));
    if let Some(req_state) = state {
        redirect_url.push_str(&format!("&state={}", url_encode(req_state)));
    }
    redirect_url.push_str(&format!("&code={}", url_encode(code)));
    redirect_url
}

fn build_intermediate_redirect_url(
    redirect_uri: &str,
    code: &str,
    state: Option<&str>,
    response_mode: Option<&str>,
) -> String {
    let pds_host = &tranquil_config::get().server.hostname;
    let mut url = format!(
        "https://{}/oauth/authorize/redirect?redirect_uri={}&code={}",
        pds_host,
        url_encode(redirect_uri),
        url_encode(code)
    );
    if let Some(s) = state {
        url.push_str(&format!("&state={}", url_encode(s)));
    }
    if let Some(rm) = response_mode {
        url.push_str(&format!("&response_mode={}", url_encode(rm)));
    }
    url
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeRedirectParams {
    redirect_uri: String,
    code: String,
    state: Option<String>,
    response_mode: Option<String>,
}

pub async fn authorize_redirect(Query(params): Query<AuthorizeRedirectParams>) -> Response {
    let final_url = build_success_redirect(
        &params.redirect_uri,
        &params.code,
        params.state.as_deref(),
        params.response_mode.as_deref(),
    );
    tracing::info!(
        final_url = %final_url,
        client_redirect = %params.redirect_uri,
        "authorize_redirect performing 303 redirect"
    );
    (
        StatusCode::SEE_OTHER,
        [
            (axum::http::header::LOCATION, final_url),
            (axum::http::header::CACHE_CONTROL, "no-store".to_string()),
        ],
    )
        .into_response()
}

#[derive(Debug, Serialize)]
pub struct AuthorizeDenyResponse {
    pub error: String,
    pub error_description: String,
}

pub async fn authorize_deny(
    State(state): State<AppState>,
    Json(form): Json<AuthorizeDenyForm>,
) -> Response {
    let deny_request_id = RequestId::from(form.request_uri.clone());
    let request_data = match state
        .oauth_repo
        .get_authorization_request(&deny_request_id)
        .await
    {
        Ok(Some(data)) => data,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "Invalid request_uri"
                })),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "An error occurred"
                })),
            )
                .into_response();
        }
    };
    let _ = state
        .oauth_repo
        .delete_authorization_request(&deny_request_id)
        .await;
    let redirect_uri = &request_data.parameters.redirect_uri;
    let mut redirect_url = redirect_uri.to_string();
    let separator = if redirect_url.contains('?') { '&' } else { '?' };
    redirect_url.push(separator);
    redirect_url.push_str("error=access_denied");
    redirect_url.push_str("&error_description=User%20denied%20the%20request");
    if let Some(state) = &request_data.parameters.state {
        redirect_url.push_str(&format!("&state={}", url_encode(state)));
    }
    Json(serde_json::json!({
        "redirect_uri": redirect_url
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeDenyForm {
    pub request_uri: String,
}

#[derive(Debug, Deserialize)]
pub struct Authorize2faQuery {
    pub request_uri: String,
    pub channel: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Authorize2faSubmit {
    pub request_uri: String,
    pub code: String,
    #[serde(default)]
    pub trust_device: bool,
}

const MAX_2FA_ATTEMPTS: i32 = 5;

pub async fn authorize_2fa_get(
    State(state): State<AppState>,
    Query(query): Query<Authorize2faQuery>,
) -> Response {
    let twofa_request_id = RequestId::from(query.request_uri.clone());
    let challenge = match state.oauth_repo.get_2fa_challenge(&twofa_request_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return redirect_to_frontend_error(
                "invalid_request",
                "No 2FA challenge found. Please start over.",
            );
        }
        Err(_) => {
            return redirect_to_frontend_error(
                "server_error",
                "An error occurred. Please try again.",
            );
        }
    };
    if challenge.expires_at < Utc::now() {
        let _ = state.oauth_repo.delete_2fa_challenge(challenge.id).await;
        return redirect_to_frontend_error(
            "invalid_request",
            "2FA code has expired. Please start over.",
        );
    }
    let _request_data = match state
        .oauth_repo
        .get_authorization_request(&twofa_request_id)
        .await
    {
        Ok(Some(d)) => d,
        Ok(None) => {
            return redirect_to_frontend_error(
                "invalid_request",
                "Authorization request not found. Please start over.",
            );
        }
        Err(_) => {
            return redirect_to_frontend_error(
                "server_error",
                "An error occurred. Please try again.",
            );
        }
    };
    let channel = query.channel.as_deref().unwrap_or("email");
    redirect_see_other(&format!(
        "/app/oauth/2fa?request_uri={}&channel={}",
        url_encode(&query.request_uri),
        url_encode(channel)
    ))
}

#[derive(Debug, Serialize)]
pub struct ScopeInfo {
    pub scope: String,
    pub category: String,
    pub required: bool,
    pub description: String,
    pub display_name: String,
    pub granted: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ConsentResponse {
    pub request_uri: String,
    pub client_id: String,
    pub client_name: Option<String>,
    pub client_uri: Option<String>,
    pub logo_uri: Option<String>,
    pub scopes: Vec<ScopeInfo>,
    pub show_consent: bool,
    pub did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_delegation: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller_handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_level: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ConsentQuery {
    pub request_uri: String,
}

#[derive(Debug, Deserialize)]
pub struct ConsentSubmit {
    pub request_uri: String,
    pub approved_scopes: Vec<String>,
    pub remember: bool,
}

pub async fn consent_get(
    State(state): State<AppState>,
    Query(query): Query<ConsentQuery>,
) -> Response {
    let consent_request_id = RequestId::from(query.request_uri.clone());
    let request_data = match state
        .oauth_repo
        .get_authorization_request(&consent_request_id)
        .await
    {
        Ok(Some(data)) => data,
        Ok(None) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid or expired request_uri",
            );
        }
        Err(e) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &format!("Database error: {:?}", e),
            );
        }
    };
    let flow_with_user = match AuthFlow::from_request_data(request_data.clone()) {
        Ok(flow) => match flow.require_user() {
            Ok(u) => u,
            Err(_) => {
                return json_error(StatusCode::FORBIDDEN, "access_denied", "Not authenticated");
            }
        },
        Err(_) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "expired_request",
                "Authorization request has expired",
            );
        }
    };

    let did = flow_with_user.did().clone();
    let client_cache = ClientMetadataCache::new(3600);
    let client_metadata = client_cache
        .get(&request_data.parameters.client_id)
        .await
        .ok();
    let requested_scope_str = request_data
        .parameters
        .scope
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("atproto");

    let controller_did_parsed: Option<Did> = request_data
        .controller_did
        .as_ref()
        .and_then(|s| s.parse().ok());
    let delegation_grant = if let Some(ref ctrl_did) = controller_did_parsed {
        state
            .delegation_repo
            .get_delegation(&did, ctrl_did)
            .await
            .ok()
            .flatten()
    } else {
        None
    };

    let effective_scope_str = if let Some(ref grant) = delegation_grant {
        crate::delegation::intersect_scopes(requested_scope_str, grant.granted_scopes.as_str())
    } else {
        requested_scope_str.to_string()
    };

    let expanded_scope_str = expand_include_scopes(&effective_scope_str).await;
    let requested_scopes: Vec<&str> = expanded_scope_str.split_whitespace().collect();
    let consent_client_id = ClientId::from(request_data.parameters.client_id.clone());
    let preferences = state
        .oauth_repo
        .get_scope_preferences(&did, &consent_client_id)
        .await
        .unwrap_or_default();
    let pref_map: std::collections::HashMap<_, _> = preferences
        .iter()
        .map(|p| (p.scope.as_str(), p.granted))
        .collect();
    let requested_scope_strings: Vec<String> =
        requested_scopes.iter().map(|s| s.to_string()).collect();
    let show_consent = should_show_consent(
        state.oauth_repo.as_ref(),
        &did,
        &consent_client_id,
        &requested_scope_strings,
    )
    .await
    .unwrap_or(true);
    let has_granular_scopes = requested_scopes.iter().any(|s| is_granular_scope(s));
    let scopes: Vec<ScopeInfo> = requested_scopes
        .iter()
        .map(|scope| {
            let (category, required, description, display_name) = if let Some(def) =
                crate::oauth::scopes::SCOPE_DEFINITIONS.get(*scope)
            {
                let desc = if *scope == "atproto" && has_granular_scopes {
                    "AT Protocol baseline scope (permissions determined by selected options below)"
                        .to_string()
                } else {
                    def.description.to_string()
                };
                let name = if *scope == "atproto" && has_granular_scopes {
                    "AT Protocol Access".to_string()
                } else {
                    def.display_name.to_string()
                };
                (
                    def.category.display_name().to_string(),
                    def.required,
                    desc,
                    name,
                )
            } else if scope.starts_with("ref:") {
                (
                    "Reference".to_string(),
                    false,
                    "Referenced scope".to_string(),
                    scope.to_string(),
                )
            } else {
                (
                    "Other".to_string(),
                    false,
                    format!("Access to {}", scope),
                    scope.to_string(),
                )
            };
            let granted = pref_map.get(*scope).copied();
            ScopeInfo {
                scope: scope.to_string(),
                category,
                required,
                description,
                display_name,
                granted,
            }
        })
        .collect();

    let account_handle = state
        .user_repo
        .get_handle_by_did(&did)
        .await
        .ok()
        .flatten()
        .map(|h| h.to_string());

    let (is_delegation, controller_did_resp, controller_handle, delegation_level) =
        if let Some(ref ctrl_did) = controller_did_parsed {
            let ctrl_handle = state
                .user_repo
                .get_handle_by_did(ctrl_did)
                .await
                .ok()
                .flatten()
                .map(|h| h.to_string());

            let level = if let Some(ref grant) = delegation_grant {
                let preset = crate::delegation::SCOPE_PRESETS
                    .iter()
                    .find(|p| p.scopes == grant.granted_scopes.as_str());
                preset
                    .map(|p| p.label.to_string())
                    .unwrap_or_else(|| "Custom".to_string())
            } else {
                "Unknown".to_string()
            };

            (
                Some(true),
                Some(ctrl_did.to_string()),
                ctrl_handle,
                Some(level),
            )
        } else {
            (None, None, None, None)
        };

    Json(ConsentResponse {
        request_uri: query.request_uri.clone(),
        client_id: request_data.parameters.client_id.clone(),
        client_name: client_metadata.as_ref().and_then(|m| m.client_name.clone()),
        client_uri: client_metadata.as_ref().and_then(|m| m.client_uri.clone()),
        logo_uri: client_metadata.as_ref().and_then(|m| m.logo_uri.clone()),
        scopes,
        show_consent,
        did: did.to_string(),
        handle: account_handle,
        is_delegation,
        controller_did: controller_did_resp,
        controller_handle,
        delegation_level,
    })
    .into_response()
}

pub async fn consent_post(
    State(state): State<AppState>,
    Json(form): Json<ConsentSubmit>,
) -> Response {
    tracing::info!(
        "consent_post: approved_scopes={:?}, remember={}",
        form.approved_scopes,
        form.remember
    );
    let consent_post_request_id = RequestId::from(form.request_uri.clone());
    let request_data = match state
        .oauth_repo
        .get_authorization_request(&consent_post_request_id)
        .await
    {
        Ok(Some(data)) => data,
        Ok(None) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid or expired request_uri",
            );
        }
        Err(e) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &format!("Database error: {:?}", e),
            );
        }
    };
    let flow_with_user = match AuthFlow::from_request_data(request_data.clone()) {
        Ok(flow) => match flow.require_user() {
            Ok(u) => u,
            Err(_) => {
                return json_error(StatusCode::FORBIDDEN, "access_denied", "Not authenticated");
            }
        },
        Err(_) => {
            let _ = state
                .oauth_repo
                .delete_authorization_request(&consent_post_request_id)
                .await;
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Authorization request has expired",
            );
        }
    };

    let did = flow_with_user.did().clone();
    let original_scope_str = request_data
        .parameters
        .scope
        .as_deref()
        .unwrap_or("atproto");

    let controller_did_parsed: Option<Did> = request_data
        .controller_did
        .as_ref()
        .and_then(|s| s.parse().ok());

    let delegation_grant = match controller_did_parsed.as_ref() {
        Some(ctrl_did) => state
            .delegation_repo
            .get_delegation(&did, ctrl_did)
            .await
            .ok()
            .flatten(),
        None => None,
    };

    let effective_scope_str = if let Some(ref grant) = delegation_grant {
        crate::delegation::intersect_scopes(original_scope_str, grant.granted_scopes.as_str())
    } else {
        original_scope_str.to_string()
    };

    let requested_scopes: Vec<&str> = effective_scope_str.split_whitespace().collect();
    let has_granular_scopes = requested_scopes.iter().any(|s| is_granular_scope(s));
    let user_denied_some_granular = has_granular_scopes
        && requested_scopes
            .iter()
            .filter(|s| is_granular_scope(s))
            .any(|s| !form.approved_scopes.contains(&s.to_string()));
    let atproto_was_requested = requested_scopes.contains(&"atproto");
    if atproto_was_requested
        && !has_granular_scopes
        && !form.approved_scopes.contains(&"atproto".to_string())
    {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The atproto scope was requested and must be approved",
        );
    }
    let final_approved: Vec<String> = if user_denied_some_granular {
        form.approved_scopes
            .iter()
            .filter(|s| *s != "atproto")
            .cloned()
            .collect()
    } else {
        form.approved_scopes.clone()
    };
    if final_approved.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "At least one scope must be approved",
        );
    }
    let approved_scope_str = final_approved.join(" ");
    let has_valid_scope = final_approved.iter().all(|s| is_valid_scope(s));
    if !has_valid_scope {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid scope format",
        );
    }
    if form.remember {
        let preferences: Vec<ScopePreference> = requested_scopes
            .iter()
            .map(|s| ScopePreference {
                scope: s.to_string(),
                granted: form.approved_scopes.contains(&s.to_string()),
            })
            .collect();
        let consent_post_client_id = ClientId::from(request_data.parameters.client_id.clone());
        let _ = state
            .oauth_repo
            .upsert_scope_preferences(&did, &consent_post_client_id, &preferences)
            .await;
    }
    if let Err(e) = state
        .oauth_repo
        .update_request_scope(&consent_post_request_id, &approved_scope_str)
        .await
    {
        tracing::warn!("Failed to update request scope: {:?}", e);
    }
    let code = Code::generate();
    let consent_post_device_id = request_data
        .device_id
        .as_ref()
        .map(|d| DeviceIdType::new(d.0.clone()));
    let consent_post_code = AuthorizationCode::from(code.0.clone());
    if state
        .oauth_repo
        .update_authorization_request(
            &consent_post_request_id,
            &did,
            consent_post_device_id.as_ref(),
            &consent_post_code,
        )
        .await
        .is_err()
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Failed to complete authorization",
        );
    }
    let redirect_uri = &request_data.parameters.redirect_uri;
    let intermediate_url = build_intermediate_redirect_url(
        redirect_uri,
        &code.0,
        request_data.parameters.state.as_deref(),
        request_data.parameters.response_mode.map(|m| m.as_str()),
    );
    tracing::info!(
        intermediate_url = %intermediate_url,
        client_redirect = %redirect_uri,
        "consent_post returning JSON with intermediate URL (for 303 redirect)"
    );
    Json(serde_json::json!({ "redirect_uri": intermediate_url })).into_response()
}

#[derive(Debug, Deserialize)]
pub struct RenewRequest {
    pub request_uri: String,
}

pub async fn authorize_renew(
    State(state): State<AppState>,
    _rate_limit: OAuthRateLimited<OAuthAuthorizeLimit>,
    Json(form): Json<RenewRequest>,
) -> Response {
    let request_id = RequestId::from(form.request_uri.clone());
    let request_data = match state
        .oauth_repo
        .get_authorization_request(&request_id)
        .await
    {
        Ok(Some(data)) => data,
        Ok(None) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Unknown authorization request",
            );
        }
        Err(_) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Database error",
            );
        }
    };

    if request_data.did.is_none() {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Authorization request not yet authenticated",
        );
    }

    let now = Utc::now();
    if request_data.expires_at >= now {
        return Json(serde_json::json!({
            "request_uri": form.request_uri,
            "renewed": false
        }))
        .into_response();
    }

    let staleness = now - request_data.expires_at;
    if staleness.num_seconds() > MAX_RENEWAL_STALENESS_SECONDS {
        let _ = state
            .oauth_repo
            .delete_authorization_request(&request_id)
            .await;
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Authorization request expired too long ago to renew",
        );
    }

    let new_expires_at = now + chrono::Duration::seconds(RENEW_EXPIRY_SECONDS);
    match state
        .oauth_repo
        .extend_authorization_request_expiry(&request_id, new_expires_at)
        .await
    {
        Ok(true) => Json(serde_json::json!({
            "request_uri": form.request_uri,
            "renewed": true
        }))
        .into_response(),
        Ok(false) => json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Authorization request could not be renewed",
        ),
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Database error",
        ),
    }
}

pub async fn authorize_2fa_post(
    State(state): State<AppState>,
    _rate_limit: OAuthRateLimited<OAuthAuthorizeLimit>,
    headers: HeaderMap,
    Json(form): Json<Authorize2faSubmit>,
) -> Response {
    let json_error = |status: StatusCode, error: &str, description: &str| -> Response {
        (
            status,
            Json(serde_json::json!({
                "error": error,
                "error_description": description
            })),
        )
            .into_response()
    };
    let twofa_post_request_id = RequestId::from(form.request_uri.clone());
    let request_data = match state
        .oauth_repo
        .get_authorization_request(&twofa_post_request_id)
        .await
    {
        Ok(Some(d)) => d,
        Ok(None) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Authorization request not found.",
            );
        }
        Err(_) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "An error occurred.",
            );
        }
    };
    if request_data.expires_at < Utc::now() {
        let _ = state
            .oauth_repo
            .delete_authorization_request(&twofa_post_request_id)
            .await;
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Authorization request has expired.",
        );
    }
    let challenge = state
        .oauth_repo
        .get_2fa_challenge(&twofa_post_request_id)
        .await
        .ok()
        .flatten();
    if let Some(challenge) = challenge {
        if challenge.expires_at < Utc::now() {
            let _ = state.oauth_repo.delete_2fa_challenge(challenge.id).await;
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "2FA code has expired. Please start over.",
            );
        }
        if challenge.attempts >= MAX_2FA_ATTEMPTS {
            let _ = state.oauth_repo.delete_2fa_challenge(challenge.id).await;
            return json_error(
                StatusCode::FORBIDDEN,
                "access_denied",
                "Too many failed attempts. Please start over.",
            );
        }
        let code_valid: bool = form
            .code
            .trim()
            .as_bytes()
            .ct_eq(challenge.code.as_bytes())
            .into();
        if !code_valid {
            let _ = state.oauth_repo.increment_2fa_attempts(challenge.id).await;
            return json_error(
                StatusCode::FORBIDDEN,
                "invalid_code",
                "Invalid verification code. Please try again.",
            );
        }
        let _ = state.oauth_repo.delete_2fa_challenge(challenge.id).await;
        let code = Code::generate();
        let device_id = extract_device_cookie(&headers);
        let twofa_totp_device_id = device_id.clone();
        let twofa_totp_code = AuthorizationCode::from(code.0.clone());
        if state
            .oauth_repo
            .update_authorization_request(
                &twofa_post_request_id,
                &challenge.did,
                twofa_totp_device_id.as_ref(),
                &twofa_totp_code,
            )
            .await
            .is_err()
        {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "An error occurred. Please try again.",
            );
        }
        let redirect_url = build_intermediate_redirect_url(
            &request_data.parameters.redirect_uri,
            &code.0,
            request_data.parameters.state.as_deref(),
            request_data.parameters.response_mode.map(|m| m.as_str()),
        );
        return Json(serde_json::json!({
            "redirect_uri": redirect_url
        }))
        .into_response();
    }
    let did_str = match &request_data.did {
        Some(d) => d.clone(),
        None => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "No 2FA challenge found. Please start over.",
            );
        }
    };
    let did: tranquil_types::Did = match did_str.parse() {
        Ok(d) => d,
        Err(_) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid DID format.",
            );
        }
    };
    if !crate::api::server::has_totp_enabled(&state, &did).await {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "No 2FA challenge found. Please start over.",
        );
    }
    let _rate_proof = match check_user_rate_limit::<TotpVerifyLimit>(&state, &did).await {
        Ok(proof) => proof,
        Err(_) => {
            return json_error(
                StatusCode::TOO_MANY_REQUESTS,
                "RateLimitExceeded",
                "Too many verification attempts. Please try again in a few minutes.",
            );
        }
    };
    let totp_valid =
        crate::api::server::verify_totp_or_backup_for_user(&state, &did, &form.code).await;
    if !totp_valid {
        return json_error(
            StatusCode::FORBIDDEN,
            "invalid_code",
            "Invalid verification code. Please try again.",
        );
    }
    let mut device_id = extract_device_cookie(&headers);
    let mut new_cookie: Option<String> = None;
    if form.trust_device {
        let trust_device_id = match &device_id {
            Some(existing_id) => existing_id.clone(),
            None => {
                let new_id = DeviceId::generate();
                let new_device_id_typed = DeviceIdType::new(new_id.0.clone());
                let device_data = DeviceData {
                    session_id: SessionId::generate(),
                    user_agent: extract_user_agent(&headers),
                    ip_address: extract_client_ip(&headers, None),
                    last_seen_at: Utc::now(),
                };
                if state
                    .oauth_repo
                    .create_device(&new_device_id_typed, &device_data)
                    .await
                    .is_ok()
                {
                    new_cookie = Some(make_device_cookie(&new_device_id_typed));
                    device_id = Some(new_device_id_typed.clone());
                }
                new_device_id_typed
            }
        };
        let _ = state
            .oauth_repo
            .upsert_account_device(&did, &trust_device_id)
            .await;
        let _ = crate::api::server::trust_device(state.oauth_repo.as_ref(), &trust_device_id).await;
    }
    let requested_scope_str = request_data
        .parameters
        .scope
        .as_deref()
        .unwrap_or("atproto");
    let requested_scopes: Vec<String> = requested_scope_str
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    let twofa_post_client_id = ClientId::from(request_data.parameters.client_id.clone());
    let needs_consent = should_show_consent(
        state.oauth_repo.as_ref(),
        &did,
        &twofa_post_client_id,
        &requested_scopes,
    )
    .await
    .unwrap_or(true);
    if needs_consent {
        let consent_url = format!(
            "/app/oauth/consent?request_uri={}",
            url_encode(&form.request_uri)
        );
        if let Some(cookie) = new_cookie {
            return (
                StatusCode::OK,
                [(SET_COOKIE, cookie)],
                Json(serde_json::json!({"redirect_uri": consent_url})),
            )
                .into_response();
        }
        return Json(serde_json::json!({"redirect_uri": consent_url})).into_response();
    }
    let code = Code::generate();
    let twofa_final_device_id = device_id.clone();
    let twofa_final_code = AuthorizationCode::from(code.0.clone());
    if state
        .oauth_repo
        .update_authorization_request(
            &twofa_post_request_id,
            &did,
            twofa_final_device_id.as_ref(),
            &twofa_final_code,
        )
        .await
        .is_err()
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "An error occurred. Please try again.",
        );
    }
    let redirect_url = build_intermediate_redirect_url(
        &request_data.parameters.redirect_uri,
        &code.0,
        request_data.parameters.state.as_deref(),
        request_data.parameters.response_mode.map(|m| m.as_str()),
    );
    if let Some(cookie) = new_cookie {
        (
            StatusCode::OK,
            [(SET_COOKIE, cookie)],
            Json(serde_json::json!({"redirect_uri": redirect_url})),
        )
            .into_response()
    } else {
        Json(serde_json::json!({"redirect_uri": redirect_url})).into_response()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckPasskeysQuery {
    pub identifier: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckPasskeysResponse {
    pub has_passkeys: bool,
}

pub async fn check_user_has_passkeys(
    State(state): State<AppState>,
    Query(query): Query<CheckPasskeysQuery>,
) -> Response {
    let hostname_for_handles = tranquil_config::get().server.hostname_without_port();
    let bare_identifier =
        BareLoginIdentifier::from_identifier(&query.identifier, hostname_for_handles);

    let user = state
        .user_repo
        .get_login_check_by_handle_or_email(bare_identifier.as_str())
        .await;

    let has_passkeys = match user {
        Ok(Some(u)) => crate::api::server::has_passkeys_for_user(&state, &u.did).await,
        _ => false,
    };

    Json(CheckPasskeysResponse { has_passkeys }).into_response()
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityStatusResponse {
    pub has_passkeys: bool,
    pub has_totp: bool,
    pub has_password: bool,
    pub is_delegated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
}

pub async fn check_user_security_status(
    State(state): State<AppState>,
    Query(query): Query<CheckPasskeysQuery>,
) -> Response {
    let hostname_for_handles = tranquil_config::get().server.hostname_without_port();
    let normalized_identifier =
        NormalizedLoginIdentifier::normalize(&query.identifier, hostname_for_handles);

    let user = state
        .user_repo
        .get_login_check_by_handle_or_email(normalized_identifier.as_str())
        .await;

    let (has_passkeys, has_totp, has_password, is_delegated, did): (
        bool,
        bool,
        bool,
        bool,
        Option<String>,
    ) = match user {
        Ok(Some(u)) => {
            let passkeys = crate::api::server::has_passkeys_for_user(&state, &u.did).await;
            let totp = crate::api::server::has_totp_enabled(&state, &u.did).await;
            let has_pw = u.password_hash.is_some();
            let has_controllers = state
                .delegation_repo
                .is_delegated_account(&u.did)
                .await
                .unwrap_or(false);
            (
                passkeys,
                totp,
                has_pw,
                has_controllers,
                Some(u.did.to_string()),
            )
        }
        _ => (false, false, false, false, None),
    };

    Json(SecurityStatusResponse {
        has_passkeys,
        has_totp,
        has_password,
        is_delegated,
        did,
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
pub struct PasskeyStartInput {
    pub request_uri: String,
    pub identifier: String,
    pub delegated_did: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyStartResponse {
    pub options: serde_json::Value,
}

pub async fn passkey_start(
    State(state): State<AppState>,
    _rate_limit: OAuthRateLimited<OAuthAuthorizeLimit>,
    Json(form): Json<PasskeyStartInput>,
) -> Response {
    let passkey_start_request_id = RequestId::from(form.request_uri.clone());
    let request_data = match state
        .oauth_repo
        .get_authorization_request(&passkey_start_request_id)
        .await
    {
        Ok(Some(data)) => data,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "Invalid or expired request_uri."
                })),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "An error occurred."
                })),
            )
                .into_response();
        }
    };

    if request_data.expires_at < Utc::now() {
        let _ = state
            .oauth_repo
            .delete_authorization_request(&passkey_start_request_id)
            .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "Authorization request has expired."
            })),
        )
            .into_response();
    }

    let hostname_for_handles = tranquil_config::get().server.hostname_without_port();
    let normalized_username =
        NormalizedLoginIdentifier::normalize(&form.identifier, hostname_for_handles);

    let user = match state
        .user_repo
        .get_login_info_by_handle_or_email(normalized_username.as_str())
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "access_denied",
                    "error_description": "User not found or has no passkeys."
                })),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "An error occurred."
                })),
            )
                .into_response();
        }
    };

    if user.deactivated_at.is_some() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "access_denied",
                "error_description": "This account has been deactivated."
            })),
        )
            .into_response();
    }

    if user.takedown_ref.is_some() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "access_denied",
                "error_description": "This account has been taken down."
            })),
        )
            .into_response();
    }

    let is_verified = user.channel_verification.has_any_verified();

    if !is_verified {
        let resend_info = crate::api::server::auto_resend_verification(&state, &user.did).await;
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "account_not_verified",
                "error_description": "Please verify your account before logging in.",
                "did": user.did,
                "handle": resend_info.as_ref().map(|r| r.handle.to_string()),
                "channel": resend_info.as_ref().map(|r| r.channel.as_str())
            })),
        )
            .into_response();
    }

    let stored_passkeys = match state.user_repo.get_passkeys_for_user(&user.did).await {
        Ok(pks) => pks,
        Err(e) => {
            tracing::error!(error = %e, "Failed to get passkeys");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "An error occurred."
                })),
            )
                .into_response();
        }
    };

    if stored_passkeys.is_empty() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "access_denied",
                "error_description": "User not found or has no passkeys."
            })),
        )
            .into_response();
    }

    let passkeys: Vec<webauthn_rs::prelude::SecurityKey> = stored_passkeys
        .iter()
        .filter_map(|sp| serde_json::from_slice(&sp.public_key).ok())
        .collect();

    if passkeys.is_empty() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "server_error",
                "error_description": "Failed to load passkeys."
            })),
        )
            .into_response();
    }

    let (rcr, auth_state) = match state.webauthn_config.start_authentication(passkeys) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!(error = %e, "Failed to start passkey authentication");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "Failed to start authentication."
                })),
            )
                .into_response();
        }
    };

    let state_json = match serde_json::to_string(&auth_state) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!(error = %e, "Failed to serialize authentication state");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "An error occurred."
                })),
            )
                .into_response();
        }
    };

    if let Err(e) = state
        .user_repo
        .save_webauthn_challenge(
            &user.did,
            WebauthnChallengeType::Authentication,
            &state_json,
        )
        .await
    {
        tracing::error!(error = %e, "Failed to save authentication state");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "server_error",
                "error_description": "An error occurred."
            })),
        )
            .into_response();
    }

    let delegation_from_param = match &form.delegated_did {
        Some(delegated_did_str) => match delegated_did_str.parse::<tranquil_types::Did>() {
            Ok(delegated_did) if delegated_did != user.did => {
                match state
                    .delegation_repo
                    .get_delegation(&delegated_did, &user.did)
                    .await
                {
                    Ok(Some(_)) => Some(delegated_did),
                    Ok(None) => None,
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            delegated_did = %delegated_did,
                            controller_did = %user.did,
                            "Failed to verify delegation relationship"
                        );
                        None
                    }
                }
            }
            _ => None,
        },
        None => None,
    };

    let is_delegation_flow = delegation_from_param.is_some()
        || request_data.did.as_ref().is_some_and(|existing_did| {
            existing_did
                .parse::<tranquil_types::Did>()
                .ok()
                .is_some_and(|parsed| parsed != user.did)
        });

    if let Some(delegated_did) = delegation_from_param {
        tracing::info!(
            delegated_did = %delegated_did,
            controller_did = %user.did,
            "Passkey auth with delegated_did param - setting delegation flow"
        );
        if state
            .oauth_repo
            .set_authorization_did(&passkey_start_request_id, &delegated_did, None)
            .await
            .is_err()
        {
            return OAuthError::ServerError("An error occurred.".into()).into_response();
        }
        if state
            .oauth_repo
            .set_controller_did(&passkey_start_request_id, &user.did)
            .await
            .is_err()
        {
            return OAuthError::ServerError("An error occurred.".into()).into_response();
        }
    } else if is_delegation_flow {
        tracing::info!(
            delegated_did = ?request_data.did,
            controller_did = %user.did,
            "Passkey auth in delegation flow - preserving delegated DID"
        );
        if state
            .oauth_repo
            .set_controller_did(&passkey_start_request_id, &user.did)
            .await
            .is_err()
        {
            return OAuthError::ServerError("An error occurred.".into()).into_response();
        }
    } else if state
        .oauth_repo
        .set_authorization_did(&passkey_start_request_id, &user.did, None)
        .await
        .is_err()
    {
        return OAuthError::ServerError("An error occurred.".into()).into_response();
    }

    let options = serde_json::to_value(&rcr).unwrap_or(serde_json::json!({}));

    Json(PasskeyStartResponse { options }).into_response()
}

#[derive(Debug, Deserialize)]
pub struct PasskeyFinishInput {
    pub request_uri: String,
    pub credential: serde_json::Value,
}

pub async fn passkey_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(form): Json<PasskeyFinishInput>,
) -> Response {
    let passkey_finish_request_id = RequestId::from(form.request_uri.clone());
    let request_data = match state
        .oauth_repo
        .get_authorization_request(&passkey_finish_request_id)
        .await
    {
        Ok(Some(data)) => data,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "Invalid or expired request_uri."
                })),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "An error occurred."
                })),
            )
                .into_response();
        }
    };

    if request_data.expires_at < Utc::now() {
        let _ = state
            .oauth_repo
            .delete_authorization_request(&passkey_finish_request_id)
            .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "Authorization request has expired."
            })),
        )
            .into_response();
    }

    let did_str = match request_data.did {
        Some(d) => d,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "No passkey authentication in progress."
                })),
            )
                .into_response();
        }
    };
    let did: tranquil_types::Did = match did_str.parse() {
        Ok(d) => d,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "Invalid DID format."
                })),
            )
                .into_response();
        }
    };

    let controller_did: Option<tranquil_types::Did> = request_data
        .controller_did
        .as_ref()
        .and_then(|s| s.parse().ok());
    let passkey_owner_did = controller_did.as_ref().unwrap_or(&did);

    let auth_state_json = match state
        .user_repo
        .load_webauthn_challenge(passkey_owner_did, WebauthnChallengeType::Authentication)
        .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "No passkey authentication in progress or challenge expired."
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to load authentication state");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "An error occurred."
                })),
            )
                .into_response();
        }
    };

    let auth_state: webauthn_rs::prelude::SecurityKeyAuthentication =
        match serde_json::from_str(&auth_state_json) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "Failed to deserialize authentication state");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "server_error",
                        "error_description": "An error occurred."
                    })),
                )
                    .into_response();
            }
        };

    let credential: webauthn_rs::prelude::PublicKeyCredential =
        match serde_json::from_value(form.credential) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to parse credential");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_request",
                        "error_description": "Failed to parse credential response."
                    })),
                )
                    .into_response();
            }
        };

    let auth_result = match state
        .webauthn_config
        .finish_authentication(&credential, &auth_state)
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, did = %did, "Failed to verify passkey authentication");
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "access_denied",
                    "error_description": "Passkey verification failed."
                })),
            )
                .into_response();
        }
    };

    if let Err(e) = state
        .user_repo
        .delete_webauthn_challenge(passkey_owner_did, WebauthnChallengeType::Authentication)
        .await
    {
        tracing::warn!(error = %e, "Failed to delete authentication state");
    }

    if auth_result.needs_update() {
        let cred_id_bytes = auth_result.cred_id().as_slice();
        match state
            .user_repo
            .update_passkey_counter(
                cred_id_bytes,
                i32::try_from(auth_result.counter()).unwrap_or(i32::MAX),
            )
            .await
        {
            Ok(false) => {
                tracing::warn!(did = %did, "Passkey counter anomaly detected - possible cloned key");
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": "access_denied",
                        "error_description": "Security key counter anomaly detected. This may indicate a cloned key."
                    })),
                )
                    .into_response();
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to update passkey counter");
            }
            Ok(true) => {}
        }
    }

    tracing::info!(did = %did, "Passkey authentication successful");

    let device_id = extract_device_cookie(&headers);
    let requested_scope_str = request_data
        .parameters
        .scope
        .as_deref()
        .unwrap_or("atproto");
    let requested_scopes: Vec<String> = requested_scope_str
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    let passkey_finish_client_id = ClientId::from(request_data.parameters.client_id.clone());
    let needs_consent = should_show_consent(
        state.oauth_repo.as_ref(),
        &did,
        &passkey_finish_client_id,
        &requested_scopes,
    )
    .await
    .unwrap_or(true);

    if needs_consent {
        let consent_url = format!(
            "/app/oauth/consent?request_uri={}",
            url_encode(&form.request_uri)
        );
        return Json(serde_json::json!({"redirect_uri": consent_url})).into_response();
    }

    let code = Code::generate();
    let passkey_final_device_id = device_id.clone();
    let passkey_final_code = AuthorizationCode::from(code.0.clone());
    if state
        .oauth_repo
        .update_authorization_request(
            &passkey_finish_request_id,
            &did,
            passkey_final_device_id.as_ref(),
            &passkey_final_code,
        )
        .await
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "server_error",
                "error_description": "An error occurred."
            })),
        )
            .into_response();
    }

    let redirect_url = build_intermediate_redirect_url(
        &request_data.parameters.redirect_uri,
        &code.0,
        request_data.parameters.state.as_deref(),
        request_data.parameters.response_mode.map(|m| m.as_str()),
    );

    Json(serde_json::json!({
        "redirect_uri": redirect_url
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
pub struct AuthorizePasskeyQuery {
    pub request_uri: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyAuthResponse {
    pub options: serde_json::Value,
    pub request_uri: String,
}

pub async fn authorize_passkey_start(
    State(state): State<AppState>,
    Query(query): Query<AuthorizePasskeyQuery>,
) -> Response {
    let auth_passkey_start_request_id = RequestId::from(query.request_uri.clone());
    let request_data = match state
        .oauth_repo
        .get_authorization_request(&auth_passkey_start_request_id)
        .await
    {
        Ok(Some(d)) => d,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "Authorization request not found."
                })),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "An error occurred."
                })),
            )
                .into_response();
        }
    };

    if request_data.expires_at < Utc::now() {
        let _ = state
            .oauth_repo
            .delete_authorization_request(&auth_passkey_start_request_id)
            .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "Authorization request has expired."
            })),
        )
            .into_response();
    }

    let did_str = match &request_data.did {
        Some(d) => d.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "User not authenticated yet."
                })),
            )
                .into_response();
        }
    };

    let did: tranquil_types::Did = match did_str.parse() {
        Ok(d) => d,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "Invalid DID format."
                })),
            )
                .into_response();
        }
    };

    let stored_passkeys = match state.user_repo.get_passkeys_for_user(&did).await {
        Ok(pks) => pks,
        Err(e) => {
            tracing::error!("Failed to get passkeys: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "server_error", "error_description": "An error occurred."})),
            )
                .into_response();
        }
    };

    if stored_passkeys.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "No passkeys registered for this account."
            })),
        )
            .into_response();
    }

    let passkeys: Vec<webauthn_rs::prelude::SecurityKey> = stored_passkeys
        .iter()
        .filter_map(|sp| serde_json::from_slice(&sp.public_key).ok())
        .collect();

    if passkeys.is_empty() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "server_error", "error_description": "Failed to load passkeys."})),
        )
            .into_response();
    }

    let (rcr, auth_state) = match state.webauthn_config.start_authentication(passkeys) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to start passkey authentication: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "server_error", "error_description": "An error occurred."})),
            )
                .into_response();
        }
    };

    let state_json = match serde_json::to_string(&auth_state) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!("Failed to serialize authentication state: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "server_error", "error_description": "An error occurred."})),
            )
                .into_response();
        }
    };

    if let Err(e) = state
        .user_repo
        .save_webauthn_challenge(&did, WebauthnChallengeType::Authentication, &state_json)
        .await
    {
        tracing::error!("Failed to save authentication state: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "server_error", "error_description": "An error occurred."})),
        )
            .into_response();
    }

    let options = serde_json::to_value(&rcr).unwrap_or(serde_json::json!({}));
    Json(PasskeyAuthResponse {
        options,
        request_uri: query.request_uri,
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizePasskeySubmit {
    pub request_uri: String,
    pub credential: serde_json::Value,
}

pub async fn authorize_passkey_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(form): Json<AuthorizePasskeySubmit>,
) -> Response {
    let pds_hostname = &tranquil_config::get().server.hostname;
    let passkey_finish_request_id = RequestId::from(form.request_uri.clone());

    let request_data = match state
        .oauth_repo
        .get_authorization_request(&passkey_finish_request_id)
        .await
    {
        Ok(Some(d)) => d,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "Authorization request not found."
                })),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "An error occurred."
                })),
            )
                .into_response();
        }
    };

    if request_data.expires_at < Utc::now() {
        let _ = state
            .oauth_repo
            .delete_authorization_request(&passkey_finish_request_id)
            .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "Authorization request has expired."
            })),
        )
            .into_response();
    }

    let did_str = match &request_data.did {
        Some(d) => d.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "User not authenticated yet."
                })),
            )
                .into_response();
        }
    };

    let did: tranquil_types::Did = match did_str.parse() {
        Ok(d) => d,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "Invalid DID format."
                })),
            )
                .into_response();
        }
    };

    let auth_state_json = match state
        .user_repo
        .load_webauthn_challenge(&did, WebauthnChallengeType::Authentication)
        .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "No passkey challenge found. Please start over."
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to load authentication state: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "server_error", "error_description": "An error occurred."})),
            )
                .into_response();
        }
    };

    let auth_state: webauthn_rs::prelude::SecurityKeyAuthentication = match serde_json::from_str(
        &auth_state_json,
    ) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to deserialize authentication state: {:?}", e);
            return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "server_error", "error_description": "An error occurred."})),
                )
                    .into_response();
        }
    };

    let credential: webauthn_rs::prelude::PublicKeyCredential =
        match serde_json::from_value(form.credential.clone()) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to parse credential: {:?}", e);
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_request",
                        "error_description": "Invalid credential format."
                    })),
                )
                    .into_response();
            }
        };

    let auth_result = match state
        .webauthn_config
        .finish_authentication(&credential, &auth_state)
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Passkey authentication failed: {:?}", e);
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "access_denied",
                    "error_description": "Passkey authentication failed."
                })),
            )
                .into_response();
        }
    };

    let _ = state
        .user_repo
        .delete_webauthn_challenge(&did, WebauthnChallengeType::Authentication)
        .await;

    match state
        .user_repo
        .update_passkey_counter(
            credential.id.as_ref(),
            i32::try_from(auth_result.counter()).unwrap_or(i32::MAX),
        )
        .await
    {
        Ok(false) => {
            tracing::warn!(did = %did, "Passkey counter anomaly detected - possible cloned key");
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "access_denied",
                    "error_description": "Security key counter anomaly detected. This may indicate a cloned key."
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::warn!("Failed to update passkey counter: {:?}", e);
        }
        Ok(true) => {}
    }

    let has_totp = state
        .user_repo
        .has_totp_enabled(&did)
        .await
        .unwrap_or(false);
    if has_totp {
        let device_cookie = extract_device_cookie(&headers);
        let device_is_trusted = if let Some(ref dev_id) = device_cookie {
            crate::api::server::is_device_trusted(state.oauth_repo.as_ref(), dev_id, &did).await
        } else {
            false
        };

        if device_is_trusted {
            if let Some(ref dev_id) = device_cookie {
                let _ = crate::api::server::extend_device_trust(state.oauth_repo.as_ref(), dev_id)
                    .await;
            }
        } else {
            let user = match state.user_repo.get_2fa_status_by_did(&did).await {
                Ok(Some(u)) => u,
                _ => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "server_error", "error_description": "An error occurred."})),
                    )
                        .into_response();
                }
            };

            let _ = state
                .oauth_repo
                .delete_2fa_challenge_by_request_uri(&passkey_finish_request_id)
                .await;
            match state
                .oauth_repo
                .create_2fa_challenge(&did, &passkey_finish_request_id)
                .await
            {
                Ok(challenge) => {
                    if let Err(e) = enqueue_2fa_code(
                        state.user_repo.as_ref(),
                        state.infra_repo.as_ref(),
                        user.id,
                        &challenge.code,
                        pds_hostname,
                    )
                    .await
                    {
                        tracing::warn!(did = %did, error = %e, "Failed to enqueue 2FA notification");
                    }
                    let channel_name = user.preferred_comms_channel.display_name();
                    let redirect_url = format!(
                        "/app/oauth/2fa?request_uri={}&channel={}",
                        url_encode(&form.request_uri),
                        url_encode(channel_name)
                    );
                    return (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "next": "2fa",
                            "redirect": redirect_url
                        })),
                    )
                        .into_response();
                }
                Err(_) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "server_error", "error_description": "An error occurred."})),
                    )
                        .into_response();
                }
            }
        }
    }

    let redirect_url = format!(
        "/app/oauth/consent?request_uri={}",
        url_encode(&form.request_uri)
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "next": "consent",
            "redirect": redirect_url
        })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct RegisterCompleteInput {
    pub request_uri: String,
    pub did: String,
    pub app_password: String,
}

pub async fn register_complete(
    State(state): State<AppState>,
    _rate_limit: OAuthRateLimited<OAuthRegisterCompleteLimit>,
    Json(form): Json<RegisterCompleteInput>,
) -> Response {
    let did = Did::from(form.did.clone());

    let request_id = RequestId::from(form.request_uri.clone());
    let request_data = match state
        .oauth_repo
        .get_authorization_request(&request_id)
        .await
    {
        Ok(Some(data)) => data,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "Invalid or expired request_uri."
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(
                request_uri = %form.request_uri,
                error = ?e,
                "register_complete: failed to fetch authorization request"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "An error occurred."
                })),
            )
                .into_response();
        }
    };

    if request_data.expires_at < Utc::now() {
        let _ = state
            .oauth_repo
            .delete_authorization_request(&request_id)
            .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "Authorization request has expired."
            })),
        )
            .into_response();
    }

    if request_data.parameters.prompt != Some(Prompt::Create) {
        tracing::warn!(
            request_uri = %form.request_uri,
            prompt = ?request_data.parameters.prompt,
            "register_complete called on non-registration OAuth flow"
        );
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "This endpoint is only for registration flows."
            })),
        )
            .into_response();
    }

    if request_data.code.is_some() {
        tracing::warn!(
            request_uri = %form.request_uri,
            "register_complete called on already-completed OAuth flow"
        );
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "Authorization has already been completed."
            })),
        )
            .into_response();
    }

    if let Some(existing_did) = &request_data.did
        && existing_did != &form.did
    {
        tracing::warn!(
            request_uri = %form.request_uri,
            existing_did = %existing_did,
            attempted_did = %form.did,
            "register_complete attempted with different DID than already bound"
        );
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "Authorization request is already bound to a different account."
            })),
        )
            .into_response();
    }

    let password_hashes = match state
        .session_repo
        .get_app_password_hashes_by_did(&did)
        .await
    {
        Ok(hashes) => hashes,
        Err(e) => {
            tracing::error!(
                did = %did,
                error = ?e,
                "register_complete: failed to fetch app password hashes"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "An error occurred."
                })),
            )
                .into_response();
        }
    };

    let mut password_valid = password_hashes.iter().fold(false, |acc, hash| {
        acc | bcrypt::verify(&form.app_password, hash).unwrap_or(false)
    });

    if !password_valid
        && let Ok(Some(account_hash)) = state.user_repo.get_password_hash_by_did(&did).await
    {
        password_valid = bcrypt::verify(&form.app_password, &account_hash).unwrap_or(false);
    }

    if !password_valid {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "access_denied",
                "error_description": "Invalid credentials."
            })),
        )
            .into_response();
    }

    let is_verified = match state.user_repo.get_session_info_by_did(&did).await {
        Ok(Some(info)) => info.channel_verification.has_any_verified(),
        Ok(None) => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "access_denied",
                    "error_description": "Account not found."
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(
                did = %did,
                error = ?e,
                "register_complete: failed to fetch session info"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "An error occurred."
                })),
            )
                .into_response();
        }
    };

    if !is_verified {
        let resend_info = crate::api::server::auto_resend_verification(&state, &did).await;
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "account_not_verified",
                "error_description": "Please verify your account before continuing.",
                "did": did,
                "handle": resend_info.as_ref().map(|r| r.handle.to_string()),
                "channel": resend_info.as_ref().map(|r| r.channel.as_str())
            })),
        )
            .into_response();
    }

    if let Err(e) = state
        .oauth_repo
        .set_authorization_did(&request_id, &did, None)
        .await
    {
        tracing::error!(
            request_uri = %form.request_uri,
            did = %did,
            error = ?e,
            "register_complete: failed to set authorization DID"
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "server_error",
                "error_description": "An error occurred."
            })),
        )
            .into_response();
    }

    let requested_scope_str = request_data
        .parameters
        .scope
        .as_deref()
        .unwrap_or("atproto");
    let requested_scopes: Vec<String> = requested_scope_str
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    let client_id_typed = ClientId::from(request_data.parameters.client_id.clone());
    let needs_consent = should_show_consent(
        state.oauth_repo.as_ref(),
        &did,
        &client_id_typed,
        &requested_scopes,
    )
    .await
    .unwrap_or(true);

    if needs_consent {
        tracing::info!(
            did = %did,
            client_id = %request_data.parameters.client_id,
            "OAuth registration complete, redirecting to consent"
        );
        let consent_url = format!(
            "/app/oauth/consent?request_uri={}",
            url_encode(&form.request_uri)
        );
        return Json(serde_json::json!({"redirect_uri": consent_url})).into_response();
    }

    let code = Code::generate();
    let auth_code = AuthorizationCode::from(code.0.clone());
    if let Err(e) = state
        .oauth_repo
        .update_authorization_request(&request_id, &did, None, &auth_code)
        .await
    {
        tracing::error!(
            request_uri = %form.request_uri,
            did = %did,
            error = ?e,
            "register_complete: failed to update authorization request with code"
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "server_error",
                "error_description": "An error occurred."
            })),
        )
            .into_response();
    }

    tracing::info!(
        did = %did,
        client_id = %request_data.parameters.client_id,
        "OAuth registration flow completed successfully"
    );

    let redirect_url = build_intermediate_redirect_url(
        &request_data.parameters.redirect_uri,
        &code.0,
        request_data.parameters.state.as_deref(),
        request_data.parameters.response_mode.map(|m| m.as_str()),
    );
    Json(serde_json::json!({"redirect_uri": redirect_url})).into_response()
}

pub async fn establish_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: crate::auth::Auth<crate::auth::Active>,
) -> Response {
    let did = &auth.did;

    let existing_device = extract_device_cookie(&headers);

    let (device_id, new_cookie) = match existing_device {
        Some(id) => {
            let _ = state.oauth_repo.upsert_account_device(did, &id).await;
            (id, None)
        }
        None => {
            let new_id = DeviceId::generate();
            let device_typed = DeviceIdType::new(new_id.0.clone());
            let device_data = DeviceData {
                session_id: SessionId::generate(),
                user_agent: extract_user_agent(&headers),
                ip_address: extract_client_ip(&headers, None),
                last_seen_at: Utc::now(),
            };

            if let Err(e) = state
                .oauth_repo
                .create_device(&device_typed, &device_data)
                .await
            {
                tracing::error!(error = ?e, "Failed to create device");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "server_error",
                        "error_description": "Failed to establish session"
                    })),
                )
                    .into_response();
            }

            if let Err(e) = state
                .oauth_repo
                .upsert_account_device(did, &device_typed)
                .await
            {
                tracing::error!(error = ?e, "Failed to link device to account");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "server_error",
                        "error_description": "Failed to establish session"
                    })),
                )
                    .into_response();
            }

            let cookie = make_device_cookie(&device_typed);
            (device_typed, Some(cookie))
        }
    };

    tracing::info!(did = %did, device_id = %device_id, "Device session established");

    match new_cookie {
        Some(cookie) => (
            StatusCode::OK,
            [(SET_COOKIE, cookie)],
            Json(serde_json::json!({
                "success": true,
                "device_id": device_id
            })),
        )
            .into_response(),
        None => Json(serde_json::json!({
            "success": true,
            "device_id": device_id
        }))
        .into_response(),
    }
}
