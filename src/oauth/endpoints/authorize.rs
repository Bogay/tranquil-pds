use crate::comms::{CommsChannel, channel_display_name, enqueue_2fa_code};
use crate::oauth::{
    Code, DeviceData, DeviceId, OAuthError, SessionId, client::ClientMetadataCache, db,
};
use crate::state::{AppState, RateLimitKind};
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
use urlencoding::encode as url_encode;

const DEVICE_COOKIE_NAME: &str = "oauth_device_id";

fn redirect_see_other(uri: &str) -> Response {
    (StatusCode::SEE_OTHER, [(LOCATION, uri.to_string())]).into_response()
}

fn redirect_to_frontend_error(error: &str, description: &str) -> Response {
    redirect_see_other(&format!(
        "/#/oauth/error?error={}&error_description={}",
        url_encode(error),
        url_encode(description)
    ))
}

fn extract_device_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookie_str| {
            for cookie in cookie_str.split(';') {
                let cookie = cookie.trim();
                if let Some(value) = cookie.strip_prefix(&format!("{}=", DEVICE_COOKIE_NAME)) {
                    return crate::config::AuthConfig::get().verify_device_cookie(value);
                }
            }
            None
        })
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
    "0.0.0.0".to_string()
}

fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn make_device_cookie(device_id: &str) -> String {
    let signed_value = crate::config::AuthConfig::get().sign_device_cookie(device_id);
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
    pub password: String,
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
    let request_data = match db::get_authorization_request(&state.db, &request_uri).await {
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
        let _ = db::delete_authorization_request(&state.db, &request_uri).await;
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
    if !force_new_account
        && let Some(device_id) = extract_device_cookie(&headers)
        && let Ok(accounts) = db::get_device_accounts(&state.db, &device_id).await
        && !accounts.is_empty()
    {
        return redirect_see_other(&format!(
            "/#/oauth/accounts?request_uri={}",
            url_encode(&request_uri)
        ));
    }
    redirect_see_other(&format!(
        "/#/oauth/login?request_uri={}",
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
    let request_data = db::get_authorization_request(&state.db, &request_uri)
        .await?
        .ok_or_else(|| OAuthError::InvalidRequest("Invalid or expired request_uri".to_string()))?;
    if request_data.expires_at < Utc::now() {
        db::delete_authorization_request(&state.db, &request_uri).await?;
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
    pub handle: String,
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
    let accounts = match db::get_device_accounts(&state.db, &device_id).await {
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
            did: row.did,
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
    headers: HeaderMap,
    Json(form): Json<AuthorizeSubmit>,
) -> Response {
    let json_response = wants_json(&headers);
    let client_ip = extract_client_ip(&headers);
    if !state
        .check_rate_limit(RateLimitKind::OAuthAuthorize, &client_ip)
        .await
    {
        tracing::warn!(ip = %client_ip, "OAuth authorize rate limit exceeded");
        if json_response {
            return (
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "error": "RateLimitExceeded",
                    "error_description": "Too many login attempts. Please try again later."
                })),
            )
                .into_response();
        }
        return redirect_to_frontend_error(
            "RateLimitExceeded",
            "Too many login attempts. Please try again later.",
        );
    }
    let request_data = match db::get_authorization_request(&state.db, &form.request_uri).await {
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
        let _ = db::delete_authorization_request(&state.db, &form.request_uri).await;
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
            "/#/oauth/login?request_uri={}&error={}",
            url_encode(&form.request_uri),
            url_encode(error_msg)
        ))
    };
    let pds_hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let normalized_username = form.username.trim();
    let normalized_username = normalized_username
        .strip_prefix('@')
        .unwrap_or(normalized_username);
    let normalized_username = if normalized_username.contains('@') {
        normalized_username.to_string()
    } else if !normalized_username.contains('.') {
        format!("{}.{}", normalized_username, pds_hostname)
    } else {
        normalized_username.to_string()
    };
    tracing::debug!(
        original_username = %form.username,
        normalized_username = %normalized_username,
        pds_hostname = %pds_hostname,
        "Normalized username for lookup"
    );
    let user = match sqlx::query!(
        r#"
        SELECT id, did, email, password_hash, password_required, two_factor_enabled,
               preferred_comms_channel as "preferred_comms_channel: CommsChannel",
               deactivated_at, takedown_ref,
               email_verified, discord_verified, telegram_verified, signal_verified
        FROM users
        WHERE handle = $1 OR email = $1
        "#,
        normalized_username
    )
    .fetch_optional(&state.db)
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
    let is_verified = user.email_verified
        || user.discord_verified
        || user.telegram_verified
        || user.signal_verified;
    if !is_verified {
        return show_login_error(
            "Please verify your account before logging in.",
            json_response,
        );
    }

    if !user.password_required {
        if db::set_authorization_did(&state.db, &form.request_uri, &user.did, None)
            .await
            .is_err()
        {
            return show_login_error("An error occurred. Please try again.", json_response);
        }
        let redirect_url = format!(
            "/#/oauth/passkey?request_uri={}",
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
    let has_totp = crate::api::server::has_totp_enabled(&state, &user.did).await;
    if has_totp {
        let device_cookie = extract_device_cookie(&headers);
        let device_is_trusted = if let Some(ref dev_id) = device_cookie {
            crate::api::server::is_device_trusted(&state.db, dev_id, &user.did).await
        } else {
            false
        };

        if device_is_trusted {
            if let Some(ref dev_id) = device_cookie {
                let _ = crate::api::server::extend_device_trust(&state.db, dev_id).await;
            }
        } else {
            if db::set_authorization_did(&state.db, &form.request_uri, &user.did, None)
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
                "/#/oauth/totp?request_uri={}",
                url_encode(&form.request_uri)
            ));
        }
    }
    if user.two_factor_enabled {
        let _ = db::delete_2fa_challenge_by_request_uri(&state.db, &form.request_uri).await;
        match db::create_2fa_challenge(&state.db, &user.did, &form.request_uri).await {
            Ok(challenge) => {
                let hostname =
                    std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
                if let Err(e) =
                    enqueue_2fa_code(&state.db, user.id, &challenge.code, &hostname).await
                {
                    tracing::warn!(
                        did = %user.did,
                        error = %e,
                        "Failed to enqueue 2FA notification"
                    );
                }
                let channel_name = channel_display_name(user.preferred_comms_channel);
                if json_response {
                    return Json(serde_json::json!({
                        "needs_2fa": true,
                        "channel": channel_name
                    }))
                    .into_response();
                }
                return redirect_see_other(&format!(
                    "/#/oauth/2fa?request_uri={}&channel={}",
                    url_encode(&form.request_uri),
                    url_encode(channel_name)
                ));
            }
            Err(_) => {
                return show_login_error("An error occurred. Please try again.", json_response);
            }
        }
    }
    let mut device_id: Option<String> = extract_device_cookie(&headers);
    let mut new_cookie: Option<String> = None;
    if form.remember_device {
        let final_device_id = if let Some(existing_id) = &device_id {
            existing_id.clone()
        } else {
            let new_id = DeviceId::generate();
            let device_data = DeviceData {
                session_id: SessionId::generate().0,
                user_agent: extract_user_agent(&headers),
                ip_address: extract_client_ip(&headers),
                last_seen_at: Utc::now(),
            };
            if db::create_device(&state.db, &new_id.0, &device_data)
                .await
                .is_ok()
            {
                new_cookie = Some(make_device_cookie(&new_id.0));
                device_id = Some(new_id.0.clone());
            }
            new_id.0
        };
        let _ = db::upsert_account_device(&state.db, &user.did, &final_device_id).await;
    }
    if db::set_authorization_did(
        &state.db,
        &form.request_uri,
        &user.did,
        device_id.as_deref(),
    )
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
    let needs_consent = db::should_show_consent(
        &state.db,
        &user.did,
        &request_data.parameters.client_id,
        &requested_scopes,
    )
    .await
    .unwrap_or(true);
    if needs_consent {
        let consent_url = format!(
            "/#/oauth/consent?request_uri={}",
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
    if db::update_authorization_request(
        &state.db,
        &form.request_uri,
        &user.did,
        device_id.as_deref(),
        &code.0,
    )
    .await
    .is_err()
    {
        return show_login_error("An error occurred. Please try again.", json_response);
    }
    let redirect_url = build_success_redirect(
        &request_data.parameters.redirect_uri,
        &code.0,
        request_data.parameters.state.as_deref(),
        request_data.parameters.response_mode.as_deref(),
    );
    if json_response {
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
    } else if let Some(cookie) = new_cookie {
        (
            StatusCode::SEE_OTHER,
            [(SET_COOKIE, cookie), (LOCATION, redirect_url)],
        )
            .into_response()
    } else {
        redirect_see_other(&redirect_url)
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
    let request_data = match db::get_authorization_request(&state.db, &form.request_uri).await {
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
        let _ = db::delete_authorization_request(&state.db, &form.request_uri).await;
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
    let account_valid = match db::verify_account_on_device(&state.db, &device_id, &form.did).await {
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
    let user = match sqlx::query!(
        r#"
        SELECT id, two_factor_enabled,
               preferred_comms_channel as "preferred_comms_channel: CommsChannel",
               email_verified, discord_verified, telegram_verified, signal_verified
        FROM users
        WHERE did = $1
        "#,
        form.did
    )
    .fetch_optional(&state.db)
    .await
    {
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
    let is_verified = user.email_verified
        || user.discord_verified
        || user.telegram_verified
        || user.signal_verified;
    if !is_verified {
        return json_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "Please verify your account before logging in.",
        );
    }
    let has_totp = crate::api::server::has_totp_enabled(&state, &form.did).await;
    if has_totp {
        if db::set_authorization_did(&state.db, &form.request_uri, &form.did, Some(&device_id))
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
    if user.two_factor_enabled {
        let _ = db::delete_2fa_challenge_by_request_uri(&state.db, &form.request_uri).await;
        match db::create_2fa_challenge(&state.db, &form.did, &form.request_uri).await {
            Ok(challenge) => {
                let hostname =
                    std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
                if let Err(e) =
                    enqueue_2fa_code(&state.db, user.id, &challenge.code, &hostname).await
                {
                    tracing::warn!(
                        did = %form.did,
                        error = %e,
                        "Failed to enqueue 2FA notification"
                    );
                }
                let channel_name = channel_display_name(user.preferred_comms_channel);
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
    let _ = db::upsert_account_device(&state.db, &form.did, &device_id).await;
    let code = Code::generate();
    if db::update_authorization_request(
        &state.db,
        &form.request_uri,
        &form.did,
        Some(&device_id),
        &code.0,
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
    let redirect_url = build_success_redirect(
        &request_data.parameters.redirect_uri,
        &code.0,
        request_data.parameters.state.as_deref(),
        request_data.parameters.response_mode.as_deref(),
    );
    Json(serde_json::json!({
        "redirect_uri": redirect_url
    }))
    .into_response()
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
    redirect_url.push_str(&format!("code={}", url_encode(code)));
    if let Some(req_state) = state {
        redirect_url.push_str(&format!("&state={}", url_encode(req_state)));
    }
    let pds_hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    redirect_url.push_str(&format!(
        "&iss={}",
        url_encode(&format!("https://{}", pds_hostname))
    ));
    redirect_url
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
    let request_data = match db::get_authorization_request(&state.db, &form.request_uri).await {
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
    let _ = db::delete_authorization_request(&state.db, &form.request_uri).await;
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
    let challenge = match db::get_2fa_challenge(&state.db, &query.request_uri).await {
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
        let _ = db::delete_2fa_challenge(&state.db, challenge.id).await;
        return redirect_to_frontend_error(
            "invalid_request",
            "2FA code has expired. Please start over.",
        );
    }
    let _request_data = match db::get_authorization_request(&state.db, &query.request_uri).await {
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
        "/#/oauth/2fa?request_uri={}&channel={}",
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
    let request_data = match db::get_authorization_request(&state.db, &query.request_uri).await {
        Ok(Some(data)) => data,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "Invalid or expired request_uri"
                })),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": format!("Database error: {:?}", e)
                })),
            )
                .into_response();
        }
    };
    if request_data.expires_at < Utc::now() {
        let _ = db::delete_authorization_request(&state.db, &query.request_uri).await;
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "Authorization request has expired"
            })),
        )
            .into_response();
    }
    let did = match &request_data.did {
        Some(d) => d.clone(),
        None => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "access_denied",
                    "error_description": "Not authenticated"
                })),
            )
                .into_response();
        }
    };
    let client_cache = ClientMetadataCache::new(3600);
    let client_metadata = client_cache
        .get(&request_data.parameters.client_id)
        .await
        .ok();
    let requested_scope_str = request_data
        .parameters
        .scope
        .as_deref()
        .unwrap_or("atproto");
    let requested_scopes: Vec<&str> = requested_scope_str.split_whitespace().collect();
    let preferences =
        db::get_scope_preferences(&state.db, &did, &request_data.parameters.client_id)
            .await
            .unwrap_or_default();
    let pref_map: std::collections::HashMap<_, _> = preferences
        .iter()
        .map(|p| (p.scope.as_str(), p.granted))
        .collect();
    let requested_scope_strings: Vec<String> =
        requested_scopes.iter().map(|s| s.to_string()).collect();
    let show_consent = db::should_show_consent(
        &state.db,
        &did,
        &request_data.parameters.client_id,
        &requested_scope_strings,
    )
    .await
    .unwrap_or(true);
    let mut scopes = Vec::new();
    for scope in &requested_scopes {
        let (category, required, description, display_name) =
            if let Some(def) = crate::oauth::scopes::SCOPE_DEFINITIONS.get(*scope) {
                (
                    def.category.display_name().to_string(),
                    def.required,
                    def.description.to_string(),
                    def.display_name.to_string(),
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
        scopes.push(ScopeInfo {
            scope: scope.to_string(),
            category,
            required,
            description,
            display_name,
            granted,
        });
    }
    Json(ConsentResponse {
        request_uri: query.request_uri.clone(),
        client_id: request_data.parameters.client_id.clone(),
        client_name: client_metadata.as_ref().and_then(|m| m.client_name.clone()),
        client_uri: client_metadata.as_ref().and_then(|m| m.client_uri.clone()),
        logo_uri: client_metadata.as_ref().and_then(|m| m.logo_uri.clone()),
        scopes,
        show_consent,
        did,
    })
    .into_response()
}

pub async fn consent_post(
    State(state): State<AppState>,
    Json(form): Json<ConsentSubmit>,
) -> Response {
    let request_data = match db::get_authorization_request(&state.db, &form.request_uri).await {
        Ok(Some(data)) => data,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "Invalid or expired request_uri"
                })),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": format!("Database error: {:?}", e)
                })),
            )
                .into_response();
        }
    };
    if request_data.expires_at < Utc::now() {
        let _ = db::delete_authorization_request(&state.db, &form.request_uri).await;
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "Authorization request has expired"
            })),
        )
            .into_response();
    }
    let did = match &request_data.did {
        Some(d) => d.clone(),
        None => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "access_denied",
                    "error_description": "Not authenticated"
                })),
            )
                .into_response();
        }
    };
    let requested_scope_str = request_data
        .parameters
        .scope
        .as_deref()
        .unwrap_or("atproto");
    let requested_scopes: Vec<&str> = requested_scope_str.split_whitespace().collect();
    let has_granular_scopes = requested_scopes.iter().any(|s| {
        s.starts_with("repo:")
            || s.starts_with("blob:")
            || s.starts_with("rpc:")
            || s.starts_with("account:")
            || s.starts_with("identity:")
    });
    let user_denied_some_granular = has_granular_scopes
        && requested_scopes
            .iter()
            .filter(|s| {
                s.starts_with("repo:")
                    || s.starts_with("blob:")
                    || s.starts_with("rpc:")
                    || s.starts_with("account:")
                    || s.starts_with("identity:")
            })
            .any(|s| !form.approved_scopes.contains(&s.to_string()));
    let atproto_was_requested = requested_scopes.contains(&"atproto");
    if atproto_was_requested
        && !has_granular_scopes
        && !form.approved_scopes.contains(&"atproto".to_string())
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "The atproto scope was requested and must be approved"
            })),
        )
            .into_response();
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
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "At least one scope must be approved"
            })),
        )
            .into_response();
    }
    let approved_scope_str = final_approved.join(" ");
    let has_valid_scope = final_approved.iter().all(|s| {
        s == "atproto"
            || s == "transition:generic"
            || s == "transition:chat.bsky"
            || s == "transition:email"
            || s.starts_with("repo:")
            || s.starts_with("blob:")
            || s.starts_with("rpc:")
            || s.starts_with("account:")
            || s.starts_with("include:")
    });
    if !has_valid_scope {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "Invalid scope format"
            })),
        )
            .into_response();
    }
    if form.remember {
        let preferences: Vec<db::ScopePreference> = requested_scopes
            .iter()
            .map(|s| db::ScopePreference {
                scope: s.to_string(),
                granted: form.approved_scopes.contains(&s.to_string()),
            })
            .collect();
        let _ = db::upsert_scope_preferences(
            &state.db,
            &did,
            &request_data.parameters.client_id,
            &preferences,
        )
        .await;
    }
    if let Err(e) =
        db::update_request_scope(&state.db, &form.request_uri, &approved_scope_str).await
    {
        tracing::warn!("Failed to update request scope: {:?}", e);
    }
    let code = Code::generate();
    if db::update_authorization_request(
        &state.db,
        &form.request_uri,
        &did,
        request_data.device_id.as_deref(),
        &code.0,
    )
    .await
    .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "server_error",
                "error_description": "Failed to complete authorization"
            })),
        )
            .into_response();
    }
    let redirect_url = build_success_redirect(
        &request_data.parameters.redirect_uri,
        &code.0,
        request_data.parameters.state.as_deref(),
        request_data.parameters.response_mode.as_deref(),
    );
    Json(serde_json::json!({
        "redirect_uri": redirect_url
    }))
    .into_response()
}

pub async fn authorize_2fa_post(
    State(state): State<AppState>,
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
    let client_ip = extract_client_ip(&headers);
    if !state
        .check_rate_limit(RateLimitKind::OAuthAuthorize, &client_ip)
        .await
    {
        tracing::warn!(ip = %client_ip, "OAuth 2FA rate limit exceeded");
        return json_error(
            StatusCode::TOO_MANY_REQUESTS,
            "RateLimitExceeded",
            "Too many attempts. Please try again later.",
        );
    }
    let request_data = match db::get_authorization_request(&state.db, &form.request_uri).await {
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
        let _ = db::delete_authorization_request(&state.db, &form.request_uri).await;
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Authorization request has expired.",
        );
    }
    let challenge = db::get_2fa_challenge(&state.db, &form.request_uri)
        .await
        .ok()
        .flatten();
    if let Some(challenge) = challenge {
        if challenge.expires_at < Utc::now() {
            let _ = db::delete_2fa_challenge(&state.db, challenge.id).await;
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "2FA code has expired. Please start over.",
            );
        }
        if challenge.attempts >= MAX_2FA_ATTEMPTS {
            let _ = db::delete_2fa_challenge(&state.db, challenge.id).await;
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
            let _ = db::increment_2fa_attempts(&state.db, challenge.id).await;
            return json_error(
                StatusCode::FORBIDDEN,
                "invalid_code",
                "Invalid verification code. Please try again.",
            );
        }
        let _ = db::delete_2fa_challenge(&state.db, challenge.id).await;
        let code = Code::generate();
        let device_id = extract_device_cookie(&headers);
        if db::update_authorization_request(
            &state.db,
            &form.request_uri,
            &challenge.did,
            device_id.as_deref(),
            &code.0,
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
        let redirect_url = build_success_redirect(
            &request_data.parameters.redirect_uri,
            &code.0,
            request_data.parameters.state.as_deref(),
            request_data.parameters.response_mode.as_deref(),
        );
        return Json(serde_json::json!({
            "redirect_uri": redirect_url
        }))
        .into_response();
    }
    let did = match &request_data.did {
        Some(d) => d.clone(),
        None => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "No 2FA challenge found. Please start over.",
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
    if !state
        .check_rate_limit(RateLimitKind::TotpVerify, &did)
        .await
    {
        tracing::warn!(did = %did, "TOTP verification rate limit exceeded");
        return json_error(
            StatusCode::TOO_MANY_REQUESTS,
            "RateLimitExceeded",
            "Too many verification attempts. Please try again in a few minutes.",
        );
    }
    let totp_valid =
        crate::api::server::verify_totp_or_backup_for_user(&state, &did, &form.code).await;
    if !totp_valid {
        return json_error(
            StatusCode::FORBIDDEN,
            "invalid_code",
            "Invalid verification code. Please try again.",
        );
    }
    let device_id = extract_device_cookie(&headers);
    if form.trust_device
        && let Some(ref dev_id) = device_id
    {
        let _ = crate::api::server::trust_device(&state.db, dev_id).await;
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
    let needs_consent = db::should_show_consent(
        &state.db,
        &did,
        &request_data.parameters.client_id,
        &requested_scopes,
    )
    .await
    .unwrap_or(true);
    if needs_consent {
        let consent_url = format!(
            "/#/oauth/consent?request_uri={}",
            url_encode(&form.request_uri)
        );
        return Json(serde_json::json!({"redirect_uri": consent_url})).into_response();
    }
    let code = Code::generate();
    if db::update_authorization_request(
        &state.db,
        &form.request_uri,
        &did,
        device_id.as_deref(),
        &code.0,
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
    let redirect_url = build_success_redirect(
        &request_data.parameters.redirect_uri,
        &code.0,
        request_data.parameters.state.as_deref(),
        request_data.parameters.response_mode.as_deref(),
    );
    Json(serde_json::json!({
        "redirect_uri": redirect_url
    }))
    .into_response()
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
    let pds_hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let normalized_identifier = query.identifier.trim();
    let normalized_identifier = normalized_identifier
        .strip_prefix('@')
        .unwrap_or(normalized_identifier);
    let normalized_identifier = if let Some(bare_handle) =
        normalized_identifier.strip_suffix(&format!(".{}", pds_hostname))
    {
        bare_handle.to_string()
    } else {
        normalized_identifier.to_string()
    };

    let user = sqlx::query!(
        "SELECT did FROM users WHERE handle = $1 OR email = $1",
        normalized_identifier
    )
    .fetch_optional(&state.db)
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
}

pub async fn check_user_security_status(
    State(state): State<AppState>,
    Query(query): Query<CheckPasskeysQuery>,
) -> Response {
    let pds_hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let identifier = query.identifier.trim();
    let identifier = identifier.strip_prefix('@').unwrap_or(identifier);
    let normalized_identifier = if identifier.contains('@') || identifier.starts_with("did:") {
        identifier.to_string()
    } else if !identifier.contains('.') {
        format!("{}.{}", identifier.to_lowercase(), pds_hostname)
    } else {
        identifier.to_lowercase()
    };

    let user = sqlx::query!(
        "SELECT did FROM users WHERE handle = $1 OR email = $1",
        normalized_identifier
    )
    .fetch_optional(&state.db)
    .await;

    let (has_passkeys, has_totp) = match user {
        Ok(Some(u)) => {
            let passkeys = crate::api::server::has_passkeys_for_user(&state, &u.did).await;
            let totp = crate::api::server::has_totp_enabled(&state, &u.did).await;
            (passkeys, totp)
        }
        _ => (false, false),
    };

    Json(SecurityStatusResponse {
        has_passkeys,
        has_totp,
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
pub struct PasskeyStartInput {
    pub request_uri: String,
    pub identifier: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyStartResponse {
    pub options: serde_json::Value,
}

pub async fn passkey_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(form): Json<PasskeyStartInput>,
) -> Response {
    let client_ip = extract_client_ip(&headers);

    if !state
        .check_rate_limit(RateLimitKind::OAuthAuthorize, &client_ip)
        .await
    {
        tracing::warn!(ip = %client_ip, "OAuth passkey rate limit exceeded");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "RateLimitExceeded",
                "error_description": "Too many login attempts. Please try again later."
            })),
        )
            .into_response();
    }

    let request_data = match db::get_authorization_request(&state.db, &form.request_uri).await {
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
        let _ = db::delete_authorization_request(&state.db, &form.request_uri).await;
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "Authorization request has expired."
            })),
        )
            .into_response();
    }

    let pds_hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let normalized_username = form.identifier.trim();
    let normalized_username = normalized_username
        .strip_prefix('@')
        .unwrap_or(normalized_username);
    let normalized_username = if normalized_username.contains('@') {
        normalized_username.to_string()
    } else if !normalized_username.contains('.') {
        format!("{}.{}", normalized_username, pds_hostname)
    } else {
        normalized_username.to_string()
    };

    let user = match sqlx::query!(
        r#"
        SELECT did, deactivated_at, takedown_ref,
               email_verified, discord_verified, telegram_verified, signal_verified
        FROM users
        WHERE handle = $1 OR email = $1
        "#,
        normalized_username
    )
    .fetch_optional(&state.db)
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

    let is_verified = user.email_verified
        || user.discord_verified
        || user.telegram_verified
        || user.signal_verified;

    if !is_verified {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "access_denied",
                "error_description": "Please verify your account before logging in."
            })),
        )
            .into_response();
    }

    let stored_passkeys =
        match crate::auth::webauthn::get_passkeys_for_user(&state.db, &user.did).await {
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
        .filter_map(|sp| sp.to_security_key().ok())
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

    let webauthn = match crate::auth::webauthn::WebAuthnConfig::new(&pds_hostname) {
        Ok(w) => w,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create WebAuthn config");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "WebAuthn configuration failed."
                })),
            )
                .into_response();
        }
    };

    let (rcr, auth_state) = match webauthn.start_authentication(passkeys) {
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

    if let Err(e) =
        crate::auth::webauthn::save_authentication_state(&state.db, &user.did, &auth_state).await
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

    if db::set_authorization_did(&state.db, &form.request_uri, &user.did, None)
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
    let request_data = match db::get_authorization_request(&state.db, &form.request_uri).await {
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
        let _ = db::delete_authorization_request(&state.db, &form.request_uri).await;
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "Authorization request has expired."
            })),
        )
            .into_response();
    }

    let did = match request_data.did {
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

    let auth_state = match crate::auth::webauthn::load_authentication_state(&state.db, &did).await {
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

    let pds_hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let webauthn = match crate::auth::webauthn::WebAuthnConfig::new(&pds_hostname) {
        Ok(w) => w,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create WebAuthn config");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "WebAuthn configuration failed."
                })),
            )
                .into_response();
        }
    };

    let auth_result = match webauthn.finish_authentication(&credential, &auth_state) {
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

    if let Err(e) = crate::auth::webauthn::delete_authentication_state(&state.db, &did).await {
        tracing::warn!(error = %e, "Failed to delete authentication state");
    }

    if auth_result.needs_update() {
        match crate::auth::webauthn::update_passkey_counter(
            &state.db,
            auth_result.cred_id(),
            auth_result.counter(),
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

    let has_totp = crate::api::server::has_totp_enabled(&state, &did).await;
    if has_totp {
        return Json(serde_json::json!({
            "needs_totp": true
        }))
        .into_response();
    }

    let user = sqlx::query!(
        "SELECT two_factor_enabled, preferred_comms_channel as \"preferred_comms_channel: CommsChannel\", id FROM users WHERE did = $1",
        did
    )
    .fetch_optional(&state.db)
    .await;

    if let Ok(Some(user)) = user
        && user.two_factor_enabled
    {
        let _ = db::delete_2fa_challenge_by_request_uri(&state.db, &form.request_uri).await;
        match db::create_2fa_challenge(&state.db, &did, &form.request_uri).await {
            Ok(challenge) => {
                let hostname =
                    std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
                if let Err(e) =
                    enqueue_2fa_code(&state.db, user.id, &challenge.code, &hostname).await
                {
                    tracing::warn!(did = %did, error = %e, "Failed to enqueue 2FA notification");
                }
                let channel_name = channel_display_name(user.preferred_comms_channel);
                return Json(serde_json::json!({
                    "needs_2fa": true,
                    "channel": channel_name
                }))
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
        }
    }

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

    let needs_consent = db::should_show_consent(
        &state.db,
        &did,
        &request_data.parameters.client_id,
        &requested_scopes,
    )
    .await
    .unwrap_or(true);

    if needs_consent {
        let consent_url = format!(
            "/#/oauth/consent?request_uri={}",
            url_encode(&form.request_uri)
        );
        return Json(serde_json::json!({"redirect_uri": consent_url})).into_response();
    }

    let code = Code::generate();
    if db::update_authorization_request(
        &state.db,
        &form.request_uri,
        &did,
        device_id.as_deref(),
        &code.0,
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

    let redirect_url = build_success_redirect(
        &request_data.parameters.redirect_uri,
        &code.0,
        request_data.parameters.state.as_deref(),
        request_data.parameters.response_mode.as_deref(),
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
    let pds_hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());

    let request_data = match db::get_authorization_request(&state.db, &query.request_uri).await {
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
        let _ = db::delete_authorization_request(&state.db, &query.request_uri).await;
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "Authorization request has expired."
            })),
        )
            .into_response();
    }

    let did = match &request_data.did {
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

    let stored_passkeys = match crate::auth::webauthn::get_passkeys_for_user(&state.db, &did).await
    {
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
        .filter_map(|sp| sp.to_security_key().ok())
        .collect();

    if passkeys.is_empty() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "server_error", "error_description": "Failed to load passkeys."})),
        )
            .into_response();
    }

    let webauthn = match crate::auth::webauthn::WebAuthnConfig::new(&pds_hostname) {
        Ok(w) => w,
        Err(e) => {
            tracing::error!("Failed to create WebAuthn config: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "server_error", "error_description": "An error occurred."})),
            )
                .into_response();
        }
    };

    let (rcr, auth_state) = match webauthn.start_authentication(passkeys) {
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

    if let Err(e) =
        crate::auth::webauthn::save_authentication_state(&state.db, &did, &auth_state).await
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
    let pds_hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());

    let request_data = match db::get_authorization_request(&state.db, &form.request_uri).await {
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
        let _ = db::delete_authorization_request(&state.db, &form.request_uri).await;
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "Authorization request has expired."
            })),
        )
            .into_response();
    }

    let did = match &request_data.did {
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

    let auth_state = match crate::auth::webauthn::load_authentication_state(&state.db, &did).await {
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

    let webauthn = match crate::auth::webauthn::WebAuthnConfig::new(&pds_hostname) {
        Ok(w) => w,
        Err(e) => {
            tracing::error!("Failed to create WebAuthn config: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "server_error", "error_description": "An error occurred."})),
            )
                .into_response();
        }
    };

    let auth_result = match webauthn.finish_authentication(&credential, &auth_state) {
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

    let _ = crate::auth::webauthn::delete_authentication_state(&state.db, &did).await;

    match crate::auth::webauthn::update_passkey_counter(
        &state.db,
        credential.id.as_ref(),
        auth_result.counter(),
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

    let has_totp = crate::api::server::has_totp_enabled_db(&state.db, &did).await;
    if has_totp {
        let device_cookie = extract_device_cookie(&headers);
        let device_is_trusted = if let Some(ref dev_id) = device_cookie {
            crate::api::server::is_device_trusted(&state.db, dev_id, &did).await
        } else {
            false
        };

        if device_is_trusted {
            if let Some(ref dev_id) = device_cookie {
                let _ = crate::api::server::extend_device_trust(&state.db, dev_id).await;
            }
        } else {
            let user = match sqlx::query!(
                r#"SELECT id, preferred_comms_channel as "preferred_comms_channel: CommsChannel" FROM users WHERE did = $1"#,
                did
            )
            .fetch_optional(&state.db)
            .await
            {
                Ok(Some(u)) => u,
                _ => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "server_error", "error_description": "An error occurred."})),
                    )
                        .into_response();
                }
            };

            let _ = db::delete_2fa_challenge_by_request_uri(&state.db, &form.request_uri).await;
            match db::create_2fa_challenge(&state.db, &did, &form.request_uri).await {
                Ok(challenge) => {
                    if let Err(e) =
                        enqueue_2fa_code(&state.db, user.id, &challenge.code, &pds_hostname).await
                    {
                        tracing::warn!(did = %did, error = %e, "Failed to enqueue 2FA notification");
                    }
                    let channel_name = channel_display_name(user.preferred_comms_channel);
                    let redirect_url = format!(
                        "/#/oauth/2fa?request_uri={}&channel={}",
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
        "/#/oauth/consent?request_uri={}",
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
