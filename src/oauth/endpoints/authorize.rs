use crate::comms::{CommsChannel, channel_display_name, enqueue_2fa_code};
use crate::oauth::{
    Code, DeviceAccount, DeviceData, DeviceId, OAuthError, SessionId, client::ClientMetadataCache, db, templates,
};
use crate::state::{AppState, RateLimitKind};
use axum::{
    Form, Json,
    extract::{Query, State},
    http::{
        HeaderMap, StatusCode,
        header::{LOCATION, SET_COOKIE},
    },
    response::{Html, IntoResponse, Redirect, Response},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use urlencoding::encode as url_encode;

const DEVICE_COOKIE_NAME: &str = "oauth_device_id";

fn redirect_see_other(uri: &str) -> Response {
    (StatusCode::SEE_OTHER, [(LOCATION, uri.to_string())]).into_response()
}

fn extract_device_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookie_str| {
            for cookie in cookie_str.split(';') {
                let cookie = cookie.trim();
                if let Some(value) = cookie.strip_prefix(&format!("{}=", DEVICE_COOKIE_NAME)) {
                    return Some(value.to_string());
                }
            }
            None
        })
}

fn extract_client_ip(headers: &HeaderMap) -> String {
    if let Some(forwarded) = headers.get("x-forwarded-for")
        && let Ok(value) = forwarded.to_str()
            && let Some(first_ip) = value.split(',').next() {
                return first_ip.trim().to_string();
            }
    if let Some(real_ip) = headers.get("x-real-ip")
        && let Ok(value) = real_ip.to_str() {
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
    format!(
        "{}={}; Path=/oauth; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000",
        DEVICE_COOKIE_NAME, device_id
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
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_request",
                        "error_description": "Missing request_uri parameter. Use PAR to initiate authorization."
                    })),
                ).into_response();
            }
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Html(templates::error_page(
                    "invalid_request",
                    Some("Missing request_uri parameter. Use PAR to initiate authorization."),
                )),
            )
                .into_response();
        }
    };
    let request_data = match db::get_authorization_request(&state.db, &request_uri).await {
        Ok(Some(data)) => data,
        Ok(None) => {
            if wants_json(&headers) {
                return (
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_request",
                        "error_description": "Invalid or expired request_uri. Please start a new authorization request."
                    })),
                ).into_response();
            }
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Html(templates::error_page(
                    "invalid_request",
                    Some(
                        "Invalid or expired request_uri. Please start a new authorization request.",
                    ),
                )),
            )
                .into_response();
        }
        Err(e) => {
            if wants_json(&headers) {
                return (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "server_error",
                        "error_description": format!("Database error: {:?}", e)
                    })),
                )
                    .into_response();
            }
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Html(templates::error_page(
                    "server_error",
                    Some(&format!("Database error: {:?}", e)),
                )),
            )
                .into_response();
        }
    };
    if request_data.expires_at < Utc::now() {
        let _ = db::delete_authorization_request(&state.db, &request_uri).await;
        if wants_json(&headers) {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": "Authorization request has expired. Please start a new request."
                })),
            ).into_response();
        }
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Html(templates::error_page(
                "invalid_request",
                Some("Authorization request has expired. Please start a new request."),
            )),
        )
            .into_response();
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
                && !accounts.is_empty() {
                    let device_accounts: Vec<DeviceAccount> = accounts
                        .into_iter()
                        .map(|row| DeviceAccount {
                            did: row.did,
                            handle: row.handle,
                            email: row.email,
                            last_used_at: row.last_used_at,
                        })
                        .collect();
                    return Html(templates::account_selector_page(
                        &request_data.parameters.client_id,
                        client_name.as_deref(),
                        &request_uri,
                        &device_accounts,
                    ))
                    .into_response();
                }
    Html(templates::login_page(
        &request_data.parameters.client_id,
        client_name.as_deref(),
        request_data.parameters.scope.as_deref(),
        &request_uri,
        None,
        request_data.parameters.login_hint.as_deref(),
    ))
    .into_response()
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

pub async fn authorize_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AuthorizeSubmit>,
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
        return (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            Html(templates::error_page(
                "RateLimitExceeded",
                Some("Too many login attempts. Please try again later."),
            )),
        )
            .into_response();
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
            return Html(templates::error_page(
                "invalid_request",
                Some("Invalid or expired request_uri. Please start a new authorization request."),
            ))
            .into_response();
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
            return Html(templates::error_page(
                "server_error",
                Some(&format!("Database error: {:?}", e)),
            ))
            .into_response();
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
        return Html(templates::error_page(
            "invalid_request",
            Some("Authorization request has expired. Please start a new request."),
        ))
        .into_response();
    }
    let client_cache = ClientMetadataCache::new(3600);
    let client_name = client_cache
        .get(&request_data.parameters.client_id)
        .await
        .ok()
        .and_then(|m| m.client_name);
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
        Html(templates::login_page(
            &request_data.parameters.client_id,
            client_name.as_deref(),
            request_data.parameters.scope.as_deref(),
            &form.request_uri,
            Some(error_msg),
            Some(&form.username),
        ))
        .into_response()
    };
    let pds_hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let normalized_username = form.username.trim();
    let normalized_username = normalized_username
        .strip_prefix('@')
        .unwrap_or(normalized_username);
    let normalized_username = if let Some(bare_handle) =
        normalized_username.strip_suffix(&format!(".{}", pds_hostname))
    {
        bare_handle.to_string()
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
        SELECT id, did, email, password_hash, two_factor_enabled,
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
            let _ = bcrypt::verify(&form.password, "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.VTtYw1ZzQKZqmK");
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
        return show_login_error("Please verify your account before logging in.", json_response);
    }
    let password_valid = match bcrypt::verify(&form.password, &user.password_hash) {
        Ok(valid) => valid,
        Err(_) => return show_login_error("An error occurred. Please try again.", json_response),
    };
    if !password_valid {
        return show_login_error("Invalid handle/email or password.", json_response);
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
                let redirect_url = format!(
                    "/oauth/authorize/2fa?request_uri={}&channel={}",
                    url_encode(&form.request_uri),
                    url_encode(channel_name)
                );
                return Redirect::temporary(&redirect_url).into_response();
            }
            Err(_) => {
                return show_login_error("An error occurred. Please try again.", json_response);
            }
        }
    }
    let code = Code::generate();
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

pub async fn authorize_select(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AuthorizeSelectSubmit>,
) -> Response {
    let request_data = match db::get_authorization_request(&state.db, &form.request_uri).await {
        Ok(Some(data)) => data,
        Ok(None) => {
            return Html(templates::error_page(
                "invalid_request",
                Some("Invalid or expired request_uri. Please start a new authorization request."),
            ))
            .into_response();
        }
        Err(_) => {
            return Html(templates::error_page(
                "server_error",
                Some("An error occurred. Please try again."),
            ))
            .into_response();
        }
    };
    if request_data.expires_at < Utc::now() {
        let _ = db::delete_authorization_request(&state.db, &form.request_uri).await;
        return Html(templates::error_page(
            "invalid_request",
            Some("Authorization request has expired. Please start a new request."),
        ))
        .into_response();
    }
    let device_id = match extract_device_cookie(&headers) {
        Some(id) => id,
        None => {
            return Html(templates::error_page(
                "invalid_request",
                Some("No device session found. Please sign in."),
            ))
            .into_response();
        }
    };
    let account_valid = match db::verify_account_on_device(&state.db, &device_id, &form.did).await {
        Ok(valid) => valid,
        Err(_) => {
            return Html(templates::error_page(
                "server_error",
                Some("An error occurred. Please try again."),
            ))
            .into_response();
        }
    };
    if !account_valid {
        return Html(templates::error_page(
            "access_denied",
            Some("This account is not available on this device. Please sign in."),
        ))
        .into_response();
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
            return Html(templates::error_page(
                "access_denied",
                Some("Account not found. Please sign in."),
            )).into_response();
        }
        Err(_) => {
            return Html(templates::error_page(
                "server_error",
                Some("An error occurred. Please try again."),
            )).into_response();
        }
    };
    let is_verified = user.email_verified
        || user.discord_verified
        || user.telegram_verified
        || user.signal_verified;
    if !is_verified {
        return Html(templates::error_page(
            "access_denied",
            Some("Please verify your account before logging in."),
        ))
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
                let redirect_url = format!(
                    "/oauth/authorize/2fa?request_uri={}&channel={}",
                    url_encode(&form.request_uri),
                    url_encode(channel_name)
                );
                return Redirect::temporary(&redirect_url).into_response();
            }
            Err(_) => {
                return Html(templates::error_page(
                    "server_error",
                    Some("An error occurred. Please try again."),
                ))
                .into_response();
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
        return Html(templates::error_page(
            "server_error",
            Some("An error occurred. Please try again."),
        ))
        .into_response();
    }
    let redirect_url = build_success_redirect(
        &request_data.parameters.redirect_uri,
        &code.0,
        request_data.parameters.state.as_deref(),
    );
    redirect_see_other(&redirect_url)
}

fn build_success_redirect(redirect_uri: &str, code: &str, state: Option<&str>) -> String {
    let mut redirect_url = redirect_uri.to_string();
    let separator = if redirect_url.contains('?') { '&' } else { '?' };
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
    Form(form): Form<AuthorizeDenyForm>,
) -> Result<Response, OAuthError> {
    let request_data = db::get_authorization_request(&state.db, &form.request_uri)
        .await?
        .ok_or_else(|| OAuthError::InvalidRequest("Invalid request_uri".to_string()))?;
    db::delete_authorization_request(&state.db, &form.request_uri).await?;
    let redirect_uri = &request_data.parameters.redirect_uri;
    let mut redirect_url = redirect_uri.to_string();
    let separator = if redirect_url.contains('?') { '&' } else { '?' };
    redirect_url.push(separator);
    redirect_url.push_str("error=access_denied");
    redirect_url.push_str("&error_description=User%20denied%20the%20request");
    if let Some(state) = &request_data.parameters.state {
        redirect_url.push_str(&format!("&state={}", url_encode(state)));
    }
    Ok(redirect_see_other(&redirect_url))
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
}

const MAX_2FA_ATTEMPTS: i32 = 5;

pub async fn authorize_2fa_get(
    State(state): State<AppState>,
    Query(query): Query<Authorize2faQuery>,
) -> Response {
    let challenge = match db::get_2fa_challenge(&state.db, &query.request_uri).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return Html(templates::error_page(
                "invalid_request",
                Some("No 2FA challenge found. Please start over."),
            ))
            .into_response();
        }
        Err(_) => {
            return Html(templates::error_page(
                "server_error",
                Some("An error occurred. Please try again."),
            ))
            .into_response();
        }
    };
    if challenge.expires_at < Utc::now() {
        let _ = db::delete_2fa_challenge(&state.db, challenge.id).await;
        return Html(templates::error_page(
            "invalid_request",
            Some("2FA code has expired. Please start over."),
        ))
        .into_response();
    }
    let _request_data = match db::get_authorization_request(&state.db, &query.request_uri).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            return Html(templates::error_page(
                "invalid_request",
                Some("Authorization request not found. Please start over."),
            ))
            .into_response();
        }
        Err(_) => {
            return Html(templates::error_page(
                "server_error",
                Some("An error occurred. Please try again."),
            ))
            .into_response();
        }
    };
    let channel = query.channel.as_deref().unwrap_or("email");
    Html(templates::two_factor_page(
        &query.request_uri,
        channel,
        None,
    ))
    .into_response()
}

pub async fn authorize_2fa_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<Authorize2faSubmit>,
) -> Response {
    let client_ip = extract_client_ip(&headers);
    if !state
        .check_rate_limit(RateLimitKind::OAuthAuthorize, &client_ip)
        .await
    {
        tracing::warn!(ip = %client_ip, "OAuth 2FA rate limit exceeded");
        return (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            Html(templates::error_page(
                "RateLimitExceeded",
                Some("Too many attempts. Please try again later."),
            )),
        )
            .into_response();
    }
    let challenge = match db::get_2fa_challenge(&state.db, &form.request_uri).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return Html(templates::error_page(
                "invalid_request",
                Some("No 2FA challenge found. Please start over."),
            ))
            .into_response();
        }
        Err(_) => {
            return Html(templates::error_page(
                "server_error",
                Some("An error occurred. Please try again."),
            ))
            .into_response();
        }
    };
    if challenge.expires_at < Utc::now() {
        let _ = db::delete_2fa_challenge(&state.db, challenge.id).await;
        return Html(templates::error_page(
            "invalid_request",
            Some("2FA code has expired. Please start over."),
        ))
        .into_response();
    }
    if challenge.attempts >= MAX_2FA_ATTEMPTS {
        let _ = db::delete_2fa_challenge(&state.db, challenge.id).await;
        return Html(templates::error_page(
            "access_denied",
            Some("Too many failed attempts. Please start over."),
        ))
        .into_response();
    }
    let code_valid: bool = form
        .code
        .trim()
        .as_bytes()
        .ct_eq(challenge.code.as_bytes())
        .into();
    if !code_valid {
        let _ = db::increment_2fa_attempts(&state.db, challenge.id).await;
        let channel = match sqlx::query_scalar!(
            r#"SELECT preferred_comms_channel as "channel: CommsChannel" FROM users WHERE did = $1"#,
            challenge.did
        )
        .fetch_optional(&state.db)
        .await
        {
            Ok(Some(ch)) => channel_display_name(ch).to_string(),
            Ok(None) | Err(_) => "email".to_string(),
        };
        let _request_data = match db::get_authorization_request(&state.db, &form.request_uri).await
        {
            Ok(Some(d)) => d,
            Ok(None) => {
                return Html(templates::error_page(
                    "invalid_request",
                    Some("Authorization request not found. Please start over."),
                ))
                .into_response();
            }
            Err(_) => {
                return Html(templates::error_page(
                    "server_error",
                    Some("An error occurred. Please try again."),
                ))
                .into_response();
            }
        };
        return Html(templates::two_factor_page(
            &form.request_uri,
            &channel,
            Some("Invalid verification code. Please try again."),
        ))
        .into_response();
    }
    let _ = db::delete_2fa_challenge(&state.db, challenge.id).await;
    let request_data = match db::get_authorization_request(&state.db, &form.request_uri).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            return Html(templates::error_page(
                "invalid_request",
                Some("Authorization request not found."),
            ))
            .into_response();
        }
        Err(_) => {
            return Html(templates::error_page(
                "server_error",
                Some("An error occurred."),
            ))
            .into_response();
        }
    };
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
        return Html(templates::error_page(
            "server_error",
            Some("An error occurred. Please try again."),
        ))
        .into_response();
    }
    let redirect_url = build_success_redirect(
        &request_data.parameters.redirect_uri,
        &code.0,
        request_data.parameters.state.as_deref(),
    );
    redirect_see_other(&redirect_url)
}
