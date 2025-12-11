use axum::{
    Form, Json,
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use urlencoding::encode as url_encode;

use crate::state::AppState;
use crate::oauth::{Code, DeviceData, DeviceId, OAuthError, SessionId, db};

fn extract_client_ip(headers: &HeaderMap) -> String {
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(value) = forwarded.to_str() {
            if let Some(first_ip) = value.split(',').next() {
                return first_ip.trim().to_string();
            }
        }
    }

    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(value) = real_ip.to_str() {
            return value.trim().to_string();
        }
    }

    "0.0.0.0".to_string()
}

fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub request_uri: Option<String>,
    pub client_id: Option<String>,
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

pub async fn authorize_get(
    State(state): State<AppState>,
    Query(query): Query<AuthorizeQuery>,
) -> Result<Json<AuthorizeResponse>, OAuthError> {
    let request_uri = query.request_uri.ok_or_else(|| {
        OAuthError::InvalidRequest("request_uri is required".to_string())
    })?;

    let request_data = db::get_authorization_request(&state.db, &request_uri)
        .await?
        .ok_or_else(|| OAuthError::InvalidRequest("Invalid or expired request_uri".to_string()))?;

    if request_data.expires_at < Utc::now() {
        db::delete_authorization_request(&state.db, &request_uri).await?;
        return Err(OAuthError::InvalidRequest("request_uri has expired".to_string()));
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
) -> Result<Response, OAuthError> {
    let request_data = db::get_authorization_request(&state.db, &form.request_uri)
        .await?
        .ok_or_else(|| OAuthError::InvalidRequest("Invalid or expired request_uri".to_string()))?;

    if request_data.expires_at < Utc::now() {
        db::delete_authorization_request(&state.db, &form.request_uri).await?;
        return Err(OAuthError::InvalidRequest("request_uri has expired".to_string()));
    }

    let user = sqlx::query!(
        r#"
        SELECT did, password_hash, deactivated_at, takedown_ref
        FROM users
        WHERE handle = $1 OR email = $1
        "#,
        form.username
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| OAuthError::ServerError(e.to_string()))?
    .ok_or_else(|| OAuthError::AccessDenied("Invalid credentials".to_string()))?;

    if user.deactivated_at.is_some() {
        return Err(OAuthError::AccessDenied("Account is deactivated".to_string()));
    }

    if user.takedown_ref.is_some() {
        return Err(OAuthError::AccessDenied("Account is taken down".to_string()));
    }

    let password_valid = bcrypt::verify(&form.password, &user.password_hash)
        .map_err(|_| OAuthError::ServerError("Password verification failed".to_string()))?;

    if !password_valid {
        return Err(OAuthError::AccessDenied("Invalid credentials".to_string()));
    }

    let code = Code::generate();
    let mut device_id: Option<String> = None;

    if form.remember_device {
        let new_device_id = DeviceId::generate();
        let device_data = DeviceData {
            session_id: SessionId::generate().0,
            user_agent: extract_user_agent(&headers),
            ip_address: extract_client_ip(&headers),
            last_seen_at: Utc::now(),
        };

        db::create_device(&state.db, &new_device_id.0, &device_data).await?;
        db::upsert_account_device(&state.db, &user.did, &new_device_id.0).await?;
        device_id = Some(new_device_id.0);
    }

    db::update_authorization_request(
        &state.db,
        &form.request_uri,
        &user.did,
        device_id.as_deref(),
        &code.0,
    )
    .await?;

    let redirect_uri = &request_data.parameters.redirect_uri;
    let mut redirect_url = redirect_uri.to_string();

    let separator = if redirect_url.contains('?') { '&' } else { '?' };
    redirect_url.push(separator);
    redirect_url.push_str(&format!("code={}", url_encode(&code.0)));

    if let Some(state) = &request_data.parameters.state {
        redirect_url.push_str(&format!("&state={}", url_encode(state)));
    }

    let pds_hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    redirect_url.push_str(&format!("&iss={}", url_encode(&format!("https://{}", pds_hostname))));

    Ok(Redirect::temporary(&redirect_url).into_response())
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

    Ok(Redirect::temporary(&redirect_url).into_response())
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeDenyForm {
    pub request_uri: String,
}
