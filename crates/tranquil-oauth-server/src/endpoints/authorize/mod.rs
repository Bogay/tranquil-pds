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
use tranquil_pds::auth::{BareLoginIdentifier, NormalizedLoginIdentifier};
use tranquil_pds::comms::comms_repo::enqueue_2fa_code;
use tranquil_pds::oauth::{
    AuthFlow, ClientMetadataCache, Code, DeviceData, DeviceId, OAuthError, Prompt, SessionId,
    db::should_show_consent, scopes::expand_include_scopes,
};
use tranquil_pds::rate_limit::{
    OAuthAuthorizeLimit, OAuthRateLimited, OAuthRegisterCompleteLimit, TotpVerifyLimit,
    check_user_rate_limit,
};
use tranquil_pds::state::AppState;
use tranquil_pds::types::{Did, Handle, PlainPassword};
use tranquil_pds::util::extract_client_ip;
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
                    .and_then(|value| {
                        tranquil_pds::config::AuthConfig::get().verify_device_cookie(value)
                    })
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
    let signed_value =
        tranquil_pds::config::AuthConfig::get().sign_device_cookie(device_id.as_str());
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

pub async fn authorize_deny(
    State(state): State<AppState>,
    Json(form): Json<AuthorizeDenyForm>,
) -> Response {
    let deny_request_id = RequestId::from(form.request_uri.clone());
    let request_data = match state
        .repos
        .oauth
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
        .repos
        .oauth
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

mod consent;
mod login;
mod passkey;
mod registration;
mod two_factor;

pub use consent::*;
pub use login::*;
pub use passkey::*;
pub use registration::*;
pub use two_factor::*;
