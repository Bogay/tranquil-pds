use axum::{
    Json,
    extract::{Query, State},
    http::{
        HeaderMap, StatusCode,
        header::{CACHE_CONTROL, CONTENT_TYPE, LOCATION, SET_COOKIE},
    },
    response::{IntoResponse, Response},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tranquil_db_traits::{ScopePreference, WebauthnChallengeType};
use tranquil_pds::auth::{BareLoginIdentifier, NormalizedLoginIdentifier};
use tranquil_pds::oauth::{
    AuthFlow, AuthStage, DeviceData, DeviceId, OAuthError, Prompt, SessionId,
    db::should_show_consent,
};
use tranquil_pds::rate_limit::{
    OAuthAuthorizeLimit, OAuthRateLimited, OAuthRegisterCompleteLimit, TotpVerifyLimit,
    check_user_rate_limit,
};
use tranquil_pds::state::AppState;
use tranquil_pds::types::{Did, Handle, PlainPassword};
use tranquil_pds::util::ClientIp;
use tranquil_types::{AuthorizationCode, ClientId, RequestId};
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

enum StoreCodeError {
    RequestChanged,
    Failed,
}

impl StoreCodeError {
    fn description(&self) -> &'static str {
        match self {
            StoreCodeError::RequestChanged => "Authorization request changed. Please start over.",
            StoreCodeError::Failed => "An error occurred. Please try again.",
        }
    }

    fn into_response(self) -> Response {
        match self {
            StoreCodeError::RequestChanged => {
                json_error(StatusCode::CONFLICT, "invalid_request", self.description())
            }
            StoreCodeError::Failed => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                self.description(),
            ),
        }
    }
}

async fn store_authorization_code(
    state: &AppState,
    request_id: &RequestId,
    did: &Did,
    controller_did: Option<&Did>,
    device_id: Option<&DeviceId>,
) -> Result<AuthorizationCode, StoreCodeError> {
    let code = AuthorizationCode::generate();
    match state
        .repos
        .oauth
        .update_authorization_request(request_id, did, controller_did, device_id, &code)
        .await
    {
        Ok(true) => Ok(code),
        Ok(false) => {
            tracing::warn!(request_id = %request_id.as_str(), did = %did, "Authorization request changed before code was issued");
            Err(StoreCodeError::RequestChanged)
        }
        Err(e) => {
            tracing::error!(error = ?e, request_id = %request_id.as_str(), "Failed to store authorization code");
            Err(StoreCodeError::Failed)
        }
    }
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

pub(crate) fn extract_device_cookie(headers: &HeaderMap) -> Option<tranquil_types::DeviceId> {
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

const COOKIE_TEST_NAME: &str = "cookie-test";
const COOKIE_TEST_PERSISTENCE_SECONDS: i64 = 31 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CookieTest {
    Testing,
    Succeeded,
}

impl CookieTest {
    fn token(self) -> &'static str {
        match self {
            CookieTest::Testing => "testing",
            CookieTest::Succeeded => "succeeded",
        }
    }
}

fn extract_cookie_test(headers: &HeaderMap) -> Option<CookieTest> {
    let value = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookie_str| {
            cookie_str
                .split(';')
                .map(str::trim)
                .find_map(|cookie| cookie.strip_prefix(&format!("{COOKIE_TEST_NAME}=")))
        })?;
    [CookieTest::Testing, CookieTest::Succeeded]
        .into_iter()
        .find(|test| test.token() == value)
}

fn make_cookie_test(test: CookieTest) -> String {
    let base = format!(
        "{}={}; Path=/oauth; HttpOnly; Secure; SameSite=Lax",
        COOKIE_TEST_NAME,
        test.token()
    );
    match test {
        CookieTest::Testing => base,
        CookieTest::Succeeded => format!("{base}; Max-Age={COOKIE_TEST_PERSISTENCE_SECONDS}"),
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn build_form_redirect_html(raw_query: Option<&str>, extra_params: &[(&str, &str)]) -> String {
    let mut inputs = String::new();
    if let Some(query_str) = raw_query {
        for pair in query_str.split('&') {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next().unwrap_or("");
            let value = parts.next().unwrap_or("");
            if key.is_empty() {
                continue;
            }
            if extra_params.iter().any(|(k, _)| *k == key) {
                continue;
            }
            inputs.push_str(&format!(
                "<input type=\"hidden\" name=\"{}\" value=\"{}\" />",
                html_escape(key),
                html_escape(&urlencoding::decode(value).unwrap_or_else(|_| value.into()))
            ));
        }
    }
    for (name, value) in extra_params {
        inputs.push_str(&format!(
            "<input type=\"hidden\" name=\"{}\" value=\"{}\" />",
            html_escape(name),
            html_escape(value)
        ));
    }
    format!(
        "<!DOCTYPE html>\
<html lang=\"en\">\
<head><meta charset=\"utf-8\"></head>\
<body>\
<form method=\"GET\" action=\"/oauth/authorize\">\
{}\
</form>\
<script>document.forms[0].submit()</script>\
</body>\
</html>",
        inputs
    )
}

fn cookie_retry_html(continue_url: &str) -> String {
    format!(
        "<!DOCTYPE html>\
<html lang=\"en\">\
<head>\
<meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>Cookies Required</title>\
</head>\
<body>\
<h1>Cookies Required</h1>\
<p>This browser may not support cookies needed for auth! Please enable cookies in your browser settings.</p>\
<hr>\
<br>\
<p>Have a nice day or whateva</p>\
<p><a href=\"{}\">Continue</a></p>\
</body>\
</html>",
        html_escape(continue_url)
    )
}

fn make_device_cookie(device_id: &tranquil_types::DeviceId) -> String {
    let signed_value = tranquil_pds::config::AuthConfig::get().sign_device_cookie(device_id);
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
    #[serde(rename = "redirect-test")]
    pub redirect_test: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthorizeResponse {
    pub client_id: ClientId,
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
pub mod scope_resolution;
mod two_factor;

pub use consent::*;
pub use login::*;
pub use passkey::*;
pub use registration::*;
pub use two_factor::*;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    fn cookie_headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn cookie_test_extracted_from_surrounding_cookies() {
        let headers =
            cookie_headers("oauth_device_id=nekomilker; cookie-test=testing; milk=strange");
        assert_eq!(extract_cookie_test(&headers), Some(CookieTest::Testing));
    }

    #[test]
    fn cookie_test_missing_leaves_none() {
        let headers = cookie_headers("oauth_device_id=nekomilker");
        assert_eq!(extract_cookie_test(&headers), None);
    }

    #[test]
    fn cookie_test_name_is_not_a_prefix_match() {
        let headers = cookie_headers("cookie-test-nekomilk=1");
        assert_eq!(extract_cookie_test(&headers), None);
    }

    #[test]
    fn unexpected_cookie_test_value_is_not_survival_evidence() {
        let headers = cookie_headers("cookie-test=nekomilk");
        assert_eq!(extract_cookie_test(&headers), None);
    }

    #[test]
    fn testing_cookie_expires_and_success_cookie_persists() {
        let testing = make_cookie_test(CookieTest::Testing);
        assert!(testing.starts_with("cookie-test=testing"));
        assert!(testing.contains("Path=/oauth"));
        assert!(testing.contains("HttpOnly"));
        assert!(!testing.contains("Max-Age"));
        let succeeded = make_cookie_test(CookieTest::Succeeded);
        assert!(succeeded.contains("Max-Age=2678400"));
    }

    #[test]
    fn form_redirect_forwards_and_escapes_query_params() {
        let html = build_form_redirect_html(
            Some("request_uri=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E&client_id=web"),
            &[("redirect-test", "1")],
        );
        assert!(html.contains("name=\"request_uri\""));
        assert!(html.contains("name=\"client_id\""));
        assert!(html.contains("value=\"&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;\""));
        assert!(html.contains("name=\"redirect-test\" value=\"1\""));
    }

    #[test]
    fn form_redirect_extra_param_wins_over_query_duplicate() {
        let html = build_form_redirect_html(
            Some("redirect-test=9&request_uri=uri"),
            &[("redirect-test", "1")],
        );
        assert_eq!(html.matches("name=\"redirect-test\"").count(), 1);
        assert!(html.contains("value=\"1\""));
    }

    #[test]
    fn retry_page_escapes_the_continue_url() {
        let html = cookie_retry_html("\"><script>alert(1)</script>");
        assert!(!html.contains("<script>"));
        assert!(html.contains("href=\"&quot;&gt;&lt;script&gt;"));
        assert!(html.contains("Cookies Required"));
    }
}
