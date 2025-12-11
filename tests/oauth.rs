mod common;
mod helpers;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use common::{base_url, client, create_account_and_login};
use reqwest::{redirect, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use wiremock::{Mock, MockServer, ResponseTemplate};
use wiremock::matchers::{method, path};

fn no_redirect_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(redirect::Policy::none())
        .build()
        .unwrap()
}

fn generate_pkce() -> (String, String) {
    let verifier_bytes: [u8; 32] = rand::random();
    let code_verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let hash = hasher.finalize();
    let code_challenge = URL_SAFE_NO_PAD.encode(&hash);

    (code_verifier, code_challenge)
}

async fn setup_mock_client_metadata(redirect_uri: &str) -> MockServer {
    let mock_server = MockServer::start().await;

    let client_id = mock_server.uri();
    let metadata = json!({
        "client_id": client_id,
        "client_name": "Test OAuth Client",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "dpop_bound_access_tokens": false
    });

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
        .mount(&mock_server)
        .await;

    mock_server
}

#[allow(dead_code)]
async fn setup_mock_dpop_client(redirect_uri: &str) -> MockServer {
    let mock_server = MockServer::start().await;

    let client_id = mock_server.uri();
    let metadata = json!({
        "client_id": client_id,
        "client_name": "DPoP Test Client",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "dpop_bound_access_tokens": true
    });

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
        .mount(&mock_server)
        .await;

    mock_server
}

#[tokio::test]
async fn test_oauth_protected_resource_metadata() {
    let url = base_url().await;
    let client = client();

    let res = client
        .get(format!("{}/.well-known/oauth-protected-resource", url))
        .send()
        .await
        .expect("Failed to fetch protected resource metadata");

    assert_eq!(res.status(), StatusCode::OK);

    let body: Value = res.json().await.expect("Invalid JSON");

    assert!(body["resource"].is_string());
    assert!(body["authorization_servers"].is_array());
    assert!(body["bearer_methods_supported"].is_array());

    let bearer_methods = body["bearer_methods_supported"].as_array().unwrap();
    assert!(bearer_methods.contains(&json!("header")));
}

#[tokio::test]
async fn test_oauth_authorization_server_metadata() {
    let url = base_url().await;
    let client = client();

    let res = client
        .get(format!("{}/.well-known/oauth-authorization-server", url))
        .send()
        .await
        .expect("Failed to fetch authorization server metadata");

    assert_eq!(res.status(), StatusCode::OK);

    let body: Value = res.json().await.expect("Invalid JSON");

    assert!(body["issuer"].is_string());
    assert!(body["authorization_endpoint"].is_string());
    assert!(body["token_endpoint"].is_string());
    assert!(body["jwks_uri"].is_string());

    let response_types = body["response_types_supported"].as_array().unwrap();
    assert!(response_types.contains(&json!("code")));

    let grant_types = body["grant_types_supported"].as_array().unwrap();
    assert!(grant_types.contains(&json!("authorization_code")));
    assert!(grant_types.contains(&json!("refresh_token")));

    let code_challenge_methods = body["code_challenge_methods_supported"].as_array().unwrap();
    assert!(code_challenge_methods.contains(&json!("S256")));

    assert_eq!(body["require_pushed_authorization_requests"], json!(true));

    let dpop_algs = body["dpop_signing_alg_values_supported"].as_array().unwrap();
    assert!(dpop_algs.contains(&json!("ES256")));
}

#[tokio::test]
async fn test_oauth_jwks_endpoint() {
    let url = base_url().await;
    let client = client();

    let res = client
        .get(format!("{}/oauth/jwks", url))
        .send()
        .await
        .expect("Failed to fetch JWKS");

    assert_eq!(res.status(), StatusCode::OK);

    let body: Value = res.json().await.expect("Invalid JSON");
    assert!(body["keys"].is_array());
}

#[tokio::test]
async fn test_par_success() {
    let url = base_url().await;
    let client = client();

    let redirect_uri = "https://example.com/callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();

    let (_code_verifier, code_challenge) = generate_pkce();

    let res = client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
            ("scope", "atproto"),
            ("state", "test-state-123"),
        ])
        .send()
        .await
        .expect("Failed to send PAR request");

    assert_eq!(res.status(), StatusCode::OK, "PAR should succeed: {:?}", res.text().await);

    let body: Value = client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
            ("scope", "atproto"),
            ("state", "test-state-123"),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .expect("Invalid JSON");

    assert!(body["request_uri"].is_string());
    assert!(body["expires_in"].is_number());

    let request_uri = body["request_uri"].as_str().unwrap();
    assert!(request_uri.starts_with("urn:ietf:params:oauth:request_uri:"));
}

#[tokio::test]
async fn test_par_requires_pkce() {
    let url = base_url().await;
    let client = client();

    let redirect_uri = "https://example.com/callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();

    let res = client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("scope", "atproto"),
        ])
        .send()
        .await
        .expect("Failed to send PAR request");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn test_par_requires_s256() {
    let url = base_url().await;
    let client = client();

    let redirect_uri = "https://example.com/callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();

    let res = client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", "test-challenge"),
            ("code_challenge_method", "plain"),
        ])
        .send()
        .await
        .expect("Failed to send PAR request");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["error"], "invalid_request");
    assert!(body["error_description"].as_str().unwrap().contains("S256"));
}

#[tokio::test]
async fn test_par_validates_redirect_uri() {
    let url = base_url().await;
    let client = client();

    let registered_redirect = "https://example.com/callback";
    let wrong_redirect = "https://evil.com/steal";
    let mock_client = setup_mock_client_metadata(registered_redirect).await;
    let client_id = mock_client.uri();

    let (_, code_challenge) = generate_pkce();

    let res = client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", wrong_redirect),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .expect("Failed to send PAR request");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn test_authorize_get_with_valid_request_uri() {
    let url = base_url().await;
    let client = client();

    let redirect_uri = "https://example.com/callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();

    let (_, code_challenge) = generate_pkce();

    let par_res = client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
            ("scope", "atproto"),
            ("state", "test-state"),
        ])
        .send()
        .await
        .expect("PAR failed");

    let par_body: Value = par_res.json().await.expect("Invalid PAR JSON");
    let request_uri = par_body["request_uri"].as_str().unwrap();

    let auth_res = client
        .get(format!("{}/oauth/authorize", url))
        .query(&[("request_uri", request_uri)])
        .send()
        .await
        .expect("Authorize GET failed");

    assert_eq!(auth_res.status(), StatusCode::OK);

    let auth_body: Value = auth_res.json().await.expect("Invalid auth JSON");
    assert_eq!(auth_body["client_id"], client_id);
    assert_eq!(auth_body["redirect_uri"], redirect_uri);
    assert_eq!(auth_body["scope"], "atproto");
    assert_eq!(auth_body["state"], "test-state");
}

#[tokio::test]
async fn test_authorize_rejects_invalid_request_uri() {
    let url = base_url().await;
    let client = client();

    let res = client
        .get(format!("{}/oauth/authorize", url))
        .query(&[("request_uri", "urn:ietf:params:oauth:request_uri:nonexistent")])
        .send()
        .await
        .expect("Request failed");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn test_authorize_requires_request_uri() {
    let url = base_url().await;
    let client = client();

    let res = client
        .get(format!("{}/oauth/authorize", url))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_full_oauth_flow_without_dpop() {
    let url = base_url().await;
    let http_client = client();

    let (_, _user_did) = create_account_and_login(&http_client).await;

    let ts = Utc::now().timestamp_millis();
    let handle = format!("oauth-test-{}", ts);
    let email = format!("oauth-test-{}@example.com", ts);
    let password = "oauth-test-password";

    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": password
        }))
        .send()
        .await
        .expect("Account creation failed");

    assert_eq!(create_res.status(), StatusCode::OK);
    let account: Value = create_res.json().await.unwrap();
    let user_did = account["did"].as_str().unwrap();

    let redirect_uri = "https://example.com/oauth/callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();

    let (code_verifier, code_challenge) = generate_pkce();
    let state = format!("state-{}", ts);

    let par_res = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
            ("scope", "atproto"),
            ("state", &state),
        ])
        .send()
        .await
        .expect("PAR failed");

    let par_status = par_res.status();
    let par_text = par_res.text().await.unwrap_or_default();
    if par_status != StatusCode::OK {
        panic!("PAR failed with status {}: {}", par_status, par_text);
    }
    let par_body: Value = serde_json::from_str(&par_text).unwrap();
    let request_uri = par_body["request_uri"].as_str().unwrap();

    let auth_client = no_redirect_client();
    let auth_res = auth_client
        .post(format!("{}/oauth/authorize", url))
        .form(&[
            ("request_uri", request_uri),
            ("username", &handle),
            ("password", password),
            ("remember_device", "false"),
        ])
        .send()
        .await
        .expect("Authorize POST failed");

    let auth_status = auth_res.status();
    if auth_status != StatusCode::TEMPORARY_REDIRECT
        && auth_status != StatusCode::SEE_OTHER
        && auth_status != StatusCode::FOUND
    {
        let auth_text = auth_res.text().await.unwrap_or_default();
        panic!(
            "Expected redirect, got {}: {}",
            auth_status, auth_text
        );
    }

    let location = auth_res.headers().get("location")
        .expect("No Location header")
        .to_str()
        .unwrap();

    assert!(location.starts_with(redirect_uri), "Redirect to wrong URI: {}", location);
    assert!(location.contains("code="), "No code in redirect: {}", location);
    assert!(location.contains(&format!("state={}", state)), "Wrong state in redirect");

    let code = location
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();

    let token_res = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", &code_verifier),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .expect("Token request failed");

    let token_status = token_res.status();
    let token_text = token_res.text().await.unwrap_or_default();
    if token_status != StatusCode::OK {
        panic!("Token request failed with status {}: {}", token_status, token_text);
    }

    let token_body: Value = serde_json::from_str(&token_text).unwrap();

    assert!(token_body["access_token"].is_string());
    assert!(token_body["refresh_token"].is_string());
    assert_eq!(token_body["token_type"], "Bearer");
    assert!(token_body["expires_in"].is_number());
    assert_eq!(token_body["sub"], user_did);
}

#[tokio::test]
async fn test_token_refresh_flow() {
    let url = base_url().await;
    let http_client = client();

    let ts = Utc::now().timestamp_millis();
    let handle = format!("refresh-test-{}", ts);
    let email = format!("refresh-test-{}@example.com", ts);
    let password = "refresh-test-password";

    http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": password
        }))
        .send()
        .await
        .expect("Account creation failed");

    let redirect_uri = "https://example.com/refresh-callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();

    let (code_verifier, code_challenge) = generate_pkce();

    let par_body: Value = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let request_uri = par_body["request_uri"].as_str().unwrap();

    let auth_client = no_redirect_client();
    let auth_res = auth_client
        .post(format!("{}/oauth/authorize", url))
        .form(&[
            ("request_uri", request_uri),
            ("username", &handle),
            ("password", password),
            ("remember_device", "false"),
        ])
        .send()
        .await
        .unwrap();

    let location = auth_res.headers().get("location").unwrap().to_str().unwrap();
    let code = location.split("code=").nth(1).unwrap().split('&').next().unwrap();

    let token_body: Value = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", &code_verifier),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let refresh_token = token_body["refresh_token"].as_str().unwrap();
    let original_access_token = token_body["access_token"].as_str().unwrap();

    let refresh_res = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .expect("Refresh request failed");

    assert_eq!(refresh_res.status(), StatusCode::OK);

    let refresh_body: Value = refresh_res.json().await.unwrap();

    assert!(refresh_body["access_token"].is_string());
    assert!(refresh_body["refresh_token"].is_string());

    let new_access_token = refresh_body["access_token"].as_str().unwrap();
    let new_refresh_token = refresh_body["refresh_token"].as_str().unwrap();

    assert_ne!(new_access_token, original_access_token, "Access token should rotate");
    assert_ne!(new_refresh_token, refresh_token, "Refresh token should rotate");
}

#[tokio::test]
async fn test_refresh_token_reuse_detection() {
    let url = base_url().await;
    let http_client = client();

    let ts = Utc::now().timestamp_millis();
    let handle = format!("reuse-test-{}", ts);
    let email = format!("reuse-test-{}@example.com", ts);
    let password = "reuse-test-password";

    http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": password
        }))
        .send()
        .await
        .unwrap();

    let redirect_uri = "https://example.com/reuse-callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();

    let (code_verifier, code_challenge) = generate_pkce();

    let par_body: Value = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let request_uri = par_body["request_uri"].as_str().unwrap();

    let auth_client = no_redirect_client();
    let auth_res = auth_client
        .post(format!("{}/oauth/authorize", url))
        .form(&[
            ("request_uri", request_uri),
            ("username", &handle),
            ("password", password),
            ("remember_device", "false"),
        ])
        .send()
        .await
        .unwrap();

    let location = auth_res.headers().get("location").unwrap().to_str().unwrap();
    let code = location.split("code=").nth(1).unwrap().split('&').next().unwrap();

    let token_body: Value = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", &code_verifier),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let original_refresh_token = token_body["refresh_token"].as_str().unwrap().to_string();

    let first_refresh: Value = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &original_refresh_token),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(first_refresh["access_token"].is_string(), "First refresh should succeed");

    let reuse_res = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &original_refresh_token),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(reuse_res.status(), StatusCode::BAD_REQUEST, "Reuse should be rejected");

    let reuse_body: Value = reuse_res.json().await.unwrap();
    assert_eq!(reuse_body["error"], "invalid_grant");
    assert!(
        reuse_body["error_description"].as_str().unwrap().to_lowercase().contains("reuse"),
        "Error should mention reuse"
    );
}

#[tokio::test]
async fn test_pkce_verification() {
    let url = base_url().await;
    let http_client = client();

    let ts = Utc::now().timestamp_millis();
    let handle = format!("pkce-test-{}", ts);
    let email = format!("pkce-test-{}@example.com", ts);
    let password = "pkce-test-password";

    http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": password
        }))
        .send()
        .await
        .unwrap();

    let redirect_uri = "https://example.com/pkce-callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();

    let (_, code_challenge) = generate_pkce();
    let wrong_verifier = "wrong-code-verifier-that-does-not-match";

    let par_body: Value = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let request_uri = par_body["request_uri"].as_str().unwrap();

    let auth_client = no_redirect_client();
    let auth_res = auth_client
        .post(format!("{}/oauth/authorize", url))
        .form(&[
            ("request_uri", request_uri),
            ("username", &handle),
            ("password", password),
            ("remember_device", "false"),
        ])
        .send()
        .await
        .unwrap();

    let location = auth_res.headers().get("location").unwrap().to_str().unwrap();
    let code = location.split("code=").nth(1).unwrap().split('&').next().unwrap();

    let token_res = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", wrong_verifier),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(token_res.status(), StatusCode::BAD_REQUEST);

    let token_body: Value = token_res.json().await.unwrap();
    assert_eq!(token_body["error"], "invalid_grant");
    assert!(token_body["error_description"].as_str().unwrap().contains("PKCE"));
}

#[tokio::test]
async fn test_authorization_code_cannot_be_reused() {
    let url = base_url().await;
    let http_client = client();

    let ts = Utc::now().timestamp_millis();
    let handle = format!("code-reuse-{}", ts);
    let email = format!("code-reuse-{}@example.com", ts);
    let password = "code-reuse-password";

    http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": password
        }))
        .send()
        .await
        .unwrap();

    let redirect_uri = "https://example.com/code-reuse-callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();

    let (code_verifier, code_challenge) = generate_pkce();

    let par_body: Value = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let request_uri = par_body["request_uri"].as_str().unwrap();

    let auth_client = no_redirect_client();
    let auth_res = auth_client
        .post(format!("{}/oauth/authorize", url))
        .form(&[
            ("request_uri", request_uri),
            ("username", &handle),
            ("password", password),
            ("remember_device", "false"),
        ])
        .send()
        .await
        .unwrap();

    let location = auth_res.headers().get("location").unwrap().to_str().unwrap();
    let code = location.split("code=").nth(1).unwrap().split('&').next().unwrap();

    let first_token_res = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", &code_verifier),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(first_token_res.status(), StatusCode::OK, "First use should succeed");

    let second_token_res = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", &code_verifier),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(second_token_res.status(), StatusCode::BAD_REQUEST, "Second use should fail");

    let error_body: Value = second_token_res.json().await.unwrap();
    assert_eq!(error_body["error"], "invalid_grant");
}

#[tokio::test]
async fn test_wrong_credentials_denied() {
    let url = base_url().await;
    let http_client = client();

    let ts = Utc::now().timestamp_millis();
    let handle = format!("wrong-creds-{}", ts);
    let email = format!("wrong-creds-{}@example.com", ts);
    let password = "correct-password";

    http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": password
        }))
        .send()
        .await
        .unwrap();

    let redirect_uri = "https://example.com/wrong-creds-callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();

    let (_, code_challenge) = generate_pkce();

    let par_body: Value = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let request_uri = par_body["request_uri"].as_str().unwrap();

    let auth_res = http_client
        .post(format!("{}/oauth/authorize", url))
        .form(&[
            ("request_uri", request_uri),
            ("username", &handle),
            ("password", "wrong-password"),
            ("remember_device", "false"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(auth_res.status(), StatusCode::FORBIDDEN);

    let error_body: Value = auth_res.json().await.unwrap();
    assert_eq!(error_body["error"], "access_denied");
}

#[tokio::test]
async fn test_token_revocation() {
    let url = base_url().await;
    let http_client = client();

    let ts = Utc::now().timestamp_millis();
    let handle = format!("revoke-test-{}", ts);
    let email = format!("revoke-test-{}@example.com", ts);
    let password = "revoke-test-password";

    http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": password
        }))
        .send()
        .await
        .unwrap();

    let redirect_uri = "https://example.com/revoke-callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();

    let (code_verifier, code_challenge) = generate_pkce();

    let par_body: Value = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let request_uri = par_body["request_uri"].as_str().unwrap();

    let auth_client = no_redirect_client();
    let auth_res = auth_client
        .post(format!("{}/oauth/authorize", url))
        .form(&[
            ("request_uri", request_uri),
            ("username", &handle),
            ("password", password),
            ("remember_device", "false"),
        ])
        .send()
        .await
        .unwrap();

    let location = auth_res.headers().get("location").unwrap().to_str().unwrap();
    let code = location.split("code=").nth(1).unwrap().split('&').next().unwrap();

    let token_body: Value = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", &code_verifier),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let refresh_token = token_body["refresh_token"].as_str().unwrap();

    let revoke_res = http_client
        .post(format!("{}/oauth/revoke", url))
        .form(&[("token", refresh_token)])
        .send()
        .await
        .unwrap();

    assert_eq!(revoke_res.status(), StatusCode::OK);

    let refresh_after_revoke = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(refresh_after_revoke.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_unsupported_grant_type() {
    let url = base_url().await;
    let http_client = client();

    let res = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "https://example.com"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "unsupported_grant_type");
}

#[tokio::test]
async fn test_invalid_refresh_token() {
    let url = base_url().await;
    let http_client = client();

    let res = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", "invalid-refresh-token"),
            ("client_id", "https://example.com"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn test_deactivated_account_cannot_authorize() {
    let url = base_url().await;
    let http_client = client();

    let ts = Utc::now().timestamp_millis();
    let handle = format!("deact-oauth-{}", ts);
    let email = format!("deact-oauth-{}@example.com", ts);
    let password = "deact-oauth-password";

    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": password
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(create_res.status(), StatusCode::OK);
    let account: Value = create_res.json().await.unwrap();
    let access_jwt = account["accessJwt"].as_str().unwrap();

    let deact_res = http_client
        .post(format!("{}/xrpc/com.atproto.server.deactivateAccount", url))
        .header("Authorization", format!("Bearer {}", access_jwt))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(deact_res.status(), StatusCode::OK);

    let redirect_uri = "https://example.com/deact-callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();

    let (_, code_challenge) = generate_pkce();

    let par_body: Value = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let request_uri = par_body["request_uri"].as_str().unwrap();

    let auth_res = http_client
        .post(format!("{}/oauth/authorize", url))
        .form(&[
            ("request_uri", request_uri),
            ("username", &handle),
            ("password", password),
            ("remember_device", "false"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(auth_res.status(), StatusCode::FORBIDDEN, "Deactivated account should not be able to authorize");
    let body: Value = auth_res.json().await.unwrap();
    assert_eq!(body["error"], "access_denied");
}

#[tokio::test]
async fn test_expired_authorization_request() {
    let url = base_url().await;
    let http_client = client();

    let res = http_client
        .get(format!("{}/oauth/authorize", url))
        .query(&[("request_uri", "urn:ietf:params:oauth:request_uri:expired-or-nonexistent")])
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn test_token_introspection() {
    let url = base_url().await;
    let http_client = client();

    let ts = Utc::now().timestamp_millis();
    let handle = format!("introspect-{}", ts);
    let email = format!("introspect-{}@example.com", ts);
    let password = "introspect-password";

    http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": password
        }))
        .send()
        .await
        .unwrap();

    let redirect_uri = "https://example.com/introspect-callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();

    let (code_verifier, code_challenge) = generate_pkce();

    let par_body: Value = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let request_uri = par_body["request_uri"].as_str().unwrap();

    let auth_client = no_redirect_client();
    let auth_res = auth_client
        .post(format!("{}/oauth/authorize", url))
        .form(&[
            ("request_uri", request_uri),
            ("username", &handle),
            ("password", password),
            ("remember_device", "false"),
        ])
        .send()
        .await
        .unwrap();

    let location = auth_res.headers().get("location").unwrap().to_str().unwrap();
    let code = location.split("code=").nth(1).unwrap().split('&').next().unwrap();

    let token_body: Value = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", &code_verifier),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let access_token = token_body["access_token"].as_str().unwrap();

    let introspect_res = http_client
        .post(format!("{}/oauth/introspect", url))
        .form(&[("token", access_token)])
        .send()
        .await
        .unwrap();

    assert_eq!(introspect_res.status(), StatusCode::OK);
    let introspect_body: Value = introspect_res.json().await.unwrap();
    assert_eq!(introspect_body["active"], true);
    assert!(introspect_body["client_id"].is_string());
    assert!(introspect_body["exp"].is_number());
}

#[tokio::test]
async fn test_introspect_invalid_token() {
    let url = base_url().await;
    let http_client = client();

    let res = http_client
        .post(format!("{}/oauth/introspect", url))
        .form(&[("token", "invalid.token.here")])
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["active"], false);
}

#[tokio::test]
async fn test_introspect_revoked_token() {
    let url = base_url().await;
    let http_client = client();

    let ts = Utc::now().timestamp_millis();
    let handle = format!("introspect-revoked-{}", ts);
    let email = format!("introspect-revoked-{}@example.com", ts);
    let password = "introspect-revoked-password";

    http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": password
        }))
        .send()
        .await
        .unwrap();

    let redirect_uri = "https://example.com/introspect-revoked-callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();

    let (code_verifier, code_challenge) = generate_pkce();

    let par_body: Value = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let request_uri = par_body["request_uri"].as_str().unwrap();

    let auth_client = no_redirect_client();
    let auth_res = auth_client
        .post(format!("{}/oauth/authorize", url))
        .form(&[
            ("request_uri", request_uri),
            ("username", &handle),
            ("password", password),
            ("remember_device", "false"),
        ])
        .send()
        .await
        .unwrap();

    let location = auth_res.headers().get("location").unwrap().to_str().unwrap();
    let code = location.split("code=").nth(1).unwrap().split('&').next().unwrap();

    let token_body: Value = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", &code_verifier),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let access_token = token_body["access_token"].as_str().unwrap();
    let refresh_token = token_body["refresh_token"].as_str().unwrap();

    http_client
        .post(format!("{}/oauth/revoke", url))
        .form(&[("token", refresh_token)])
        .send()
        .await
        .unwrap();

    let introspect_res = http_client
        .post(format!("{}/oauth/introspect", url))
        .form(&[("token", access_token)])
        .send()
        .await
        .unwrap();

    assert_eq!(introspect_res.status(), StatusCode::OK);
    let body: Value = introspect_res.json().await.unwrap();
    assert_eq!(body["active"], false, "Revoked token should be inactive");
}

#[tokio::test]
async fn test_state_with_special_chars() {
    let url = base_url().await;
    let http_client = client();

    let ts = Utc::now().timestamp_millis();
    let handle = format!("state-special-{}", ts);
    let email = format!("state-special-{}@example.com", ts);
    let password = "state-special-password";

    http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": password
        }))
        .send()
        .await
        .unwrap();

    let redirect_uri = "https://example.com/state-special-callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();

    let (_code_verifier, code_challenge) = generate_pkce();
    let special_state = "state=with&special=chars&plus+more";

    let par_body: Value = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
            ("state", special_state),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let request_uri = par_body["request_uri"].as_str().unwrap();

    let auth_client = no_redirect_client();
    let auth_res = auth_client
        .post(format!("{}/oauth/authorize", url))
        .form(&[
            ("request_uri", request_uri),
            ("username", &handle),
            ("password", password),
            ("remember_device", "false"),
        ])
        .send()
        .await
        .unwrap();

    assert!(
        auth_res.status().is_redirection(),
        "Should redirect even with special chars in state"
    );
    let location = auth_res.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.contains("state="), "State should be in redirect URL");

    let encoded_state = urlencoding::encode(special_state);
    assert!(
        location.contains(&format!("state={}", encoded_state)),
        "State should be URL-encoded. Got: {}",
        location
    );
}
