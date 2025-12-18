mod common;
mod helpers;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use common::{base_url, client, create_account_and_login, get_db_connection_string};
use reqwest::{StatusCode, redirect};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn no_redirect_client() -> reqwest::Client {
    reqwest::Client::builder().redirect(redirect::Policy::none()).build().unwrap()
}

fn generate_pkce() -> (String, String) {
    let verifier_bytes: [u8; 32] = rand::random();
    let code_verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let code_challenge = URL_SAFE_NO_PAD.encode(&hasher.finalize());
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

#[tokio::test]
async fn test_oauth_metadata_endpoints() {
    let url = base_url().await;
    let client = client();
    let pr_res = client.get(format!("{}/.well-known/oauth-protected-resource", url)).send().await.unwrap();
    assert_eq!(pr_res.status(), StatusCode::OK);
    let pr_body: Value = pr_res.json().await.unwrap();
    assert!(pr_body["resource"].is_string());
    assert!(pr_body["authorization_servers"].is_array());
    assert!(pr_body["bearer_methods_supported"].as_array().unwrap().contains(&json!("header")));
    let as_res = client.get(format!("{}/.well-known/oauth-authorization-server", url)).send().await.unwrap();
    assert_eq!(as_res.status(), StatusCode::OK);
    let as_body: Value = as_res.json().await.unwrap();
    assert!(as_body["issuer"].is_string());
    assert!(as_body["authorization_endpoint"].is_string());
    assert!(as_body["token_endpoint"].is_string());
    assert!(as_body["jwks_uri"].is_string());
    assert!(as_body["response_types_supported"].as_array().unwrap().contains(&json!("code")));
    assert!(as_body["grant_types_supported"].as_array().unwrap().contains(&json!("authorization_code")));
    assert!(as_body["code_challenge_methods_supported"].as_array().unwrap().contains(&json!("S256")));
    assert_eq!(as_body["require_pushed_authorization_requests"], json!(true));
    assert!(as_body["dpop_signing_alg_values_supported"].as_array().unwrap().contains(&json!("ES256")));
    let jwks_res = client.get(format!("{}/oauth/jwks", url)).send().await.unwrap();
    assert_eq!(jwks_res.status(), StatusCode::OK);
    let jwks_body: Value = jwks_res.json().await.unwrap();
    assert!(jwks_body["keys"].is_array());
}

#[tokio::test]
async fn test_par_and_authorize() {
    let url = base_url().await;
    let client = client();
    let redirect_uri = "https://example.com/callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();
    let (_, code_challenge) = generate_pkce();
    let par_res = client
        .post(format!("{}/oauth/par", url))
        .form(&[("response_type", "code"), ("client_id", &client_id), ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge), ("code_challenge_method", "S256"), ("scope", "atproto"), ("state", "test-state")])
        .send().await.unwrap();
    assert_eq!(par_res.status(), StatusCode::CREATED, "PAR should succeed");
    let par_body: Value = par_res.json().await.unwrap();
    assert!(par_body["request_uri"].is_string());
    assert!(par_body["expires_in"].is_number());
    let request_uri = par_body["request_uri"].as_str().unwrap();
    assert!(request_uri.starts_with("urn:ietf:params:oauth:request_uri:"));
    let auth_res = client
        .get(format!("{}/oauth/authorize", url))
        .header("Accept", "application/json")
        .query(&[("request_uri", request_uri)])
        .send().await.unwrap();
    assert_eq!(auth_res.status(), StatusCode::OK);
    let auth_body: Value = auth_res.json().await.unwrap();
    assert_eq!(auth_body["client_id"], client_id);
    assert_eq!(auth_body["redirect_uri"], redirect_uri);
    assert_eq!(auth_body["scope"], "atproto");
    let invalid_res = client
        .get(format!("{}/oauth/authorize", url))
        .header("Accept", "application/json")
        .query(&[("request_uri", "urn:ietf:params:oauth:request_uri:nonexistent")])
        .send().await.unwrap();
    assert_eq!(invalid_res.status(), StatusCode::BAD_REQUEST);
    let missing_res = client.get(format!("{}/oauth/authorize", url)).send().await.unwrap();
    assert_eq!(missing_res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_full_oauth_flow() {
    let url = base_url().await;
    let http_client = client();
    let ts = Utc::now().timestamp_millis();
    let handle = format!("oauth-test-{}", ts);
    let email = format!("oauth-test-{}@example.com", ts);
    let password = "oauth-test-password";
    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({ "handle": handle, "email": email, "password": password }))
        .send().await.unwrap();
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
        .form(&[("response_type", "code"), ("client_id", &client_id), ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge), ("code_challenge_method", "S256"), ("scope", "atproto"), ("state", &state)])
        .send().await.unwrap();
    let par_body: Value = par_res.json().await.unwrap();
    let request_uri = par_body["request_uri"].as_str().unwrap();
    let auth_client = no_redirect_client();
    let auth_res = auth_client
        .post(format!("{}/oauth/authorize", url))
        .form(&[("request_uri", request_uri), ("username", &handle), ("password", password), ("remember_device", "false")])
        .send().await.unwrap();
    assert!(auth_res.status().is_redirection(), "Expected redirect, got {}", auth_res.status());
    let location = auth_res.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with(redirect_uri), "Redirect to wrong URI");
    assert!(location.contains("code="), "No code in redirect");
    assert!(location.contains(&format!("state={}", state)), "Wrong state");
    let code = location.split("code=").nth(1).unwrap().split('&').next().unwrap();
    let token_res = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[("grant_type", "authorization_code"), ("code", code), ("redirect_uri", redirect_uri),
            ("code_verifier", &code_verifier), ("client_id", &client_id)])
        .send().await.unwrap();
    assert_eq!(token_res.status(), StatusCode::OK, "Token exchange failed");
    let token_body: Value = token_res.json().await.unwrap();
    assert!(token_body["access_token"].is_string());
    assert!(token_body["refresh_token"].is_string());
    assert_eq!(token_body["token_type"], "Bearer");
    assert!(token_body["expires_in"].is_number());
    assert_eq!(token_body["sub"], user_did);
    let access_token = token_body["access_token"].as_str().unwrap();
    let refresh_token = token_body["refresh_token"].as_str().unwrap();
    let refresh_res = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[("grant_type", "refresh_token"), ("refresh_token", refresh_token), ("client_id", &client_id)])
        .send().await.unwrap();
    assert_eq!(refresh_res.status(), StatusCode::OK);
    let refresh_body: Value = refresh_res.json().await.unwrap();
    assert_ne!(refresh_body["access_token"].as_str().unwrap(), access_token);
    assert_ne!(refresh_body["refresh_token"].as_str().unwrap(), refresh_token);
    let introspect_res = http_client
        .post(format!("{}/oauth/introspect", url))
        .form(&[("token", refresh_body["access_token"].as_str().unwrap())])
        .send().await.unwrap();
    assert_eq!(introspect_res.status(), StatusCode::OK);
    let introspect_body: Value = introspect_res.json().await.unwrap();
    assert_eq!(introspect_body["active"], true);
    let revoke_res = http_client
        .post(format!("{}/oauth/revoke", url))
        .form(&[("token", refresh_body["refresh_token"].as_str().unwrap())])
        .send().await.unwrap();
    assert_eq!(revoke_res.status(), StatusCode::OK);
    let introspect_after = http_client
        .post(format!("{}/oauth/introspect", url))
        .form(&[("token", refresh_body["access_token"].as_str().unwrap())])
        .send().await.unwrap();
    let after_body: Value = introspect_after.json().await.unwrap();
    assert_eq!(after_body["active"], false, "Revoked token should be inactive");
}

#[tokio::test]
async fn test_oauth_error_cases() {
    let url = base_url().await;
    let http_client = client();
    let ts = Utc::now().timestamp_millis();
    let handle = format!("wrong-creds-{}", ts);
    let email = format!("wrong-creds-{}@example.com", ts);
    http_client.post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({ "handle": handle, "email": email, "password": "correct-password" }))
        .send().await.unwrap();
    let redirect_uri = "https://example.com/callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();
    let (_, code_challenge) = generate_pkce();
    let par_body: Value = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[("response_type", "code"), ("client_id", &client_id), ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge), ("code_challenge_method", "S256")])
        .send().await.unwrap().json().await.unwrap();
    let request_uri = par_body["request_uri"].as_str().unwrap();
    let auth_res = http_client
        .post(format!("{}/oauth/authorize", url))
        .header("Accept", "application/json")
        .form(&[("request_uri", request_uri), ("username", &handle), ("password", "wrong-password"), ("remember_device", "false")])
        .send().await.unwrap();
    assert_eq!(auth_res.status(), StatusCode::FORBIDDEN);
    let error_body: Value = auth_res.json().await.unwrap();
    assert_eq!(error_body["error"], "access_denied");
    let unsupported = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[("grant_type", "client_credentials"), ("client_id", "https://example.com")])
        .send().await.unwrap();
    assert_eq!(unsupported.status(), StatusCode::BAD_REQUEST);
    let body: Value = unsupported.json().await.unwrap();
    assert_eq!(body["error"], "unsupported_grant_type");
    let invalid_refresh = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[("grant_type", "refresh_token"), ("refresh_token", "invalid-token"), ("client_id", "https://example.com")])
        .send().await.unwrap();
    assert_eq!(invalid_refresh.status(), StatusCode::BAD_REQUEST);
    let body: Value = invalid_refresh.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
    let invalid_introspect = http_client
        .post(format!("{}/oauth/introspect", url))
        .form(&[("token", "invalid.token.here")])
        .send().await.unwrap();
    assert_eq!(invalid_introspect.status(), StatusCode::OK);
    let body: Value = invalid_introspect.json().await.unwrap();
    assert_eq!(body["active"], false);
    let expired_res = http_client
        .get(format!("{}/oauth/authorize", url))
        .header("Accept", "application/json")
        .query(&[("request_uri", "urn:ietf:params:oauth:request_uri:expired")])
        .send().await.unwrap();
    assert_eq!(expired_res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_oauth_2fa_flow() {
    let url = base_url().await;
    let http_client = client();
    let ts = Utc::now().timestamp_millis();
    let handle = format!("2fa-test-{}", ts);
    let email = format!("2fa-test-{}@example.com", ts);
    let password = "2fa-test-password";
    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({ "handle": handle, "email": email, "password": password }))
        .send().await.unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);
    let account: Value = create_res.json().await.unwrap();
    let user_did = account["did"].as_str().unwrap();
    let db_url = get_db_connection_string().await;
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&db_url).await.unwrap();
    sqlx::query("UPDATE users SET two_factor_enabled = true WHERE did = $1")
        .bind(user_did).execute(&pool).await.unwrap();
    let redirect_uri = "https://example.com/2fa-callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();
    let (code_verifier, code_challenge) = generate_pkce();
    let par_body: Value = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[("response_type", "code"), ("client_id", &client_id), ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge), ("code_challenge_method", "S256")])
        .send().await.unwrap().json().await.unwrap();
    let request_uri = par_body["request_uri"].as_str().unwrap();
    let auth_client = no_redirect_client();
    let auth_res = auth_client
        .post(format!("{}/oauth/authorize", url))
        .form(&[("request_uri", request_uri), ("username", &handle), ("password", password), ("remember_device", "false")])
        .send().await.unwrap();
    assert!(auth_res.status().is_redirection(), "Should redirect to 2FA page");
    let location = auth_res.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.contains("/oauth/authorize/2fa"), "Should redirect to 2FA page, got: {}", location);
    let twofa_invalid = http_client
        .post(format!("{}/oauth/authorize/2fa", url))
        .form(&[("request_uri", request_uri), ("code", "000000")])
        .send().await.unwrap();
    assert_eq!(twofa_invalid.status(), StatusCode::OK);
    let body = twofa_invalid.text().await.unwrap();
    assert!(body.contains("Invalid verification code") || body.contains("invalid"));
    let twofa_code: String = sqlx::query_scalar("SELECT code FROM oauth_2fa_challenge WHERE request_uri = $1")
        .bind(request_uri).fetch_one(&pool).await.unwrap();
    let twofa_res = auth_client
        .post(format!("{}/oauth/authorize/2fa", url))
        .form(&[("request_uri", request_uri), ("code", &twofa_code)])
        .send().await.unwrap();
    assert!(twofa_res.status().is_redirection(), "Valid 2FA code should redirect");
    let final_location = twofa_res.headers().get("location").unwrap().to_str().unwrap();
    assert!(final_location.starts_with(redirect_uri) && final_location.contains("code="));
    let auth_code = final_location.split("code=").nth(1).unwrap().split('&').next().unwrap();
    let token_res = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[("grant_type", "authorization_code"), ("code", auth_code), ("redirect_uri", redirect_uri),
            ("code_verifier", &code_verifier), ("client_id", &client_id)])
        .send().await.unwrap();
    assert_eq!(token_res.status(), StatusCode::OK);
    let token_body: Value = token_res.json().await.unwrap();
    assert_eq!(token_body["sub"], user_did);
}

#[tokio::test]
async fn test_oauth_2fa_lockout() {
    let url = base_url().await;
    let http_client = client();
    let ts = Utc::now().timestamp_millis();
    let handle = format!("2fa-lockout-{}", ts);
    let email = format!("2fa-lockout-{}@example.com", ts);
    let password = "2fa-test-password";
    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({ "handle": handle, "email": email, "password": password }))
        .send().await.unwrap();
    let account: Value = create_res.json().await.unwrap();
    let user_did = account["did"].as_str().unwrap();
    let db_url = get_db_connection_string().await;
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&db_url).await.unwrap();
    sqlx::query("UPDATE users SET two_factor_enabled = true WHERE did = $1")
        .bind(user_did).execute(&pool).await.unwrap();
    let redirect_uri = "https://example.com/2fa-lockout-callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();
    let (_, code_challenge) = generate_pkce();
    let par_body: Value = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[("response_type", "code"), ("client_id", &client_id), ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge), ("code_challenge_method", "S256")])
        .send().await.unwrap().json().await.unwrap();
    let request_uri = par_body["request_uri"].as_str().unwrap();
    let auth_client = no_redirect_client();
    let auth_res = auth_client
        .post(format!("{}/oauth/authorize", url))
        .form(&[("request_uri", request_uri), ("username", &handle), ("password", password), ("remember_device", "false")])
        .send().await.unwrap();
    assert!(auth_res.status().is_redirection());
    for i in 0..5 {
        let res = http_client
            .post(format!("{}/oauth/authorize/2fa", url))
            .form(&[("request_uri", request_uri), ("code", "999999")])
            .send().await.unwrap();
        if i < 4 {
            assert_eq!(res.status(), StatusCode::OK);
        }
    }
    let lockout_res = http_client
        .post(format!("{}/oauth/authorize/2fa", url))
        .form(&[("request_uri", request_uri), ("code", "999999")])
        .send().await.unwrap();
    let body = lockout_res.text().await.unwrap();
    assert!(body.contains("Too many failed attempts") || body.contains("No 2FA challenge found"));
}

#[tokio::test]
async fn test_account_selector_with_2fa() {
    let url = base_url().await;
    let http_client = client();
    let ts = Utc::now().timestamp_millis();
    let handle = format!("selector-2fa-{}", ts);
    let email = format!("selector-2fa-{}@example.com", ts);
    let password = "selector-2fa-password";
    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({ "handle": handle, "email": email, "password": password }))
        .send().await.unwrap();
    let account: Value = create_res.json().await.unwrap();
    let user_did = account["did"].as_str().unwrap().to_string();
    let redirect_uri = "https://example.com/selector-2fa-callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();
    let (code_verifier, code_challenge) = generate_pkce();
    let par_body: Value = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[("response_type", "code"), ("client_id", &client_id), ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge), ("code_challenge_method", "S256")])
        .send().await.unwrap().json().await.unwrap();
    let request_uri = par_body["request_uri"].as_str().unwrap();
    let auth_client = no_redirect_client();
    let auth_res = auth_client
        .post(format!("{}/oauth/authorize", url))
        .form(&[("request_uri", request_uri), ("username", &handle), ("password", password), ("remember_device", "true")])
        .send().await.unwrap();
    assert!(auth_res.status().is_redirection());
    let device_cookie = auth_res.headers().get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(';').next().unwrap_or("").to_string())
        .expect("Should have device cookie");
    let location = auth_res.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.contains("code="));
    let code = location.split("code=").nth(1).unwrap().split('&').next().unwrap();
    let _ = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[("grant_type", "authorization_code"), ("code", code), ("redirect_uri", redirect_uri),
            ("code_verifier", &code_verifier), ("client_id", &client_id)])
        .send().await.unwrap().json::<Value>().await.unwrap();
    let db_url = get_db_connection_string().await;
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&db_url).await.unwrap();
    sqlx::query("UPDATE users SET two_factor_enabled = true WHERE did = $1")
        .bind(&user_did).execute(&pool).await.unwrap();
    let (code_verifier2, code_challenge2) = generate_pkce();
    let par_body2: Value = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[("response_type", "code"), ("client_id", &client_id), ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge2), ("code_challenge_method", "S256")])
        .send().await.unwrap().json().await.unwrap();
    let request_uri2 = par_body2["request_uri"].as_str().unwrap();
    let select_res = auth_client
        .post(format!("{}/oauth/authorize/select", url))
        .header("cookie", &device_cookie)
        .form(&[("request_uri", request_uri2), ("did", &user_did)])
        .send().await.unwrap();
    assert!(select_res.status().is_redirection());
    let select_location = select_res.headers().get("location").unwrap().to_str().unwrap();
    assert!(select_location.contains("/oauth/authorize/2fa"), "Should redirect to 2FA page");
    let twofa_code: String = sqlx::query_scalar("SELECT code FROM oauth_2fa_challenge WHERE request_uri = $1")
        .bind(request_uri2).fetch_one(&pool).await.unwrap();
    let twofa_res = auth_client
        .post(format!("{}/oauth/authorize/2fa", url))
        .header("cookie", &device_cookie)
        .form(&[("request_uri", request_uri2), ("code", &twofa_code)])
        .send().await.unwrap();
    assert!(twofa_res.status().is_redirection());
    let final_location = twofa_res.headers().get("location").unwrap().to_str().unwrap();
    assert!(final_location.starts_with(redirect_uri) && final_location.contains("code="));
    let final_code = final_location.split("code=").nth(1).unwrap().split('&').next().unwrap();
    let token_res = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[("grant_type", "authorization_code"), ("code", final_code), ("redirect_uri", redirect_uri),
            ("code_verifier", &code_verifier2), ("client_id", &client_id)])
        .send().await.unwrap();
    assert_eq!(token_res.status(), StatusCode::OK);
    let final_token: Value = token_res.json().await.unwrap();
    assert_eq!(final_token["sub"], user_did);
}

#[tokio::test]
async fn test_oauth_state_encoding() {
    let url = base_url().await;
    let http_client = client();
    let ts = Utc::now().timestamp_millis();
    let handle = format!("state-special-{}", ts);
    let email = format!("state-special-{}@example.com", ts);
    let password = "state-special-password";
    http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({ "handle": handle, "email": email, "password": password }))
        .send().await.unwrap();
    let redirect_uri = "https://example.com/state-special-callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();
    let (_, code_challenge) = generate_pkce();
    let special_state = "state=with&special=chars&plus+more";
    let par_body: Value = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[("response_type", "code"), ("client_id", &client_id), ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge), ("code_challenge_method", "S256"), ("state", special_state)])
        .send().await.unwrap().json().await.unwrap();
    let request_uri = par_body["request_uri"].as_str().unwrap();
    let auth_client = no_redirect_client();
    let auth_res = auth_client
        .post(format!("{}/oauth/authorize", url))
        .form(&[("request_uri", request_uri), ("username", &handle), ("password", password), ("remember_device", "false")])
        .send().await.unwrap();
    assert!(auth_res.status().is_redirection());
    let location = auth_res.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.contains("state="));
    let encoded_state = urlencoding::encode(special_state);
    assert!(location.contains(&format!("state={}", encoded_state)), "State should be URL-encoded. Got: {}", location);
}
