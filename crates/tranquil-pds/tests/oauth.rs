mod common;
mod helpers;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{base_url, client, get_test_db_pool};
use helpers::verify_new_account;
use reqwest::{StatusCode, redirect};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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
    let code_challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());
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
    let pr_res = client
        .get(format!("{}/.well-known/oauth-protected-resource", url))
        .send()
        .await
        .unwrap();
    assert_eq!(pr_res.status(), StatusCode::OK);
    let pr_body: Value = pr_res.json().await.unwrap();
    assert!(pr_body["resource"].is_string());
    assert!(pr_body["authorization_servers"].is_array());
    assert!(
        pr_body["bearer_methods_supported"]
            .as_array()
            .unwrap()
            .contains(&json!("header"))
    );
    let as_res = client
        .get(format!("{}/.well-known/oauth-authorization-server", url))
        .send()
        .await
        .unwrap();
    assert_eq!(as_res.status(), StatusCode::OK);
    let as_body: Value = as_res.json().await.unwrap();
    assert!(as_body["issuer"].is_string());
    assert!(as_body["authorization_endpoint"].is_string());
    assert!(as_body["token_endpoint"].is_string());
    assert!(as_body["jwks_uri"].is_string());
    assert!(
        as_body["response_types_supported"]
            .as_array()
            .unwrap()
            .contains(&json!("code"))
    );
    assert!(
        as_body["grant_types_supported"]
            .as_array()
            .unwrap()
            .contains(&json!("authorization_code"))
    );
    assert!(
        as_body["code_challenge_methods_supported"]
            .as_array()
            .unwrap()
            .contains(&json!("S256"))
    );
    assert_eq!(
        as_body["require_pushed_authorization_requests"],
        json!(true)
    );
    assert!(
        as_body["dpop_signing_alg_values_supported"]
            .as_array()
            .unwrap()
            .contains(&json!("ES256"))
    );
    let jwks_res = client
        .get(format!("{}/oauth/jwks", url))
        .send()
        .await
        .unwrap();
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
        .unwrap();
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
        .send()
        .await
        .unwrap();
    assert_eq!(auth_res.status(), StatusCode::OK);
    let auth_body: Value = auth_res.json().await.unwrap();
    assert_eq!(auth_body["client_id"], client_id);
    assert_eq!(auth_body["redirect_uri"], redirect_uri);
    assert_eq!(auth_body["scope"], "atproto");
    let invalid_res = client
        .get(format!("{}/oauth/authorize", url))
        .header("Accept", "application/json")
        .query(&[(
            "request_uri",
            "urn:ietf:params:oauth:request_uri:nonexistent",
        )])
        .send()
        .await
        .unwrap();
    assert_eq!(invalid_res.status(), StatusCode::BAD_REQUEST);
    let missing_client = no_redirect_client();
    let missing_res = missing_client
        .get(format!("{}/oauth/authorize", url))
        .send()
        .await
        .unwrap();
    assert!(
        missing_res.status().is_redirection(),
        "Should redirect to error page"
    );
    let error_location = missing_res
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        error_location.contains("oauth/error"),
        "Should redirect to error page"
    );
}

#[tokio::test]
async fn test_full_oauth_flow() {
    let url = base_url().await;
    let http_client = client();
    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let handle = format!("ot{}", suffix);
    let email = format!("ot{}@example.com", suffix);
    let password = "Oauthtest123!";
    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({ "handle": handle, "email": email, "password": password }))
        .send()
        .await
        .unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);
    let account: Value = create_res.json().await.unwrap();
    let user_did = account["did"].as_str().unwrap();
    verify_new_account(&http_client, user_did).await;
    let redirect_uri = "https://example.com/oauth/callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();
    let (code_verifier, code_challenge) = generate_pkce();
    let state = format!("state-{}", suffix);
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
        .unwrap();
    let par_body: Value = par_res.json().await.unwrap();
    let request_uri = par_body["request_uri"].as_str().unwrap();
    let auth_res = http_client
        .post(format!("{}/oauth/authorize", url))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&json!({"request_uri": request_uri, "username": &handle, "password": password, "remember_device": false}))
        .send().await.unwrap();
    assert_eq!(
        auth_res.status(),
        StatusCode::OK,
        "Expected OK with JSON response"
    );
    let auth_body: Value = auth_res.json().await.unwrap();
    let mut location = auth_body["redirect_uri"]
        .as_str()
        .expect("Expected redirect_uri in response")
        .to_string();
    if location.contains("/oauth/consent") {
        let consent_res = http_client
            .post(format!("{}/oauth/authorize/consent", url))
            .header("Content-Type", "application/json")
            .json(&json!({"request_uri": request_uri, "approved_scopes": ["atproto"], "remember": false}))
            .send().await.unwrap();
        let consent_status = consent_res.status();
        let consent_body: Value = consent_res.json().await.unwrap();
        assert_eq!(
            consent_status,
            StatusCode::OK,
            "Consent should succeed. Got: {:?}",
            consent_body
        );
        location = consent_body["redirect_uri"]
            .as_str()
            .expect("Expected redirect_uri from consent")
            .to_string();
    }
    assert!(
        location.contains("code="),
        "No code in redirect URI: {}",
        location
    );
    assert!(
        location.contains(&format!("state={}", state))
            || location.contains(&format!("state%3D{}", state)),
        "Wrong state in redirect: {}",
        location
    );
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
        .unwrap();
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
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(refresh_res.status(), StatusCode::OK);
    let refresh_body: Value = refresh_res.json().await.unwrap();
    assert_ne!(refresh_body["access_token"].as_str().unwrap(), access_token);
    assert_ne!(
        refresh_body["refresh_token"].as_str().unwrap(),
        refresh_token
    );
    let introspect_res = http_client
        .post(format!("{}/oauth/introspect", url))
        .form(&[("token", refresh_body["access_token"].as_str().unwrap())])
        .send()
        .await
        .unwrap();
    assert_eq!(introspect_res.status(), StatusCode::OK);
    let introspect_body: Value = introspect_res.json().await.unwrap();
    assert_eq!(introspect_body["active"], true);
    let revoke_res = http_client
        .post(format!("{}/oauth/revoke", url))
        .form(&[("token", refresh_body["refresh_token"].as_str().unwrap())])
        .send()
        .await
        .unwrap();
    assert_eq!(revoke_res.status(), StatusCode::OK);
    let introspect_after = http_client
        .post(format!("{}/oauth/introspect", url))
        .form(&[("token", refresh_body["access_token"].as_str().unwrap())])
        .send()
        .await
        .unwrap();
    let after_body: Value = introspect_after.json().await.unwrap();
    assert_eq!(
        after_body["active"], false,
        "Revoked token should be inactive"
    );
}

#[tokio::test]
async fn test_oauth_error_cases() {
    let url = base_url().await;
    let http_client = client();
    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let handle = format!("wc{}", suffix);
    let email = format!("wc{}@example.com", suffix);
    http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({ "handle": handle, "email": email, "password": "Correct123!" }))
        .send()
        .await
        .unwrap();
    let redirect_uri = "https://example.com/callback";
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
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&json!({"request_uri": request_uri, "username": &handle, "password": "wrong-password", "remember_device": false}))
        .send().await.unwrap();
    assert_eq!(auth_res.status(), StatusCode::FORBIDDEN);
    let error_body: Value = auth_res.json().await.unwrap();
    assert_eq!(error_body["error"], "access_denied");
    let unsupported = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "https://example.com"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(unsupported.status(), StatusCode::BAD_REQUEST);
    let body: Value = unsupported.json().await.unwrap();
    assert_eq!(body["error"], "unsupported_grant_type");
    let invalid_refresh = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", "invalid-token"),
            ("client_id", "https://example.com"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(invalid_refresh.status(), StatusCode::BAD_REQUEST);
    let body: Value = invalid_refresh.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
    let invalid_introspect = http_client
        .post(format!("{}/oauth/introspect", url))
        .form(&[("token", "invalid.token.here")])
        .send()
        .await
        .unwrap();
    assert_eq!(invalid_introspect.status(), StatusCode::OK);
    let body: Value = invalid_introspect.json().await.unwrap();
    assert_eq!(body["active"], false);
    let expired_res = http_client
        .get(format!("{}/oauth/authorize", url))
        .header("Accept", "application/json")
        .query(&[("request_uri", "urn:ietf:params:oauth:request_uri:expired")])
        .send()
        .await
        .unwrap();
    assert_eq!(expired_res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_oauth_2fa_flow() {
    let url = base_url().await;
    let http_client = client();
    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let handle = format!("ft{}", suffix);
    let email = format!("ft{}@example.com", suffix);
    let password = "Twofa123test!";
    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({ "handle": handle, "email": email, "password": password }))
        .send()
        .await
        .unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);
    let account: Value = create_res.json().await.unwrap();
    let user_did = account["did"].as_str().unwrap();
    verify_new_account(&http_client, user_did).await;
    let pool = get_test_db_pool().await;
    sqlx::query("UPDATE users SET two_factor_enabled = true WHERE did = $1")
        .bind(user_did)
        .execute(pool)
        .await
        .unwrap();
    let redirect_uri = "https://example.com/2fa-callback";
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
    let auth_res = http_client
        .post(format!("{}/oauth/authorize", url))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&json!({"request_uri": request_uri, "username": &handle, "password": password, "remember_device": false}))
        .send().await.unwrap();
    assert_eq!(
        auth_res.status(),
        StatusCode::OK,
        "Should return OK with needs_2fa"
    );
    let auth_body: Value = auth_res.json().await.unwrap();
    assert!(
        auth_body["needs_2fa"].as_bool().unwrap_or(false),
        "Should need 2FA, got: {:?}",
        auth_body
    );
    let twofa_invalid = http_client
        .post(format!("{}/oauth/authorize/2fa", url))
        .header("Content-Type", "application/json")
        .json(&json!({"request_uri": request_uri, "code": "000000"}))
        .send()
        .await
        .unwrap();
    assert_eq!(twofa_invalid.status(), StatusCode::FORBIDDEN);
    let body: Value = twofa_invalid.json().await.unwrap();
    assert!(
        body["error_description"]
            .as_str()
            .unwrap_or("")
            .contains("Invalid")
            || body["error"].as_str().unwrap_or("") == "invalid_code"
    );
    let twofa_code: String =
        sqlx::query_scalar("SELECT code FROM oauth_2fa_challenge WHERE request_uri = $1")
            .bind(request_uri)
            .fetch_one(pool)
            .await
            .unwrap();
    let twofa_res = http_client
        .post(format!("{}/oauth/authorize/2fa", url))
        .header("Content-Type", "application/json")
        .json(&json!({"request_uri": request_uri, "code": &twofa_code}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        twofa_res.status(),
        StatusCode::OK,
        "Valid 2FA code should succeed"
    );
    let twofa_body: Value = twofa_res.json().await.unwrap();
    let final_location = twofa_body["redirect_uri"].as_str().unwrap();
    assert!(
        final_location.contains("code="),
        "No code in redirect URI: {}",
        final_location
    );
    let auth_code = final_location
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
            ("code", auth_code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", &code_verifier),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(token_res.status(), StatusCode::OK);
    let token_body: Value = token_res.json().await.unwrap();
    assert_eq!(token_body["sub"], user_did);
}

#[tokio::test]
async fn test_oauth_2fa_lockout() {
    let url = base_url().await;
    let http_client = client();
    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let handle = format!("fl{}", suffix);
    let email = format!("fl{}@example.com", suffix);
    let password = "Twofa123test!";
    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({ "handle": handle, "email": email, "password": password }))
        .send()
        .await
        .unwrap();
    let account: Value = create_res.json().await.unwrap();
    let user_did = account["did"].as_str().unwrap();
    verify_new_account(&http_client, user_did).await;
    let pool = get_test_db_pool().await;
    sqlx::query("UPDATE users SET two_factor_enabled = true WHERE did = $1")
        .bind(user_did)
        .execute(pool)
        .await
        .unwrap();
    let redirect_uri = "https://example.com/2fa-lockout-callback";
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
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&json!({"request_uri": request_uri, "username": &handle, "password": password, "remember_device": false}))
        .send().await.unwrap();
    assert_eq!(
        auth_res.status(),
        StatusCode::OK,
        "Should return OK with needs_2fa"
    );
    let auth_body: Value = auth_res.json().await.unwrap();
    assert!(
        auth_body["needs_2fa"].as_bool().unwrap_or(false),
        "Should need 2FA"
    );
    for i in 0..5 {
        let res = http_client
            .post(format!("{}/oauth/authorize/2fa", url))
            .header("Content-Type", "application/json")
            .json(&json!({"request_uri": request_uri, "code": "999999"}))
            .send()
            .await
            .unwrap();
        if i < 4 {
            assert_eq!(
                res.status(),
                StatusCode::FORBIDDEN,
                "Attempt {} should return 403",
                i
            );
        }
    }
    let lockout_res = http_client
        .post(format!("{}/oauth/authorize/2fa", url))
        .header("Content-Type", "application/json")
        .json(&json!({"request_uri": request_uri, "code": "999999"}))
        .send()
        .await
        .unwrap();
    let body: Value = lockout_res.json().await.unwrap();
    let desc = body["error_description"].as_str().unwrap_or("");
    assert!(
        desc.contains("Too many") || desc.contains("No 2FA") || body["error"] == "invalid_request",
        "Expected lockout error, got: {:?}",
        body
    );
}

#[tokio::test]
async fn test_account_selector_with_2fa() {
    let url = base_url().await;
    let http_client = client();
    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let handle = format!("sf{}", suffix);
    let email = format!("sf{}@example.com", suffix);
    let password = "Selector2fa123!";
    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({ "handle": handle, "email": email, "password": password }))
        .send()
        .await
        .unwrap();
    let account: Value = create_res.json().await.unwrap();
    let user_did = account["did"].as_str().unwrap().to_string();
    verify_new_account(&http_client, &user_did).await;
    let redirect_uri = "https://example.com/selector-2fa-callback";
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
    let auth_res = http_client
        .post(format!("{}/oauth/authorize", url))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&json!({"request_uri": request_uri, "username": &handle, "password": password, "remember_device": true}))
        .send().await.unwrap();
    assert_eq!(
        auth_res.status(),
        StatusCode::OK,
        "Expected OK with JSON response"
    );
    let device_cookie = auth_res
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(';').next().unwrap_or("").to_string())
        .expect("Should have device cookie");
    let auth_body: Value = auth_res.json().await.unwrap();
    let mut location = auth_body["redirect_uri"]
        .as_str()
        .expect("Expected redirect_uri")
        .to_string();
    if location.contains("/oauth/consent") {
        let consent_res = http_client
            .post(format!("{}/oauth/authorize/consent", url))
            .header("Content-Type", "application/json")
            .json(&json!({"request_uri": request_uri, "approved_scopes": ["atproto"], "remember": true}))
            .send().await.unwrap();
        assert_eq!(
            consent_res.status(),
            StatusCode::OK,
            "Consent should succeed"
        );
        let consent_body: Value = consent_res.json().await.unwrap();
        location = consent_body["redirect_uri"]
            .as_str()
            .expect("Expected redirect_uri from consent")
            .to_string();
    }
    assert!(location.contains("code="));
    let code = location
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let _ = http_client
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
        .json::<Value>()
        .await
        .unwrap();
    let pool = get_test_db_pool().await;
    sqlx::query("UPDATE users SET two_factor_enabled = true WHERE did = $1")
        .bind(&user_did)
        .execute(pool)
        .await
        .unwrap();
    let (code_verifier2, code_challenge2) = generate_pkce();
    let par_body2: Value = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge2),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let request_uri2 = par_body2["request_uri"].as_str().unwrap();
    let select_res = http_client
        .post(format!("{}/oauth/authorize/select", url))
        .header("cookie", &device_cookie)
        .header("Content-Type", "application/json")
        .json(&json!({"request_uri": request_uri2, "did": &user_did}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        select_res.status(),
        StatusCode::OK,
        "Select should return OK with JSON"
    );
    let select_body: Value = select_res.json().await.unwrap();
    assert!(
        select_body["needs_2fa"].as_bool().unwrap_or(false),
        "Should need 2FA"
    );
    let twofa_code: String =
        sqlx::query_scalar("SELECT code FROM oauth_2fa_challenge WHERE request_uri = $1")
            .bind(request_uri2)
            .fetch_one(pool)
            .await
            .unwrap();
    let twofa_res = http_client
        .post(format!("{}/oauth/authorize/2fa", url))
        .header("cookie", &device_cookie)
        .header("Content-Type", "application/json")
        .json(&json!({"request_uri": request_uri2, "code": &twofa_code}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        twofa_res.status(),
        StatusCode::OK,
        "Valid 2FA should succeed"
    );
    let twofa_body: Value = twofa_res.json().await.unwrap();
    let final_location = twofa_body["redirect_uri"].as_str().unwrap();
    assert!(
        final_location.contains("code="),
        "No code in redirect URI: {}",
        final_location
    );
    let final_code = final_location
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
            ("code", final_code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", &code_verifier2),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(token_res.status(), StatusCode::OK);
    let final_token: Value = token_res.json().await.unwrap();
    assert_eq!(final_token["sub"], user_did);
}

#[tokio::test]
async fn test_oauth_state_encoding() {
    let url = base_url().await;
    let http_client = client();
    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let handle = format!("ss{}", suffix);
    let email = format!("ss{}@example.com", suffix);
    let password = "State123special!";
    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({ "handle": handle, "email": email, "password": password }))
        .send()
        .await
        .unwrap();
    let account: Value = create_res.json().await.unwrap();
    verify_new_account(&http_client, account["did"].as_str().unwrap()).await;
    let redirect_uri = "https://example.com/state-special-callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();
    let (_, code_challenge) = generate_pkce();
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
    let auth_res = http_client
        .post(format!("{}/oauth/authorize", url))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&json!({"request_uri": request_uri, "username": &handle, "password": password, "remember_device": false}))
        .send().await.unwrap();
    assert_eq!(
        auth_res.status(),
        StatusCode::OK,
        "Expected OK with JSON response"
    );
    let auth_body: Value = auth_res.json().await.unwrap();
    let mut location = auth_body["redirect_uri"]
        .as_str()
        .expect("Expected redirect_uri")
        .to_string();
    if location.contains("/oauth/consent") {
        let consent_res = http_client
            .post(format!("{}/oauth/authorize/consent", url))
            .header("Content-Type", "application/json")
            .json(&json!({"request_uri": request_uri, "approved_scopes": ["atproto"], "remember": false}))
            .send().await.unwrap();
        assert_eq!(
            consent_res.status(),
            StatusCode::OK,
            "Consent should succeed"
        );
        let consent_body: Value = consent_res.json().await.unwrap();
        location = consent_body["redirect_uri"]
            .as_str()
            .expect("Expected redirect_uri from consent")
            .to_string();
    }
    assert!(location.contains("state="));
    let encoded_state = urlencoding::encode(special_state);
    assert!(
        location.contains(&format!("state={}", encoded_state)),
        "State should be URL-encoded. Got: {}",
        location
    );
}

async fn get_oauth_token_with_scope(scope: &str) -> (String, String, String) {
    let url = base_url().await;
    let http_client = client();
    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let handle = format!("st{}", suffix);
    let email = format!("st{}@example.com", suffix);
    let password = "Scopetest123!";
    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({ "handle": handle, "email": email, "password": password }))
        .send()
        .await
        .unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);
    let account: Value = create_res.json().await.unwrap();
    let user_did = account["did"].as_str().unwrap().to_string();
    verify_new_account(&http_client, &user_did).await;
    let redirect_uri = "https://example.com/scope-callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();
    let (code_verifier, code_challenge) = generate_pkce();
    let par_res = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
            ("scope", scope),
            ("state", "test"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        par_res.status(),
        StatusCode::CREATED,
        "PAR should succeed for scope: {}",
        scope
    );
    let par_body: Value = par_res.json().await.unwrap();
    let request_uri = par_body["request_uri"].as_str().unwrap();
    let auth_res = http_client
        .post(format!("{}/oauth/authorize", url))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&json!({"request_uri": request_uri, "username": &handle, "password": password, "remember_device": false}))
        .send().await.unwrap();
    assert_eq!(auth_res.status(), StatusCode::OK);
    let auth_body: Value = auth_res.json().await.unwrap();
    let mut location = auth_body["redirect_uri"]
        .as_str()
        .expect("Expected redirect_uri")
        .to_string();
    if location.contains("/oauth/consent") {
        let approved_scopes: Vec<&str> = scope.split_whitespace().collect();
        let consent_res = http_client
            .post(format!("{}/oauth/authorize/consent", url))
            .header("Content-Type", "application/json")
            .json(&json!({"request_uri": request_uri, "approved_scopes": approved_scopes, "remember": false}))
            .send().await.unwrap();
        let consent_status = consent_res.status();
        let consent_body: Value = consent_res.json().await.unwrap();
        assert_eq!(
            consent_status,
            StatusCode::OK,
            "Consent should succeed. Scope: {}, Body: {:?}",
            scope,
            consent_body
        );
        location = consent_body["redirect_uri"]
            .as_str()
            .expect("Expected redirect_uri from consent")
            .to_string();
    }
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
        .unwrap();
    assert_eq!(token_res.status(), StatusCode::OK, "Token exchange failed");
    let token_body: Value = token_res.json().await.unwrap();
    let access_token = token_body["access_token"].as_str().unwrap().to_string();
    (access_token, user_did, handle)
}

#[tokio::test]
async fn test_granular_scope_repo_create_only() {
    let url = base_url().await;
    let http_client = client();
    let (token, did, _) =
        get_oauth_token_with_scope("repo:app.bsky.feed.post?action=create blob:*/*").await;
    let now = chrono::Utc::now().to_rfc3339();
    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", url))
        .bearer_auth(&token)
        .json(&json!({
            "repo": &did,
            "collection": "app.bsky.feed.post",
            "record": { "$type": "app.bsky.feed.post", "text": "test post", "createdAt": now }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        create_res.status(),
        StatusCode::OK,
        "Should allow creating posts with repo:app.bsky.feed.post?action=create"
    );
    let body: Value = create_res.json().await.unwrap();
    let uri = body["uri"].as_str().expect("Should have uri");
    let rkey = uri.split('/').next_back().unwrap();
    let delete_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.deleteRecord", url))
        .bearer_auth(&token)
        .json(&json!({ "repo": &did, "collection": "app.bsky.feed.post", "rkey": rkey }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        delete_res.status(),
        StatusCode::FORBIDDEN,
        "Should NOT allow deleting with create-only scope"
    );
    let like_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", url))
        .bearer_auth(&token)
        .json(&json!({
            "repo": &did,
            "collection": "app.bsky.feed.like",
            "record": { "$type": "app.bsky.feed.like", "subject": { "uri": uri, "cid": body["cid"] }, "createdAt": now }
        }))
        .send().await.unwrap();
    assert_eq!(
        like_res.status(),
        StatusCode::FORBIDDEN,
        "Should NOT allow creating likes (wrong collection)"
    );
}

#[tokio::test]
async fn test_granular_scope_wildcard_collection() {
    let url = base_url().await;
    let http_client = client();
    let (token, did, _) = get_oauth_token_with_scope(
        "repo:app.bsky.*?action=create&action=update&action=delete blob:*/*",
    )
    .await;
    let now = chrono::Utc::now().to_rfc3339();
    let post_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", url))
        .bearer_auth(&token)
        .json(&json!({
            "repo": &did,
            "collection": "app.bsky.feed.post",
            "record": { "$type": "app.bsky.feed.post", "text": "wildcard test", "createdAt": now }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        post_res.status(),
        StatusCode::OK,
        "Should allow app.bsky.feed.post with app.bsky.* scope"
    );
    let body: Value = post_res.json().await.unwrap();
    let uri = body["uri"].as_str().unwrap();
    let rkey = uri.split('/').next_back().unwrap();
    let delete_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.deleteRecord", url))
        .bearer_auth(&token)
        .json(&json!({ "repo": &did, "collection": "app.bsky.feed.post", "rkey": rkey }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        delete_res.status(),
        StatusCode::OK,
        "Should allow delete with action=delete"
    );
    let other_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", url))
        .bearer_auth(&token)
        .json(&json!({
            "repo": &did,
            "collection": "com.example.record",
            "record": { "$type": "com.example.record", "data": "test", "createdAt": now }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        other_res.status(),
        StatusCode::FORBIDDEN,
        "Should NOT allow com.example.* with app.bsky.* scope"
    );
}

#[tokio::test]
async fn test_granular_scope_email_read() {
    let url = base_url().await;
    let http_client = client();
    let (token, did, _) = get_oauth_token_with_scope("account:email?action=read").await;
    let session_res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(session_res.status(), StatusCode::OK);
    let body: Value = session_res.json().await.unwrap();
    assert_eq!(body["did"], did);
    assert!(
        body["email"].is_string(),
        "Email should be visible with account:email?action=read. Got: {:?}",
        body
    );
}

#[tokio::test]
async fn test_granular_scope_no_email_access() {
    let url = base_url().await;
    let http_client = client();
    let (token, did, _) = get_oauth_token_with_scope("repo:*?action=create blob:*/*").await;
    let session_res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(session_res.status(), StatusCode::OK);
    let body: Value = session_res.json().await.unwrap();
    assert_eq!(body["did"], did);
    assert!(
        body["email"].is_null() || body.get("email").is_none(),
        "Email should be hidden without account:email scope. Got: {:?}",
        body["email"]
    );
}

#[tokio::test]
async fn test_granular_scope_rpc_specific_method() {
    let url = base_url().await;
    let http_client = client();
    let (token, _, _) = get_oauth_token_with_scope("rpc:app.bsky.feed.getTimeline?aud=*").await;
    let allowed_res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getServiceAuth", url))
        .bearer_auth(&token)
        .query(&[
            ("aud", "did:web:api.bsky.app"),
            ("lxm", "app.bsky.feed.getTimeline"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        allowed_res.status(),
        StatusCode::OK,
        "Should allow getServiceAuth for app.bsky.feed.getTimeline"
    );
    let body: Value = allowed_res.json().await.unwrap();
    assert!(body["token"].is_string(), "Should return service token");
    let blocked_res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getServiceAuth", url))
        .bearer_auth(&token)
        .query(&[
            ("aud", "did:web:api.bsky.app"),
            ("lxm", "app.bsky.feed.getAuthorFeed"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        blocked_res.status(),
        StatusCode::FORBIDDEN,
        "Should NOT allow getServiceAuth for app.bsky.feed.getAuthorFeed"
    );
    let blocked_body: Value = blocked_res.json().await.unwrap();
    assert!(
        blocked_body["error"]
            .as_str()
            .unwrap_or("")
            .contains("Scope")
            || blocked_body["message"]
                .as_str()
                .unwrap_or("")
                .contains("scope"),
        "Should mention scope restriction: {:?}",
        blocked_body
    );
    let no_lxm_res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getServiceAuth", url))
        .bearer_auth(&token)
        .query(&[("aud", "did:web:api.bsky.app")])
        .send()
        .await
        .unwrap();
    assert_eq!(
        no_lxm_res.status(),
        StatusCode::BAD_REQUEST,
        "Should require lxm parameter for granular scopes"
    );
}

#[tokio::test]
async fn test_oauth_metadata_includes_prompt_values_supported() {
    let url = base_url().await;
    let client = client();
    let as_res = client
        .get(format!("{}/.well-known/oauth-authorization-server", url))
        .send()
        .await
        .unwrap();
    assert_eq!(as_res.status(), StatusCode::OK);
    let as_body: Value = as_res.json().await.unwrap();
    let prompt_values = as_body["prompt_values_supported"]
        .as_array()
        .expect("prompt_values_supported should be an array");
    assert!(
        prompt_values.contains(&json!("none")),
        "Should support prompt=none"
    );
    assert!(
        prompt_values.contains(&json!("login")),
        "Should support prompt=login"
    );
    assert!(
        prompt_values.contains(&json!("consent")),
        "Should support prompt=consent"
    );
    assert!(
        prompt_values.contains(&json!("select_account")),
        "Should support prompt=select_account"
    );
    assert!(
        prompt_values.contains(&json!("create")),
        "Should support prompt=create"
    );
}

#[tokio::test]
async fn test_par_accepts_valid_prompt_values() {
    let url = base_url().await;
    let client = client();
    let redirect_uri = "https://example.com/callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();
    let (_, code_challenge) = generate_pkce();
    let valid_prompts = ["none", "login", "consent", "select_account", "create"];
    for prompt in valid_prompts {
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
                ("prompt", prompt),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(
            par_res.status(),
            StatusCode::CREATED,
            "PAR should accept prompt={}",
            prompt
        );
    }
}

#[tokio::test]
async fn test_par_rejects_invalid_prompt_value() {
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
            ("prompt", "invalid_prompt"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        par_res.status(),
        StatusCode::BAD_REQUEST,
        "PAR should reject invalid prompt value"
    );
    let body: Value = par_res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap_or("")
            .contains("prompt"),
        "Error should mention prompt"
    );
}

#[tokio::test]
async fn test_prompt_create_redirects_to_register() {
    let url = base_url().await;
    let client = no_redirect_client();
    let redirect_uri = "https://example.com/callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();
    let (_, code_challenge) = generate_pkce();
    let par_res = reqwest::Client::new()
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
            ("scope", "atproto"),
            ("state", "test-state"),
            ("prompt", "create"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(par_res.status(), StatusCode::CREATED);
    let par_body: Value = par_res.json().await.unwrap();
    let request_uri = par_body["request_uri"].as_str().unwrap();
    let auth_res = client
        .get(format!("{}/oauth/authorize", url))
        .query(&[("request_uri", request_uri)])
        .send()
        .await
        .unwrap();
    assert!(
        auth_res.status().is_redirection(),
        "Should redirect when prompt=create"
    );
    let location = auth_res
        .headers()
        .get("location")
        .expect("Should have Location header")
        .to_str()
        .unwrap();
    assert!(
        location.contains("/app/oauth/register"),
        "Should redirect to /app/oauth/register, got: {}",
        location
    );
    assert!(
        location.contains("request_uri="),
        "Should include request_uri in redirect"
    );
}

#[tokio::test]
async fn test_register_complete_rejects_invalid_request_uri() {
    let url = base_url().await;
    let client = client();
    let res = client
        .post(format!("{}/oauth/register/complete", url))
        .json(&json!({
            "request_uri": "urn:ietf:params:oauth:request_uri:nonexistent",
            "did": "did:plc:test123",
            "app_password": "test-password"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "Should reject invalid request_uri"
    );
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn test_register_complete_rejects_wrong_credentials() {
    let url = base_url().await;
    let http_client = client();
    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let handle = format!("rc{}", suffix);
    let email = format!("rc{}@example.com", suffix);
    let password = "Regcomplete123!";
    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({ "handle": handle, "email": email, "password": password }))
        .send()
        .await
        .unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);
    let account: Value = create_res.json().await.unwrap();
    let user_did = account["did"].as_str().unwrap();
    verify_new_account(&http_client, user_did).await;
    let redirect_uri = "https://example.com/callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();
    let (_, code_challenge) = generate_pkce();
    let par_res = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
            ("scope", "atproto"),
            ("state", "test-state"),
            ("prompt", "create"),
        ])
        .send()
        .await
        .unwrap();
    let par_body: Value = par_res.json().await.unwrap();
    let request_uri = par_body["request_uri"].as_str().unwrap();
    let res = http_client
        .post(format!("{}/oauth/register/complete", url))
        .json(&json!({
            "request_uri": request_uri,
            "did": user_did,
            "app_password": "wrong-password"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "Should reject wrong credentials"
    );
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "access_denied");
}

#[tokio::test]
async fn test_full_oauth_registration_flow() {
    let url = base_url().await;
    let http_client = client();

    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let handle = format!("oauthreg{}", suffix);
    let email = format!("oauthreg{}@example.com", suffix);
    let password = "OauthRegTest123!";

    let redirect_uri = "https://example.com/callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();
    let (code_verifier, code_challenge) = generate_pkce();
    let state = format!("state-{}", suffix);

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
            ("prompt", "create"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        par_res.status(),
        StatusCode::CREATED,
        "PAR with prompt=create should succeed"
    );
    let par_body: Value = par_res.json().await.unwrap();
    let request_uri = par_body["request_uri"].as_str().unwrap();

    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({ "handle": handle, "email": email, "password": password }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        create_res.status(),
        StatusCode::OK,
        "Account creation should succeed"
    );
    let account: Value = create_res.json().await.unwrap();
    let user_did = account["did"].as_str().unwrap();
    let access_jwt = account["accessJwt"].as_str().unwrap();

    let app_password_res = http_client
        .post(format!("{}/xrpc/com.atproto.server.createAppPassword", url))
        .header("Authorization", format!("Bearer {}", access_jwt))
        .json(&json!({ "name": "oauth-test-app" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        app_password_res.status(),
        StatusCode::OK,
        "App password creation should succeed"
    );
    let app_password_body: Value = app_password_res.json().await.unwrap();
    let app_password = app_password_body["password"].as_str().unwrap();

    verify_new_account(&http_client, user_did).await;

    let complete_res = http_client
        .post(format!("{}/oauth/register/complete", url))
        .json(&json!({
            "request_uri": request_uri,
            "did": user_did,
            "app_password": app_password
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        complete_res.status(),
        StatusCode::OK,
        "register_complete should succeed"
    );
    let complete_body: Value = complete_res.json().await.unwrap();
    let mut redirect_location = complete_body["redirect_uri"]
        .as_str()
        .expect("Expected redirect_uri from register_complete")
        .to_string();

    if redirect_location.contains("/oauth/consent") {
        let consent_res = http_client
            .post(format!("{}/oauth/authorize/consent", url))
            .header("Content-Type", "application/json")
            .json(&json!({
                "request_uri": request_uri,
                "approved_scopes": ["atproto"],
                "remember": false
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            consent_res.status(),
            StatusCode::OK,
            "Consent should succeed"
        );
        let consent_body: Value = consent_res.json().await.unwrap();
        redirect_location = consent_body["redirect_uri"]
            .as_str()
            .expect("Expected redirect_uri from consent")
            .to_string();
    }

    assert!(
        redirect_location.contains("code="),
        "Should have authorization code in redirect: {}",
        redirect_location
    );

    let code = redirect_location
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
        .unwrap();
    assert_eq!(
        token_res.status(),
        StatusCode::OK,
        "Token exchange should succeed"
    );
    let token_body: Value = token_res.json().await.unwrap();
    assert!(
        token_body["access_token"].is_string(),
        "Should have access_token"
    );
    assert!(
        token_body["refresh_token"].is_string(),
        "Should have refresh_token"
    );
    assert_eq!(token_body["token_type"], "Bearer");
    assert_eq!(
        token_body["sub"], user_did,
        "Token sub should match user DID"
    );
}
