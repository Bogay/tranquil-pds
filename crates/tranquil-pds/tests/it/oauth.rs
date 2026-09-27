use crate::common::{base_url, client};
use crate::helpers::verify_new_account;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
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
async fn test_par_public_client_empty_assertion_fields() {
    let url = base_url().await;
    let client = client();
    let redirect_uri = "https://nels.evil.oauth.pet/callback";
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
            ("client_assertion", ""),
            ("client_assertion_type", ""),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        par_res.status(),
        StatusCode::CREATED,
        "PAR with empty assertion fields from a public client should succeed"
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
        get_oauth_token_with_scope("atproto repo:app.bsky.feed.post?action=create blob:*/*").await;
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
        "atproto repo:app.bsky.*?action=create&action=update&action=delete blob:*/*",
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
    let (token, did, _) = get_oauth_token_with_scope("atproto account:email?action=read").await;
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
    let (token, did, _) = get_oauth_token_with_scope("atproto repo:*?action=create blob:*/*").await;
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
    let (token, _, _) =
        get_oauth_token_with_scope("atproto rpc:app.bsky.feed.getTimeline?aud=*").await;
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
async fn test_granular_scope_rpc_aud_with_service_id() {
    let url = base_url().await;
    let http_client = client();
    let (token, _, _) = get_oauth_token_with_scope(
        "atproto rpc:app.bsky.feed.getTimeline?aud=did:web:api.bsky.app#bsky_appview",
    )
    .await;
    let allowed_res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getServiceAuth", url))
        .bearer_auth(&token)
        .query(&[
            ("aud", "did:web:api.bsky.app#bsky_appview"),
            ("lxm", "app.bsky.feed.getTimeline"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        allowed_res.status(),
        StatusCode::OK,
        "the granted service id must cover a request naming it"
    );
    let body: Value = allowed_res.json().await.unwrap();
    let service_token = body["token"].as_str().unwrap();
    let payload = service_token.split('.').nth(1).unwrap();
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    assert_eq!(
        claims["aud"], "did:web:api.bsky.app#bsky_appview",
        "the service id must reach the signed claim even on the granular scope path"
    );

    for (aud, reason) in [
        (
            "did:web:api.bsky.app#atproto_labeler",
            "a scope for the appview must not mint tokens for the labeler on the same DID",
        ),
        (
            "did:web:api.bsky.app",
            "a scope for one service must not widen to the whole DID",
        ),
        (
            "did:web:other.example#bsky_appview",
            "a service id must not smuggle in a different audience",
        ),
    ] {
        let blocked_res = http_client
            .get(format!("{}/xrpc/com.atproto.server.getServiceAuth", url))
            .bearer_auth(&token)
            .query(&[("aud", aud), ("lxm", "app.bsky.feed.getTimeline")])
            .send()
            .await
            .unwrap();
        assert_eq!(blocked_res.status(), StatusCode::FORBIDDEN, "{reason}");
    }
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
