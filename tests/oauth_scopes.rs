mod common;
mod helpers;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use common::{base_url, client};
use helpers::verify_new_account;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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
        "client_name": "Test OAuth Scope Client",
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

struct OAuthSession {
    access_token: String,
    #[allow(dead_code)]
    refresh_token: String,
    did: String,
    #[allow(dead_code)]
    client_id: String,
    scope: String,
}

async fn create_user_and_oauth_session_with_scope(
    handle_prefix: &str,
    redirect_uri: &str,
    scope: &str,
) -> (OAuthSession, MockServer) {
    let url = base_url().await;
    let http_client = client();
    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..4];
    let handle = format!("{}{}", handle_prefix, suffix);
    let email = format!("{}{}@example.com", handle_prefix, suffix);
    let password = format!("{}Pass123!", handle_prefix);

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
    let user_did = account["did"].as_str().unwrap().to_string();

    let _ = verify_new_account(&http_client, &user_did).await;

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
        ])
        .send()
        .await
        .expect("PAR failed");
    assert!(
        par_res.status() == StatusCode::OK || par_res.status() == StatusCode::CREATED,
        "PAR should succeed, got {}",
        par_res.status()
    );
    let par_body: Value = par_res.json().await.unwrap();
    let request_uri = par_body["request_uri"].as_str().unwrap();

    let auth_res = http_client
        .post(format!("{}/oauth/authorize", url))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&json!({
            "request_uri": request_uri,
            "username": &handle,
            "password": &password,
            "remember_device": false
        }))
        .send()
        .await
        .expect("Authorize failed");
    assert_eq!(
        auth_res.status(),
        StatusCode::OK,
        "Authorize should return OK"
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
            .send().await.expect("Consent request failed");
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
    assert_eq!(token_res.status(), StatusCode::OK);
    let token_body: Value = token_res.json().await.unwrap();

    let session = OAuthSession {
        access_token: token_body["access_token"].as_str().unwrap().to_string(),
        refresh_token: token_body["refresh_token"].as_str().unwrap().to_string(),
        did: user_did,
        client_id,
        scope: scope.to_string(),
    };
    (session, mock_client)
}

#[tokio::test]
async fn test_atproto_scope_allows_full_access() {
    let url = base_url().await;
    let http_client = client();
    let (session, _mock) = create_user_and_oauth_session_with_scope(
        "scope-full",
        "https://example.com/callback",
        "atproto",
    )
    .await;

    let collection = "app.bsky.feed.post";
    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", url))
        .bearer_auth(&session.access_token)
        .json(&json!({
            "repo": session.did,
            "collection": collection,
            "record": {
                "$type": collection,
                "text": "Full access post",
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        create_res.status(),
        StatusCode::OK,
        "atproto scope should allow creating records"
    );
    let create_body: Value = create_res.json().await.unwrap();
    let rkey = create_body["uri"]
        .as_str()
        .unwrap()
        .split('/')
        .last()
        .unwrap();

    let put_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.putRecord", url))
        .bearer_auth(&session.access_token)
        .json(&json!({
            "repo": session.did,
            "collection": collection,
            "rkey": rkey,
            "record": {
                "$type": collection,
                "text": "Updated post",
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        put_res.status(),
        StatusCode::OK,
        "atproto scope should allow updating records"
    );

    let delete_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.deleteRecord", url))
        .bearer_auth(&session.access_token)
        .json(&json!({
            "repo": session.did,
            "collection": collection,
            "rkey": rkey
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        delete_res.status(),
        StatusCode::OK,
        "atproto scope should allow deleting records"
    );
}

#[tokio::test]
async fn test_atproto_scope_allows_blob_upload() {
    let url = base_url().await;
    let http_client = client();
    let (session, _mock) = create_user_and_oauth_session_with_scope(
        "scope-blob",
        "https://example.com/callback",
        "atproto",
    )
    .await;

    let blob_data = b"Test blob data for scope test";
    let upload_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.uploadBlob", url))
        .bearer_auth(&session.access_token)
        .header("Content-Type", "text/plain")
        .body(blob_data.to_vec())
        .send()
        .await
        .unwrap();

    assert_eq!(
        upload_res.status(),
        StatusCode::OK,
        "atproto scope should allow blob upload"
    );
    let upload_body: Value = upload_res.json().await.unwrap();
    assert!(upload_body["blob"]["ref"]["$link"].is_string());
}

#[tokio::test]
async fn test_atproto_scope_allows_batch_writes() {
    let url = base_url().await;
    let http_client = client();
    let (session, _mock) = create_user_and_oauth_session_with_scope(
        "scope-batch",
        "https://example.com/callback",
        "atproto",
    )
    .await;

    let collection = "app.bsky.feed.post";
    let now = Utc::now().to_rfc3339();
    let apply_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.applyWrites", url))
        .bearer_auth(&session.access_token)
        .json(&json!({
            "repo": session.did,
            "writes": [
                {
                    "$type": "com.atproto.repo.applyWrites#create",
                    "collection": collection,
                    "rkey": "batch-scope-1",
                    "value": {
                        "$type": collection,
                        "text": "Batch post 1",
                        "createdAt": now
                    }
                },
                {
                    "$type": "com.atproto.repo.applyWrites#create",
                    "collection": collection,
                    "rkey": "batch-scope-2",
                    "value": {
                        "$type": collection,
                        "text": "Batch post 2",
                        "createdAt": now
                    }
                }
            ]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        apply_res.status(),
        StatusCode::OK,
        "atproto scope should allow batch writes"
    );
}

#[tokio::test]
async fn test_transition_generic_scope_allows_access() {
    let url = base_url().await;
    let http_client = client();
    let (session, _mock) = create_user_and_oauth_session_with_scope(
        "scope-trans",
        "https://example.com/callback",
        "atproto transition:generic",
    )
    .await;

    let collection = "app.bsky.feed.post";
    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", url))
        .bearer_auth(&session.access_token)
        .json(&json!({
            "repo": session.did,
            "collection": collection,
            "record": {
                "$type": collection,
                "text": "Post with transition scope",
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        create_res.status(),
        StatusCode::OK,
        "transition:generic scope combined with atproto should work"
    );
}

#[tokio::test]
async fn test_consent_endpoint_returns_scope_info() {
    let url = base_url().await;
    let http_client = client();

    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let handle = format!("ct{}", suffix);
    let email = format!("ct{}@example.com", suffix);
    let password = "Consent123!";
    let redirect_uri = "https://consent-test.example.com/callback";

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
    let user_did = account["did"].as_str().unwrap();
    let _ = verify_new_account(&http_client, user_did).await;

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
            ("scope", "atproto transition:generic"),
        ])
        .send()
        .await
        .unwrap();
    let par_body: Value = par_res.json().await.unwrap();
    let request_uri = par_body["request_uri"].as_str().unwrap();

    let auth_res = http_client
        .post(format!("{}/oauth/authorize", url))
        .header("Accept", "application/json")
        .json(&json!({
            "request_uri": request_uri,
            "username": &handle,
            "password": password,
            "remember_device": false
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(auth_res.status(), StatusCode::OK, "Auth should succeed");

    let consent_res = http_client
        .get(format!("{}/oauth/authorize/consent", url))
        .query(&[("request_uri", request_uri)])
        .send()
        .await
        .unwrap();

    assert_eq!(consent_res.status(), StatusCode::OK);
    let consent_body: Value = consent_res.json().await.unwrap();

    assert_eq!(consent_body["client_id"], client_id);
    assert_eq!(consent_body["did"], user_did);
    assert!(consent_body["scopes"].is_array());

    let scopes = consent_body["scopes"].as_array().unwrap();
    assert!(!scopes.is_empty(), "Should have scopes in response");

    let atproto_scope = scopes.iter().find(|s| s["scope"] == "atproto");
    assert!(atproto_scope.is_some(), "Should include atproto scope");
    let atproto = atproto_scope.unwrap();
    assert_eq!(atproto["required"], true, "atproto should be required");
    assert!(atproto["description"].is_string());
    assert!(atproto["display_name"].is_string());

    let transition_scope = scopes.iter().find(|s| s["scope"] == "transition:generic");
    assert!(
        transition_scope.is_some(),
        "Should include transition:generic scope"
    );
    let transition = transition_scope.unwrap();
    assert_eq!(
        transition["required"], false,
        "transition:generic should be optional"
    );
}

#[tokio::test]
async fn test_consent_post_generates_code() {
    let url = base_url().await;
    let http_client = client();

    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let handle = format!("cp{}", suffix);
    let email = format!("cp{}@example.com", suffix);
    let password = "ConsentPost123!";
    let redirect_uri = "https://consent-post.example.com/callback";

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
    let user_did = account["did"].as_str().unwrap();
    let _ = verify_new_account(&http_client, user_did).await;

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
            ("scope", "atproto"),
        ])
        .send()
        .await
        .unwrap();
    let par_body: Value = par_res.json().await.unwrap();
    let request_uri = par_body["request_uri"].as_str().unwrap();

    let auth_res = http_client
        .post(format!("{}/oauth/authorize", url))
        .header("Accept", "application/json")
        .json(&json!({
            "request_uri": request_uri,
            "username": &handle,
            "password": password,
            "remember_device": false
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(auth_res.status(), StatusCode::OK, "Auth should succeed");

    let consent_post_res = http_client
        .post(format!("{}/oauth/authorize/consent", url))
        .json(&json!({
            "request_uri": request_uri,
            "approved_scopes": ["atproto"],
            "remember": false
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(consent_post_res.status(), StatusCode::OK);
    let consent_body: Value = consent_post_res.json().await.unwrap();
    assert!(
        consent_body["redirect_uri"].is_string(),
        "Should return redirect URI"
    );

    let redirect_uri_response = consent_body["redirect_uri"].as_str().unwrap();
    assert!(
        redirect_uri_response.contains("code="),
        "Redirect URI should contain authorization code"
    );

    let code = redirect_uri_response
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
    assert!(token_body["access_token"].is_string());
}

#[tokio::test]
async fn test_consent_post_requires_atproto_scope() {
    let url = base_url().await;
    let http_client = client();

    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let handle = format!("cq{}", suffix);
    let email = format!("cq{}@example.com", suffix);
    let password = "ConsentReq123!";
    let redirect_uri = "https://consent-req.example.com/callback";

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
    let user_did = account["did"].as_str().unwrap();
    let _ = verify_new_account(&http_client, user_did).await;

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
            ("scope", "atproto transition:generic"),
        ])
        .send()
        .await
        .unwrap();
    let par_body: Value = par_res.json().await.unwrap();
    let request_uri = par_body["request_uri"].as_str().unwrap();

    let auth_res = http_client
        .post(format!("{}/oauth/authorize", url))
        .header("Accept", "application/json")
        .json(&json!({
            "request_uri": request_uri,
            "username": &handle,
            "password": password,
            "remember_device": false
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(auth_res.status(), StatusCode::OK, "Auth should succeed");

    let consent_post_res = http_client
        .post(format!("{}/oauth/authorize/consent", url))
        .json(&json!({
            "request_uri": request_uri,
            "approved_scopes": ["transition:generic"],
            "remember": false
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        consent_post_res.status(),
        StatusCode::BAD_REQUEST,
        "Should reject consent without atproto scope"
    );
    let error_body: Value = consent_post_res.json().await.unwrap();
    assert!(
        error_body["error_description"]
            .as_str()
            .unwrap()
            .contains("atproto")
    );
}

#[tokio::test]
async fn test_token_contains_requested_scope() {
    let scope = "atproto transition:generic";
    let (session, _mock) = create_user_and_oauth_session_with_scope(
        "scope-token",
        "https://example.com/callback",
        scope,
    )
    .await;

    assert_eq!(
        session.scope, scope,
        "Session should have the requested scope"
    );

    let parts: Vec<&str> = session.access_token.split('.').collect();
    assert_eq!(parts.len(), 3, "Token should be a valid JWT");

    let payload_json = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let payload: Value = serde_json::from_slice(&payload_json).unwrap();

    assert!(
        payload["scope"].is_string(),
        "Token payload should contain scope"
    );
    let token_scope = payload["scope"].as_str().unwrap();
    assert!(
        token_scope.contains("atproto"),
        "Token scope should contain atproto"
    );
}

#[tokio::test]
async fn test_dereference_scope_endpoint() {
    let url = base_url().await;
    let http_client = client();
    let (session, _mock) = create_user_and_oauth_session_with_scope(
        "scope-deref",
        "https://example.com/callback",
        "atproto",
    )
    .await;

    let deref_res = http_client
        .post(format!("{}/xrpc/com.atproto.temp.dereferenceScope", url))
        .bearer_auth(&session.access_token)
        .json(&json!({
            "scope": "atproto transition:generic"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(deref_res.status(), StatusCode::OK);
    let deref_body: Value = deref_res.json().await.unwrap();
    assert!(deref_body["scope"].is_string());
    let resolved_scope = deref_body["scope"].as_str().unwrap();
    assert!(resolved_scope.contains("atproto"));
    assert!(resolved_scope.contains("transition:generic"));
}

#[tokio::test]
async fn test_dereference_scope_requires_auth() {
    let url = base_url().await;
    let http_client = client();

    let deref_res = http_client
        .post(format!("{}/xrpc/com.atproto.temp.dereferenceScope", url))
        .json(&json!({
            "scope": "atproto"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        deref_res.status(),
        StatusCode::UNAUTHORIZED,
        "Should require authentication"
    );
}
