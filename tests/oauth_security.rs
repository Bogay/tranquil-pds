#![allow(unused_imports)]
mod common;
mod helpers;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use common::{base_url, client};
use helpers::verify_new_account;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tranquil_pds::oauth::dpop::{DPoPJwk, DPoPVerifier, compute_jwk_thumbprint};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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
    let metadata = json!({
        "client_id": mock_server.uri(),
        "client_name": "Security Test Client",
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

async fn get_oauth_tokens(http_client: &reqwest::Client, url: &str) -> (String, String, String) {
    let ts = Utc::now().timestamp_millis();
    let handle = format!("sec-test-{}", ts);
    let create_res = http_client.post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({ "handle": handle, "email": format!("{}@example.com", handle), "password": "Security123!" }))
        .send().await.unwrap();
    let account: Value = create_res.json().await.unwrap();
    let did = account["did"].as_str().unwrap();
    verify_new_account(http_client, did).await;
    let redirect_uri = "https://example.com/sec-callback";
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
    let auth_res = http_client.post(format!("{}/oauth/authorize", url))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&json!({"request_uri": request_uri, "username": &handle, "password": "Security123!", "remember_device": false}))
        .send().await.unwrap();
    let auth_body: Value = auth_res.json().await.unwrap();
    let mut location = auth_body["redirect_uri"].as_str().unwrap().to_string();
    if location.contains("/oauth/consent") {
        let consent_res = http_client.post(format!("{}/oauth/authorize/consent", url))
            .header("Content-Type", "application/json")
            .json(&json!({"request_uri": request_uri, "approved_scopes": ["atproto"], "remember": false}))
            .send().await.unwrap();
        let consent_body: Value = consent_res.json().await.unwrap();
        location = consent_body["redirect_uri"].as_str().unwrap().to_string();
    }
    let code = location
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
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
    (
        token_body["access_token"].as_str().unwrap().to_string(),
        token_body["refresh_token"].as_str().unwrap().to_string(),
        client_id,
    )
}

#[tokio::test]
async fn test_token_tampering_attacks() {
    let url = base_url().await;
    let http_client = client();
    let (access_token, _, _) = get_oauth_tokens(&http_client, url).await;
    let parts: Vec<&str> = access_token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let forged_sig = URL_SAFE_NO_PAD.encode(&[0u8; 32]);
    let forged_token = format!("{}.{}.{}", parts[0], parts[1], forged_sig);
    assert_eq!(
        http_client
            .get(format!("{}/xrpc/com.atproto.server.getSession", url))
            .bearer_auth(&forged_token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED,
        "Forged signature should be rejected"
    );
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let mut payload: Value = serde_json::from_slice(&payload_bytes).unwrap();
    payload["sub"] = json!("did:plc:attacker");
    let modified_payload = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());
    let modified_token = format!("{}.{}.{}", parts[0], modified_payload, parts[2]);
    assert_eq!(
        http_client
            .get(format!("{}/xrpc/com.atproto.server.getSession", url))
            .bearer_auth(&modified_token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED,
        "Modified payload should be rejected"
    );
    let none_header = json!({ "alg": "none", "typ": "at+jwt" });
    let none_payload = json!({ "iss": "https://test.pds", "sub": "did:plc:attacker", "aud": "https://test.pds",
        "iat": Utc::now().timestamp(), "exp": Utc::now().timestamp() + 3600, "jti": "fake", "scope": "atproto" });
    let none_token = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(serde_json::to_string(&none_header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_string(&none_payload).unwrap())
    );
    assert_eq!(
        http_client
            .get(format!("{}/xrpc/com.atproto.server.getSession", url))
            .bearer_auth(&none_token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED,
        "alg=none should be rejected"
    );
    let rs256_header = json!({ "alg": "RS256", "typ": "at+jwt" });
    let rs256_token = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_string(&rs256_header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_string(&none_payload).unwrap()),
        URL_SAFE_NO_PAD.encode(&[1u8; 64])
    );
    assert_eq!(
        http_client
            .get(format!("{}/xrpc/com.atproto.server.getSession", url))
            .bearer_auth(&rs256_token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED,
        "Algorithm substitution should be rejected"
    );
    let expired_payload = json!({ "iss": "https://test.pds", "sub": "did:plc:test", "aud": "https://test.pds",
        "iat": Utc::now().timestamp() - 7200, "exp": Utc::now().timestamp() - 3600, "jti": "expired" });
    let expired_token = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD
            .encode(serde_json::to_string(&json!({"alg":"HS256","typ":"at+jwt"})).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_string(&expired_payload).unwrap()),
        URL_SAFE_NO_PAD.encode(&[1u8; 32])
    );
    assert_eq!(
        http_client
            .get(format!("{}/xrpc/com.atproto.server.getSession", url))
            .bearer_auth(&expired_token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED,
        "Expired token should be rejected"
    );
}

#[tokio::test]
async fn test_pkce_security() {
    let url = base_url().await;
    let http_client = client();
    let redirect_uri = "https://example.com/pkce-callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();
    let res = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", "plain-text-challenge"),
            ("code_challenge_method", "plain"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "PKCE plain method should be rejected"
    );
    let body: Value = res.json().await.unwrap();
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("s256")
    );
    let res = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "Missing PKCE challenge should be rejected"
    );
    let ts = Utc::now().timestamp_millis();
    let handle = format!("pkce-attack-{}", ts);
    let create_res = http_client.post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({ "handle": handle, "email": format!("{}@example.com", handle), "password": "Pkce123pass!" }))
        .send().await.unwrap();
    let account: Value = create_res.json().await.unwrap();
    verify_new_account(&http_client, account["did"].as_str().unwrap()).await;
    let (_, code_challenge) = generate_pkce();
    let (attacker_verifier, _) = generate_pkce();
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
    let auth_res = http_client.post(format!("{}/oauth/authorize", url))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&json!({"request_uri": request_uri, "username": &handle, "password": "Pkce123pass!", "remember_device": false}))
        .send().await.unwrap();
    assert_eq!(auth_res.status(), StatusCode::OK);
    let auth_body: Value = auth_res.json().await.unwrap();
    let mut location = auth_body["redirect_uri"].as_str().unwrap().to_string();
    if location.contains("/oauth/consent") {
        let consent_res = http_client.post(format!("{}/oauth/authorize/consent", url))
            .header("Content-Type", "application/json")
            .json(&json!({"request_uri": request_uri, "approved_scopes": ["atproto"], "remember": false}))
            .send().await.unwrap();
        let consent_body: Value = consent_res.json().await.unwrap();
        location = consent_body["redirect_uri"].as_str().unwrap().to_string();
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
            ("code_verifier", &attacker_verifier),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        token_res.status(),
        StatusCode::BAD_REQUEST,
        "Wrong PKCE verifier should be rejected"
    );
}

#[tokio::test]
async fn test_replay_attacks() {
    let url = base_url().await;
    let http_client = client();
    let ts = Utc::now().timestamp_millis();
    let handle = format!("replay-{}", ts);
    let create_res = http_client.post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({ "handle": handle, "email": format!("{}@example.com", handle), "password": "Replay123pass!" }))
        .send().await.unwrap();
    let account: Value = create_res.json().await.unwrap();
    verify_new_account(&http_client, account["did"].as_str().unwrap()).await;
    let redirect_uri = "https://example.com/replay-callback";
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
    let auth_res = http_client.post(format!("{}/oauth/authorize", url))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&json!({"request_uri": request_uri, "username": &handle, "password": "Replay123pass!", "remember_device": false}))
        .send().await.unwrap();
    assert_eq!(auth_res.status(), StatusCode::OK);
    let auth_body: Value = auth_res.json().await.unwrap();
    let mut location = auth_body["redirect_uri"].as_str().unwrap().to_string();
    if location.contains("/oauth/consent") {
        let consent_res = http_client.post(format!("{}/oauth/authorize/consent", url))
            .header("Content-Type", "application/json")
            .json(&json!({"request_uri": request_uri, "approved_scopes": ["atproto"], "remember": false}))
            .send().await.unwrap();
        let consent_body: Value = consent_res.json().await.unwrap();
        location = consent_body["redirect_uri"].as_str().unwrap().to_string();
    }
    let code = location
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .to_string();
    let first = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", &code_verifier),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK, "First use should succeed");
    let first_body: Value = first.json().await.unwrap();
    let replay = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", &code_verifier),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        replay.status(),
        StatusCode::BAD_REQUEST,
        "Auth code replay should fail"
    );
    let stolen_rt = first_body["refresh_token"].as_str().unwrap().to_string();
    let first_refresh: Value = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &stolen_rt),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        first_refresh["access_token"].is_string(),
        "First refresh should succeed"
    );
    let new_rt = first_refresh["refresh_token"].as_str().unwrap();
    let rt_replay = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &stolen_rt),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        rt_replay.status(),
        StatusCode::BAD_REQUEST,
        "Refresh token replay should fail"
    );
    let body: Value = rt_replay.json().await.unwrap();
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("reuse")
    );
    let family_revoked = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", new_rt),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        family_revoked.status(),
        StatusCode::BAD_REQUEST,
        "Token family should be revoked"
    );
}

#[tokio::test]
async fn test_oauth_security_boundaries() {
    let url = base_url().await;
    let http_client = client();
    let registered_redirect = "https://legitimate-app.com/callback";
    let mock_client = setup_mock_client_metadata(registered_redirect).await;
    let client_id = mock_client.uri();
    let (_, code_challenge) = generate_pkce();
    let res = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", "https://attacker.com/steal"),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "Unregistered redirect_uri should be rejected"
    );
    let ts = Utc::now().timestamp_millis();
    let handle = format!("deact-{}", ts);
    let create_res = http_client.post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({ "handle": handle, "email": format!("{}@example.com", handle), "password": "Deact123pass!" }))
        .send().await.unwrap();
    let account: Value = create_res.json().await.unwrap();
    let access_jwt = verify_new_account(&http_client, account["did"].as_str().unwrap()).await;
    http_client
        .post(format!("{}/xrpc/com.atproto.server.deactivateAccount", url))
        .bearer_auth(&access_jwt)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    let deact_par: Value = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", registered_redirect),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let auth_res = http_client.post(format!("{}/oauth/authorize", url))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&json!({"request_uri": deact_par["request_uri"].as_str().unwrap(), "username": &handle, "password": "Deact123pass!", "remember_device": false}))
        .send().await.unwrap();
    assert_eq!(
        auth_res.status(),
        StatusCode::FORBIDDEN,
        "Deactivated account should be blocked"
    );
    let redirect_uri_a = "https://app-a.com/callback";
    let mock_a = setup_mock_client_metadata(redirect_uri_a).await;
    let client_id_a = mock_a.uri();
    let mock_b = setup_mock_client_metadata("https://app-b.com/callback").await;
    let client_id_b = mock_b.uri();
    let ts2 = Utc::now().timestamp_millis();
    let handle2 = format!("cross-{}", ts2);
    let create_res2 = http_client.post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({ "handle": handle2, "email": format!("{}@example.com", handle2), "password": "Cross123pass!" }))
        .send().await.unwrap();
    let account2: Value = create_res2.json().await.unwrap();
    verify_new_account(&http_client, account2["did"].as_str().unwrap()).await;
    let (code_verifier2, code_challenge2) = generate_pkce();
    let par_a: Value = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id_a),
            ("redirect_uri", redirect_uri_a),
            ("code_challenge", &code_challenge2),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let request_uri_a = par_a["request_uri"].as_str().unwrap();
    let auth_a = http_client.post(format!("{}/oauth/authorize", url))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&json!({"request_uri": request_uri_a, "username": &handle2, "password": "Cross123pass!", "remember_device": false}))
        .send().await.unwrap();
    assert_eq!(auth_a.status(), StatusCode::OK);
    let auth_body_a: Value = auth_a.json().await.unwrap();
    let mut loc_a = auth_body_a["redirect_uri"].as_str().unwrap().to_string();
    if loc_a.contains("/oauth/consent") {
        let consent_res = http_client.post(format!("{}/oauth/authorize/consent", url))
            .header("Content-Type", "application/json")
            .json(&json!({"request_uri": request_uri_a, "approved_scopes": ["atproto"], "remember": false}))
            .send().await.unwrap();
        let consent_body: Value = consent_res.json().await.unwrap();
        loc_a = consent_body["redirect_uri"].as_str().unwrap().to_string();
    }
    let code_a = loc_a
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let cross_client = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code_a),
            ("redirect_uri", redirect_uri_a),
            ("code_verifier", &code_verifier2),
            ("client_id", &client_id_b),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        cross_client.status(),
        StatusCode::BAD_REQUEST,
        "Cross-client code exchange must be rejected"
    );
}

#[tokio::test]
async fn test_malformed_tokens_and_headers() {
    let url = base_url().await;
    let http_client = client();
    let malformed = vec![
        "",
        "not-a-token",
        "one.two",
        "one.two.three.four",
        "....",
        "eyJhbGciOiJIUzI1NiJ9",
        "eyJhbGciOiJIUzI1NiJ9.",
        "eyJhbGciOiJIUzI1NiJ9..",
        ".eyJzdWIiOiJ0ZXN0In0.",
        "!!invalid!!.eyJ9.sig",
    ];
    for token in &malformed {
        assert_eq!(
            http_client
                .get(format!("{}/xrpc/com.atproto.server.getSession", url))
                .bearer_auth(token)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let wrong_types = vec!["JWT", "jwt", "at+JWT", ""];
    for typ in wrong_types {
        let header = json!({ "alg": "HS256", "typ": typ });
        let payload = json!({ "iss": "x", "sub": "did:plc:x", "aud": "x", "iat": Utc::now().timestamp(), "exp": Utc::now().timestamp() + 3600, "jti": "x" });
        let token = format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap()),
            URL_SAFE_NO_PAD.encode(&[1u8; 32])
        );
        assert_eq!(
            http_client
                .get(format!("{}/xrpc/com.atproto.server.getSession", url))
                .bearer_auth(&token)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED,
            "typ='{}' should be rejected",
            typ
        );
    }
    let (access_token, _, _) = get_oauth_tokens(&http_client, url).await;
    let invalid_formats = vec![
        format!("Basic {}", access_token),
        format!("Digest {}", access_token),
        access_token.clone(),
        format!("Bearer{}", access_token),
    ];
    for auth in &invalid_formats {
        assert_eq!(
            http_client
                .get(format!("{}/xrpc/com.atproto.server.getSession", url))
                .header("Authorization", auth)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        http_client
            .get(format!("{}/xrpc/com.atproto.server.getSession", url))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        http_client
            .get(format!("{}/xrpc/com.atproto.server.getSession", url))
            .header("Authorization", "")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let grants = vec![
        "client_credentials",
        "password",
        "implicit",
        "",
        "AUTHORIZATION_CODE",
    ];
    for grant in grants {
        assert_eq!(
            http_client
                .post(format!("{}/oauth/token", url))
                .form(&[("grant_type", grant), ("client_id", "https://example.com")])
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST,
            "Grant '{}' should be rejected",
            grant
        );
    }
}

#[tokio::test]
async fn test_token_revocation() {
    let url = base_url().await;
    let http_client = client();
    let (access_token, refresh_token, _) = get_oauth_tokens(&http_client, url).await;
    assert_eq!(
        http_client
            .post(format!("{}/oauth/revoke", url))
            .form(&[("token", &refresh_token)])
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let introspect: Value = http_client
        .post(format!("{}/oauth/introspect", url))
        .form(&[("token", &access_token)])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        introspect["active"], false,
        "Revoked token should be inactive"
    );
}

fn create_dpop_proof(
    method: &str,
    uri: &str,
    _nonce: Option<&str>,
    ath: Option<&str>,
    iat_offset: i64,
) -> String {
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let point = signing_key.verifying_key().to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());
    let header = json!({ "typ": "dpop+jwt", "alg": "ES256", "jwk": { "kty": "EC", "crv": "P-256", "x": x, "y": y } });
    let mut payload = json!({ "jti": format!("unique-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)),
        "htm": method, "htu": uri, "iat": Utc::now().timestamp() + iat_offset });
    if let Some(a) = ath {
        payload["ath"] = json!(a);
    }
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    format!(
        "{}.{}",
        signing_input,
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

#[test]
fn test_dpop_nonce_security() {
    let secret1 = b"test-dpop-secret-32-bytes-long!!";
    let secret2 = b"different-secret-32-bytes-long!!";
    let v1 = DPoPVerifier::new(secret1);
    let v2 = DPoPVerifier::new(secret2);
    let nonce = v1.generate_nonce();
    assert!(!nonce.is_empty());
    assert!(v1.validate_nonce(&nonce).is_ok(), "Valid nonce should pass");
    assert!(
        v2.validate_nonce(&nonce).is_err(),
        "Nonce from different secret should fail"
    );
    let nonce_bytes = URL_SAFE_NO_PAD.decode(&nonce).unwrap();
    let mut tampered = nonce_bytes.clone();
    if !tampered.is_empty() {
        tampered[0] ^= 0xFF;
    }
    assert!(
        v1.validate_nonce(&URL_SAFE_NO_PAD.encode(&tampered))
            .is_err(),
        "Tampered nonce should fail"
    );
    assert!(v1.validate_nonce("invalid").is_err());
    assert!(v1.validate_nonce("").is_err());
    assert!(v1.validate_nonce("!!!not-base64!!!").is_err());
}

#[test]
fn test_dpop_proof_validation() {
    let secret = b"test-dpop-secret-32-bytes-long!!";
    let verifier = DPoPVerifier::new(secret);
    assert!(
        verifier
            .verify_proof("not.enough", "POST", "https://example.com", None)
            .is_err()
    );
    assert!(
        verifier
            .verify_proof("invalid", "POST", "https://example.com", None)
            .is_err()
    );
    let proof = create_dpop_proof("POST", "https://example.com/token", None, None, 0);
    assert!(
        verifier
            .verify_proof(&proof, "GET", "https://example.com/token", None)
            .is_err(),
        "Method mismatch"
    );
    assert!(
        verifier
            .verify_proof(&proof, "POST", "https://other.com/token", None)
            .is_err(),
        "URI mismatch"
    );
    assert!(
        verifier
            .verify_proof(&proof, "POST", "https://example.com/token?foo=bar", None)
            .is_ok(),
        "Query params should be ignored"
    );
    let old_proof = create_dpop_proof("POST", "https://example.com/token", None, None, -600);
    assert!(
        verifier
            .verify_proof(&old_proof, "POST", "https://example.com/token", None)
            .is_err(),
        "iat too old"
    );
    let future_proof = create_dpop_proof("POST", "https://example.com/token", None, None, 600);
    assert!(
        verifier
            .verify_proof(&future_proof, "POST", "https://example.com/token", None)
            .is_err(),
        "iat in future"
    );
    let ath_proof = create_dpop_proof(
        "GET",
        "https://example.com/resource",
        None,
        Some("wrong"),
        0,
    );
    assert!(
        verifier
            .verify_proof(
                &ath_proof,
                "GET",
                "https://example.com/resource",
                Some("correct")
            )
            .is_err(),
        "ath mismatch"
    );
    let no_ath_proof = create_dpop_proof("GET", "https://example.com/resource", None, None, 0);
    assert!(
        verifier
            .verify_proof(
                &no_ath_proof,
                "GET",
                "https://example.com/resource",
                Some("expected")
            )
            .is_err(),
        "Missing ath"
    );
}

#[test]
fn test_dpop_proof_signature_attacks() {
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let secret = b"test-dpop-secret-32-bytes-long!!";
    let verifier = DPoPVerifier::new(secret);
    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let attacker_key = SigningKey::random(&mut rand::thread_rng());
    let attacker_point = attacker_key.verifying_key().to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(attacker_point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(attacker_point.y().unwrap());
    let header = json!({ "typ": "dpop+jwt", "alg": "ES256", "jwk": { "kty": "EC", "crv": "P-256", "x": x, "y": y } });
    let payload = json!({ "jti": format!("key-sub-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)),
        "htm": "POST", "htu": "https://example.com/token", "iat": Utc::now().timestamp() });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    let mismatched = format!(
        "{}.{}",
        signing_input,
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    );
    assert!(
        verifier
            .verify_proof(&mismatched, "POST", "https://example.com/token", None)
            .is_err(),
        "Mismatched key should fail"
    );
    let point = signing_key.verifying_key().to_encoded_point(false);
    let good_header = json!({ "typ": "dpop+jwt", "alg": "ES256", "jwk": { "kty": "EC", "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()), "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()) } });
    let good_header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&good_header).unwrap());
    let good_input = format!("{}.{}", good_header_b64, payload_b64);
    let good_sig: Signature = signing_key.sign(good_input.as_bytes());
    let mut sig_bytes = good_sig.to_bytes().to_vec();
    sig_bytes[0] ^= 0xFF;
    let tampered = format!("{}.{}", good_input, URL_SAFE_NO_PAD.encode(&sig_bytes));
    assert!(
        verifier
            .verify_proof(&tampered, "POST", "https://example.com/token", None)
            .is_err(),
        "Tampered sig should fail"
    );
}

#[test]
fn test_jwk_thumbprint() {
    let jwk = DPoPJwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        x: Some("WbbXrPhtCg66wuF0NLhzXxF5PFzNZ7wNJm9M_1pCcXY".to_string()),
        y: Some("DubR6_2kU1H5EYhbcNpYZGy1EY6GEKKxv6PYx8VW0rA".to_string()),
    };
    let tp1 = compute_jwk_thumbprint(&jwk).unwrap();
    let tp2 = compute_jwk_thumbprint(&jwk).unwrap();
    assert_eq!(tp1, tp2, "Thumbprint should be deterministic");
    assert!(!tp1.is_empty());
    assert!(
        compute_jwk_thumbprint(&DPoPJwk {
            kty: "EC".to_string(),
            crv: Some("secp256k1".to_string()),
            x: Some("x".to_string()),
            y: Some("y".to_string())
        })
        .is_ok()
    );
    assert!(
        compute_jwk_thumbprint(&DPoPJwk {
            kty: "OKP".to_string(),
            crv: Some("Ed25519".to_string()),
            x: Some("x".to_string()),
            y: None
        })
        .is_ok()
    );
    assert!(
        compute_jwk_thumbprint(&DPoPJwk {
            kty: "EC".to_string(),
            crv: None,
            x: Some("x".to_string()),
            y: Some("y".to_string())
        })
        .is_err()
    );
    assert!(
        compute_jwk_thumbprint(&DPoPJwk {
            kty: "EC".to_string(),
            crv: Some("P-256".to_string()),
            x: None,
            y: Some("y".to_string())
        })
        .is_err()
    );
    assert!(
        compute_jwk_thumbprint(&DPoPJwk {
            kty: "EC".to_string(),
            crv: Some("P-256".to_string()),
            x: Some("x".to_string()),
            y: None
        })
        .is_err()
    );
    assert!(
        compute_jwk_thumbprint(&DPoPJwk {
            kty: "RSA".to_string(),
            crv: None,
            x: None,
            y: None
        })
        .is_err()
    );
}

#[test]
fn test_dpop_clock_skew() {
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let secret = b"test-dpop-secret-32-bytes-long!!";
    let verifier = DPoPVerifier::new(secret);
    let test_cases = vec![
        (-600, true),
        (-301, true),
        (-299, false),
        (0, false),
        (299, false),
        (301, true),
        (600, true),
    ];
    for (offset, should_fail) in test_cases {
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let point = signing_key.verifying_key().to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());
        let header = json!({ "typ": "dpop+jwt", "alg": "ES256", "jwk": { "kty": "EC", "crv": "P-256", "x": x, "y": y } });
        let payload = json!({ "jti": format!("clock-{}-{}", offset, Utc::now().timestamp_nanos_opt().unwrap_or(0)),
            "htm": "POST", "htu": "https://example.com/token", "iat": Utc::now().timestamp() + offset });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let signature: Signature = signing_key.sign(signing_input.as_bytes());
        let proof = format!(
            "{}.{}",
            signing_input,
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );
        let result = verifier.verify_proof(&proof, "POST", "https://example.com/token", None);
        if should_fail {
            assert!(result.is_err(), "offset {} should fail", offset);
        } else {
            assert!(result.is_ok(), "offset {} should pass", offset);
        }
    }
}

#[test]
fn test_dpop_http_method_case() {
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let secret = b"test-dpop-secret-32-bytes-long!!";
    let verifier = DPoPVerifier::new(secret);
    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let point = signing_key.verifying_key().to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());
    let header = json!({ "typ": "dpop+jwt", "alg": "ES256", "jwk": { "kty": "EC", "crv": "P-256", "x": x, "y": y } });
    let payload = json!({ "jti": format!("case-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)),
        "htm": "post", "htu": "https://example.com/token", "iat": Utc::now().timestamp() });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    let proof = format!(
        "{}.{}",
        signing_input,
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    );
    assert!(
        verifier
            .verify_proof(&proof, "POST", "https://example.com/token", None)
            .is_ok(),
        "HTTP method should be case-insensitive"
    );
}
