#![allow(unused_imports)]
#![allow(unused_variables)]

mod common;
mod helpers;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bspds::oauth::dpop::{DPoPVerifier, DPoPJwk, compute_jwk_thumbprint};
use chrono::Utc;
use common::{base_url, client};
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

async fn get_oauth_tokens(
    http_client: &reqwest::Client,
    url: &str,
) -> (String, String, String) {
    let ts = Utc::now().timestamp_millis();
    let handle = format!("sec-test-{}", ts);
    let email = format!("sec-test-{}@example.com", ts);
    let password = "security-test-password";

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

    let access_token = token_body["access_token"].as_str().unwrap().to_string();
    let refresh_token = token_body["refresh_token"].as_str().unwrap().to_string();

    (access_token, refresh_token, client_id)
}

#[tokio::test]
async fn test_security_forged_token_signature_rejected() {
    let url = base_url().await;
    let http_client = client();

    let (access_token, _, _) = get_oauth_tokens(&http_client, url).await;

    let parts: Vec<&str> = access_token.split('.').collect();
    assert_eq!(parts.len(), 3, "Token should have 3 parts");

    let forged_signature = URL_SAFE_NO_PAD.encode(&[0u8; 32]);
    let forged_token = format!("{}.{}.{}", parts[0], parts[1], forged_signature);

    let res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", format!("Bearer {}", forged_token))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "Forged signature should be rejected");
}

#[tokio::test]
async fn test_security_modified_payload_rejected() {
    let url = base_url().await;
    let http_client = client();

    let (access_token, _, _) = get_oauth_tokens(&http_client, url).await;

    let parts: Vec<&str> = access_token.split('.').collect();

    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let mut payload: Value = serde_json::from_slice(&payload_bytes).unwrap();
    payload["sub"] = json!("did:plc:attacker");
    let modified_payload = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());
    let modified_token = format!("{}.{}.{}", parts[0], modified_payload, parts[2]);

    let res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", format!("Bearer {}", modified_token))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "Modified payload should be rejected");
}

#[tokio::test]
async fn test_security_algorithm_none_attack_rejected() {
    let url = base_url().await;
    let http_client = client();

    let header = json!({
        "alg": "none",
        "typ": "at+jwt"
    });
    let payload = json!({
        "iss": "https://test.pds",
        "sub": "did:plc:attacker",
        "aud": "https://test.pds",
        "iat": Utc::now().timestamp(),
        "exp": Utc::now().timestamp() + 3600,
        "jti": "fake-token-id",
        "scope": "atproto"
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());
    let malicious_token = format!("{}.{}.", header_b64, payload_b64);

    let res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", format!("Bearer {}", malicious_token))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "Algorithm 'none' attack should be rejected");
}

#[tokio::test]
async fn test_security_algorithm_substitution_attack_rejected() {
    let url = base_url().await;
    let http_client = client();

    let header = json!({
        "alg": "RS256",
        "typ": "at+jwt"
    });
    let payload = json!({
        "iss": "https://test.pds",
        "sub": "did:plc:attacker",
        "aud": "https://test.pds",
        "iat": Utc::now().timestamp(),
        "exp": Utc::now().timestamp() + 3600,
        "jti": "fake-token-id"
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());
    let fake_sig = URL_SAFE_NO_PAD.encode(&[1u8; 64]);
    let malicious_token = format!("{}.{}.{}", header_b64, payload_b64, fake_sig);

    let res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", format!("Bearer {}", malicious_token))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "Algorithm substitution attack should be rejected");
}

#[tokio::test]
async fn test_security_expired_token_rejected() {
    let url = base_url().await;
    let http_client = client();

    let header = json!({
        "alg": "HS256",
        "typ": "at+jwt"
    });
    let payload = json!({
        "iss": "https://test.pds",
        "sub": "did:plc:test",
        "aud": "https://test.pds",
        "iat": Utc::now().timestamp() - 7200,
        "exp": Utc::now().timestamp() - 3600,
        "jti": "expired-token-id"
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());
    let fake_sig = URL_SAFE_NO_PAD.encode(&[1u8; 32]);
    let expired_token = format!("{}.{}.{}", header_b64, payload_b64, fake_sig);

    let res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", format!("Bearer {}", expired_token))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "Expired token should be rejected");
}

#[tokio::test]
async fn test_security_pkce_plain_method_rejected() {
    let url = base_url().await;
    let http_client = client();

    let redirect_uri = "https://example.com/pkce-plain-callback";
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

    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "PKCE plain method should be rejected");
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request");
    assert!(
        body["error_description"].as_str().unwrap().to_lowercase().contains("s256"),
        "Error should mention S256 requirement"
    );
}

#[tokio::test]
async fn test_security_pkce_missing_challenge_rejected() {
    let url = base_url().await;
    let http_client = client();

    let redirect_uri = "https://example.com/no-pkce-callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();

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

    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "Missing PKCE challenge should be rejected");
}

#[tokio::test]
async fn test_security_pkce_wrong_verifier_rejected() {
    let url = base_url().await;
    let http_client = client();

    let ts = Utc::now().timestamp_millis();
    let handle = format!("pkce-attack-{}", ts);
    let email = format!("pkce-attack-{}@example.com", ts);
    let password = "pkce-attack-password";

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

    let redirect_uri = "https://example.com/pkce-attack-callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();

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
            ("code_verifier", &attacker_verifier),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(token_res.status(), StatusCode::BAD_REQUEST, "Wrong PKCE verifier should be rejected");
    let body: Value = token_res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn test_security_authorization_code_replay_attack() {
    let url = base_url().await;
    let http_client = client();

    let ts = Utc::now().timestamp_millis();
    let handle = format!("code-replay-{}", ts);
    let email = format!("code-replay-{}@example.com", ts);
    let password = "code-replay-password";

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

    let redirect_uri = "https://example.com/code-replay-callback";
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
    let stolen_code = code.to_string();

    let first_res = http_client
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

    assert_eq!(first_res.status(), StatusCode::OK, "First use should succeed");

    let replay_res = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &stolen_code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", &code_verifier),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(replay_res.status(), StatusCode::BAD_REQUEST, "Replay attack should fail");
    let body: Value = replay_res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn test_security_refresh_token_replay_attack() {
    let url = base_url().await;
    let http_client = client();

    let ts = Utc::now().timestamp_millis();
    let handle = format!("rt-replay-{}", ts);
    let email = format!("rt-replay-{}@example.com", ts);
    let password = "rt-replay-password";

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

    let redirect_uri = "https://example.com/rt-replay-callback";
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

    let stolen_refresh_token = token_body["refresh_token"].as_str().unwrap().to_string();

    let first_refresh: Value = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &stolen_refresh_token),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(first_refresh["access_token"].is_string(), "First refresh should succeed");
    let new_refresh_token = first_refresh["refresh_token"].as_str().unwrap();

    let replay_res = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &stolen_refresh_token),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(replay_res.status(), StatusCode::BAD_REQUEST, "Refresh token replay should fail");
    let body: Value = replay_res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
    assert!(
        body["error_description"].as_str().unwrap().to_lowercase().contains("reuse"),
        "Error should mention token reuse"
    );

    let family_revoked_res = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", new_refresh_token),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(
        family_revoked_res.status(),
        StatusCode::BAD_REQUEST,
        "Token family should be revoked after replay detection"
    );
}

#[tokio::test]
async fn test_security_redirect_uri_manipulation() {
    let url = base_url().await;
    let http_client = client();

    let registered_redirect = "https://legitimate-app.com/callback";
    let attacker_redirect = "https://attacker.com/steal";
    let mock_client = setup_mock_client_metadata(registered_redirect).await;
    let client_id = mock_client.uri();

    let (_, code_challenge) = generate_pkce();

    let res = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", attacker_redirect),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "Unregistered redirect_uri should be rejected");
}

#[tokio::test]
async fn test_security_deactivated_account_blocked() {
    let url = base_url().await;
    let http_client = client();

    let ts = Utc::now().timestamp_millis();
    let handle = format!("deact-sec-{}", ts);
    let email = format!("deact-sec-{}@example.com", ts);
    let password = "deact-sec-password";

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

    let redirect_uri = "https://example.com/deact-sec-callback";
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
        .header("Accept", "application/json")
        .form(&[
            ("request_uri", request_uri),
            ("username", &handle),
            ("password", password),
            ("remember_device", "false"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(auth_res.status(), StatusCode::FORBIDDEN, "Deactivated account should be blocked from OAuth");
    let body: Value = auth_res.json().await.unwrap();
    assert_eq!(body["error"], "access_denied");
}

#[tokio::test]
async fn test_security_url_injection_in_state_parameter() {
    let url = base_url().await;
    let http_client = client();

    let ts = Utc::now().timestamp_millis();
    let handle = format!("inject-state-{}", ts);
    let email = format!("inject-state-{}@example.com", ts);
    let password = "inject-state-password";

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

    let redirect_uri = "https://example.com/inject-callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();

    let (code_verifier, code_challenge) = generate_pkce();

    let malicious_state = "state&redirect_uri=https://attacker.com&extra=";

    let par_body: Value = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
            ("state", malicious_state),
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

    assert!(auth_res.status().is_redirection(), "Should redirect successfully");
    let location = auth_res.headers().get("location").unwrap().to_str().unwrap();

    assert!(
        location.starts_with(redirect_uri),
        "Redirect should go to registered URI, not attacker URI. Got: {}",
        location
    );

    let redirect_uri_count = location.matches("redirect_uri=").count();
    assert!(
        redirect_uri_count <= 1,
        "State injection should not add extra redirect_uri parameters"
    );

    assert!(
        location.contains(&urlencoding::encode(malicious_state).to_string()) ||
        location.contains("state=state%26redirect_uri"),
        "State parameter should be properly URL-encoded. Got: {}",
        location
    );
}

#[tokio::test]
async fn test_security_cross_client_token_theft() {
    let url = base_url().await;
    let http_client = client();

    let ts = Utc::now().timestamp_millis();
    let handle = format!("cross-client-{}", ts);
    let email = format!("cross-client-{}@example.com", ts);
    let password = "cross-client-password";

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

    let redirect_uri_a = "https://app-a.com/callback";
    let mock_client_a = setup_mock_client_metadata(redirect_uri_a).await;
    let client_id_a = mock_client_a.uri();

    let redirect_uri_b = "https://app-b.com/callback";
    let mock_client_b = setup_mock_client_metadata(redirect_uri_b).await;
    let client_id_b = mock_client_b.uri();

    let (code_verifier, code_challenge) = generate_pkce();

    let par_body: Value = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id_a),
            ("redirect_uri", redirect_uri_a),
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
            ("redirect_uri", redirect_uri_a),
            ("code_verifier", &code_verifier),
            ("client_id", &client_id_b),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(
        token_res.status(),
        StatusCode::BAD_REQUEST,
        "Cross-client code exchange must be explicitly rejected (defense-in-depth)"
    );
    let body: Value = token_res.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
    assert!(
        body["error_description"].as_str().unwrap().contains("client_id"),
        "Error should mention client_id mismatch"
    );
}

#[test]
fn test_security_dpop_nonce_tamper_detection() {
    let secret = b"test-dpop-secret-32-bytes-long!!";
    let verifier = DPoPVerifier::new(secret);

    let nonce = verifier.generate_nonce();
    let nonce_bytes = URL_SAFE_NO_PAD.decode(&nonce).unwrap();

    let mut tampered = nonce_bytes.clone();
    if !tampered.is_empty() {
        tampered[0] ^= 0xFF;
    }
    let tampered_nonce = URL_SAFE_NO_PAD.encode(&tampered);

    let result = verifier.validate_nonce(&tampered_nonce);
    assert!(result.is_err(), "Tampered nonce should be rejected");
}

#[test]
fn test_security_dpop_nonce_cross_server_rejected() {
    let secret1 = b"server-1-secret-32-bytes-long!!!";
    let secret2 = b"server-2-secret-32-bytes-long!!!";

    let verifier1 = DPoPVerifier::new(secret1);
    let verifier2 = DPoPVerifier::new(secret2);

    let nonce_from_server1 = verifier1.generate_nonce();

    let result = verifier2.validate_nonce(&nonce_from_server1);
    assert!(result.is_err(), "Nonce from different server should be rejected");
}

#[test]
fn test_security_dpop_proof_signature_tampering() {
    use p256::ecdsa::{SigningKey, Signature, signature::Signer};
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let secret = b"test-dpop-secret-32-bytes-long!!";
    let verifier = DPoPVerifier::new(secret);

    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);

    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

    let header = json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y
        }
    });

    let payload = json!({
        "jti": format!("tamper-test-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)),
        "htm": "POST",
        "htu": "https://example.com/token",
        "iat": Utc::now().timestamp()
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());

    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    let mut sig_bytes = signature.to_bytes().to_vec();

    sig_bytes[0] ^= 0xFF;
    let tampered_sig = URL_SAFE_NO_PAD.encode(&sig_bytes);

    let tampered_proof = format!("{}.{}.{}", header_b64, payload_b64, tampered_sig);

    let result = verifier.verify_proof(&tampered_proof, "POST", "https://example.com/token", None);
    assert!(result.is_err(), "Tampered DPoP signature should be rejected");
}

#[test]
fn test_security_dpop_proof_key_substitution() {
    use p256::ecdsa::{SigningKey, Signature, signature::Signer};
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let secret = b"test-dpop-secret-32-bytes-long!!";
    let verifier = DPoPVerifier::new(secret);

    let signing_key = SigningKey::random(&mut rand::thread_rng());

    let attacker_key = SigningKey::random(&mut rand::thread_rng());
    let attacker_verifying = attacker_key.verifying_key();
    let attacker_point = attacker_verifying.to_encoded_point(false);

    let x = URL_SAFE_NO_PAD.encode(attacker_point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(attacker_point.y().unwrap());

    let header = json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y
        }
    });

    let payload = json!({
        "jti": format!("key-sub-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)),
        "htm": "POST",
        "htu": "https://example.com/token",
        "iat": Utc::now().timestamp()
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    let mismatched_proof = format!("{}.{}.{}", header_b64, payload_b64, signature_b64);

    let result = verifier.verify_proof(&mismatched_proof, "POST", "https://example.com/token", None);
    assert!(result.is_err(), "DPoP proof with mismatched key should be rejected");
}

#[test]
fn test_security_jwk_thumbprint_consistency() {
    let jwk = DPoPJwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        x: Some("WbbXrPhtCg66wuF0NLhzXxF5PFzNZ7wNJm9M_1pCcXY".to_string()),
        y: Some("DubR6_2kU1H5EYhbcNpYZGy1EY6GEKKxv6PYx8VW0rA".to_string()),
    };

    let mut results = Vec::new();
    for _ in 0..100 {
        results.push(compute_jwk_thumbprint(&jwk).unwrap());
    }

    let first = &results[0];
    for (i, result) in results.iter().enumerate() {
        assert_eq!(first, result, "Thumbprint should be deterministic, but iteration {} differs", i);
    }
}

#[test]
fn test_security_dpop_iat_clock_skew_limits() {
    use p256::ecdsa::{SigningKey, Signature, signature::Signer};
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let secret = b"test-dpop-secret-32-bytes-long!!";
    let verifier = DPoPVerifier::new(secret);

    let test_offsets = vec![
        (-600, true),
        (-301, true),
        (-299, false),
        (0, false),
        (299, false),
        (301, true),
        (600, true),
    ];

    for (offset_secs, should_fail) in test_offsets {
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);

        let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

        let header = json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": x,
                "y": y
            }
        });

        let payload = json!({
            "jti": format!("clock-{}-{}", offset_secs, Utc::now().timestamp_nanos_opt().unwrap_or(0)),
            "htm": "POST",
            "htu": "https://example.com/token",
            "iat": Utc::now().timestamp() + offset_secs
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let signature: Signature = signing_key.sign(signing_input.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        let proof = format!("{}.{}.{}", header_b64, payload_b64, signature_b64);

        let result = verifier.verify_proof(&proof, "POST", "https://example.com/token", None);

        if should_fail {
            assert!(result.is_err(), "iat offset {} should be rejected", offset_secs);
        } else {
            assert!(result.is_ok(), "iat offset {} should be accepted", offset_secs);
        }
    }
}

#[test]
fn test_security_dpop_method_case_insensitivity() {
    use p256::ecdsa::{SigningKey, Signature, signature::Signer};
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let secret = b"test-dpop-secret-32-bytes-long!!";
    let verifier = DPoPVerifier::new(secret);

    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);

    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

    let header = json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y
        }
    });

    let payload = json!({
        "jti": format!("case-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)),
        "htm": "post",
        "htu": "https://example.com/token",
        "iat": Utc::now().timestamp()
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    let proof = format!("{}.{}.{}", header_b64, payload_b64, signature_b64);

    let result = verifier.verify_proof(&proof, "POST", "https://example.com/token", None);
    assert!(result.is_ok(), "HTTP method comparison should be case-insensitive");
}

#[tokio::test]
async fn test_security_invalid_grant_type_rejected() {
    let url = base_url().await;
    let http_client = client();

    let grant_types = vec![
        "client_credentials",
        "password",
        "implicit",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "urn:ietf:params:oauth:grant-type:device_code",
        "",
        "AUTHORIZATION_CODE",
        "Authorization_Code",
    ];

    for grant_type in grant_types {
        let res = http_client
            .post(format!("{}/oauth/token", url))
            .form(&[
                ("grant_type", grant_type),
                ("client_id", "https://example.com"),
            ])
            .send()
            .await
            .unwrap();

        assert_eq!(
            res.status(),
            StatusCode::BAD_REQUEST,
            "Grant type '{}' should be rejected",
            grant_type
        );
    }
}

#[tokio::test]
async fn test_security_token_with_wrong_typ_rejected() {
    let url = base_url().await;
    let http_client = client();

    let wrong_types = vec![
        "JWT",
        "jwt",
        "at+JWT",
        "access_token",
        "",
    ];

    for typ in wrong_types {
        let header = json!({
            "alg": "HS256",
            "typ": typ
        });
        let payload = json!({
            "iss": "https://test.pds",
            "sub": "did:plc:test",
            "aud": "https://test.pds",
            "iat": Utc::now().timestamp(),
            "exp": Utc::now().timestamp() + 3600,
            "jti": "wrong-typ-token"
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());
        let fake_sig = URL_SAFE_NO_PAD.encode(&[1u8; 32]);
        let token = format!("{}.{}.{}", header_b64, payload_b64, fake_sig);

        let res = http_client
            .get(format!("{}/xrpc/com.atproto.server.getSession", url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .unwrap();

        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "Token with typ='{}' should be rejected",
            typ
        );
    }
}

#[tokio::test]
async fn test_security_missing_required_claims_rejected() {
    let url = base_url().await;
    let http_client = client();

    let tokens_missing_claims = vec![
        (json!({"iss": "x", "sub": "x", "aud": "x", "iat": 0}), "exp"),
        (json!({"iss": "x", "sub": "x", "aud": "x", "exp": 9999999999i64}), "iat"),
        (json!({"iss": "x", "aud": "x", "iat": 0, "exp": 9999999999i64}), "sub"),
    ];

    for (payload, missing_claim) in tokens_missing_claims {
        let header = json!({
            "alg": "HS256",
            "typ": "at+jwt"
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());
        let fake_sig = URL_SAFE_NO_PAD.encode(&[1u8; 32]);
        let token = format!("{}.{}.{}", header_b64, payload_b64, fake_sig);

        let res = http_client
            .get(format!("{}/xrpc/com.atproto.server.getSession", url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .unwrap();

        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "Token missing '{}' claim should be rejected",
            missing_claim
        );
    }
}

#[tokio::test]
async fn test_security_malformed_tokens_rejected() {
    let url = base_url().await;
    let http_client = client();

    let malformed_tokens = vec![
        "",
        "not-a-token",
        "one.two",
        "one.two.three.four",
        "....",
        "eyJhbGciOiJIUzI1NiJ9",
        "eyJhbGciOiJIUzI1NiJ9.",
        "eyJhbGciOiJIUzI1NiJ9..",
        ".eyJzdWIiOiJ0ZXN0In0.",
        "!!invalid-base64!!.eyJzdWIiOiJ0ZXN0In0.sig",
        "eyJhbGciOiJIUzI1NiJ9.!!invalid!!.sig",
    ];

    for token in malformed_tokens {
        let res = http_client
            .get(format!("{}/xrpc/com.atproto.server.getSession", url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .unwrap();

        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "Malformed token '{}' should be rejected",
            if token.len() > 50 { &token[..50] } else { token }
        );
    }
}

#[tokio::test]
async fn test_security_authorization_header_formats() {
    let url = base_url().await;
    let http_client = client();

    let (access_token, _, _) = get_oauth_tokens(&http_client, url).await;

    let valid_case_variants = vec![
        format!("bearer {}", access_token),
        format!("BEARER {}", access_token),
        format!("Bearer  {}", access_token),
    ];

    for auth_header in valid_case_variants {
        let res = http_client
            .get(format!("{}/xrpc/com.atproto.server.getSession", url))
            .header("Authorization", &auth_header)
            .send()
            .await
            .unwrap();

        assert_eq!(
            res.status(),
            StatusCode::OK,
            "Auth header '{}...' should be accepted (RFC 7235 case-insensitivity)",
            if auth_header.len() > 30 { &auth_header[..30] } else { &auth_header }
        );
    }

    let invalid_formats = vec![
        format!("Basic {}", access_token),
        format!("Digest {}", access_token),
        access_token.clone(),
        format!("Bearer{}", access_token),
    ];

    for auth_header in invalid_formats {
        let res = http_client
            .get(format!("{}/xrpc/com.atproto.server.getSession", url))
            .header("Authorization", &auth_header)
            .send()
            .await
            .unwrap();

        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "Auth header '{}...' should be rejected",
            if auth_header.len() > 30 { &auth_header[..30] } else { &auth_header }
        );
    }
}

#[tokio::test]
async fn test_security_no_authorization_header() {
    let url = base_url().await;
    let http_client = client();

    let res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "Missing auth header should return 401");
}

#[tokio::test]
async fn test_security_empty_authorization_header() {
    let url = base_url().await;
    let http_client = client();

    let res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", "")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "Empty auth header should return 401");
}

#[tokio::test]
async fn test_security_revoked_token_rejected() {
    let url = base_url().await;
    let http_client = client();

    let (access_token, refresh_token, _) = get_oauth_tokens(&http_client, url).await;

    let revoke_res = http_client
        .post(format!("{}/oauth/revoke", url))
        .form(&[("token", &refresh_token)])
        .send()
        .await
        .unwrap();

    assert_eq!(revoke_res.status(), StatusCode::OK);

    let introspect_res = http_client
        .post(format!("{}/oauth/introspect", url))
        .form(&[("token", &access_token)])
        .send()
        .await
        .unwrap();

    let introspect_body: Value = introspect_res.json().await.unwrap();
    assert_eq!(introspect_body["active"], false, "Revoked token should be inactive");
}

#[tokio::test]
async fn test_security_oauth_authorize_rate_limiting() {
    let url = base_url().await;
    let http_client = no_redirect_client();

    let ts = Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let unique_ip = format!("10.{}.{}.{}", (ts >> 16) & 0xFF, (ts >> 8) & 0xFF, ts & 0xFF);

    let redirect_uri = "https://example.com/rate-limit-callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();

    let (_, code_challenge) = generate_pkce();

    let client_for_par = client();
    let par_body: Value = client_for_par
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

    let mut rate_limited_count = 0;
    let mut other_count = 0;

    for _ in 0..15 {
        let res = http_client
            .post(format!("{}/oauth/authorize", url))
            .header("X-Forwarded-For", &unique_ip)
            .form(&[
                ("request_uri", request_uri),
                ("username", "nonexistent_user"),
                ("password", "wrong_password"),
                ("remember_device", "false"),
            ])
            .send()
            .await
            .unwrap();

        match res.status() {
            StatusCode::TOO_MANY_REQUESTS => rate_limited_count += 1,
            _ => other_count += 1,
        }
    }

    assert!(
        rate_limited_count > 0,
        "Expected at least one rate-limited response after 15 OAuth authorize attempts. Got {} other and {} rate limited.",
        other_count,
        rate_limited_count
    );
}
