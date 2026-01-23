mod common;
mod helpers;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use common::{base_url, client, create_account_and_login, pds_endpoint};
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
    let code_challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());
    (code_verifier, code_challenge)
}

async fn setup_mock_client_metadata(redirect_uri: &str, dpop_bound: bool) -> MockServer {
    let mock_server = MockServer::start().await;
    let metadata = json!({
        "client_id": mock_server.uri(),
        "client_name": "Auth Extractor Test Client",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "dpop_bound_access_tokens": dpop_bound
    });
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
        .mount(&mock_server)
        .await;
    mock_server
}

async fn get_oauth_session(
    http_client: &reqwest::Client,
    url: &str,
    dpop_bound: bool,
) -> (String, String, String, String) {
    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let handle = format!("ae{}", suffix);
    let password = "AuthExtract123!";
    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({
            "handle": handle,
            "email": format!("{}@example.com", handle),
            "password": password
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);
    let account: Value = create_res.json().await.unwrap();
    let did = account["did"].as_str().unwrap().to_string();
    verify_new_account(http_client, &did).await;

    let redirect_uri = "https://example.com/auth-callback";
    let mock_client = setup_mock_client_metadata(redirect_uri, dpop_bound).await;
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
        .json(&json!({
            "request_uri": request_uri,
            "username": &handle,
            "password": password,
            "remember_device": false
        }))
        .send()
        .await
        .unwrap();
    let auth_body: Value = auth_res.json().await.unwrap();
    let mut location = auth_body["redirect_uri"].as_str().unwrap().to_string();

    if location.contains("/oauth/consent") {
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
        did,
    )
}

#[tokio::test]
async fn test_oauth_token_works_with_bearer_auth() {
    let url = base_url().await;
    let http_client = client();
    let (access_token, _, _, did) = get_oauth_session(&http_client, url, false).await;

    let res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .bearer_auth(&access_token)
        .send()
        .await
        .unwrap();

    assert_eq!(
        res.status(),
        StatusCode::OK,
        "OAuth token should work with BearerAuth extractor"
    );
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["did"].as_str().unwrap(), did);
}

#[tokio::test]
async fn test_session_token_still_works() {
    let url = base_url().await;
    let http_client = client();
    let (jwt, did) = create_account_and_login(&http_client).await;

    let res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap();

    assert_eq!(
        res.status(),
        StatusCode::OK,
        "Session token should still work"
    );
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["did"].as_str().unwrap(), did);
}

#[tokio::test]
async fn test_oauth_admin_extractor_allows_oauth_tokens() {
    let url = base_url().await;
    let http_client = client();

    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let handle = format!("adm{}", suffix);
    let password = "AdminOAuth123!";
    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({
            "handle": handle,
            "email": format!("{}@example.com", handle),
            "password": password
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);
    let account: Value = create_res.json().await.unwrap();
    let did = account["did"].as_str().unwrap().to_string();
    verify_new_account(&http_client, &did).await;

    let pool = common::get_test_db_pool().await;
    sqlx::query!("UPDATE users SET is_admin = TRUE WHERE did = $1", &did)
        .execute(pool)
        .await
        .expect("Failed to mark user as admin");

    let redirect_uri = "https://example.com/admin-callback";
    let mock_client = setup_mock_client_metadata(redirect_uri, false).await;
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
        .json(&json!({
            "request_uri": request_uri,
            "username": &handle,
            "password": password,
            "remember_device": false
        }))
        .send()
        .await
        .unwrap();
    let auth_body: Value = auth_res.json().await.unwrap();
    let mut location = auth_body["redirect_uri"].as_str().unwrap().to_string();
    if location.contains("/oauth/consent") {
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
    let access_token = token_body["access_token"].as_str().unwrap();

    let res = http_client
        .get(format!(
            "{}/xrpc/com.atproto.admin.getAccountInfos?dids={}",
            url, did
        ))
        .bearer_auth(access_token)
        .send()
        .await
        .unwrap();

    assert_eq!(
        res.status(),
        StatusCode::OK,
        "OAuth token for admin user should work with admin endpoint"
    );
}

#[tokio::test]
async fn test_expired_oauth_token_returns_proper_error() {
    let url = base_url().await;
    let http_client = client();

    let now = Utc::now().timestamp();
    let header = json!({"alg": "HS256", "typ": "at+jwt"});
    let payload = json!({
        "iss": url,
        "sub": "did:plc:test123",
        "aud": url,
        "iat": now - 7200,
        "exp": now - 3600,
        "jti": "expired-token",
        "sid": "expired-session",
        "scope": "atproto",
        "client_id": "https://example.com"
    });
    let fake_token = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap()),
        URL_SAFE_NO_PAD.encode([1u8; 32])
    );

    let res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .bearer_auth(&fake_token)
        .send()
        .await
        .unwrap();

    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "Expired token should be rejected"
    );
}

#[tokio::test]
async fn test_dpop_nonce_error_has_proper_headers() {
    let url = base_url().await;
    let pds_url = pds_endpoint();
    let http_client = client();

    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let handle = format!("dpop{}", suffix);
    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", url))
        .json(&json!({
            "handle": handle,
            "email": format!("{}@test.com", handle),
            "password": "DpopTest123!"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);
    let account: Value = create_res.json().await.unwrap();
    let did = account["did"].as_str().unwrap();
    verify_new_account(&http_client, did).await;

    let redirect_uri = "https://example.com/dpop-callback";
    let mock_server = MockServer::start().await;
    let client_id = mock_server.uri();
    let metadata = json!({
        "client_id": &client_id,
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
        .json(&json!({
            "request_uri": request_uri,
            "username": &handle,
            "password": "DpopTest123!",
            "remember_device": false
        }))
        .send()
        .await
        .unwrap();
    let auth_body: Value = auth_res.json().await.unwrap();
    let mut location = auth_body["redirect_uri"].as_str().unwrap().to_string();
    if location.contains("/oauth/consent") {
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

    let token_endpoint = format!("{}/oauth/token", pds_url);
    let (_, dpop_proof) = generate_dpop_proof("POST", &token_endpoint, None);

    let token_res = http_client
        .post(format!("{}/oauth/token", url))
        .header("DPoP", &dpop_proof)
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

    let token_status = token_res.status();
    let token_nonce = token_res
        .headers()
        .get("dpop-nonce")
        .map(|h| h.to_str().unwrap().to_string());
    let token_body: Value = token_res.json().await.unwrap();

    let access_token = if token_status == StatusCode::OK {
        token_body["access_token"].as_str().unwrap().to_string()
    } else if token_body.get("error").and_then(|e| e.as_str()) == Some("use_dpop_nonce") {
        let nonce =
            token_nonce.expect("Token endpoint should return DPoP-Nonce on use_dpop_nonce error");
        let (_, dpop_proof_with_nonce) = generate_dpop_proof("POST", &token_endpoint, Some(&nonce));

        let retry_res = http_client
            .post(format!("{}/oauth/token", url))
            .header("DPoP", &dpop_proof_with_nonce)
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
        let retry_body: Value = retry_res.json().await.unwrap();
        retry_body["access_token"]
            .as_str()
            .expect("Should get access_token after nonce retry")
            .to_string()
    } else {
        panic!("Token exchange failed unexpectedly: {:?}", token_body);
    };

    let res = http_client
        .get(format!("{}/xrpc/com.atproto.server.getSession", url))
        .header("Authorization", format!("DPoP {}", access_token))
        .send()
        .await
        .unwrap();

    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "DPoP token without proof should fail"
    );

    let www_auth = res
        .headers()
        .get("www-authenticate")
        .map(|h| h.to_str().unwrap());
    assert!(www_auth.is_some(), "Should have WWW-Authenticate header");
    assert!(
        www_auth.unwrap().contains("use_dpop_nonce"),
        "WWW-Authenticate should indicate dpop nonce required"
    );

    let nonce = res.headers().get("dpop-nonce").map(|h| h.to_str().unwrap());
    assert!(nonce.is_some(), "Should return DPoP-Nonce header");

    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"].as_str().unwrap(), "use_dpop_nonce");
}

fn generate_dpop_proof(method: &str, uri: &str, nonce: Option<&str>) -> (Value, String) {
    use p256::ecdsa::{SigningKey, signature::Signer};
    use p256::elliptic_curve::rand_core::OsRng;

    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

    let jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y
    });

    let header = {
        let h = json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": jwk.clone()
        });
        h
    };

    let mut payload = json!({
        "jti": uuid::Uuid::new_v4().to_string(),
        "htm": method,
        "htu": uri,
        "iat": Utc::now().timestamp()
    });
    if let Some(n) = nonce {
        payload["nonce"] = json!(n);
    }

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap());
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let signature: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    let proof = format!("{}.{}", signing_input, sig_b64);
    (jwk, proof)
}
