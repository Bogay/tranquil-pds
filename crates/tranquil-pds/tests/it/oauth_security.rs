#![allow(unused_imports)]
use crate::common::mock_oidc::MockUser;
use crate::common::{
    base_url, client, create_account_and_login, get_test_repos, pds_hostname, setup_mock_oidc,
};
use crate::helpers::verify_new_account;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tranquil_pds::oauth::{DPoPJwk, DPoPVerifier, compute_jwk_thumbprint};
use tranquil_types::{Did, RequestId};
use webauthn_authenticator_rs::prelude::{
    CreationChallengeResponse, RequestChallengeResponse, Url, WebauthnAuthenticator,
};
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
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
    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let handle = format!("se{}", suffix);
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

struct PasskeyUser {
    did: String,
    handle: String,
    app_password: String,
    authenticator: WebauthnAuthenticator<SoftPasskey>,
}

async fn create_passkey_user(prefix: &str) -> PasskeyUser {
    create_passkey_user_for(prefix, None).await
}

async fn create_passkey_user_for(prefix: &str, request_uri: Option<&str>) -> PasskeyUser {
    let http = client();
    let url = base_url().await;
    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let handle = format!("{}{}.test", prefix, suffix);
    let email = format!("{}{}@test.com", prefix, suffix);

    let create_res = http
        .post(format!("{}/xrpc/_account.createPasskeyAccount", url))
        .json(&json!({ "handle": handle, "email": email, "requestUri": request_uri }))
        .send()
        .await
        .unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);
    let body: Value = create_res.json().await.unwrap();
    let did = body["did"].as_str().unwrap().to_string();
    let setup_token = body["setupToken"].as_str().unwrap().to_string();

    verify_new_account(&http, &did).await;

    let origin = Url::parse(&format!("https://{}", pds_hostname())).unwrap();

    let reg_start_res = http
        .post(format!(
            "{}/xrpc/_account.startPasskeyRegistrationForSetup",
            url
        ))
        .json(&json!({ "did": did, "setupToken": setup_token }))
        .send()
        .await
        .unwrap();
    assert_eq!(reg_start_res.status(), StatusCode::OK);
    let reg_body: Value = reg_start_res.json().await.unwrap();
    let mut ccr: CreationChallengeResponse =
        serde_json::from_value(reg_body["options"].clone()).unwrap();
    if let Some(sel) = ccr.public_key.authenticator_selection.as_mut() {
        sel.require_resident_key = false;
        sel.resident_key = None;
    }

    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let reg_credential = authenticator.do_registration(origin, ccr).unwrap();

    let complete_res = http
        .post(format!("{}/xrpc/_account.completePasskeySetup", url))
        .json(&json!({
            "did": did,
            "setupToken": setup_token,
            "passkeyCredential": serde_json::to_value(&reg_credential).unwrap(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(complete_res.status(), StatusCode::OK);
    let complete_body: Value = complete_res.json().await.unwrap();
    let app_password = complete_body["appPassword"].as_str().unwrap().to_string();

    PasskeyUser {
        did,
        handle,
        app_password,
        authenticator,
    }
}

async fn session_jwt(user: &PasskeyUser) -> String {
    let session: Value = client()
        .post(format!(
            "{}/xrpc/com.atproto.server.createSession",
            base_url().await
        ))
        .json(&json!({ "identifier": user.handle, "password": user.app_password }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    session["accessJwt"].as_str().unwrap().to_string()
}

async fn handle_of(jwt: &str) -> String {
    let session: Value = client()
        .get(format!(
            "{}/xrpc/com.atproto.server.getSession",
            base_url().await
        ))
        .bearer_auth(jwt)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    session["handle"].as_str().unwrap().to_string()
}

const TOTP_SECRET: [u8; 20] = [0u8; 20];

async fn enable_totp_for_user(did: &str) {
    let repos = get_test_repos().await;
    let encrypted = tranquil_pds::auth::encrypt_totp_secret(&TOTP_SECRET).unwrap();
    repos
        .user
        .enable_totp_verified(&Did::new(did.to_string()).unwrap(), &encrypted)
        .await
        .unwrap();
}

async fn create_delegated_account(controller_jwt: &str, prefix: &str) -> (String, String) {
    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let res = client()
        .post(format!(
            "{}/xrpc/_delegation.createDelegatedAccount",
            base_url().await
        ))
        .bearer_auth(controller_jwt)
        .json(&json!({
            "handle": format!("{}{}", prefix, suffix),
            "controllerScopes": "atproto"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    (
        body["did"].as_str().unwrap().to_string(),
        body["handle"].as_str().unwrap().to_string(),
    )
}

async fn par_request(client_id: &str, redirect_uri: &str) -> (String, String) {
    par_request_with(client_id, redirect_uri, &[]).await
}

async fn par_request_with(
    client_id: &str,
    redirect_uri: &str,
    extra: &[(&str, &str)],
) -> (String, String) {
    let (code_verifier, code_challenge) = generate_pkce();
    let par_body: Value = client()
        .post(format!("{}/oauth/par", base_url().await))
        .form(
            &[
                ("response_type", "code"),
                ("client_id", client_id),
                ("redirect_uri", redirect_uri),
                ("code_challenge", &code_challenge),
                ("code_challenge_method", "S256"),
                ("scope", "atproto"),
            ]
            .iter()
            .chain(extra)
            .collect::<Vec<_>>(),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    (
        par_body["request_uri"].as_str().unwrap().to_string(),
        code_verifier,
    )
}

fn current_totp_code() -> String {
    totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        TOTP_SECRET.to_vec(),
        None,
        String::new(),
    )
    .unwrap()
    .generate_current()
    .unwrap()
}

async fn submit_2fa(request_uri: &str, code: &str, trust_device: bool) -> reqwest::Response {
    client()
        .post(format!("{}/oauth/authorize/2fa", base_url().await))
        .json(&json!({
            "request_uri": request_uri,
            "code": code,
            "trust_device": trust_device,
        }))
        .send()
        .await
        .unwrap()
}

async fn submit_delegation_totp(request_uri: &str, code: &str) -> reqwest::Response {
    client()
        .post(format!("{}/oauth/delegation/totp", base_url().await))
        .json(&json!({
            "request_uri": request_uri,
            "code": code,
        }))
        .send()
        .await
        .unwrap()
}

async fn get_email_2fa_code(request_uri: &str) -> String {
    let repos = get_test_repos().await;
    let challenge = repos
        .oauth
        .get_2fa_challenge(&RequestId::from(request_uri.to_string()))
        .await
        .unwrap()
        .expect("no 2FA challenge for request");
    challenge.code
}

async fn identify(request_uri: &str, username: &str, password: &str) -> Value {
    let res = client()
        .post(format!("{}/oauth/authorize", base_url().await))
        .header("Accept", "application/json")
        .json(&json!({
            "request_uri": request_uri,
            "username": username,
            "password": password,
            "remember_device": false
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    res.json().await.unwrap()
}

async fn passkey_page_login(request_uri: &str, user: &mut PasskeyUser) -> Value {
    let origin = Url::parse(&format!("https://{}", pds_hostname())).unwrap();
    let start: Value = client()
        .get(format!("{}/oauth/authorize/passkey", base_url().await))
        .query(&[("request_uri", request_uri)])
        .header("Accept", "application/json")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rcr: RequestChallengeResponse = serde_json::from_value(start["options"].clone()).unwrap();
    let credential = user.authenticator.do_authentication(origin, rcr).unwrap();
    client()
        .post(format!("{}/oauth/authorize/passkey", base_url().await))
        .header("Accept", "application/json")
        .json(&json!({ "requestUri": request_uri, "credential": credential }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn assert_login_rejected(request_uri: &str) {
    let get = client()
        .get(format!("{}/oauth/authorize/consent", base_url().await))
        .query(&[("request_uri", request_uri)])
        .send()
        .await
        .unwrap();
    assert_eq!(
        get.status(),
        StatusCode::FORBIDDEN,
        "consent GET must reject"
    );

    let post = client()
        .post(format!("{}/oauth/authorize/consent", base_url().await))
        .json(&json!({
            "request_uri": request_uri,
            "approved_scopes": ["atproto"],
            "remember": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        post.status(),
        StatusCode::FORBIDDEN,
        "consent POST must reject"
    );
}

#[tokio::test]
async fn test_token_tampering_attacks() {
    let url = base_url().await;
    let http_client = client();
    let (access_token, _, _) = get_oauth_tokens(&http_client, url).await;
    let parts: Vec<&str> = access_token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let forged_sig = URL_SAFE_NO_PAD.encode([0u8; 32]);
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
        URL_SAFE_NO_PAD.encode([1u8; 64])
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
        URL_SAFE_NO_PAD.encode([1u8; 32])
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
    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let handle = format!("pa{}", suffix);
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
    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let handle = format!("rp{}", suffix);
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
        StatusCode::OK,
        "Refresh token reuse within grace period should return existing tokens"
    );
    let grace_body: Value = rt_replay.json().await.unwrap();
    assert_eq!(
        grace_body["refresh_token"].as_str().unwrap(),
        new_rt,
        "Grace period response should return the current refresh token"
    );
    let second_refresh: Value = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", new_rt),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        second_refresh["access_token"].is_string(),
        "Second refresh with new token should succeed"
    );
    let newest_rt = second_refresh["refresh_token"].as_str().unwrap();
    let replay_after_rotation = http_client
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
        replay_after_rotation.status(),
        StatusCode::BAD_REQUEST,
        "Replay of original token after another rotation should fail"
    );
    let body: Value = replay_after_rotation.json().await.unwrap();
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("reuse"),
        "Error should indicate token reuse"
    );
    let family_revoked = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", newest_rt),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        family_revoked.status(),
        StatusCode::BAD_REQUEST,
        "Token family should be revoked after replay detection"
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
    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let handle = format!("da{}", suffix);
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
    let suffix2 = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let handle2 = format!("cr{}", suffix2);
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
            URL_SAFE_NO_PAD.encode([1u8; 32])
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

#[tokio::test]
async fn test_delegation_viewer_scope_cannot_write() {
    let url = base_url().await;
    let http_client = client();
    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];

    let (controller_jwt, controller_did) = create_account_and_login(&http_client).await;

    let delegated_handle = format!("dg{}", suffix);
    let delegated_res = http_client
        .post(format!("{}/xrpc/_delegation.createDelegatedAccount", url))
        .bearer_auth(controller_jwt)
        .json(&json!({
            "handle": delegated_handle,
            "controllerScopes": ""
        }))
        .send()
        .await
        .unwrap();
    if delegated_res.status() != StatusCode::OK {
        let error_body = delegated_res.text().await.unwrap();
        panic!("Failed to create delegated account: {}", error_body);
    }
    let delegated_account: Value = delegated_res.json().await.unwrap();
    let delegated_did = delegated_account["did"].as_str().unwrap();

    let redirect_uri = "https://example.com/deleg-callback";
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
            ("scope", "atproto"),
            ("login_hint", delegated_did),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let request_uri = par_body["request_uri"].as_str().unwrap();

    let auth_res = http_client
        .post(format!("{}/oauth/delegation/auth", url))
        .header("Content-Type", "application/json")
        .json(&json!({
            "request_uri": request_uri,
            "delegated_did": delegated_did,
            "controller_did": controller_did,
            "password": "Testpass123!",
            "remember_device": false
        }))
        .send()
        .await
        .unwrap();
    if auth_res.status() != StatusCode::OK {
        let error_body = auth_res.text().await.unwrap();
        panic!("Delegation auth failed: {}", error_body);
    }
    let auth_body: Value = auth_res.json().await.unwrap();
    assert!(
        auth_body["success"].as_bool().unwrap_or(false),
        "Delegation auth should succeed: {:?}",
        auth_body
    );

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
    if consent_res.status() != StatusCode::OK {
        let error_body = consent_res.text().await.unwrap();
        panic!("Consent failed: {}", error_body);
    }
    let consent_body: Value = consent_res.json().await.unwrap();
    let location = consent_body["redirect_uri"].as_str().unwrap();

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
    assert_eq!(token_res.status(), StatusCode::OK);
    let tokens: Value = token_res.json().await.unwrap();
    let access_token = tokens["access_token"].as_str().unwrap();

    let create_post_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", url))
        .bearer_auth(access_token)
        .json(&json!({
            "repo": delegated_did,
            "collection": "app.bsky.feed.post",
            "record": {
                "$type": "app.bsky.feed.post",
                "text": "Test post from viewer",
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        create_post_res.status(),
        StatusCode::FORBIDDEN,
        "Viewer scope delegation should not be able to create posts"
    );
    let error_body: Value = create_post_res.json().await.unwrap();
    assert_eq!(
        error_body["error"].as_str().unwrap(),
        "InsufficientScope",
        "Error should be InsufficientScope"
    );
}

async fn consent_and_exchange(
    request_uri: &str,
    client_id: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Value {
    let location = approve_consent(request_uri, false).await;
    exchange_code_for(client_id, redirect_uri, &location, code_verifier).await
}

async fn seed_sso_identity(did: &str, subject: &str, email: &str) {
    let repos = get_test_repos().await;
    let mock = setup_mock_oidc().await;
    mock.register_user(MockUser {
        subject: subject.to_string(),
        email: email.to_string(),
        email_verified: true,
        username: Some(subject.to_string()),
    });
    repos
        .sso
        .create_external_identity(
            &Did::new(did.to_string()).unwrap(),
            tranquil_db_traits::SsoProviderType::Oidc,
            subject,
            Some(subject),
            Some(email),
        )
        .await
        .unwrap();
}

async fn sso_login_follow(request_uri: &str, subject: &str) -> reqwest::Response {
    let http = client();
    let initiate: Value = http
        .post(format!("{}/oauth/sso/initiate", base_url().await))
        .json(&json!({
            "provider": "oidc",
            "request_uri": request_uri,
            "action": "login"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let authorize_url = initiate["redirect_url"].as_str().unwrap();
    let separator = if authorize_url.contains('?') {
        '&'
    } else {
        '?'
    };
    let authorize_url = format!(
        "{}{}login_hint={}",
        authorize_url,
        separator,
        urlencoding::encode(subject)
    );

    let no_redirect = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let authorize_res = no_redirect.get(&authorize_url).send().await.unwrap();
    assert_eq!(
        authorize_res.status(),
        StatusCode::FOUND,
        "mock authorize must 302 back to callback"
    );
    let location = authorize_res
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let mut callback = Url::parse(&location).unwrap();
    callback.set_scheme("http").unwrap();
    callback.set_host(Some("127.0.0.1")).unwrap();
    no_redirect.get(callback).send().await.unwrap()
}

struct OAuthApp {
    _server: MockServer,
    id: String,
    redirect_uri: String,
}

async fn oauth_app(name: &str) -> OAuthApp {
    let redirect_uri = format!("https://example.com/{name}-callback");
    let server = setup_mock_client_metadata(&redirect_uri).await;
    OAuthApp {
        id: server.uri(),
        _server: server,
        redirect_uri,
    }
}

async fn new_request(app: &OAuthApp) -> (String, String) {
    par_request(&app.id, &app.redirect_uri).await
}

fn code_from(location: &str) -> String {
    location
        .split("code=")
        .nth(1)
        .unwrap_or_else(|| panic!("no authorization code in {location}"))
        .split('&')
        .next()
        .unwrap()
        .to_string()
}

async fn approve_consent(request_uri: &str, remember: bool) -> String {
    let res = client()
        .post(format!("{}/oauth/authorize/consent", base_url().await))
        .json(&json!({
            "request_uri": request_uri,
            "approved_scopes": ["atproto"],
            "remember": remember
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "consent must succeed");
    let body: Value = res.json().await.unwrap();
    body["redirect_uri"].as_str().unwrap().to_string()
}

async fn exchange_code_for(
    client_id: &str,
    redirect_uri: &str,
    location: &str,
    code_verifier: &str,
) -> Value {
    let res = client()
        .post(format!("{}/oauth/token", base_url().await))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code_from(location).as_str()),
            ("redirect_uri", redirect_uri),
            ("code_verifier", code_verifier),
            ("client_id", client_id),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "token exchange must succeed");
    res.json().await.unwrap()
}

async fn exchange_code(app: &OAuthApp, location: &str, code_verifier: &str) -> Value {
    exchange_code_for(&app.id, &app.redirect_uri, location, code_verifier).await
}

async fn email_challenge_did(request_uri: &str) -> String {
    get_test_repos()
        .await
        .oauth
        .get_2fa_challenge(&RequestId::from(request_uri.to_string()))
        .await
        .unwrap()
        .expect("an email code must have been issued for this request")
        .did
        .to_string()
}

async fn delegation_totp(request_uri: &str, code: &str) -> Value {
    let res = submit_delegation_totp(request_uri, code).await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "the delegation TOTP endpoint reports its outcome in the body"
    );
    res.json().await.unwrap()
}

async fn assert_first_factor_required(res: reqwest::Response) {
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "the code page must refuse a request without a first factor"
    );
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body["error"], "access_denied",
        "the refusal must be for the missing first factor"
    );
}

async fn enable_email_2fa(did: &str) {
    get_test_repos()
        .await
        .user
        .set_two_factor_enabled(&Did::new(did.to_string()).unwrap(), true)
        .await
        .unwrap();
}

async fn assert_wrong_code_rejected(request_uri: &str) {
    let res = submit_2fa(request_uri, "000000", false).await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "a wrong code must be rejected"
    );
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body["error"], "invalid_code",
        "the rejection must be for the wrong code, not the login state"
    );
}

async fn redirect_after_code(res: reqwest::Response) -> String {
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "the correct code must be accepted"
    );
    let body: Value = res.json().await.unwrap();
    body["redirect_uri"].as_str().unwrap().to_string()
}

async fn passkey_start(
    request_uri: &str,
    identifier: &str,
    delegated_did: Option<&str>,
) -> reqwest::Response {
    client()
        .post(format!("{}/oauth/passkey/start", base_url().await))
        .json(&json!({
            "request_uri": request_uri,
            "identifier": identifier,
            "delegated_did": delegated_did,
        }))
        .send()
        .await
        .unwrap()
}

async fn passkey_finish(
    request_uri: &str,
    user: &mut PasskeyUser,
    start: Value,
) -> reqwest::Response {
    let origin = Url::parse(&format!("https://{}", pds_hostname())).unwrap();
    let rcr: RequestChallengeResponse = serde_json::from_value(start["options"].clone()).unwrap();
    let credential = user.authenticator.do_authentication(origin, rcr).unwrap();
    client()
        .post(format!("{}/oauth/passkey/finish", base_url().await))
        .json(&json!({
            "request_uri": request_uri,
            "credential": serde_json::to_value(&credential).unwrap(),
        }))
        .send()
        .await
        .unwrap()
}

async fn passkey_login(
    request_uri: &str,
    user: &mut PasskeyUser,
    identifier: &str,
    delegated_did: Option<&str>,
) -> String {
    let start = passkey_start(request_uri, identifier, delegated_did).await;
    assert_eq!(start.status(), StatusCode::OK, "passkey start must succeed");
    let start: Value = start.json().await.unwrap();
    let finish = passkey_finish(request_uri, user, start).await;
    assert_eq!(
        finish.status(),
        StatusCode::OK,
        "passkey finish must succeed"
    );
    let body: Value = finish.json().await.unwrap();
    body["redirect_uri"].as_str().unwrap().to_string()
}

async fn delegation_auth(
    request_uri: &str,
    delegated_did: &str,
    controller_did: &str,
    password: &str,
) -> Value {
    client()
        .post(format!("{}/oauth/delegation/auth", base_url().await))
        .json(&json!({
            "request_uri": request_uri,
            "delegated_did": delegated_did,
            "controller_did": controller_did,
            "password": password,
            "remember_device": false
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn sso_callback_location(request_uri: &str, subject: &str) -> String {
    sso_login_follow(request_uri, subject)
        .await
        .headers()
        .get("location")
        .expect("SSO callback must redirect")
        .to_str()
        .unwrap()
        .to_string()
}

async fn select_account(
    request_uri: &str,
    did: &str,
    device_cookie: Option<&str>,
) -> reqwest::Response {
    let req = client()
        .post(format!("{}/oauth/authorize/select", base_url().await))
        .json(&json!({ "request_uri": request_uri, "did": did }));
    let req = match device_cookie {
        Some(cookie) => req.header("cookie", cookie),
        None => req,
    };
    req.send().await.unwrap()
}

#[tokio::test]
async fn test_password_login_flow() {
    let http = client();
    let (jwt, did) = create_account_and_login(&http).await;
    let handle = handle_of(&jwt).await;
    let app = oauth_app("password-flow").await;

    let state = format!("state-{}", uuid::Uuid::new_v4().simple());
    let (request_uri, verifier) =
        par_request_with(&app.id, &app.redirect_uri, &[("state", &state)]).await;
    let body = identify(&request_uri, &handle, "Testpass123!").await;
    assert!(
        body["redirect_uri"]
            .as_str()
            .unwrap()
            .contains("/oauth/consent"),
        "a login without a second factor must go straight to consent"
    );
    let location = approve_consent(&request_uri, false).await;
    assert!(
        location.contains(&format!("state={state}"))
            || location.contains(&format!("state%3D{state}")),
        "the client's state must be returned: {location}"
    );
    let token = exchange_code(&app, &location, &verifier).await;
    assert_eq!(
        token["sub"], did,
        "token must be issued for the logged-in account"
    );
    assert_eq!(
        token["token_type"], "Bearer",
        "tokens must be bearer tokens"
    );
    assert!(
        token["expires_in"].is_number(),
        "the token must state its lifetime"
    );
    let access_token = token["access_token"].as_str().unwrap();
    let refresh_token = token["refresh_token"].as_str().unwrap();
    let refreshed: Value = http
        .post(format!("{}/oauth/token", base_url().await))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", app.id.as_str()),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_ne!(
        refreshed["access_token"].as_str().unwrap(),
        access_token,
        "refresh must rotate the access token"
    );
    assert_ne!(
        refreshed["refresh_token"].as_str().unwrap(),
        refresh_token,
        "refresh must rotate the refresh token"
    );
    let introspect = |token: String| {
        let http = http.clone();
        async move {
            http.post(format!("{}/oauth/introspect", base_url().await))
                .form(&[("token", token.as_str())])
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        }
    };
    let new_access = refreshed["access_token"].as_str().unwrap().to_string();
    assert_eq!(
        introspect(new_access.clone()).await["active"],
        true,
        "refreshed token must be active"
    );
    let revoke = http
        .post(format!("{}/oauth/revoke", base_url().await))
        .form(&[("token", refreshed["refresh_token"].as_str().unwrap())])
        .send()
        .await
        .unwrap();
    assert_eq!(
        revoke.status(),
        StatusCode::OK,
        "revoking the refresh token must succeed"
    );
    assert_eq!(
        introspect(new_access).await["active"],
        false,
        "revoked token must be inactive"
    );

    let (victim_jwt, _) = create_account_and_login(&http).await;
    let (_, victim_handle) = create_delegated_account(&victim_jwt, "pwreident").await;
    let (request_uri, _) = new_request(&app).await;
    let body = identify(&request_uri, &handle, "Testpass123!").await;
    assert!(
        body["redirect_uri"]
            .as_str()
            .unwrap_or("")
            .contains("/oauth/consent"),
        "the legitimate login must reach consent before the account is swapped: {body}"
    );
    identify(&request_uri, &victim_handle, "").await;
    assert_login_rejected(&request_uri).await;

    enable_email_2fa(&did).await;
    let (request_uri, _) = new_request(&app).await;
    let body = identify(&request_uri, &handle, "Testpass123!").await;
    assert_eq!(
        body["needs_2fa"], true,
        "email 2FA must be required once enabled"
    );
    for attempt in 1..=5 {
        let res = submit_2fa(&request_uri, "999999", false).await;
        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "wrong attempt {attempt} must be rejected"
        );
        let body: Value = res.json().await.unwrap();
        assert_eq!(
            body["error"], "invalid_code",
            "wrong attempt {attempt} must report an invalid code"
        );
    }
    let correct_code = get_email_2fa_code(&request_uri).await;
    let locked = submit_2fa(&request_uri, &correct_code, false).await;
    assert_eq!(
        locked.status(),
        StatusCode::FORBIDDEN,
        "after five wrong codes even the correct code must be refused"
    );
    let body: Value = locked.json().await.unwrap();
    assert_eq!(
        body["error"], "access_denied",
        "five wrong codes must lock the request"
    );
    assert_eq!(
        body["error_description"], "Too many failed attempts. Please start over.",
        "the lockout must explain why the request was refused"
    );

    let (request_uri, _) = new_request(&app).await;
    let body = identify(&request_uri, &handle, "Testpass123!").await;
    assert_eq!(
        body["needs_2fa"], true,
        "email 2FA must be required on a fresh request"
    );
    assert_login_rejected(&request_uri).await;
    assert_wrong_code_rejected(&request_uri).await;

    enable_totp_for_user(&did).await;
    let (request_uri, verifier) = new_request(&app).await;
    let wrong_password = http
        .post(format!("{}/oauth/authorize", base_url().await))
        .header("Accept", "application/json")
        .json(&json!({
            "request_uri": request_uri,
            "username": handle,
            "password": "not-the-password",
            "remember_device": false
        }))
        .send()
        .await
        .unwrap();
    let wrong_password: Value = wrong_password.json().await.unwrap();
    assert!(
        wrong_password["needs_totp"].is_null() && wrong_password["redirect_uri"].is_null(),
        "a wrong password must not move the login forward: {wrong_password}"
    );
    assert_first_factor_required(submit_2fa(&request_uri, &current_totp_code(), false).await).await;
    let body = identify(&request_uri, &handle, "Testpass123!").await;
    assert_eq!(
        body["needs_totp"], true,
        "TOTP takes precedence when both factors are enabled"
    );
    assert!(
        !body["needs_2fa"].as_bool().unwrap_or(false),
        "email 2FA must not be prompted alongside TOTP"
    );
    assert_login_rejected(&request_uri).await;
    assert_wrong_code_rejected(&request_uri).await;
    let location =
        redirect_after_code(submit_2fa(&request_uri, &current_totp_code(), false).await).await;
    assert!(
        location.contains("/oauth/consent"),
        "TOTP login must reach consent, got: {location}"
    );
    let token = consent_and_exchange(&request_uri, &app.id, &app.redirect_uri, &verifier).await;
    assert_eq!(
        token["sub"], did,
        "TOTP login must issue a token for the account"
    );
}

#[tokio::test]
async fn test_account_selector_login_flow() {
    let http = client();
    let (jwt, did) = create_account_and_login(&http).await;
    let handle = handle_of(&jwt).await;
    let app = oauth_app("selector-flow").await;

    let remember_login = |request_uri: String, handle: String| {
        let http = http.clone();
        async move {
            let res = http
                .post(format!("{}/oauth/authorize", base_url().await))
                .header("Accept", "application/json")
                .json(&json!({
                    "request_uri": request_uri,
                    "username": handle,
                    "password": "Testpass123!",
                    "remember_device": true
                }))
                .send()
                .await
                .unwrap();
            assert_eq!(
                res.status(),
                StatusCode::OK,
                "a remembered login must succeed"
            );
            res.headers()
                .get("set-cookie")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.split(';').next().unwrap_or("").to_string())
                .expect("remember_device must set a device cookie")
        }
    };
    let (request_uri, verifier) = new_request(&app).await;
    let device_cookie = remember_login(request_uri.clone(), handle.clone()).await;
    let location = approve_consent(&request_uri, true).await;
    let token = exchange_code(&app, &location, &verifier).await;
    assert_eq!(
        token["sub"], did,
        "the remembered login must issue a token for the account"
    );

    let (request_uri, _) = new_request(&app).await;
    let res = select_account(&request_uri, &did, None).await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "selecting an account without a device cookie must be refused"
    );
    assert_login_rejected(&request_uri).await;

    let (other_jwt, _) = create_account_and_login(&http).await;
    let other_handle = handle_of(&other_jwt).await;
    let (other_uri, _) = new_request(&app).await;
    let other_cookie = remember_login(other_uri, other_handle).await;
    let (request_uri, _) = new_request(&app).await;
    let res = select_account(&request_uri, &did, Some(&other_cookie)).await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "another account's device cookie must not select this account"
    );
    assert_login_rejected(&request_uri).await;

    enable_email_2fa(&did).await;
    let (request_uri, verifier) = new_request(&app).await;
    let body: Value = select_account(&request_uri, &did, Some(&device_cookie))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(
        body["needs_2fa"], true,
        "a remembered account must still need email 2FA"
    );
    assert_login_rejected(&request_uri).await;
    assert_wrong_code_rejected(&request_uri).await;
    let code = get_email_2fa_code(&request_uri).await;
    let location = redirect_after_code(submit_2fa(&request_uri, &code, false).await).await;
    assert!(
        location.contains("code="),
        "remembered consent must go straight to a code, got: {location}"
    );
    let token = exchange_code(&app, &location, &verifier).await;
    assert_eq!(
        token["sub"], did,
        "email 2FA selection must issue a token for the account"
    );

    enable_totp_for_user(&did).await;
    let (request_uri, verifier) = new_request(&app).await;
    let body: Value = select_account(&request_uri, &did, Some(&device_cookie))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(
        body["needs_totp"], true,
        "TOTP takes precedence when both factors are enabled"
    );
    assert_login_rejected(&request_uri).await;
    assert_wrong_code_rejected(&request_uri).await;
    let location =
        redirect_after_code(submit_2fa(&request_uri, &current_totp_code(), false).await).await;
    assert!(
        location.contains("code="),
        "remembered consent must go straight to a code, got: {location}"
    );
    let token = exchange_code(&app, &location, &verifier).await;
    assert_eq!(
        token["sub"], did,
        "TOTP selection must issue a token for the account"
    );
}

#[tokio::test]
async fn test_passkey_login_flow() {
    let mut alice = create_passkey_user("alice").await;
    let mut bob = create_passkey_user("bob").await;
    let alice_handle = alice.handle.clone();
    let bob_handle = bob.handle.clone();
    let app = oauth_app("passkey-flow").await;

    let (request_uri, _) = new_request(&app).await;
    identify(&request_uri, &alice_handle, "").await;
    assert_login_rejected(&request_uri).await;

    let (request_uri, _) = new_request(&app).await;
    let start = passkey_start(&request_uri, &alice_handle, None).await;
    assert_eq!(
        start.status(),
        StatusCode::OK,
        "starting a passkey login must succeed"
    );
    assert_login_rejected(&request_uri).await;

    let (request_uri, verifier) = new_request(&app).await;
    identify(&request_uri, &alice_handle, "").await;
    passkey_login(&request_uri, &mut bob, &bob_handle, None).await;
    let location = approve_consent(&request_uri, true).await;
    let token = exchange_code(&app, &location, &verifier).await;
    assert_eq!(
        token["sub"], bob.did,
        "a passkey must log in its own account, not the identified one"
    );

    let (request_uri, verifier) = new_request(&app).await;
    identify(&request_uri, &alice_handle, "").await;
    let location = passkey_login(&request_uri, &mut alice, &alice_handle, None).await;
    assert!(
        location.contains("/oauth/consent"),
        "a passkey login must reach consent for a client not yet approved, got: {location}"
    );
    let token = consent_and_exchange(&request_uri, &app.id, &app.redirect_uri, &verifier).await;
    assert_eq!(
        token["sub"], alice.did,
        "the passkey login must issue a token for the account"
    );

    enable_email_2fa(&alice.did).await;
    let (request_uri, _) = new_request(&app).await;
    identify(&request_uri, &alice_handle, "").await;
    let location = passkey_login(&request_uri, &mut alice, &alice_handle, None).await;
    assert!(
        location.contains("/oauth/2fa"),
        "passkey login must require email 2FA, got: {location}"
    );
    assert_login_rejected(&request_uri).await;
    assert_wrong_code_rejected(&request_uri).await;

    enable_totp_for_user(&alice.did).await;
    let (request_uri, _) = new_request(&app).await;
    let start = passkey_start(&request_uri, &alice_handle, None).await;
    assert_eq!(
        start.status(),
        StatusCode::OK,
        "starting a passkey login must succeed"
    );
    assert_first_factor_required(submit_2fa(&request_uri, &current_totp_code(), false).await).await;
    assert_login_rejected(&request_uri).await;

    let (request_uri, verifier) = new_request(&app).await;
    identify(&request_uri, &alice_handle, "").await;
    let location = passkey_login(&request_uri, &mut alice, &alice_handle, None).await;
    assert!(
        location.contains("/oauth/totp"),
        "passkey login must require TOTP, which takes precedence over email, got: {location}"
    );
    assert_login_rejected(&request_uri).await;
    assert_wrong_code_rejected(&request_uri).await;
    let location =
        redirect_after_code(submit_2fa(&request_uri, &current_totp_code(), false).await).await;
    assert!(
        location.contains("/oauth/consent"),
        "TOTP must lead to consent, got: {location}"
    );
    let token = consent_and_exchange(&request_uri, &app.id, &app.redirect_uri, &verifier).await;
    assert_eq!(
        token["sub"], alice.did,
        "TOTP passkey login must issue a token for the account"
    );
}

#[tokio::test]
async fn test_passkey_page_login_flow() {
    let mut alice = create_passkey_user("alice").await;
    let app = oauth_app("passkey-page-flow").await;

    let (request_uri, verifier) = new_request(&app).await;
    let identified = identify(&request_uri, &alice.handle, "").await;
    assert_eq!(
        identified["next"], "passkey",
        "a passkey-only account must be sent to the passkey page"
    );
    let finish = passkey_page_login(&request_uri, &mut alice).await;
    assert_eq!(
        finish["next"], "consent",
        "a passkey login without a second factor must reach consent"
    );
    let passkeys = get_test_repos()
        .await
        .user
        .get_passkeys_for_user(&Did::new(alice.did.clone()).unwrap())
        .await
        .unwrap();
    assert!(
        !passkeys.is_empty(),
        "the account must have a registered passkey"
    );
    assert!(
        passkeys.iter().all(|passkey| passkey.sign_count > 0),
        "a passkey login must record the signature counter"
    );
    let token = consent_and_exchange(&request_uri, &app.id, &app.redirect_uri, &verifier).await;
    assert_eq!(
        token["sub"], alice.did,
        "the passkey page login must issue a token for the account"
    );

    enable_email_2fa(&alice.did).await;
    let (request_uri, _) = new_request(&app).await;
    identify(&request_uri, &alice.handle, "").await;
    let finish = passkey_page_login(&request_uri, &mut alice).await;
    assert_eq!(
        finish["next"], "2fa",
        "passkey page login must require email 2FA"
    );
    assert_login_rejected(&request_uri).await;
    assert_wrong_code_rejected(&request_uri).await;

    enable_totp_for_user(&alice.did).await;
    let (request_uri, verifier) = new_request(&app).await;
    identify(&request_uri, &alice.handle, "").await;
    let finish = passkey_page_login(&request_uri, &mut alice).await;
    assert_eq!(
        finish["next"], "totp",
        "passkey page login must require TOTP"
    );
    assert_login_rejected(&request_uri).await;
    assert_wrong_code_rejected(&request_uri).await;
    let location =
        redirect_after_code(submit_2fa(&request_uri, &current_totp_code(), false).await).await;
    assert!(
        location.contains("/oauth/consent"),
        "the correct code must lead to consent for a client not yet approved, got: {location}"
    );
    let token = consent_and_exchange(&request_uri, &app.id, &app.redirect_uri, &verifier).await;
    assert_eq!(
        token["sub"], alice.did,
        "TOTP page login must issue a token for the account"
    );
}

#[tokio::test]
async fn test_sso_login_flow() {
    setup_mock_oidc().await;
    let (_, did) = create_account_and_login(&client()).await;
    let subject = format!("sso-flow-{}", uuid::Uuid::new_v4().simple());
    seed_sso_identity(&did, &subject, &format!("{subject}@example.com")).await;
    let app = oauth_app("sso-flow").await;

    let (request_uri, verifier) = new_request(&app).await;
    let location = sso_callback_location(&request_uri, &subject).await;
    assert!(
        location.contains("/app/oauth/consent"),
        "SSO login without a second factor must go to consent, got: {location}"
    );
    let token = consent_and_exchange(&request_uri, &app.id, &app.redirect_uri, &verifier).await;
    assert_eq!(
        token["sub"], did,
        "SSO login must issue a token for the linked account"
    );

    enable_email_2fa(&did).await;
    let (request_uri, _) = new_request(&app).await;
    let location = sso_callback_location(&request_uri, &subject).await;
    assert!(
        location.contains("/app/oauth/2fa"),
        "SSO login must require email 2FA when enabled, got: {location}"
    );
    assert_login_rejected(&request_uri).await;
    assert_wrong_code_rejected(&request_uri).await;

    enable_totp_for_user(&did).await;
    let (request_uri, verifier) = new_request(&app).await;
    let location = sso_callback_location(&request_uri, &subject).await;
    assert!(
        location.contains("/app/oauth/totp"),
        "SSO login must require TOTP when enabled, got: {location}"
    );
    assert_login_rejected(&request_uri).await;
    assert_wrong_code_rejected(&request_uri).await;
    let location =
        redirect_after_code(submit_2fa(&request_uri, &current_totp_code(), false).await).await;
    assert!(
        location.contains("/oauth/consent"),
        "the correct code must lead to consent for a client not yet approved, got: {location}"
    );
    let token = consent_and_exchange(&request_uri, &app.id, &app.redirect_uri, &verifier).await;
    assert_eq!(
        token["sub"], did,
        "TOTP SSO login must issue a token for the account"
    );
}

#[tokio::test]
async fn test_delegated_login_flow() {
    let http = client();
    let (controller_jwt, controller_did) = create_account_and_login(&http).await;
    let (delegated_did, delegated_handle) =
        create_delegated_account(&controller_jwt, "dlgflow").await;
    let (revoked_did, _) = create_delegated_account(&controller_jwt, "dlgflowrev").await;
    let app = oauth_app("delegated-flow").await;

    let (request_uri, _) = new_request(&app).await;
    identify(&request_uri, &delegated_handle, "").await;
    assert_login_rejected(&request_uri).await;
    let renew = http
        .post(format!("{}/oauth/authorize/renew", base_url().await))
        .json(&json!({ "request_uri": request_uri }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        renew.status(),
        StatusCode::BAD_REQUEST,
        "renew must refuse a request whose login never completed"
    );

    let (request_uri, _) = new_request(&app).await;
    let body = delegation_auth(
        &request_uri,
        &delegated_did,
        &controller_did,
        "wrong-password",
    )
    .await;
    assert_eq!(
        body["success"], false,
        "a wrong controller password must be rejected"
    );
    assert_login_rejected(&request_uri).await;

    let (request_uri, verifier) = new_request(&app).await;
    let body = delegation_auth(
        &request_uri,
        &delegated_did,
        &controller_did,
        "Testpass123!",
    )
    .await;
    assert_eq!(
        body["success"], true,
        "the controller's password must authenticate: {body}"
    );
    let token = consent_and_exchange(&request_uri, &app.id, &app.redirect_uri, &verifier).await;
    assert_eq!(
        token["sub"], delegated_did,
        "the token must be for the delegated account"
    );
    assert_ne!(
        token["sub"], controller_did,
        "the token must not be for the controller"
    );

    let (pending_uri, _) = new_request(&app).await;
    let body = delegation_auth(&pending_uri, &revoked_did, &controller_did, "Testpass123!").await;
    assert_eq!(
        body["success"], true,
        "the login must complete before the grant is revoked: {body}"
    );
    let controller = Did::new(controller_did.clone()).unwrap();
    let revoked = get_test_repos()
        .await
        .delegation
        .revoke_delegation(
            &Did::new(revoked_did.clone()).unwrap(),
            &controller,
            &controller,
        )
        .await
        .unwrap();
    assert!(revoked, "the grant must be revoked");
    assert_login_rejected(&pending_uri).await;
    let (request_uri, _) = new_request(&app).await;
    let body = delegation_auth(&request_uri, &revoked_did, &controller_did, "Testpass123!").await;
    assert_eq!(
        body["success"], false,
        "a revoked controller must not log in"
    );
    assert_eq!(
        body["error"], "No delegation grant found for this controller",
        "the refusal must be for the missing grant"
    );

    enable_email_2fa(&controller_did).await;
    let (request_uri, _) = new_request(&app).await;
    let body = delegation_auth(
        &request_uri,
        &delegated_did,
        &controller_did,
        "Testpass123!",
    )
    .await;
    assert_eq!(
        body["needs_2fa"], true,
        "delegation login must require the controller's email 2FA"
    );
    assert_eq!(
        email_challenge_did(&request_uri).await,
        controller_did,
        "the email code must be issued to the controller, who is signing in"
    );
    assert_login_rejected(&request_uri).await;
    assert_wrong_code_rejected(&request_uri).await;

    enable_totp_for_user(&controller_did).await;
    let (request_uri, verifier) = new_request(&app).await;
    let body = delegation_auth(
        &request_uri,
        &delegated_did,
        &controller_did,
        "Testpass123!",
    )
    .await;
    assert_eq!(
        body["needs_totp"], true,
        "delegation login must require the controller's TOTP"
    );
    assert!(
        !body["needs_2fa"].as_bool().unwrap_or(false),
        "TOTP takes precedence over email 2FA"
    );
    assert_login_rejected(&request_uri).await;
    let wrong = delegation_totp(&request_uri, "000000").await;
    assert_eq!(
        wrong["success"], false,
        "a wrong TOTP code must be rejected"
    );
    assert_eq!(
        wrong["error"], "Invalid TOTP code",
        "the rejection must be for the wrong code"
    );
    let accepted = delegation_totp(&request_uri, &current_totp_code()).await;
    assert_eq!(
        accepted["success"], true,
        "the controller's TOTP must be accepted: {accepted}"
    );
    let token = consent_and_exchange(&request_uri, &app.id, &app.redirect_uri, &verifier).await;
    assert_eq!(
        token["sub"], delegated_did,
        "TOTP delegation must issue a token for the delegated account"
    );
}

#[tokio::test]
async fn test_delegated_passkey_login_flow() {
    let mut bob = create_passkey_user("bob").await;
    let alice = create_passkey_user("alice").await;
    let bob_handle = bob.handle.clone();
    let bob_jwt = session_jwt(&bob).await;
    let (delegated_did, _) = create_delegated_account(&bob_jwt, "dpkflow").await;
    let app = oauth_app("delegated-passkey-flow").await;

    let (request_uri, _) = new_request(&app).await;
    let res = passkey_start(&request_uri, &bob_handle, Some(&alice.did)).await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "a passkey must not open an account its owner has no grant for"
    );
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body["error"], "access_denied",
        "the refusal must be an access denial"
    );

    let (request_uri, _) = new_request(&app).await;
    let start = passkey_start(&request_uri, &bob_handle, Some(&delegated_did)).await;
    assert_eq!(
        start.status(),
        StatusCode::OK,
        "starting the delegated passkey login must succeed"
    );
    let start: Value = start.json().await.unwrap();
    identify(&request_uri, &alice.handle, "").await;
    let finish = passkey_finish(&request_uri, &mut bob, start).await;
    assert!(
        finish.status().is_client_error(),
        "a stale controller passkey must not authenticate a re-identified account"
    );
    assert_login_rejected(&request_uri).await;

    let (request_uri, verifier) = new_request(&app).await;
    identify(&request_uri, &bob_handle, "").await;
    let location = passkey_login(&request_uri, &mut bob, &bob_handle, Some(&delegated_did)).await;
    assert!(
        location.contains("/oauth/consent"),
        "delegated passkey login must reach consent, got: {location}"
    );
    let token = consent_and_exchange(&request_uri, &app.id, &app.redirect_uri, &verifier).await;
    assert_eq!(
        token["sub"], delegated_did,
        "the token must be for the delegated account"
    );

    enable_email_2fa(&bob.did).await;
    let (request_uri, _) = new_request(&app).await;
    identify(&request_uri, &bob_handle, "").await;
    let location = passkey_login(&request_uri, &mut bob, &bob_handle, Some(&delegated_did)).await;
    assert!(
        location.contains("/oauth/2fa"),
        "delegated passkey login must require the controller's email 2FA, got: {location}"
    );
    assert_eq!(
        email_challenge_did(&request_uri).await,
        bob.did,
        "the email code must be issued to the controller, who is signing in"
    );
    assert_login_rejected(&request_uri).await;
    assert_wrong_code_rejected(&request_uri).await;

    enable_totp_for_user(&bob.did).await;
    let (request_uri, _) = new_request(&app).await;
    let start = passkey_start(&request_uri, &bob_handle, Some(&delegated_did)).await;
    assert_eq!(
        start.status(),
        StatusCode::OK,
        "starting the delegated passkey login must succeed"
    );
    let early = delegation_totp(&request_uri, &current_totp_code()).await;
    assert_eq!(
        early["success"], false,
        "the delegation TOTP page must refuse a passkey login that was never finished"
    );
    assert_eq!(
        early["error"], "Controller not authenticated",
        "the refusal must be because the controller has not authenticated"
    );
    assert_login_rejected(&request_uri).await;

    let (request_uri, verifier) = new_request(&app).await;
    identify(&request_uri, &bob_handle, "").await;
    let location = passkey_login(&request_uri, &mut bob, &bob_handle, Some(&delegated_did)).await;
    assert!(
        location.contains("/oauth/delegation-totp"),
        "delegated passkey login must require the controller's TOTP, got: {location}"
    );
    assert_login_rejected(&request_uri).await;
    let wrong = delegation_totp(&request_uri, "000000").await;
    assert_eq!(
        wrong["success"], false,
        "a wrong TOTP code must be rejected"
    );
    assert_eq!(
        wrong["error"], "Invalid TOTP code",
        "the rejection must be for the wrong code"
    );
    let accepted = delegation_totp(&request_uri, &current_totp_code()).await;
    assert_eq!(
        accepted["success"], true,
        "the controller's TOTP must be accepted: {accepted}"
    );
    let token = consent_and_exchange(&request_uri, &app.id, &app.redirect_uri, &verifier).await;
    assert_eq!(
        token["sub"], delegated_did,
        "TOTP must issue a token for the delegated account"
    );
}
