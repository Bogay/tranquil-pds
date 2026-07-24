mod common;
mod helpers;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use common::{base_url, client, create_account_and_login};
use helpers::verify_new_account;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tranquil_types::TokenId;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PERMISSION_SET_NSID: &str = "io.atcr.authFullApp";
const PERMISSION_SET_GRANULAR_SCOPE: &str =
    "repo:io.atcr.manifest?action=create rpc:io.atcr.getManifest?aud=*";

fn disable_rate_limiting_once() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| tranquil_pds::state::set_rate_limiting_disabled(true));
}

fn generate_pkce() -> (String, String) {
    let verifier_bytes: [u8; 32] = rand::random();
    let code_verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let hash = hasher.finalize();
    let code_challenge = URL_SAFE_NO_PAD.encode(hash);
    (code_verifier, code_challenge)
}

async fn setup_mock_client_metadata(redirect_uri: &str) -> MockServer {
    let mock_server = MockServer::start().await;
    let client_id = mock_server.uri();
    let metadata = json!({
        "client_id": client_id,
        "client_name": "Test Permission Set Client",
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

async fn seed_permission_set(nsid: &str, granular_scope: &str) {
    let state = common::get_test_app_state().await;
    let key = tranquil_pds::cache_keys::permission_set_key(
        &tranquil_types::Nsid::new(nsid).unwrap(),
        None,
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let val = json!({
        "scope": granular_scope,
        "title": "Basic",
        "detail": null,
        "refreshed_at": now
    })
    .to_string();
    state
        .cache
        .set(&key, &val, std::time::Duration::from_secs(3600))
        .await
        .unwrap();
}

fn decode_jwt_payload(jwt: &str) -> Value {
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "Token should be a valid JWT");
    let payload_json = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    serde_json::from_slice(&payload_json).unwrap()
}

fn token_id_from_jwt(jwt: &str) -> TokenId {
    let payload = decode_jwt_payload(jwt);
    let sid = payload["sid"]
        .as_str()
        .expect("Token payload should contain sid claim");
    TokenId::new(sid)
}

struct DelegatedSession {
    access_token: String,
    #[allow(dead_code)]
    refresh_token: String,
    delegated_did: String,
    #[allow(dead_code)]
    controller_did: String,
    #[allow(dead_code)]
    client_id: String,
}

async fn create_delegated_session_with_scope(
    handle_prefix: &str,
    redirect_uri: &str,
    scope: &str,
) -> (DelegatedSession, Value, MockServer) {
    let url = base_url().await;
    disable_rate_limiting_once();
    let http_client = client();

    let (controller_jwt, controller_did) = create_account_and_login(&http_client).await;

    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..4];
    let delegated_handle = format!("{}{}", handle_prefix, suffix);
    let delegated_res = http_client
        .post(format!("{}/xrpc/_delegation.createDelegatedAccount", url))
        .bearer_auth(&controller_jwt)
        .json(&json!({
            "handle": delegated_handle,
            "controllerScopes": tranquil_pds::delegation::OWNER_FULL_SCOPES
        }))
        .send()
        .await
        .expect("createDelegatedAccount request failed");
    if delegated_res.status() != StatusCode::OK {
        let error_body = delegated_res.text().await.unwrap();
        panic!("Failed to create delegated account: {}", error_body);
    }
    let delegated_account: Value = delegated_res.json().await.unwrap();
    let delegated_did = delegated_account["did"].as_str().unwrap().to_string();

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
            ("login_hint", delegated_did.as_str()),
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
    let request_uri = par_body["request_uri"].as_str().unwrap().to_string();

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
        .expect("Delegation auth request failed");
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

    let consent_get_res = http_client
        .get(format!("{}/oauth/authorize/consent", url))
        .query(&[("request_uri", request_uri.as_str())])
        .send()
        .await
        .expect("Consent GET failed");
    assert_eq!(
        consent_get_res.status(),
        StatusCode::OK,
        "Consent GET should succeed"
    );
    let consent_get_body: Value = consent_get_res.json().await.unwrap();

    let approved_scopes: Vec<&str> = scope.split_whitespace().collect();
    let consent_post_res = http_client
        .post(format!("{}/oauth/authorize/consent", url))
        .header("Content-Type", "application/json")
        .json(&json!({
            "request_uri": request_uri,
            "approved_scopes": approved_scopes,
            "remember": false
        }))
        .send()
        .await
        .expect("Consent POST failed");
    if consent_post_res.status() != StatusCode::OK {
        let error_body = consent_post_res.text().await.unwrap();
        panic!("Consent POST failed: {}", error_body);
    }
    let consent_post_body: Value = consent_post_res.json().await.unwrap();
    let location = consent_post_body["redirect_uri"]
        .as_str()
        .expect("Expected redirect_uri from consent")
        .to_string();

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
    assert_eq!(
        token_res.status(),
        StatusCode::OK,
        "Token exchange should succeed"
    );
    let token_body: Value = token_res.json().await.unwrap();

    let session = DelegatedSession {
        access_token: token_body["access_token"].as_str().unwrap().to_string(),
        refresh_token: token_body["refresh_token"].as_str().unwrap().to_string(),
        delegated_did,
        controller_did,
        client_id,
    };
    (session, consent_get_body, mock_client)
}

#[tokio::test]
async fn test_delegated_consent_marks_restricted_scopes() {
    seed_permission_set(PERMISSION_SET_NSID, PERMISSION_SET_GRANULAR_SCOPE).await;

    let scope = format!("atproto include:{}", PERMISSION_SET_NSID);
    let (_session, consent_body, _mock) = create_delegated_session_with_scope(
        "psr",
        "https://example.com/permset-restricted-callback",
        &scope,
    )
    .await;

    let set_entry = consent_body["permission_sets"]
        .as_array()
        .and_then(|sets| {
            sets.iter()
                .find(|s| s["nsid"].as_str() == Some(PERMISSION_SET_NSID))
        })
        .unwrap_or_else(|| {
            panic!(
                "expected a permission_sets entry for '{}'. Got: {:?}",
                PERMISSION_SET_NSID, consent_body
            )
        });

    assert_eq!(
        set_entry["restricted"].as_bool(),
        Some(false),
        "a partially-covered set must not be flagged fully restricted"
    );

    let expanded = set_entry["expanded"]
        .as_array()
        .expect("permission_sets entry should have an expanded array");

    let repo = expanded
        .iter()
        .find(|s| s["scope"].as_str() == Some("repo:io.atcr.manifest?action=create"))
        .expect("expanded[] should list the repo scope");
    assert_eq!(
        repo["restricted"].as_bool(),
        Some(false),
        "repo scope is covered by the repo:* grant and must not be restricted"
    );

    let rpc = expanded
        .iter()
        .find(|s| s["scope"].as_str() == Some("rpc:io.atcr.getManifest?aud=*"))
        .expect("expanded[] should list the rpc scope");
    assert_eq!(
        rpc["restricted"].as_bool(),
        Some(true),
        "rpc scope is not conferred by the OWNER grant and must be restricted"
    );
}

#[tokio::test]
async fn test_delegated_include_scope_shows_granular_on_consent() {
    seed_permission_set(PERMISSION_SET_NSID, PERMISSION_SET_GRANULAR_SCOPE).await;

    let scope = format!("atproto include:{}", PERMISSION_SET_NSID);
    let (_session, consent_body, _mock) = create_delegated_session_with_scope(
        "psc",
        "https://example.com/permset-consent-callback",
        &scope,
    )
    .await;

    let permission_sets = consent_body["permission_sets"]
        .as_array()
        .expect("consent response should have a permission_sets array");
    assert!(
        !permission_sets.is_empty(),
        "consent permission_sets should not be empty. Got: {:?}",
        consent_body
    );

    let set_entry = permission_sets
        .iter()
        .find(|s| s["nsid"].as_str() == Some(PERMISSION_SET_NSID))
        .unwrap_or_else(|| {
            panic!(
                "permission_sets should contain an entry for nsid '{}'. Got: {:?}",
                PERMISSION_SET_NSID, permission_sets
            )
        });

    assert_eq!(
        set_entry["include_scope"].as_str(),
        Some(format!("include:{}", PERMISSION_SET_NSID).as_str()),
        "permission_sets entry should carry the include: token the frontend submits"
    );

    let expanded = set_entry["expanded"]
        .as_array()
        .expect("permission_sets entry should have an expanded array");
    let has_granular = expanded
        .iter()
        .any(|s| s["scope"].as_str() == Some("repo:io.atcr.manifest?action=create"));
    assert!(
        has_granular,
        "permission_sets entry's expanded[] should list the granular scope \
         'repo:io.atcr.manifest?action=create'. Got: {:?}",
        expanded
    );

    let scopes = consent_body["scopes"]
        .as_array()
        .expect("consent response should have a scopes array");

    let has_raw_include = scopes.iter().any(|s| {
        s["scope"]
            .as_str()
            .map(|sc| sc.starts_with("include:"))
            .unwrap_or(false)
    });
    assert!(
        !has_raw_include,
        "consent scopes[] should not carry the raw include: token"
    );
}

#[tokio::test]
async fn test_grant_row_keeps_include_jwt_carries_expanded() {
    seed_permission_set(PERMISSION_SET_NSID, PERMISSION_SET_GRANULAR_SCOPE).await;

    let scope = format!("atproto include:{}", PERMISSION_SET_NSID);
    let (session, _consent_body, _mock) = create_delegated_session_with_scope(
        "psg",
        "https://example.com/permset-grant-callback",
        &scope,
    )
    .await;

    let payload = decode_jwt_payload(&session.access_token);
    let jwt_scope = payload["scope"]
        .as_str()
        .expect("access token JWT should have a scope claim");
    assert!(
        jwt_scope.contains("repo:io.atcr.manifest?action=create"),
        "JWT scope claim should carry the expanded granular scope, got: {}",
        jwt_scope
    );
    assert!(
        !jwt_scope.contains("include:"),
        "JWT scope claim should not carry the raw include: token, got: {}",
        jwt_scope
    );

    let token_id = token_id_from_jwt(&session.access_token);
    let token_data = common::get_test_repos()
        .await
        .oauth
        .get_token_by_id(&token_id)
        .await
        .expect("get_token_by_id query failed")
        .expect("token row should exist");
    let row_scope = token_data
        .scope
        .expect("stored token row should have a scope");
    assert!(
        row_scope.contains(&format!("include:{}", PERMISSION_SET_NSID)),
        "Stored oauth_token.scope row should still preserve the include: token, got: {}",
        row_scope
    );
}

#[tokio::test]
async fn test_introspect_reads_expanded_jwt_scope() {
    seed_permission_set(PERMISSION_SET_NSID, PERMISSION_SET_GRANULAR_SCOPE).await;

    let scope = format!("atproto include:{}", PERMISSION_SET_NSID);
    let (session, _consent_body, _mock) = create_delegated_session_with_scope(
        "psi",
        "https://example.com/permset-introspect-callback",
        &scope,
    )
    .await;

    let url = base_url().await;
    let http_client = client();
    let introspect_res = http_client
        .post(format!("{}/oauth/introspect", url))
        .form(&[("token", session.access_token.as_str())])
        .send()
        .await
        .expect("introspect request failed");
    assert_eq!(introspect_res.status(), StatusCode::OK);
    let introspect_body: Value = introspect_res.json().await.unwrap();

    assert_eq!(
        introspect_body["active"].as_bool(),
        Some(true),
        "token should be active"
    );
    let introspect_scope = introspect_body["scope"]
        .as_str()
        .expect("introspect response should have a scope string");
    assert!(
        introspect_scope.contains("repo:io.atcr.manifest?action=create"),
        "introspect scope should contain the expanded granular scope, got: {}",
        introspect_scope
    );
    assert!(
        !introspect_scope.contains("include:"),
        "introspect scope should not contain the raw include: token, got: {}",
        introspect_scope
    );
}

#[tokio::test]
async fn test_enforcement_uses_expanded_jwt_scope() {
    seed_permission_set(PERMISSION_SET_NSID, PERMISSION_SET_GRANULAR_SCOPE).await;

    let scope = format!("atproto include:{}", PERMISSION_SET_NSID);
    let (session, _consent_body, _mock) = create_delegated_session_with_scope(
        "pse",
        "https://example.com/permset-enforce-callback",
        &scope,
    )
    .await;

    let url = base_url().await;
    let http_client = client();
    let collection = "io.atcr.manifest";
    let create_res = http_client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", url))
        .bearer_auth(&session.access_token)
        .json(&json!({
            "repo": session.delegated_did,
            "collection": collection,
            "validate": false,
            "record": {
                "$type": collection,
                "note": "permission set enforcement test",
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .expect("createRecord request failed");

    assert_ne!(
        create_res.status(),
        StatusCode::FORBIDDEN,
        "createRecord for a collection covered by the permission set's expanded scope \
         should not be forbidden -- enforcement must read the expanded JWT scope, not \
         the include:-only stored row. Got body: {:?}",
        create_res.text().await
    );
}

#[tokio::test]
async fn test_consent_post_errors_when_set_unresolvable() {
    const UNRESOLVABLE_NSID: &str = "io.atcr.authUnresolvableSet";
    seed_permission_set(UNRESOLVABLE_NSID, PERMISSION_SET_GRANULAR_SCOPE).await;

    let url = base_url().await;
    disable_rate_limiting_once();
    let http_client = client();

    let (controller_jwt, controller_did) = create_account_and_login(&http_client).await;

    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..4];
    let delegated_handle = format!("psu{}", suffix);
    let delegated_res = http_client
        .post(format!("{}/xrpc/_delegation.createDelegatedAccount", url))
        .bearer_auth(&controller_jwt)
        .json(&json!({
            "handle": delegated_handle,
            "controllerScopes": tranquil_pds::delegation::OWNER_FULL_SCOPES
        }))
        .send()
        .await
        .expect("createDelegatedAccount request failed");
    if delegated_res.status() != StatusCode::OK {
        let error_body = delegated_res.text().await.unwrap();
        panic!("Failed to create delegated account: {}", error_body);
    }
    let delegated_account: Value = delegated_res.json().await.unwrap();
    let delegated_did = delegated_account["did"].as_str().unwrap().to_string();

    let redirect_uri = "https://example.com/permset-unresolvable-callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();
    let (_code_verifier, code_challenge) = generate_pkce();

    let scope = format!("atproto include:{}", UNRESOLVABLE_NSID);
    let par_res = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
            ("scope", scope.as_str()),
            ("login_hint", delegated_did.as_str()),
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
    let request_uri = par_body["request_uri"].as_str().unwrap().to_string();

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
        .expect("Delegation auth request failed");
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

    let consent_get_res = http_client
        .get(format!("{}/oauth/authorize/consent", url))
        .query(&[("request_uri", request_uri.as_str())])
        .send()
        .await
        .expect("Consent GET failed");
    assert_eq!(
        consent_get_res.status(),
        StatusCode::OK,
        "Consent GET should succeed"
    );

    let state = common::get_test_app_state().await;
    let key = tranquil_pds::cache_keys::permission_set_key(
        &tranquil_types::Nsid::new(UNRESOLVABLE_NSID).unwrap(),
        None,
    );
    state.cache.delete(&key).await.unwrap();

    let approved_scopes: Vec<&str> = scope.split_whitespace().collect();
    let consent_post_res = http_client
        .post(format!("{}/oauth/authorize/consent", url))
        .header("Content-Type", "application/json")
        .json(&json!({
            "request_uri": request_uri,
            "approved_scopes": approved_scopes,
            "remember": true
        }))
        .send()
        .await
        .expect("Consent POST failed");
    assert_eq!(
        consent_post_res.status(),
        StatusCode::BAD_REQUEST,
        "Consent POST must fail closed (400) when the include: set can no longer be \
         resolved, instead of silently persisting/granting truncated scopes"
    );
    let error_body: Value = consent_post_res.json().await.unwrap();
    assert_eq!(
        error_body["error"].as_str(),
        Some("invalid_scope"),
        "Expected invalid_scope error, got: {:?}",
        error_body
    );
}

#[tokio::test]
async fn test_consent_post_succeeds_when_unapproved_set_fails() {
    const GOOD_SET_NSID: &str = "io.atcr.goodSet";
    const BAD_SET_NSID: &str = "io.atcr.badSet";
    seed_permission_set(GOOD_SET_NSID, PERMISSION_SET_GRANULAR_SCOPE).await;

    let url = base_url().await;
    disable_rate_limiting_once();
    let http_client = client();

    let (controller_jwt, controller_did) = create_account_and_login(&http_client).await;

    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..4];
    let delegated_handle = format!("psg{}", suffix);
    let delegated_res = http_client
        .post(format!("{}/xrpc/_delegation.createDelegatedAccount", url))
        .bearer_auth(&controller_jwt)
        .json(&json!({
            "handle": delegated_handle,
            "controllerScopes": tranquil_pds::delegation::OWNER_FULL_SCOPES
        }))
        .send()
        .await
        .expect("createDelegatedAccount request failed");
    if delegated_res.status() != StatusCode::OK {
        let error_body = delegated_res.text().await.unwrap();
        panic!("Failed to create delegated account: {}", error_body);
    }
    let delegated_account: Value = delegated_res.json().await.unwrap();
    let delegated_did = delegated_account["did"].as_str().unwrap().to_string();

    let redirect_uri = "https://example.com/permset-partial-fail-callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();
    let (_code_verifier, code_challenge) = generate_pkce();

    let scope = format!("atproto include:{} include:{}", GOOD_SET_NSID, BAD_SET_NSID);
    let par_res = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
            ("scope", scope.as_str()),
            ("login_hint", delegated_did.as_str()),
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
    let request_uri = par_body["request_uri"].as_str().unwrap().to_string();

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
        .expect("Delegation auth request failed");
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

    let consent_get_res = http_client
        .get(format!("{}/oauth/authorize/consent", url))
        .query(&[("request_uri", request_uri.as_str())])
        .send()
        .await
        .expect("Consent GET failed");
    assert_eq!(
        consent_get_res.status(),
        StatusCode::OK,
        "Consent GET should succeed"
    );
    let consent_get_body: Value = consent_get_res.json().await.unwrap();

    let permission_sets = consent_get_body["permission_sets"]
        .as_array()
        .expect("consent response should have a permission_sets array");
    assert!(
        permission_sets
            .iter()
            .any(|s| s["nsid"].as_str() == Some(GOOD_SET_NSID)),
        "the resolvable set should be presented as a permission set. Got: {:?}",
        consent_get_body
    );
    let failed_sets = consent_get_body["failed_sets"]
        .as_array()
        .expect("consent response should have a failed_sets array");
    assert!(
        failed_sets
            .iter()
            .any(|s| s["nsid"].as_str() == Some(BAD_SET_NSID)),
        "the unresolvable set should be presented as a failed set. Got: {:?}",
        consent_get_body
    );

    let approved_scopes = vec!["atproto".to_string(), format!("include:{}", GOOD_SET_NSID)];
    let consent_post_res = http_client
        .post(format!("{}/oauth/authorize/consent", url))
        .header("Content-Type", "application/json")
        .json(&json!({
            "request_uri": request_uri,
            "approved_scopes": approved_scopes,
            "remember": false
        }))
        .send()
        .await
        .expect("Consent POST failed");
    let status = consent_post_res.status();
    let consent_post_body: Value = consent_post_res.json().await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "Consent POST must succeed when the user approves only the resolvable set and \
         leaves the unresolvable set unapproved. Got: {:?}",
        consent_post_body
    );
    assert!(
        consent_post_body["redirect_uri"].as_str().is_some(),
        "Consent POST should return a redirect_uri. Got: {:?}",
        consent_post_body
    );
}

#[tokio::test]
async fn test_consent_remember_persists_set_preference() {
    const REMEMBER_SET_NSID: &str = "io.atcr.rememberSet";
    seed_permission_set(REMEMBER_SET_NSID, PERMISSION_SET_GRANULAR_SCOPE).await;

    let url = base_url().await;
    disable_rate_limiting_once();
    let http_client = client();

    let (controller_jwt, controller_did) = create_account_and_login(&http_client).await;

    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..4];
    let delegated_handle = format!("psr{}", suffix);
    let delegated_res = http_client
        .post(format!("{}/xrpc/_delegation.createDelegatedAccount", url))
        .bearer_auth(&controller_jwt)
        .json(&json!({
            "handle": delegated_handle,
            "controllerScopes": tranquil_pds::delegation::OWNER_FULL_SCOPES
        }))
        .send()
        .await
        .expect("createDelegatedAccount request failed");
    if delegated_res.status() != StatusCode::OK {
        let error_body = delegated_res.text().await.unwrap();
        panic!("Failed to create delegated account: {}", error_body);
    }
    let delegated_account: Value = delegated_res.json().await.unwrap();
    let delegated_did = delegated_account["did"].as_str().unwrap().to_string();

    let redirect_uri = "https://example.com/permset-remember-callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();
    let (_code_verifier, code_challenge) = generate_pkce();

    let scope = format!("atproto include:{}", REMEMBER_SET_NSID);
    let par_res = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
            ("scope", scope.as_str()),
            ("login_hint", delegated_did.as_str()),
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
    let request_uri = par_body["request_uri"].as_str().unwrap().to_string();

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
        .expect("Delegation auth request failed");
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

    let consent_get_res = http_client
        .get(format!("{}/oauth/authorize/consent", url))
        .query(&[("request_uri", request_uri.as_str())])
        .send()
        .await
        .expect("Consent GET failed");
    assert_eq!(
        consent_get_res.status(),
        StatusCode::OK,
        "Consent GET should succeed"
    );

    let approved_scopes = vec![
        "atproto".to_string(),
        format!("include:{}", REMEMBER_SET_NSID),
    ];
    let consent_post_res = http_client
        .post(format!("{}/oauth/authorize/consent", url))
        .header("Content-Type", "application/json")
        .json(&json!({
            "request_uri": request_uri,
            "approved_scopes": approved_scopes,
            "remember": true
        }))
        .send()
        .await
        .expect("Consent POST failed");
    if consent_post_res.status() != StatusCode::OK {
        let error_body = consent_post_res.text().await.unwrap();
        panic!("Consent POST with remember:true failed: {}", error_body);
    }

    let did: tranquil_types::Did = delegated_did.parse().expect("valid did");
    let client_id_typed = tranquil_types::ClientId::new(client_id.clone());
    let stored_prefs = common::get_test_repos()
        .await
        .oauth
        .get_scope_preferences(&did, &client_id_typed)
        .await
        .expect("get_scope_preferences query failed");
    let include_token = format!("include:{}", REMEMBER_SET_NSID);
    let set_pref = stored_prefs
        .iter()
        .find(|p| p.scope == include_token)
        .unwrap_or_else(|| {
            panic!(
                "expected a stored scope preference for '{}', got: {:?}",
                include_token, stored_prefs
            )
        });
    assert!(
        set_pref.granted,
        "the remembered set preference should be granted: true, got: {:?}",
        set_pref
    );
    assert!(
        !stored_prefs
            .iter()
            .any(|p| p.scope.starts_with("repo:") || p.scope.starts_with("rpc:")),
        "remember must not store the expanded granular scopes as preferences, got: {:?}",
        stored_prefs
    );

    let (code_verifier2, code_challenge2) = generate_pkce();
    let par_res2 = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge2),
            ("code_challenge_method", "S256"),
            ("scope", scope.as_str()),
            ("login_hint", delegated_did.as_str()),
        ])
        .send()
        .await
        .expect("second PAR failed");
    let _ = code_verifier2;
    assert!(par_res2.status() == StatusCode::OK || par_res2.status() == StatusCode::CREATED);
    let par_body2: Value = par_res2.json().await.unwrap();
    let request_uri2 = par_body2["request_uri"].as_str().unwrap().to_string();

    let auth_res2 = http_client
        .post(format!("{}/oauth/delegation/auth", url))
        .header("Content-Type", "application/json")
        .json(&json!({
            "request_uri": request_uri2,
            "delegated_did": delegated_did,
            "controller_did": controller_did,
            "password": "Testpass123!",
            "remember_device": false
        }))
        .send()
        .await
        .expect("second delegation auth failed");
    assert_eq!(auth_res2.status(), StatusCode::OK);

    let consent_get_res2 = http_client
        .get(format!("{}/oauth/authorize/consent", url))
        .query(&[("request_uri", request_uri2.as_str())])
        .send()
        .await
        .expect("second consent GET failed");
    assert_eq!(consent_get_res2.status(), StatusCode::OK);
    let consent_get_body2: Value = consent_get_res2.json().await.unwrap();
    let permission_sets2 = consent_get_body2["permission_sets"]
        .as_array()
        .expect("consent response should have a permission_sets array");
    let set_entry2 = permission_sets2
        .iter()
        .find(|s| s["nsid"].as_str() == Some(REMEMBER_SET_NSID))
        .unwrap_or_else(|| {
            panic!(
                "expected permission_sets to contain '{}', got: {:?}",
                REMEMBER_SET_NSID, consent_get_body2
            )
        });
    assert_eq!(
        set_entry2["granted"].as_bool(),
        Some(true),
        "the remembered set's include: token preference should round-trip as granted: true \
         on a subsequent consent_get. Got: {:?}",
        set_entry2
    );
}

#[tokio::test]
async fn test_legacy_granular_token_survives_refresh() {
    let url = base_url().await;
    disable_rate_limiting_once();
    let http_client = client();
    let redirect_uri = "https://example.com/permset-legacy-callback";
    let scope = "atproto repo:*?action=create";

    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..4];
    let handle = format!("psl{}", suffix);
    let email = format!("psl{}@example.com", suffix);
    let password = "LegacyPass123!";

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
    assert!(par_res.status() == StatusCode::OK || par_res.status() == StatusCode::CREATED);
    let par_body: Value = par_res.json().await.unwrap();
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
        .expect("Authorize failed");
    assert_eq!(auth_res.status(), StatusCode::OK);
    let auth_body: Value = auth_res.json().await.unwrap();
    let mut location = auth_body["redirect_uri"]
        .as_str()
        .expect("Expected redirect_uri")
        .to_string();
    if location.contains("/oauth/consent") {
        let consent_res = http_client
            .post(format!("{}/oauth/authorize/consent", url))
            .header("Content-Type", "application/json")
            .json(&json!({
                "request_uri": request_uri,
                "approved_scopes": scope.split_whitespace().collect::<Vec<_>>(),
                "remember": false
            }))
            .send()
            .await
            .expect("Consent request failed");
        assert_eq!(consent_res.status(), StatusCode::OK);
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
    let access_token = token_body["access_token"].as_str().unwrap().to_string();
    let refresh_token = token_body["refresh_token"].as_str().unwrap().to_string();

    let original_payload = decode_jwt_payload(&access_token);
    let original_scope = original_payload["scope"].as_str().unwrap();
    assert!(original_scope.contains("repo:*?action=create"));

    let refresh_res = http_client
        .post(format!("{}/oauth/token", url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
            ("client_id", &client_id),
        ])
        .send()
        .await
        .expect("Refresh request failed");
    assert_eq!(
        refresh_res.status(),
        StatusCode::OK,
        "Refreshing a legacy granular-scope token should succeed"
    );
    let refresh_body: Value = refresh_res.json().await.unwrap();
    let new_access_token = refresh_body["access_token"].as_str().unwrap();
    assert_ne!(new_access_token, access_token);

    let new_scope_from_response = refresh_body["scope"]
        .as_str()
        .expect("refresh response should include scope");
    assert!(
        new_scope_from_response.contains("repo:*?action=create"),
        "Refresh response scope should still contain the granular scope, got: {}",
        new_scope_from_response
    );

    let new_payload = decode_jwt_payload(new_access_token);
    let new_jwt_scope = new_payload["scope"]
        .as_str()
        .expect("new JWT should have a scope claim");
    assert!(
        new_jwt_scope.contains("repo:*?action=create"),
        "New JWT scope claim should still contain the granular scope after refresh, got: {}",
        new_jwt_scope
    );
}

#[tokio::test]
async fn test_consent_post_drops_unpresented_scope() {
    seed_permission_set(PERMISSION_SET_NSID, PERMISSION_SET_GRANULAR_SCOPE).await;

    let url = base_url().await;
    disable_rate_limiting_once();
    let http_client = client();

    let (controller_jwt, controller_did) = create_account_and_login(&http_client).await;

    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..4];
    let delegated_handle = format!("psd{}", suffix);
    let delegated_res = http_client
        .post(format!("{}/xrpc/_delegation.createDelegatedAccount", url))
        .bearer_auth(&controller_jwt)
        .json(&json!({
            "handle": delegated_handle,
            "controllerScopes": tranquil_pds::delegation::OWNER_FULL_SCOPES
        }))
        .send()
        .await
        .expect("createDelegatedAccount request failed");
    if delegated_res.status() != StatusCode::OK {
        let error_body = delegated_res.text().await.unwrap();
        panic!("Failed to create delegated account: {}", error_body);
    }
    let delegated_account: Value = delegated_res.json().await.unwrap();
    let delegated_did = delegated_account["did"].as_str().unwrap().to_string();

    let redirect_uri = "https://example.com/permset-unpresented-callback";
    let mock_client = setup_mock_client_metadata(redirect_uri).await;
    let client_id = mock_client.uri();
    let (code_verifier, code_challenge) = generate_pkce();

    let scope = format!("atproto include:{}", PERMISSION_SET_NSID);
    let par_res = http_client
        .post(format!("{}/oauth/par", url))
        .form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", &code_challenge),
            ("code_challenge_method", "S256"),
            ("scope", scope.as_str()),
            ("login_hint", delegated_did.as_str()),
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
    let request_uri = par_body["request_uri"].as_str().unwrap().to_string();

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
        .expect("Delegation auth request failed");
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

    let approved_scopes = vec![
        "atproto".to_string(),
        format!("include:{}", PERMISSION_SET_NSID),
        "repo:com.evil.collection?action=create".to_string(),
    ];
    let consent_post_res = http_client
        .post(format!("{}/oauth/authorize/consent", url))
        .header("Content-Type", "application/json")
        .json(&json!({
            "request_uri": request_uri,
            "approved_scopes": approved_scopes,
            "remember": false
        }))
        .send()
        .await
        .expect("Consent POST failed");
    if consent_post_res.status() != StatusCode::OK {
        let error_body = consent_post_res.text().await.unwrap();
        panic!("Consent POST failed: {}", error_body);
    }
    let consent_post_body: Value = consent_post_res.json().await.unwrap();
    let location = consent_post_body["redirect_uri"]
        .as_str()
        .expect("Expected redirect_uri from consent")
        .to_string();

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
    assert_eq!(
        token_res.status(),
        StatusCode::OK,
        "Token exchange should succeed"
    );
    let token_body: Value = token_res.json().await.unwrap();
    let access_token = token_body["access_token"].as_str().unwrap().to_string();

    let token_id = token_id_from_jwt(&access_token);
    let token_data = common::get_test_repos()
        .await
        .oauth
        .get_token_by_id(&token_id)
        .await
        .expect("get_token_by_id query failed")
        .expect("token row should exist");
    let row_scope = token_data
        .scope
        .expect("stored token row should have a scope");
    assert!(
        !row_scope.contains("com.evil.collection"),
        "Stored oauth_token.scope row must not contain a scope that was never presented \
         to the resource owner, got: {}",
        row_scope
    );
    assert!(
        row_scope.contains(&format!("include:{}", PERMISSION_SET_NSID)),
        "Stored oauth_token.scope row should still preserve the legitimately approved \
         include: token, got: {}",
        row_scope
    );
}
