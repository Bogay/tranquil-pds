mod common;
mod helpers;
use common::*;
use helpers::verify_new_account;
use reqwest::StatusCode;
use serde_json::{Value, json};

#[tokio::test]
async fn test_server_basics() {
    let client = client();
    let base = base_url().await;
    let health = client.get(format!("{}/health", base)).send().await.unwrap();
    assert_eq!(health.status(), StatusCode::OK);
    assert!(
        health
            .text()
            .await
            .unwrap()
            .starts_with("{\"version\":\"tranquil ")
    );
    let describe = client
        .get(format!("{}/xrpc/com.atproto.server.describeServer", base))
        .send()
        .await
        .unwrap();
    assert_eq!(describe.status(), StatusCode::OK);
    let body: Value = describe.json().await.unwrap();
    assert!(body.get("availableUserDomains").is_some());
}

#[tokio::test]
async fn test_account_and_session_lifecycle() {
    let client = client();
    let base = base_url().await;
    let handle = format!("u{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let payload = json!({ "handle": handle, "email": format!("{}@example.com", handle), "password": "Testpass123!" });
    let create_res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);
    let create_body: Value = create_res.json().await.unwrap();
    let did = create_body["did"].as_str().unwrap();
    let _ = verify_new_account(&client, did).await;
    let login = client
        .post(format!("{}/xrpc/com.atproto.server.createSession", base))
        .json(&json!({ "identifier": handle, "password": "Testpass123!" }))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let login_body: Value = login.json().await.unwrap();
    let access_jwt = login_body["accessJwt"].as_str().unwrap().to_string();
    let refresh_jwt = login_body["refreshJwt"].as_str().unwrap().to_string();
    let refresh = client
        .post(format!("{}/xrpc/com.atproto.server.refreshSession", base))
        .bearer_auth(&refresh_jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(refresh.status(), StatusCode::OK);
    let refresh_body: Value = refresh.json().await.unwrap();
    assert!(refresh_body["accessJwt"].as_str().is_some());
    assert_ne!(refresh_body["accessJwt"].as_str().unwrap(), access_jwt);
    assert_ne!(refresh_body["refreshJwt"].as_str().unwrap(), refresh_jwt);
    let missing_id = client
        .post(format!("{}/xrpc/com.atproto.server.createSession", base))
        .json(&json!({ "password": "Testpass123!" }))
        .send()
        .await
        .unwrap();
    assert_eq!(missing_id.status(), StatusCode::BAD_REQUEST);
    let invalid_handle = client.post(format!("{}/xrpc/com.atproto.server.createAccount", base))
        .json(&json!({ "handle": "invalid!handle.com", "email": "test@example.com", "password": "Testpass123!" }))
        .send().await.unwrap();
    assert_eq!(invalid_handle.status(), StatusCode::BAD_REQUEST);
    let unauth_session = client
        .get(format!("{}/xrpc/com.atproto.server.getSession", base))
        .bearer_auth(AUTH_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(unauth_session.status(), StatusCode::UNAUTHORIZED);
    let delete_session = client
        .post(format!("{}/xrpc/com.atproto.server.deleteSession", base))
        .bearer_auth(AUTH_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(delete_session.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_service_auth() {
    let client = client();
    let base = base_url().await;
    let (access_jwt, did) = create_account_and_login(&client).await;
    let res = client
        .get(format!("{}/xrpc/com.atproto.server.getServiceAuth", base))
        .bearer_auth(&access_jwt)
        .query(&[("aud", "did:web:example.com")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let token = body["token"].as_str().unwrap();
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "Token should be a valid JWT");
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let claims: Value = serde_json::from_slice(&payload_bytes).unwrap();
    assert_eq!(claims["iss"], did);
    assert_eq!(claims["sub"], did);
    assert_eq!(claims["aud"], "did:web:example.com");
    let lxm_res = client
        .get(format!("{}/xrpc/com.atproto.server.getServiceAuth", base))
        .bearer_auth(&access_jwt)
        .query(&[
            ("aud", "did:web:example.com"),
            ("lxm", "com.atproto.repo.getRecord"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(lxm_res.status(), StatusCode::OK);
    let lxm_body: Value = lxm_res.json().await.unwrap();
    let lxm_token = lxm_body["token"].as_str().unwrap();
    let lxm_parts: Vec<&str> = lxm_token.split('.').collect();
    let lxm_payload = URL_SAFE_NO_PAD.decode(lxm_parts[1]).unwrap();
    let lxm_claims: Value = serde_json::from_slice(&lxm_payload).unwrap();
    assert_eq!(lxm_claims["lxm"], "com.atproto.repo.getRecord");
    let unauth = client
        .get(format!("{}/xrpc/com.atproto.server.getServiceAuth", base))
        .query(&[("aud", "did:web:example.com")])
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);
    let missing_aud = client
        .get(format!("{}/xrpc/com.atproto.server.getServiceAuth", base))
        .bearer_auth(&access_jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(missing_aud.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_account_status_and_activation() {
    let client = client();
    let base = base_url().await;
    let (access_jwt, _) = create_account_and_login(&client).await;
    let status = client
        .get(format!(
            "{}/xrpc/com.atproto.server.checkAccountStatus",
            base
        ))
        .bearer_auth(&access_jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::OK);
    let body: Value = status.json().await.unwrap();
    assert_eq!(body["activated"], true);
    assert_eq!(body["validDid"], true);
    assert!(body["repoCommit"].is_string());
    assert!(body["repoRev"].is_string());
    assert!(body["indexedRecords"].is_number());
    let unauth_status = client
        .get(format!(
            "{}/xrpc/com.atproto.server.checkAccountStatus",
            base
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth_status.status(), StatusCode::UNAUTHORIZED);
    let activate = client
        .post(format!("{}/xrpc/com.atproto.server.activateAccount", base))
        .bearer_auth(&access_jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(activate.status(), StatusCode::OK);
    let unauth_activate = client
        .post(format!("{}/xrpc/com.atproto.server.activateAccount", base))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth_activate.status(), StatusCode::UNAUTHORIZED);
    let deactivate = client
        .post(format!(
            "{}/xrpc/com.atproto.server.deactivateAccount",
            base
        ))
        .bearer_auth(&access_jwt)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(deactivate.status(), StatusCode::OK);
}
