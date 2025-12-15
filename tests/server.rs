mod common;
mod helpers;
use common::*;
use helpers::verify_new_account;
use reqwest::StatusCode;
use serde_json::{Value, json};

#[tokio::test]
async fn test_health() {
    let client = client();
    let res = client
        .get(format!("{}/health", base_url().await))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.text().await.unwrap(), "OK");
}

#[tokio::test]
async fn test_describe_server() {
    let client = client();
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.server.describeServer",
            base_url().await
        ))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert!(body.get("availableUserDomains").is_some());
}

#[tokio::test]
async fn test_create_session() {
    let client = client();
    let handle = format!("user_{}", uuid::Uuid::new_v4());
    let payload = json!({
        "handle": handle,
        "email": format!("{}@example.com", handle),
        "password": "password"
    });
    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .json(&payload)
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(create_res.status(), StatusCode::OK);
    let create_body: Value = create_res.json().await.unwrap();
    let did = create_body["did"].as_str().unwrap();
    let _ = verify_new_account(&client, did).await;
    let payload = json!({
        "identifier": handle,
        "password": "password"
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createSession",
            base_url().await
        ))
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert!(body.get("accessJwt").is_some());
}

#[tokio::test]
async fn test_create_session_missing_identifier() {
    let client = client();
    let payload = json!({
        "password": "password"
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createSession",
            base_url().await
        ))
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    assert!(
        res.status() == StatusCode::BAD_REQUEST || res.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "Expected 400 or 422 for missing identifier, got {}",
        res.status()
    );
}

#[tokio::test]
async fn test_create_account_invalid_handle() {
    let client = client();
    let payload = json!({
        "handle": "invalid!handle.com",
        "email": "test@example.com",
        "password": "password"
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "Expected 400 for invalid handle chars"
    );
}

#[tokio::test]
async fn test_get_session() {
    let client = client();
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.server.getSession",
            base_url().await
        ))
        .bearer_auth(AUTH_TOKEN)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_refresh_session() {
    let client = client();
    let handle = format!("refresh_user_{}", uuid::Uuid::new_v4());
    let payload = json!({
        "handle": handle,
        "email": format!("{}@example.com", handle),
        "password": "password"
    });
    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .json(&payload)
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(create_res.status(), StatusCode::OK);
    let create_body: Value = create_res.json().await.unwrap();
    let did = create_body["did"].as_str().unwrap();
    let _ = verify_new_account(&client, did).await;
    let login_payload = json!({
        "identifier": handle,
        "password": "password"
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createSession",
            base_url().await
        ))
        .json(&login_payload)
        .send()
        .await
        .expect("Failed to login");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    let refresh_jwt = body["refreshJwt"]
        .as_str()
        .expect("No refreshJwt")
        .to_string();
    let access_jwt = body["accessJwt"]
        .as_str()
        .expect("No accessJwt")
        .to_string();
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.refreshSession",
            base_url().await
        ))
        .bearer_auth(&refresh_jwt)
        .send()
        .await
        .expect("Failed to refresh");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert!(body["accessJwt"].as_str().is_some());
    assert!(body["refreshJwt"].as_str().is_some());
    assert_ne!(body["accessJwt"].as_str().unwrap(), access_jwt);
    assert_ne!(body["refreshJwt"].as_str().unwrap(), refresh_jwt);
}

#[tokio::test]
async fn test_delete_session() {
    let client = client();
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.deleteSession",
            base_url().await
        ))
        .bearer_auth(AUTH_TOKEN)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_get_service_auth_success() {
    let client = client();
    let (access_jwt, did) = create_account_and_login(&client).await;
    let params = [("aud", "did:web:example.com")];
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.server.getServiceAuth",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .query(&params)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert!(body["token"].is_string());
    let token = body["token"].as_str().unwrap();
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "Token should be a valid JWT");
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).expect("payload b64");
    let claims: Value = serde_json::from_slice(&payload_bytes).expect("payload json");
    assert_eq!(claims["iss"], did);
    assert_eq!(claims["sub"], did);
    assert_eq!(claims["aud"], "did:web:example.com");
}

#[tokio::test]
async fn test_get_service_auth_with_lxm() {
    let client = client();
    let (access_jwt, did) = create_account_and_login(&client).await;
    let params = [("aud", "did:web:example.com"), ("lxm", "com.atproto.repo.getRecord")];
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.server.getServiceAuth",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .query(&params)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let token = body["token"].as_str().unwrap();
    let parts: Vec<&str> = token.split('.').collect();
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).expect("payload b64");
    let claims: Value = serde_json::from_slice(&payload_bytes).expect("payload json");
    assert_eq!(claims["iss"], did);
    assert_eq!(claims["lxm"], "com.atproto.repo.getRecord");
}

#[tokio::test]
async fn test_get_service_auth_no_auth() {
    let client = client();
    let params = [("aud", "did:web:example.com")];
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.server.getServiceAuth",
            base_url().await
        ))
        .query(&params)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["error"], "AuthenticationRequired");
}

#[tokio::test]
async fn test_get_service_auth_missing_aud() {
    let client = client();
    let (access_jwt, _) = create_account_and_login(&client).await;
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.server.getServiceAuth",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_check_account_status_success() {
    let client = client();
    let (access_jwt, _) = create_account_and_login(&client).await;
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.server.checkAccountStatus",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["activated"], true);
    assert_eq!(body["validDid"], true);
    assert!(body["repoCommit"].is_string());
    assert!(body["repoRev"].is_string());
    assert!(body["indexedRecords"].is_number());
}

#[tokio::test]
async fn test_check_account_status_no_auth() {
    let client = client();
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.server.checkAccountStatus",
            base_url().await
        ))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["error"], "AuthenticationRequired");
}

#[tokio::test]
async fn test_activate_account_success() {
    let client = client();
    let (access_jwt, _) = create_account_and_login(&client).await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.activateAccount",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_activate_account_no_auth() {
    let client = client();
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.activateAccount",
            base_url().await
        ))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_deactivate_account_success() {
    let client = client();
    let (access_jwt, _) = create_account_and_login(&client).await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.deactivateAccount",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .json(&json!({}))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
}
