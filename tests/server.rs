mod common;
use common::*;

use reqwest::StatusCode;
use serde_json::{json, Value};

#[tokio::test]
async fn test_health() {
    let client = client();
    let res = client.get(format!("{}/health", base_url().await))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.text().await.unwrap(), "OK");
}

#[tokio::test]
async fn test_describe_server() {
    let client = client();
    let res = client.get(format!("{}/xrpc/com.atproto.server.describeServer", base_url().await))
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
    let _ = client.post(format!("{}/xrpc/com.atproto.server.createAccount", base_url().await))
        .json(&payload)
        .send()
        .await;

    let payload = json!({
        "identifier": handle,
        "password": "password"
    });

    let res = client.post(format!("{}/xrpc/com.atproto.server.createSession", base_url().await))
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

    let res = client.post(format!("{}/xrpc/com.atproto.server.createSession", base_url().await))
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");

    assert!(res.status() == StatusCode::BAD_REQUEST || res.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "Expected 400 or 422 for missing identifier, got {}", res.status());
}

#[tokio::test]
async fn test_create_account_invalid_handle() {
    let client = client();
    let payload = json!({
        "handle": "invalid!handle.com",
        "email": "test@example.com",
        "password": "password"
    });

    let res = client.post(format!("{}/xrpc/com.atproto.server.createAccount", base_url().await))
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "Expected 400 for invalid handle chars");
}

#[tokio::test]
async fn test_get_session() {
    let client = client();
    let res = client.get(format!("{}/xrpc/com.atproto.server.getSession", base_url().await))
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
    let _ = client.post(format!("{}/xrpc/com.atproto.server.createAccount", base_url().await))
        .json(&payload)
        .send()
        .await;

    let login_payload = json!({
        "identifier": handle,
        "password": "password"
    });
    let res = client.post(format!("{}/xrpc/com.atproto.server.createSession", base_url().await))
        .json(&login_payload)
        .send()
        .await
        .expect("Failed to login");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    let refresh_jwt = body["refreshJwt"].as_str().expect("No refreshJwt").to_string();
    let access_jwt = body["accessJwt"].as_str().expect("No accessJwt").to_string();

    let res = client.post(format!("{}/xrpc/com.atproto.server.refreshSession", base_url().await))
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
    let res = client.post(format!("{}/xrpc/com.atproto.server.deleteSession", base_url().await))
        .bearer_auth(AUTH_TOKEN)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}
