mod common;
mod helpers;
use helpers::verify_new_account;
use reqwest::StatusCode;
use serde_json::{Value, json};

#[tokio::test]
async fn test_reserve_signing_key_without_did() {
    let client = common::client();
    let base_url = common::base_url().await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.reserveSigningKey",
            base_url
        ))
        .json(&json!({}))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert!(body["signingKey"].is_string());
    let signing_key = body["signingKey"].as_str().unwrap();
    assert!(
        signing_key.starts_with("did:key:z"),
        "Signing key should be in did:key format with multibase prefix"
    );
}

#[tokio::test]
async fn test_reserve_signing_key_with_did() {
    let client = common::client();
    let base_url = common::base_url().await;
    let pool = common::get_test_db_pool().await;
    let target_did = "did:plc:test123456";
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.reserveSigningKey",
            base_url
        ))
        .json(&json!({ "did": target_did }))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    let signing_key = body["signingKey"].as_str().unwrap();
    assert!(signing_key.starts_with("did:key:z"));
    let row = sqlx::query!(
        "SELECT did, public_key_did_key FROM reserved_signing_keys WHERE public_key_did_key = $1",
        signing_key
    )
    .fetch_one(pool)
    .await
    .expect("Reserved key not found in database");
    assert_eq!(row.did.as_deref(), Some(target_did));
    assert_eq!(row.public_key_did_key, signing_key);
}

#[tokio::test]
async fn test_reserve_signing_key_stores_private_key() {
    let client = common::client();
    let base_url = common::base_url().await;
    let pool = common::get_test_db_pool().await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.reserveSigningKey",
            base_url
        ))
        .json(&json!({}))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    let signing_key = body["signingKey"].as_str().unwrap();
    let row = sqlx::query!(
        "SELECT private_key_bytes, expires_at, used_at FROM reserved_signing_keys WHERE public_key_did_key = $1",
        signing_key
    )
    .fetch_one(pool)
    .await
    .expect("Reserved key not found in database");
    assert_eq!(
        row.private_key_bytes.len(),
        32,
        "Private key should be 32 bytes for secp256k1"
    );
    assert!(
        row.used_at.is_none(),
        "Reserved key should not be marked as used yet"
    );
    assert!(
        row.expires_at > chrono::Utc::now(),
        "Key should expire in the future"
    );
}

#[tokio::test]
async fn test_reserve_signing_key_unique_keys() {
    let client = common::client();
    let base_url = common::base_url().await;
    let res1 = client
        .post(format!(
            "{}/xrpc/com.atproto.server.reserveSigningKey",
            base_url
        ))
        .json(&json!({}))
        .send()
        .await
        .expect("Failed to send request 1");
    assert_eq!(res1.status(), StatusCode::OK);
    let body1: Value = res1.json().await.unwrap();
    let key1 = body1["signingKey"].as_str().unwrap();
    let res2 = client
        .post(format!(
            "{}/xrpc/com.atproto.server.reserveSigningKey",
            base_url
        ))
        .json(&json!({}))
        .send()
        .await
        .expect("Failed to send request 2");
    assert_eq!(res2.status(), StatusCode::OK);
    let body2: Value = res2.json().await.unwrap();
    let key2 = body2["signingKey"].as_str().unwrap();
    assert_ne!(key1, key2, "Each call should generate a unique signing key");
}

#[tokio::test]
async fn test_reserve_signing_key_is_public() {
    let client = common::client();
    let base_url = common::base_url().await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.reserveSigningKey",
            base_url
        ))
        .json(&json!({}))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "reserveSigningKey should work without authentication"
    );
}

#[tokio::test]
async fn test_create_account_with_reserved_signing_key() {
    let client = common::client();
    let base_url = common::base_url().await;
    let pool = common::get_test_db_pool().await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.reserveSigningKey",
            base_url
        ))
        .json(&json!({}))
        .send()
        .await
        .expect("Failed to reserve signing key");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let signing_key = body["signingKey"].as_str().unwrap();
    let handle = format!("rk{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url
        ))
        .json(&json!({
            "handle": handle,
            "email": format!("{}@example.com", handle),
            "password": "Testpass123!",
            "signingKey": signing_key
        }))
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    assert!(body["did"].is_string());
    let did = body["did"].as_str().unwrap();
    let access_jwt = verify_new_account(&client, did).await;
    assert!(!access_jwt.is_empty());
    let reserved = sqlx::query!(
        "SELECT used_at FROM reserved_signing_keys WHERE public_key_did_key = $1",
        signing_key
    )
    .fetch_one(pool)
    .await
    .expect("Reserved key not found");
    assert!(
        reserved.used_at.is_some(),
        "Reserved key should be marked as used"
    );
}

#[tokio::test]
async fn test_create_account_with_invalid_signing_key() {
    let client = common::client();
    let base_url = common::base_url().await;
    let handle = format!("bk{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url
        ))
        .json(&json!({
            "handle": handle,
            "email": format!("{}@example.com", handle),
            "password": "Testpass123!",
            "signingKey": "did:key:zNonExistentKey12345"
        }))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidSigningKey");
}

#[tokio::test]
async fn test_create_account_cannot_reuse_signing_key() {
    let client = common::client();
    let base_url = common::base_url().await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.reserveSigningKey",
            base_url
        ))
        .json(&json!({}))
        .send()
        .await
        .expect("Failed to reserve signing key");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let signing_key = body["signingKey"].as_str().unwrap();
    let handle1 = format!("r1{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url
        ))
        .json(&json!({
            "handle": handle1,
            "email": format!("{}@example.com", handle1),
            "password": "Testpass123!",
            "signingKey": signing_key
        }))
        .send()
        .await
        .expect("Failed to create first account");
    assert_eq!(res.status(), StatusCode::OK);
    let handle2 = format!("r2{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url
        ))
        .json(&json!({
            "handle": handle2,
            "email": format!("{}@example.com", handle2),
            "password": "Testpass123!",
            "signingKey": signing_key
        }))
        .send()
        .await
        .expect("Failed to send second request");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidSigningKey");
    assert!(body["message"].as_str().unwrap().contains("already used"));
}

#[tokio::test]
async fn test_reserved_key_tokens_work() {
    let client = common::client();
    let base_url = common::base_url().await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.reserveSigningKey",
            base_url
        ))
        .json(&json!({}))
        .send()
        .await
        .expect("Failed to reserve signing key");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let signing_key = body["signingKey"].as_str().unwrap();
    let handle = format!("tu{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url
        ))
        .json(&json!({
            "handle": handle,
            "email": format!("{}@example.com", handle),
            "password": "Testpass123!",
            "signingKey": signing_key
        }))
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let did = body["did"].as_str().unwrap();
    let access_jwt = verify_new_account(&client, did).await;
    let res = client
        .get(format!("{}/xrpc/com.atproto.server.getSession", base_url))
        .bearer_auth(&access_jwt)
        .send()
        .await
        .expect("Failed to get session");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let session_handle = body["handle"].as_str().unwrap();
    assert!(
        session_handle.starts_with(&handle),
        "Session handle should start with requested handle"
    );
}
