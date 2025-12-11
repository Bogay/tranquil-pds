mod common;

use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;

async fn get_pool() -> PgPool {
    let conn_str = common::get_db_connection_string().await;
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&conn_str)
        .await
        .expect("Failed to connect to test database")
}

#[tokio::test]
async fn test_email_update_flow_success() {
    let client = common::client();
    let base_url = common::base_url().await;
    let pool = get_pool().await;

    let handle = format!("emailup_{}", uuid::Uuid::new_v4());
    let email = format!("{}@example.com", handle);
    let payload = json!({
        "handle": handle,
        "email": email,
        "password": "password"
    });

    let res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base_url))
        .json(&payload)
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    let access_jwt = body["accessJwt"].as_str().expect("No accessJwt");

    let new_email = format!("new_{}@example.com", handle);
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.requestEmailUpdate", base_url))
        .bearer_auth(access_jwt)
        .json(&json!({"email": new_email}))
        .send()
        .await
        .expect("Failed to request email update");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["tokenRequired"], true);

    let user = sqlx::query!(
        "SELECT email_pending_verification, email_confirmation_code, email FROM users WHERE handle = $1",
        handle
    )
    .fetch_one(&pool)
    .await
    .expect("User not found");

    assert_eq!(user.email_pending_verification.as_deref(), Some(new_email.as_str()));
    assert!(user.email_confirmation_code.is_some());
    let code = user.email_confirmation_code.unwrap();

    let res = client
        .post(format!("{}/xrpc/com.atproto.server.confirmEmail", base_url))
        .bearer_auth(access_jwt)
        .json(&json!({
            "email": new_email,
            "token": code
        }))
        .send()
        .await
        .expect("Failed to confirm email");
    assert_eq!(res.status(), StatusCode::OK);

    let user = sqlx::query!(
        "SELECT email, email_pending_verification, email_confirmation_code FROM users WHERE handle = $1",
        handle
    )
    .fetch_one(&pool)
    .await
    .expect("User not found");

    assert_eq!(user.email, new_email);
    assert!(user.email_pending_verification.is_none());
    assert!(user.email_confirmation_code.is_none());
}

#[tokio::test]
async fn test_request_email_update_taken_email() {
    let client = common::client();
    let base_url = common::base_url().await;

    let handle1 = format!("emailup_taken1_{}", uuid::Uuid::new_v4());
    let email1 = format!("{}@example.com", handle1);
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base_url))
        .json(&json!({
            "handle": handle1,
            "email": email1,
            "password": "password"
        }))
        .send()
        .await
        .expect("Failed to create account 1");
    assert_eq!(res.status(), StatusCode::OK);

    let handle2 = format!("emailup_taken2_{}", uuid::Uuid::new_v4());
    let email2 = format!("{}@example.com", handle2);
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base_url))
        .json(&json!({
            "handle": handle2,
            "email": email2,
            "password": "password"
        }))
        .send()
        .await
        .expect("Failed to create account 2");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    let access_jwt2 = body["accessJwt"].as_str().expect("No accessJwt");

    let res = client
        .post(format!("{}/xrpc/com.atproto.server.requestEmailUpdate", base_url))
        .bearer_auth(access_jwt2)
        .json(&json!({"email": email1}))
        .send()
        .await
        .expect("Failed to request email update");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["error"], "EmailTaken");
}

#[tokio::test]
async fn test_confirm_email_invalid_token() {
    let client = common::client();
    let base_url = common::base_url().await;

    let handle = format!("emailup_inv_{}", uuid::Uuid::new_v4());
    let email = format!("{}@example.com", handle);
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base_url))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": "password"
        }))
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    let access_jwt = body["accessJwt"].as_str().expect("No accessJwt");

    let new_email = format!("new_{}@example.com", handle);
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.requestEmailUpdate", base_url))
        .bearer_auth(access_jwt)
        .json(&json!({"email": new_email}))
        .send()
        .await
        .expect("Failed to request email update");
    assert_eq!(res.status(), StatusCode::OK);

    let res = client
        .post(format!("{}/xrpc/com.atproto.server.confirmEmail", base_url))
        .bearer_auth(access_jwt)
        .json(&json!({
            "email": new_email,
            "token": "wrong-token"
        }))
        .send()
        .await
        .expect("Failed to confirm email");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["error"], "InvalidToken");
}

#[tokio::test]
async fn test_confirm_email_wrong_email() {
    let client = common::client();
    let base_url = common::base_url().await;
    let pool = get_pool().await;

    let handle = format!("emailup_wrong_{}", uuid::Uuid::new_v4());
    let email = format!("{}@example.com", handle);
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base_url))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": "password"
        }))
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    let access_jwt = body["accessJwt"].as_str().expect("No accessJwt");

    let new_email = format!("new_{}@example.com", handle);
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.requestEmailUpdate", base_url))
        .bearer_auth(access_jwt)
        .json(&json!({"email": new_email}))
        .send()
        .await
        .expect("Failed to request email update");
    assert_eq!(res.status(), StatusCode::OK);

    let user = sqlx::query!("SELECT email_confirmation_code FROM users WHERE handle = $1", handle)
        .fetch_one(&pool)
        .await
        .expect("User not found");
    let code = user.email_confirmation_code.unwrap();

    let res = client
        .post(format!("{}/xrpc/com.atproto.server.confirmEmail", base_url))
        .bearer_auth(access_jwt)
        .json(&json!({
            "email": "another_random@example.com",
            "token": code
        }))
        .send()
        .await
        .expect("Failed to confirm email");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["message"], "Email does not match pending update");
}

#[tokio::test]
async fn test_update_email_success_no_token_required() {
    let client = common::client();
    let base_url = common::base_url().await;
    let pool = get_pool().await;

    let handle = format!("emailup_direct_{}", uuid::Uuid::new_v4());
    let email = format!("{}@example.com", handle);
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base_url))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": "password"
        }))
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    let access_jwt = body["accessJwt"].as_str().expect("No accessJwt");

    let new_email = format!("direct_{}@example.com", handle);
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.updateEmail", base_url))
        .bearer_auth(access_jwt)
        .json(&json!({ "email": new_email }))
        .send()
        .await
        .expect("Failed to update email");

    assert_eq!(res.status(), StatusCode::OK);

    let user = sqlx::query!("SELECT email FROM users WHERE handle = $1", handle)
        .fetch_one(&pool)
        .await
        .expect("User not found");
    assert_eq!(user.email, new_email);
}

#[tokio::test]
async fn test_update_email_same_email_noop() {
    let client = common::client();
    let base_url = common::base_url().await;

    let handle = format!("emailup_same_{}", uuid::Uuid::new_v4());
    let email = format!("{}@example.com", handle);
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base_url))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": "password"
        }))
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    let access_jwt = body["accessJwt"].as_str().expect("No accessJwt");

    let res = client
        .post(format!("{}/xrpc/com.atproto.server.updateEmail", base_url))
        .bearer_auth(access_jwt)
        .json(&json!({ "email": email }))
        .send()
        .await
        .expect("Failed to update email");

    assert_eq!(res.status(), StatusCode::OK, "Updating to same email should succeed as no-op");
}

#[tokio::test]
async fn test_update_email_requires_token_after_pending() {
    let client = common::client();
    let base_url = common::base_url().await;

    let handle = format!("emailup_token_{}", uuid::Uuid::new_v4());
    let email = format!("{}@example.com", handle);
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base_url))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": "password"
        }))
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    let access_jwt = body["accessJwt"].as_str().expect("No accessJwt");

    let new_email = format!("pending_{}@example.com", handle);
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.requestEmailUpdate", base_url))
        .bearer_auth(access_jwt)
        .json(&json!({"email": new_email}))
        .send()
        .await
        .expect("Failed to request email update");
    assert_eq!(res.status(), StatusCode::OK);

    let res = client
        .post(format!("{}/xrpc/com.atproto.server.updateEmail", base_url))
        .bearer_auth(access_jwt)
        .json(&json!({ "email": new_email }))
        .send()
        .await
        .expect("Failed to attempt email update");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["error"], "TokenRequired");
}

#[tokio::test]
async fn test_update_email_with_valid_token() {
    let client = common::client();
    let base_url = common::base_url().await;
    let pool = get_pool().await;

    let handle = format!("emailup_valid_{}", uuid::Uuid::new_v4());
    let email = format!("{}@example.com", handle);
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base_url))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": "password"
        }))
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    let access_jwt = body["accessJwt"].as_str().expect("No accessJwt");

    let new_email = format!("valid_{}@example.com", handle);
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.requestEmailUpdate", base_url))
        .bearer_auth(access_jwt)
        .json(&json!({"email": new_email}))
        .send()
        .await
        .expect("Failed to request email update");
    assert_eq!(res.status(), StatusCode::OK);

    let user = sqlx::query!(
        "SELECT email_confirmation_code FROM users WHERE handle = $1",
        handle
    )
    .fetch_one(&pool)
    .await
    .expect("User not found");
    let code = user.email_confirmation_code.unwrap();

    let res = client
        .post(format!("{}/xrpc/com.atproto.server.updateEmail", base_url))
        .bearer_auth(access_jwt)
        .json(&json!({
            "email": new_email,
            "token": code
        }))
        .send()
        .await
        .expect("Failed to update email");

    assert_eq!(res.status(), StatusCode::OK);

    let user = sqlx::query!("SELECT email, email_pending_verification FROM users WHERE handle = $1", handle)
        .fetch_one(&pool)
        .await
        .expect("User not found");
    assert_eq!(user.email, new_email);
    assert!(user.email_pending_verification.is_none());
}

#[tokio::test]
async fn test_update_email_invalid_token() {
    let client = common::client();
    let base_url = common::base_url().await;

    let handle = format!("emailup_badtok_{}", uuid::Uuid::new_v4());
    let email = format!("{}@example.com", handle);
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base_url))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": "password"
        }))
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    let access_jwt = body["accessJwt"].as_str().expect("No accessJwt");

    let new_email = format!("badtok_{}@example.com", handle);
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.requestEmailUpdate", base_url))
        .bearer_auth(access_jwt)
        .json(&json!({"email": new_email}))
        .send()
        .await
        .expect("Failed to request email update");
    assert_eq!(res.status(), StatusCode::OK);

    let res = client
        .post(format!("{}/xrpc/com.atproto.server.updateEmail", base_url))
        .bearer_auth(access_jwt)
        .json(&json!({
            "email": new_email,
            "token": "wrong-token-12345"
        }))
        .send()
        .await
        .expect("Failed to attempt email update");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["error"], "InvalidToken");
}

#[tokio::test]
async fn test_update_email_already_taken() {
    let client = common::client();
    let base_url = common::base_url().await;

    let handle1 = format!("emailup_dup1_{}", uuid::Uuid::new_v4());
    let email1 = format!("{}@example.com", handle1);
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base_url))
        .json(&json!({
            "handle": handle1,
            "email": email1,
            "password": "password"
        }))
        .send()
        .await
        .expect("Failed to create account 1");
    assert_eq!(res.status(), StatusCode::OK);

    let handle2 = format!("emailup_dup2_{}", uuid::Uuid::new_v4());
    let email2 = format!("{}@example.com", handle2);
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base_url))
        .json(&json!({
            "handle": handle2,
            "email": email2,
            "password": "password"
        }))
        .send()
        .await
        .expect("Failed to create account 2");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    let access_jwt2 = body["accessJwt"].as_str().expect("No accessJwt");

    let res = client
        .post(format!("{}/xrpc/com.atproto.server.updateEmail", base_url))
        .bearer_auth(access_jwt2)
        .json(&json!({ "email": email1 }))
        .send()
        .await
        .expect("Failed to attempt email update");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert!(body["message"].as_str().unwrap().contains("already in use") || body["error"] == "InvalidRequest");
}

#[tokio::test]
async fn test_update_email_no_auth() {
    let client = common::client();
    let base_url = common::base_url().await;

    let res = client
        .post(format!("{}/xrpc/com.atproto.server.updateEmail", base_url))
        .json(&json!({ "email": "test@example.com" }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["error"], "AuthenticationRequired");
}

#[tokio::test]
async fn test_update_email_invalid_format() {
    let client = common::client();
    let base_url = common::base_url().await;

    let handle = format!("emailup_fmt_{}", uuid::Uuid::new_v4());
    let email = format!("{}@example.com", handle);
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base_url))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": "password"
        }))
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    let access_jwt = body["accessJwt"].as_str().expect("No accessJwt");

    let res = client
        .post(format!("{}/xrpc/com.atproto.server.updateEmail", base_url))
        .bearer_auth(access_jwt)
        .json(&json!({ "email": "not-an-email" }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["error"], "InvalidEmail");
}
