mod common;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sqlx::PgPool;

async fn get_pool() -> PgPool {
    let conn_str = common::get_db_connection_string().await;
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&conn_str)
        .await
        .expect("Failed to connect to test database")
}

async fn create_verified_account(
    client: &reqwest::Client,
    base_url: &str,
    handle: &str,
    email: &str,
) -> String {
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url
        ))
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
    let did = body["did"].as_str().expect("No did");
    common::verify_new_account(client, did).await
}

#[tokio::test]
async fn test_email_update_flow_success() {
    let client = common::client();
    let base_url = common::base_url().await;
    let pool = get_pool().await;
    let handle = format!("emailup_{}", uuid::Uuid::new_v4());
    let email = format!("{}@example.com", handle);
    let access_jwt = create_verified_account(&client, &base_url, &handle, &email).await;
    let new_email = format!("new_{}@example.com", handle);
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestEmailUpdate",
            base_url
        ))
        .bearer_auth(&access_jwt)
        .json(&json!({"email": new_email}))
        .send()
        .await
        .expect("Failed to request email update");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["tokenRequired"], true);

    let verification = sqlx::query!(
        "SELECT pending_identifier, code FROM channel_verifications WHERE user_id = (SELECT id FROM users WHERE handle = $1) AND channel = 'email'",
        handle
    )
    .fetch_one(&pool)
    .await
    .expect("Verification not found");

    assert_eq!(
        verification.pending_identifier.as_deref(),
        Some(new_email.as_str())
    );
    let code = verification.code;
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.confirmEmail", base_url))
        .bearer_auth(&access_jwt)
        .json(&json!({
            "email": new_email,
            "token": code
        }))
        .send()
        .await
        .expect("Failed to confirm email");
    assert_eq!(res.status(), StatusCode::OK);
    let user = sqlx::query!(
        "SELECT email FROM users WHERE handle = $1",
        handle
    )
    .fetch_one(&pool)
    .await
    .expect("User not found");
    assert_eq!(user.email, Some(new_email));

    let verification = sqlx::query!(
        "SELECT code FROM channel_verifications WHERE user_id = (SELECT id FROM users WHERE handle = $1) AND channel = 'email'",
        handle
    )
    .fetch_optional(&pool)
    .await
    .expect("DB error");
    assert!(verification.is_none());
}

#[tokio::test]
async fn test_request_email_update_taken_email() {
    let client = common::client();
    let base_url = common::base_url().await;
    let handle1 = format!("emailup_taken1_{}", uuid::Uuid::new_v4());
    let email1 = format!("{}@example.com", handle1);
    let _ = create_verified_account(&client, &base_url, &handle1, &email1).await;
    let handle2 = format!("emailup_taken2_{}", uuid::Uuid::new_v4());
    let email2 = format!("{}@example.com", handle2);
    let access_jwt2 = create_verified_account(&client, &base_url, &handle2, &email2).await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestEmailUpdate",
            base_url
        ))
        .bearer_auth(&access_jwt2)
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
    let access_jwt = create_verified_account(&client, &base_url, &handle, &email).await;
    let new_email = format!("new_{}@example.com", handle);
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestEmailUpdate",
            base_url
        ))
        .bearer_auth(&access_jwt)
        .json(&json!({"email": new_email}))
        .send()
        .await
        .expect("Failed to request email update");
    assert_eq!(res.status(), StatusCode::OK);
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.confirmEmail", base_url))
        .bearer_auth(&access_jwt)
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
    let access_jwt = create_verified_account(&client, &base_url, &handle, &email).await;
    let new_email = format!("new_{}@example.com", handle);
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestEmailUpdate",
            base_url
        ))
        .bearer_auth(&access_jwt)
        .json(&json!({"email": new_email}))
        .send()
        .await
        .expect("Failed to request email update");
    assert_eq!(res.status(), StatusCode::OK);
    let verification = sqlx::query!(
        "SELECT code FROM channel_verifications WHERE user_id = (SELECT id FROM users WHERE handle = $1) AND channel = 'email'",
        handle
    )
    .fetch_one(&pool)
    .await
    .expect("Verification not found");
    let code = verification.code;
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.confirmEmail", base_url))
        .bearer_auth(&access_jwt)
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
    let access_jwt = create_verified_account(&client, &base_url, &handle, &email).await;
    let new_email = format!("direct_{}@example.com", handle);
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.updateEmail", base_url))
        .bearer_auth(&access_jwt)
        .json(&json!({ "email": new_email }))
        .send()
        .await
        .expect("Failed to update email");
    assert_eq!(res.status(), StatusCode::OK);
    let user = sqlx::query!("SELECT email FROM users WHERE handle = $1", handle)
        .fetch_one(&pool)
        .await
        .expect("User not found");
    assert_eq!(user.email, Some(new_email));
}

#[tokio::test]
async fn test_update_email_same_email_noop() {
    let client = common::client();
    let base_url = common::base_url().await;
    let handle = format!("emailup_same_{}", uuid::Uuid::new_v4());
    let email = format!("{}@example.com", handle);
    let access_jwt = create_verified_account(&client, &base_url, &handle, &email).await;
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.updateEmail", base_url))
        .bearer_auth(&access_jwt)
        .json(&json!({ "email": email }))
        .send()
        .await
        .expect("Failed to update email");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "Updating to same email should succeed as no-op"
    );
}

#[tokio::test]
async fn test_update_email_requires_token_after_pending() {
    let client = common::client();
    let base_url = common::base_url().await;
    let handle = format!("emailup_token_{}", uuid::Uuid::new_v4());
    let email = format!("{}@example.com", handle);
    let access_jwt = create_verified_account(&client, &base_url, &handle, &email).await;
    let new_email = format!("pending_{}@example.com", handle);
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestEmailUpdate",
            base_url
        ))
        .bearer_auth(&access_jwt)
        .json(&json!({"email": new_email}))
        .send()
        .await
        .expect("Failed to request email update");
    assert_eq!(res.status(), StatusCode::OK);
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.updateEmail", base_url))
        .bearer_auth(&access_jwt)
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
    let access_jwt = create_verified_account(&client, &base_url, &handle, &email).await;
    let new_email = format!("valid_{}@example.com", handle);
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestEmailUpdate",
            base_url
        ))
        .bearer_auth(&access_jwt)
        .json(&json!({"email": new_email}))
        .send()
        .await
        .expect("Failed to request email update");
    assert_eq!(res.status(), StatusCode::OK);
    let verification = sqlx::query!(
        "SELECT code FROM channel_verifications WHERE user_id = (SELECT id FROM users WHERE handle = $1) AND channel = 'email'",
        handle
    )
    .fetch_one(&pool)
    .await
    .expect("Verification not found");
    let code = verification.code;
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.updateEmail", base_url))
        .bearer_auth(&access_jwt)
        .json(&json!({
            "email": new_email,
            "token": code
        }))
        .send()
        .await
        .expect("Failed to update email");
    assert_eq!(res.status(), StatusCode::OK);
    let user = sqlx::query!(
        "SELECT email FROM users WHERE handle = $1",
        handle
    )
    .fetch_one(&pool)
    .await
    .expect("User not found");
    assert_eq!(user.email, Some(new_email));
    let verification = sqlx::query!(
        "SELECT code FROM channel_verifications WHERE user_id = (SELECT id FROM users WHERE handle = $1) AND channel = 'email'",
        handle
    )
    .fetch_optional(&pool)
    .await
    .expect("DB error");
    assert!(verification.is_none());
}

#[tokio::test]
async fn test_update_email_invalid_token() {
    let client = common::client();
    let base_url = common::base_url().await;
    let handle = format!("emailup_badtok_{}", uuid::Uuid::new_v4());
    let email = format!("{}@example.com", handle);
    let access_jwt = create_verified_account(&client, &base_url, &handle, &email).await;
    let new_email = format!("badtok_{}@example.com", handle);
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestEmailUpdate",
            base_url
        ))
        .bearer_auth(&access_jwt)
        .json(&json!({"email": new_email}))
        .send()
        .await
        .expect("Failed to request email update");
    assert_eq!(res.status(), StatusCode::OK);
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.updateEmail", base_url))
        .bearer_auth(&access_jwt)
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
    let _ = create_verified_account(&client, &base_url, &handle1, &email1).await;
    let handle2 = format!("emailup_dup2_{}", uuid::Uuid::new_v4());
    let email2 = format!("{}@example.com", handle2);
    let access_jwt2 = create_verified_account(&client, &base_url, &handle2, &email2).await;
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.updateEmail", base_url))
        .bearer_auth(&access_jwt2)
        .json(&json!({ "email": email1 }))
        .send()
        .await
        .expect("Failed to attempt email update");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert!(
        body["message"].as_str().unwrap().contains("already in use")
            || body["error"] == "InvalidRequest"
    );
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
    let access_jwt = create_verified_account(&client, &base_url, &handle, &email).await;
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.updateEmail", base_url))
        .bearer_auth(&access_jwt)
        .json(&json!({ "email": "not-an-email" }))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["error"], "InvalidEmail");
}
