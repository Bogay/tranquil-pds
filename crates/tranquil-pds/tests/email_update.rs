mod common;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sqlx::PgPool;

async fn get_email_update_token(pool: &PgPool, did: &str) -> String {
    let body_text: String = sqlx::query_scalar!(
        "SELECT body FROM comms_queue WHERE user_id = (SELECT id FROM users WHERE did = $1) AND comms_type = 'email_update' ORDER BY created_at DESC LIMIT 1",
        did
    )
    .fetch_one(pool)
    .await
    .expect("Verification not found");

    body_text
        .lines()
        .skip_while(|line| !line.contains("verification code"))
        .nth(1)
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty() && line.contains('-'))
        .unwrap_or_else(|| {
            body_text
                .lines()
                .find(|line| line.trim().starts_with("MX") && line.contains('-'))
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        })
}

async fn create_verified_account(
    client: &reqwest::Client,
    base_url: &str,
    handle: &str,
    email: &str,
) -> (String, String) {
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url
        ))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": "Testpass123!"
        }))
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    let did = body["did"].as_str().expect("No did").to_string();
    let jwt = common::verify_new_account(client, &did).await;
    (jwt, did)
}

#[tokio::test]
async fn test_request_email_update_returns_token_required() {
    let client = common::client();
    let base_url = common::base_url().await;
    let handle = format!("er{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let email = format!("{}@example.com", handle);
    let (access_jwt, _) = create_verified_account(&client, base_url, &handle, &email).await;

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestEmailUpdate",
            base_url
        ))
        .bearer_auth(&access_jwt)
        .send()
        .await
        .expect("Failed to request email update");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["tokenRequired"], true);
}

#[tokio::test]
async fn test_update_email_flow_success() {
    let client = common::client();
    let base_url = common::base_url().await;
    let pool = common::get_test_db_pool().await;
    let handle = format!("eu{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let email = format!("{}@example.com", handle);
    let (access_jwt, did) = create_verified_account(&client, base_url, &handle, &email).await;
    let new_email = format!("new_{}@example.com", handle);

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestEmailUpdate",
            base_url
        ))
        .bearer_auth(&access_jwt)
        .send()
        .await
        .expect("Failed to request email update");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["tokenRequired"], true);

    let code = get_email_update_token(pool, &did).await;

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

    let user_email: Option<String> =
        sqlx::query_scalar!("SELECT email FROM users WHERE did = $1", did)
            .fetch_one(pool)
            .await
            .expect("User not found");
    assert_eq!(user_email, Some(new_email));
}

#[tokio::test]
async fn test_update_email_requires_token_when_verified() {
    let client = common::client();
    let base_url = common::base_url().await;
    let handle = format!("ed{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let email = format!("{}@example.com", handle);
    let (access_jwt, _) = create_verified_account(&client, base_url, &handle, &email).await;
    let new_email = format!("direct_{}@example.com", handle);

    let res = client
        .post(format!("{}/xrpc/com.atproto.server.updateEmail", base_url))
        .bearer_auth(&access_jwt)
        .json(&json!({ "email": new_email }))
        .send()
        .await
        .expect("Failed to update email");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["error"], "TokenRequired");
}

#[tokio::test]
async fn test_update_email_same_email_noop() {
    let client = common::client();
    let base_url = common::base_url().await;
    let handle = format!("es{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let email = format!("{}@example.com", handle);
    let (access_jwt, _) = create_verified_account(&client, base_url, &handle, &email).await;

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
async fn test_update_email_invalid_token() {
    let client = common::client();
    let base_url = common::base_url().await;
    let handle = format!("eb{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let email = format!("{}@example.com", handle);
    let (access_jwt, _) = create_verified_account(&client, base_url, &handle, &email).await;
    let new_email = format!("badtok_{}@example.com", handle);

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestEmailUpdate",
            base_url
        ))
        .bearer_auth(&access_jwt)
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
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["error"], "InvalidToken");
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
    let handle = format!("ef{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let email = format!("{}@example.com", handle);
    let (access_jwt, _) = create_verified_account(&client, base_url, &handle, &email).await;

    let res = client
        .post(format!("{}/xrpc/com.atproto.server.updateEmail", base_url))
        .bearer_auth(&access_jwt)
        .json(&json!({ "email": "not-an-email" }))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_confirm_email_confirms_existing_email() {
    let client = common::client();
    let base_url = common::base_url().await;
    let pool = common::get_test_db_pool().await;
    let handle = format!("ec{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let email = format!("{}@example.com", handle);

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url
        ))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": "Testpass123!"
        }))
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    let did = body["did"].as_str().expect("No did").to_string();
    let access_jwt = body["accessJwt"]
        .as_str()
        .expect("No accessJwt")
        .to_string();

    let body_text: String = sqlx::query_scalar!(
        "SELECT body FROM comms_queue WHERE user_id = (SELECT id FROM users WHERE did = $1) AND comms_type = 'email_verification' ORDER BY created_at DESC LIMIT 1",
        did
    )
    .fetch_one(pool)
    .await
    .expect("Verification email not found");

    let code = body_text
        .lines()
        .find(|line| line.trim().starts_with("MX") && line.contains('-'))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let res = client
        .post(format!("{}/xrpc/com.atproto.server.confirmEmail", base_url))
        .bearer_auth(&access_jwt)
        .json(&json!({
            "email": email,
            "token": code
        }))
        .send()
        .await
        .expect("Failed to confirm email");
    assert_eq!(res.status(), StatusCode::OK);

    let verified: bool =
        sqlx::query_scalar!("SELECT email_verified FROM users WHERE did = $1", did)
            .fetch_one(pool)
            .await
            .expect("User not found");
    assert!(verified);
}

#[tokio::test]
async fn test_confirm_email_rejects_wrong_email() {
    let client = common::client();
    let base_url = common::base_url().await;
    let pool = common::get_test_db_pool().await;
    let handle = format!("ew{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let email = format!("{}@example.com", handle);

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url
        ))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": "Testpass123!"
        }))
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    let did = body["did"].as_str().expect("No did").to_string();
    let access_jwt = body["accessJwt"]
        .as_str()
        .expect("No accessJwt")
        .to_string();

    let body_text: String = sqlx::query_scalar!(
        "SELECT body FROM comms_queue WHERE user_id = (SELECT id FROM users WHERE did = $1) AND comms_type = 'email_verification' ORDER BY created_at DESC LIMIT 1",
        did
    )
    .fetch_one(pool)
    .await
    .expect("Verification email not found");

    let code = body_text
        .lines()
        .find(|line| line.trim().starts_with("MX") && line.contains('-'))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let res = client
        .post(format!("{}/xrpc/com.atproto.server.confirmEmail", base_url))
        .bearer_auth(&access_jwt)
        .json(&json!({
            "email": "different@example.com",
            "token": code
        }))
        .send()
        .await
        .expect("Failed to confirm email");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["error"], "InvalidEmail");
}

#[tokio::test]
async fn test_confirm_email_invalid_token() {
    let client = common::client();
    let base_url = common::base_url().await;
    let handle = format!("ei{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let email = format!("{}@example.com", handle);

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url
        ))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": "Testpass123!"
        }))
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    let access_jwt = body["accessJwt"]
        .as_str()
        .expect("No accessJwt")
        .to_string();

    let res = client
        .post(format!("{}/xrpc/com.atproto.server.confirmEmail", base_url))
        .bearer_auth(&access_jwt)
        .json(&json!({
            "email": email,
            "token": "wrong-token"
        }))
        .send()
        .await
        .expect("Failed to confirm email");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["error"], "InvalidToken");
}

#[tokio::test]
async fn test_unverified_account_can_update_email_without_token() {
    let client = common::client();
    let base_url = common::base_url().await;
    let pool = common::get_test_db_pool().await;
    let handle = format!("ev{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let email = format!("{}@example.com", handle);

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url
        ))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": "Testpass123!"
        }))
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    let did = body["did"].as_str().expect("No did").to_string();
    let access_jwt = body["accessJwt"]
        .as_str()
        .expect("No accessJwt")
        .to_string();

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestEmailUpdate",
            base_url
        ))
        .bearer_auth(&access_jwt)
        .send()
        .await
        .expect("Failed to request email update");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(
        body["tokenRequired"], false,
        "Unverified account should not require token"
    );

    let new_email = format!("new_{}@example.com", handle);
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.updateEmail", base_url))
        .bearer_auth(&access_jwt)
        .json(&json!({ "email": new_email }))
        .send()
        .await
        .expect("Failed to update email");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "Unverified account should be able to update email without token"
    );

    let user_email: Option<String> =
        sqlx::query_scalar!("SELECT email FROM users WHERE did = $1", did)
            .fetch_one(pool)
            .await
            .expect("User not found");
    assert_eq!(user_email, Some(new_email));
}

#[tokio::test]
async fn test_update_email_to_same_as_another_user_allowed() {
    let client = common::client();
    let base_url = common::base_url().await;
    let pool = common::get_test_db_pool().await;

    let handle1 = format!("d1{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let email1 = format!("{}@example.com", handle1);
    let (_, _) = create_verified_account(&client, base_url, &handle1, &email1).await;

    let handle2 = format!("d2{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let email2 = format!("{}@example.com", handle2);
    let (access_jwt2, did2) = create_verified_account(&client, base_url, &handle2, &email2).await;

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestEmailUpdate",
            base_url
        ))
        .bearer_auth(&access_jwt2)
        .send()
        .await
        .expect("Failed to request email update");
    assert_eq!(res.status(), StatusCode::OK);

    let code = get_email_update_token(pool, &did2).await;

    let res = client
        .post(format!("{}/xrpc/com.atproto.server.updateEmail", base_url))
        .bearer_auth(&access_jwt2)
        .json(&json!({
            "email": email1,
            "token": code
        }))
        .send()
        .await
        .expect("Failed to update email");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "Multiple accounts can share the same email address"
    );

    let user_email: Option<String> =
        sqlx::query_scalar!("SELECT email FROM users WHERE did = $1", did2)
            .fetch_one(pool)
            .await
            .expect("User not found");
    assert_eq!(user_email, Some(email1.clone()));
}
