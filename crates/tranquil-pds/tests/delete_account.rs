mod common;
mod helpers;
use chrono::Utc;
use common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};

async fn create_verified_account(
    client: &reqwest::Client,
    base_url: &str,
    handle: &str,
    email: &str,
    password: &str,
) -> (String, String) {
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url
        ))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": password
        }))
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    let did = body["did"].as_str().expect("No did").to_string();
    let jwt = verify_new_account(client, &did).await;
    (did, jwt)
}

#[tokio::test]
async fn test_delete_account_full_flow() {
    let client = client();
    let base_url = base_url().await;
    let ts = Utc::now().timestamp_millis();
    let handle = format!("delete-test-{}.test", ts);
    let email = format!("delete-test-{}@test.com", ts);
    let password = "Delete123pass!";
    let (did, jwt) = create_verified_account(&client, base_url, &handle, &email, password).await;
    let request_delete_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestAccountDelete",
            base_url
        ))
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("Failed to request account deletion");
    assert_eq!(request_delete_res.status(), StatusCode::OK);
    let pool = get_test_db_pool().await;
    let row = sqlx::query!(
        "SELECT token FROM account_deletion_requests WHERE did = $1",
        did
    )
    .fetch_one(pool)
    .await
    .expect("Failed to query deletion token");
    let token = row.token;
    let delete_payload = json!({
        "did": did,
        "password": password,
        "token": token
    });
    let delete_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.deleteAccount",
            base_url
        ))
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to delete account");
    assert_eq!(delete_res.status(), StatusCode::OK);
    let user_row = sqlx::query!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(pool)
        .await
        .expect("Failed to query user");
    assert!(user_row.is_none(), "User should be deleted from database");
    let session_res = client
        .get(format!("{}/xrpc/com.atproto.server.getSession", base_url))
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("Failed to check session");
    assert_eq!(session_res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_delete_account_wrong_password() {
    let client = client();
    let base_url = base_url().await;
    let ts = Utc::now().timestamp_millis();
    let handle = format!("delete-wrongpw-{}.test", ts);
    let email = format!("delete-wrongpw-{}@test.com", ts);
    let password = "Correct123!";
    let (did, jwt) = create_verified_account(&client, base_url, &handle, &email, password).await;
    let request_delete_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestAccountDelete",
            base_url
        ))
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("Failed to request account deletion");
    assert_eq!(request_delete_res.status(), StatusCode::OK);
    let pool = get_test_db_pool().await;
    let row = sqlx::query!(
        "SELECT token FROM account_deletion_requests WHERE did = $1",
        did
    )
    .fetch_one(pool)
    .await
    .expect("Failed to query deletion token");
    let token = row.token;
    let delete_payload = json!({
        "did": did,
        "password": "wrong-password",
        "token": token
    });
    let delete_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.deleteAccount",
            base_url
        ))
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to send delete request");
    assert_eq!(delete_res.status(), StatusCode::UNAUTHORIZED);
    let body: Value = delete_res.json().await.unwrap();
    assert_eq!(body["error"], "AuthenticationFailed");
}

#[tokio::test]
async fn test_delete_account_invalid_token() {
    let client = client();
    let base_url = base_url().await;
    let ts = Utc::now().timestamp_millis();
    let handle = format!("delete-badtoken-{}.test", ts);
    let email = format!("delete-badtoken-{}@test.com", ts);
    let password = "Delete123!";
    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url
        ))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": password
        }))
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(create_res.status(), StatusCode::OK);
    let create_body: Value = create_res.json().await.unwrap();
    let did = create_body["did"].as_str().unwrap().to_string();
    let delete_payload = json!({
        "did": did,
        "password": password,
        "token": "invalid-token-12345"
    });
    let delete_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.deleteAccount",
            base_url
        ))
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to send delete request");
    assert_eq!(delete_res.status(), StatusCode::UNAUTHORIZED);
    let body: Value = delete_res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidToken");
}

#[tokio::test]
async fn test_delete_account_expired_token() {
    let client = client();
    let base_url = base_url().await;
    let ts = Utc::now().timestamp_millis();
    let handle = format!("delete-expired-{}.test", ts);
    let email = format!("delete-expired-{}@test.com", ts);
    let password = "Delete123!";
    let (did, jwt) = create_verified_account(&client, base_url, &handle, &email, password).await;
    let request_delete_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestAccountDelete",
            base_url
        ))
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("Failed to request account deletion");
    assert_eq!(request_delete_res.status(), StatusCode::OK);
    let pool = get_test_db_pool().await;
    let row = sqlx::query!(
        "SELECT token FROM account_deletion_requests WHERE did = $1",
        did
    )
    .fetch_one(pool)
    .await
    .expect("Failed to query deletion token");
    let token = row.token;
    sqlx::query!(
        "UPDATE account_deletion_requests SET expires_at = NOW() - INTERVAL '1 hour' WHERE token = $1",
        token
    )
    .execute(pool)
    .await
    .expect("Failed to expire token");
    let delete_payload = json!({
        "did": did,
        "password": password,
        "token": token
    });
    let delete_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.deleteAccount",
            base_url
        ))
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to send delete request");
    assert_eq!(delete_res.status(), StatusCode::BAD_REQUEST);
    let body: Value = delete_res.json().await.unwrap();
    assert_eq!(body["error"], "ExpiredToken");
}

#[tokio::test]
async fn test_delete_account_token_mismatch() {
    let client = client();
    let base_url = base_url().await;
    let ts = Utc::now().timestamp_millis();
    let handle1 = format!("delete-user1-{}.test", ts);
    let email1 = format!("delete-user1-{}@test.com", ts);
    let password1 = "User1pass123!";
    let (did1, jwt1) =
        create_verified_account(&client, base_url, &handle1, &email1, password1).await;
    let handle2 = format!("delete-user2-{}.test", ts);
    let email2 = format!("delete-user2-{}@test.com", ts);
    let password2 = "User2pass123!";
    let (did2, _) = create_verified_account(&client, base_url, &handle2, &email2, password2).await;
    let request_delete_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestAccountDelete",
            base_url
        ))
        .bearer_auth(&jwt1)
        .send()
        .await
        .expect("Failed to request account deletion");
    assert_eq!(request_delete_res.status(), StatusCode::OK);
    let pool = get_test_db_pool().await;
    let row = sqlx::query!(
        "SELECT token FROM account_deletion_requests WHERE did = $1",
        did1
    )
    .fetch_one(pool)
    .await
    .expect("Failed to query deletion token");
    let token = row.token;
    let delete_payload = json!({
        "did": did2,
        "password": password2,
        "token": token
    });
    let delete_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.deleteAccount",
            base_url
        ))
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to send delete request");
    assert_eq!(delete_res.status(), StatusCode::UNAUTHORIZED);
    let body: Value = delete_res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidToken");
}

#[tokio::test]
async fn test_delete_account_with_app_password() {
    let client = client();
    let base_url = base_url().await;
    let ts = Utc::now().timestamp_millis();
    let handle = format!("delete-apppw-{}.test", ts);
    let email = format!("delete-apppw-{}@test.com", ts);
    let main_password = "Mainpass123!";
    let (did, jwt) =
        create_verified_account(&client, base_url, &handle, &email, main_password).await;
    let app_password_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAppPassword",
            base_url
        ))
        .bearer_auth(&jwt)
        .json(&json!({ "name": "delete-test-app" }))
        .send()
        .await
        .expect("Failed to create app password");
    assert_eq!(app_password_res.status(), StatusCode::OK);
    let app_password_body: Value = app_password_res.json().await.unwrap();
    let app_password = app_password_body["password"].as_str().unwrap().to_string();
    let request_delete_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestAccountDelete",
            base_url
        ))
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("Failed to request account deletion");
    assert_eq!(request_delete_res.status(), StatusCode::OK);
    let pool = get_test_db_pool().await;
    let row = sqlx::query!(
        "SELECT token FROM account_deletion_requests WHERE did = $1",
        did
    )
    .fetch_one(pool)
    .await
    .expect("Failed to query deletion token");
    let token = row.token;
    let delete_payload = json!({
        "did": did,
        "password": app_password,
        "token": token
    });
    let delete_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.deleteAccount",
            base_url
        ))
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to delete account");
    assert_eq!(delete_res.status(), StatusCode::OK);
    let user_row = sqlx::query!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(pool)
        .await
        .expect("Failed to query user");
    assert!(user_row.is_none(), "User should be deleted from database");
}

#[tokio::test]
async fn test_delete_account_missing_fields() {
    let client = client();
    let base_url = base_url().await;
    let res1 = client
        .post(format!(
            "{}/xrpc/com.atproto.server.deleteAccount",
            base_url
        ))
        .json(&json!({
            "password": "test",
            "token": "test"
        }))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res1.status(), StatusCode::BAD_REQUEST);
    let res2 = client
        .post(format!(
            "{}/xrpc/com.atproto.server.deleteAccount",
            base_url
        ))
        .json(&json!({
            "did": "did:web:test",
            "token": "test"
        }))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res2.status(), StatusCode::BAD_REQUEST);
    let res3 = client
        .post(format!(
            "{}/xrpc/com.atproto.server.deleteAccount",
            base_url
        ))
        .json(&json!({
            "did": "did:web:test",
            "password": "test"
        }))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res3.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_delete_account_nonexistent_user() {
    let client = client();
    let base_url = base_url().await;
    let delete_payload = json!({
        "did": "did:web:nonexistent.user",
        "password": "any-password",
        "token": "any-token"
    });
    let delete_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.deleteAccount",
            base_url
        ))
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to send delete request");
    assert_eq!(delete_res.status(), StatusCode::BAD_REQUEST);
    let body: Value = delete_res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidRequest");
}
