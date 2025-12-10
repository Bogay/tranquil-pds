mod common;
mod helpers;

use common::*;

use chrono::Utc;
use reqwest::StatusCode;
use serde_json::{Value, json};

#[tokio::test]
async fn test_delete_account_full_flow() {
    let client = client();
    let ts = Utc::now().timestamp_millis();
    let handle = format!("delete-test-{}.test", ts);
    let email = format!("delete-test-{}@test.com", ts);
    let password = "delete-password-123";

    let create_payload = json!({
        "handle": handle,
        "email": email,
        "password": password
    });
    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(create_res.status(), StatusCode::OK);
    let create_body: Value = create_res.json().await.unwrap();
    let did = create_body["did"].as_str().unwrap().to_string();
    let jwt = create_body["accessJwt"].as_str().unwrap().to_string();

    let request_delete_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestAccountDelete",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("Failed to request account deletion");
    assert_eq!(request_delete_res.status(), StatusCode::OK);

    let db_url = get_db_connection_string().await;
    let pool = sqlx::PgPool::connect(&db_url).await.expect("Failed to connect to test DB");

    let row = sqlx::query!("SELECT token FROM account_deletion_requests WHERE did = $1", did)
        .fetch_one(&pool)
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
            base_url().await
        ))
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to delete account");
    assert_eq!(delete_res.status(), StatusCode::OK);

    let user_row = sqlx::query!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(&pool)
        .await
        .expect("Failed to query user");
    assert!(user_row.is_none(), "User should be deleted from database");

    let session_res = client
        .get(format!(
            "{}/xrpc/com.atproto.server.getSession",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("Failed to check session");
    assert_eq!(session_res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_delete_account_wrong_password() {
    let client = client();
    let ts = Utc::now().timestamp_millis();
    let handle = format!("delete-wrongpw-{}.test", ts);
    let email = format!("delete-wrongpw-{}@test.com", ts);
    let password = "correct-password";

    let create_payload = json!({
        "handle": handle,
        "email": email,
        "password": password
    });
    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(create_res.status(), StatusCode::OK);
    let create_body: Value = create_res.json().await.unwrap();
    let did = create_body["did"].as_str().unwrap().to_string();
    let jwt = create_body["accessJwt"].as_str().unwrap().to_string();

    let request_delete_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestAccountDelete",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("Failed to request account deletion");
    assert_eq!(request_delete_res.status(), StatusCode::OK);

    let db_url = get_db_connection_string().await;
    let pool = sqlx::PgPool::connect(&db_url).await.expect("Failed to connect to test DB");

    let row = sqlx::query!("SELECT token FROM account_deletion_requests WHERE did = $1", did)
        .fetch_one(&pool)
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
            base_url().await
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
    let ts = Utc::now().timestamp_millis();
    let handle = format!("delete-badtoken-{}.test", ts);
    let email = format!("delete-badtoken-{}@test.com", ts);
    let password = "delete-password";

    let create_payload = json!({
        "handle": handle,
        "email": email,
        "password": password
    });
    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .json(&create_payload)
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
            base_url().await
        ))
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to send delete request");
    assert_eq!(delete_res.status(), StatusCode::BAD_REQUEST);

    let body: Value = delete_res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidToken");
}

#[tokio::test]
async fn test_delete_account_expired_token() {
    let client = client();
    let ts = Utc::now().timestamp_millis();
    let handle = format!("delete-expired-{}.test", ts);
    let email = format!("delete-expired-{}@test.com", ts);
    let password = "delete-password";

    let create_payload = json!({
        "handle": handle,
        "email": email,
        "password": password
    });
    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(create_res.status(), StatusCode::OK);
    let create_body: Value = create_res.json().await.unwrap();
    let did = create_body["did"].as_str().unwrap().to_string();
    let jwt = create_body["accessJwt"].as_str().unwrap().to_string();

    let request_delete_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestAccountDelete",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("Failed to request account deletion");
    assert_eq!(request_delete_res.status(), StatusCode::OK);

    let db_url = get_db_connection_string().await;
    let pool = sqlx::PgPool::connect(&db_url).await.expect("Failed to connect to test DB");

    let row = sqlx::query!("SELECT token FROM account_deletion_requests WHERE did = $1", did)
        .fetch_one(&pool)
        .await
        .expect("Failed to query deletion token");
    let token = row.token;

    sqlx::query!(
        "UPDATE account_deletion_requests SET expires_at = NOW() - INTERVAL '1 hour' WHERE token = $1",
        token
    )
    .execute(&pool)
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
            base_url().await
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
    let ts = Utc::now().timestamp_millis();

    let handle1 = format!("delete-user1-{}.test", ts);
    let email1 = format!("delete-user1-{}@test.com", ts);
    let password1 = "user1-password";

    let create1_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .json(&json!({
            "handle": handle1,
            "email": email1,
            "password": password1
        }))
        .send()
        .await
        .expect("Failed to create account 1");
    assert_eq!(create1_res.status(), StatusCode::OK);
    let create1_body: Value = create1_res.json().await.unwrap();
    let did1 = create1_body["did"].as_str().unwrap().to_string();
    let jwt1 = create1_body["accessJwt"].as_str().unwrap().to_string();

    let handle2 = format!("delete-user2-{}.test", ts);
    let email2 = format!("delete-user2-{}@test.com", ts);
    let password2 = "user2-password";

    let create2_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .json(&json!({
            "handle": handle2,
            "email": email2,
            "password": password2
        }))
        .send()
        .await
        .expect("Failed to create account 2");
    assert_eq!(create2_res.status(), StatusCode::OK);
    let create2_body: Value = create2_res.json().await.unwrap();
    let did2 = create2_body["did"].as_str().unwrap().to_string();

    let request_delete_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestAccountDelete",
            base_url().await
        ))
        .bearer_auth(&jwt1)
        .send()
        .await
        .expect("Failed to request account deletion");
    assert_eq!(request_delete_res.status(), StatusCode::OK);

    let db_url = get_db_connection_string().await;
    let pool = sqlx::PgPool::connect(&db_url).await.expect("Failed to connect to test DB");

    let row = sqlx::query!("SELECT token FROM account_deletion_requests WHERE did = $1", did1)
        .fetch_one(&pool)
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
            base_url().await
        ))
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to send delete request");
    assert_eq!(delete_res.status(), StatusCode::BAD_REQUEST);

    let body: Value = delete_res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidToken");
}

#[tokio::test]
async fn test_delete_account_with_app_password() {
    let client = client();
    let ts = Utc::now().timestamp_millis();
    let handle = format!("delete-apppw-{}.test", ts);
    let email = format!("delete-apppw-{}@test.com", ts);
    let main_password = "main-password-123";

    let create_payload = json!({
        "handle": handle,
        "email": email,
        "password": main_password
    });
    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(create_res.status(), StatusCode::OK);
    let create_body: Value = create_res.json().await.unwrap();
    let did = create_body["did"].as_str().unwrap().to_string();
    let jwt = create_body["accessJwt"].as_str().unwrap().to_string();

    let app_password_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAppPassword",
            base_url().await
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
            base_url().await
        ))
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("Failed to request account deletion");
    assert_eq!(request_delete_res.status(), StatusCode::OK);

    let db_url = get_db_connection_string().await;
    let pool = sqlx::PgPool::connect(&db_url).await.expect("Failed to connect to test DB");

    let row = sqlx::query!("SELECT token FROM account_deletion_requests WHERE did = $1", did)
        .fetch_one(&pool)
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
            base_url().await
        ))
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to delete account");
    assert_eq!(delete_res.status(), StatusCode::OK);

    let user_row = sqlx::query!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(&pool)
        .await
        .expect("Failed to query user");
    assert!(user_row.is_none(), "User should be deleted from database");
}

#[tokio::test]
async fn test_delete_account_missing_fields() {
    let client = client();

    let res1 = client
        .post(format!(
            "{}/xrpc/com.atproto.server.deleteAccount",
            base_url().await
        ))
        .json(&json!({
            "password": "test",
            "token": "test"
        }))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res1.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let res2 = client
        .post(format!(
            "{}/xrpc/com.atproto.server.deleteAccount",
            base_url().await
        ))
        .json(&json!({
            "did": "did:web:test",
            "token": "test"
        }))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res2.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let res3 = client
        .post(format!(
            "{}/xrpc/com.atproto.server.deleteAccount",
            base_url().await
        ))
        .json(&json!({
            "did": "did:web:test",
            "password": "test"
        }))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res3.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn test_delete_account_nonexistent_user() {
    let client = client();

    let delete_payload = json!({
        "did": "did:web:nonexistent.user",
        "password": "any-password",
        "token": "any-token"
    });
    let delete_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.deleteAccount",
            base_url().await
        ))
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to send delete request");
    assert_eq!(delete_res.status(), StatusCode::BAD_REQUEST);

    let body: Value = delete_res.json().await.unwrap();
    assert_eq!(body["error"], "AccountNotFound");
}
