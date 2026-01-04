mod common;

use reqwest::StatusCode;
use serde_json::{Value, json};

#[tokio::test]
async fn test_send_email_success() {
    let client = common::client();
    let base_url = common::base_url().await;
    let pool = common::get_test_db_pool().await;
    let (access_jwt, did) = common::create_admin_account_and_login(&client).await;
    let res = client
        .post(format!("{}/xrpc/com.atproto.admin.sendEmail", base_url))
        .bearer_auth(&access_jwt)
        .json(&json!({
            "recipientDid": did,
            "senderDid": "did:plc:admin",
            "content": "Hello, this is a test email from the admin.",
            "subject": "Test Admin Email"
        }))
        .send()
        .await
        .expect("Failed to send email");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["sent"], true);
    let user = sqlx::query!("SELECT id FROM users WHERE did = $1", did)
        .fetch_one(pool)
        .await
        .expect("User not found");
    let notification = sqlx::query!(
        "SELECT subject, body, comms_type as \"comms_type: String\" FROM comms_queue WHERE user_id = $1 AND comms_type = 'admin_email' ORDER BY created_at DESC LIMIT 1",
        user.id
    )
    .fetch_one(pool)
    .await
    .expect("Notification not found");
    assert_eq!(notification.subject.as_deref(), Some("Test Admin Email"));
    assert!(
        notification
            .body
            .contains("Hello, this is a test email from the admin.")
    );
}

#[tokio::test]
async fn test_send_email_default_subject() {
    let client = common::client();
    let base_url = common::base_url().await;
    let pool = common::get_test_db_pool().await;
    let (access_jwt, did) = common::create_admin_account_and_login(&client).await;
    let res = client
        .post(format!("{}/xrpc/com.atproto.admin.sendEmail", base_url))
        .bearer_auth(&access_jwt)
        .json(&json!({
            "recipientDid": did,
            "senderDid": "did:plc:admin",
            "content": "Email without subject"
        }))
        .send()
        .await
        .expect("Failed to send email");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["sent"], true);
    let user = sqlx::query!("SELECT id FROM users WHERE did = $1", did)
        .fetch_one(pool)
        .await
        .expect("User not found");
    let notification = sqlx::query!(
        "SELECT subject FROM comms_queue WHERE user_id = $1 AND comms_type = 'admin_email' AND body = 'Email without subject' LIMIT 1",
        user.id
    )
    .fetch_one(pool)
    .await
    .expect("Notification not found");
    assert!(notification.subject.is_some());
    assert!(notification.subject.unwrap().contains("Message from"));
}

#[tokio::test]
async fn test_send_email_recipient_not_found() {
    let client = common::client();
    let base_url = common::base_url().await;
    let (access_jwt, _) = common::create_admin_account_and_login(&client).await;
    let res = client
        .post(format!("{}/xrpc/com.atproto.admin.sendEmail", base_url))
        .bearer_auth(&access_jwt)
        .json(&json!({
            "recipientDid": "did:plc:nonexistent",
            "senderDid": "did:plc:admin",
            "content": "Test content"
        }))
        .send()
        .await
        .expect("Failed to send email");
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["error"], "AccountNotFound");
}

#[tokio::test]
async fn test_send_email_missing_content() {
    let client = common::client();
    let base_url = common::base_url().await;
    let (access_jwt, did) = common::create_admin_account_and_login(&client).await;
    let res = client
        .post(format!("{}/xrpc/com.atproto.admin.sendEmail", base_url))
        .bearer_auth(&access_jwt)
        .json(&json!({
            "recipientDid": did,
            "senderDid": "did:plc:admin",
            "content": ""
        }))
        .send()
        .await
        .expect("Failed to send email");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn test_send_email_missing_recipient() {
    let client = common::client();
    let base_url = common::base_url().await;
    let (access_jwt, _) = common::create_admin_account_and_login(&client).await;
    let res = client
        .post(format!("{}/xrpc/com.atproto.admin.sendEmail", base_url))
        .bearer_auth(&access_jwt)
        .json(&json!({
            "recipientDid": "",
            "senderDid": "did:plc:admin",
            "content": "Test content"
        }))
        .send()
        .await
        .expect("Failed to send email");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_send_email_requires_auth() {
    let client = common::client();
    let base_url = common::base_url().await;
    let res = client
        .post(format!("{}/xrpc/com.atproto.admin.sendEmail", base_url))
        .json(&json!({
            "recipientDid": "did:plc:test",
            "senderDid": "did:plc:admin",
            "content": "Test content"
        }))
        .send()
        .await
        .expect("Failed to send email");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}
