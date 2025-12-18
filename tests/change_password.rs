mod common;
mod helpers;
use common::*;
use helpers::*;
use reqwest::StatusCode;
use serde_json::{Value, json};

#[tokio::test]
async fn test_change_password_success() {
    let client = client();
    let ts = chrono::Utc::now().timestamp_millis();
    let handle = format!("change-pw-{}.test", ts);
    let email = format!("change-pw-{}@test.com", ts);
    let old_password = "old-password-123";
    let new_password = "new-password-456";
    let create_payload = json!({
        "handle": handle,
        "email": email,
        "password": old_password
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
    let did = create_body["did"].as_str().unwrap();
    let jwt = verify_new_account(&client, did).await;
    let change_res = client
        .post(format!(
            "{}/xrpc/com.tranquil.account.changePassword",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&json!({
            "currentPassword": old_password,
            "newPassword": new_password
        }))
        .send()
        .await
        .expect("Failed to change password");
    assert_eq!(change_res.status(), StatusCode::OK);
    let login_old = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createSession",
            base_url().await
        ))
        .json(&json!({
            "identifier": handle,
            "password": old_password
        }))
        .send()
        .await
        .expect("Failed to try old password");
    assert_eq!(login_old.status(), StatusCode::UNAUTHORIZED, "Old password should not work");
    let login_new = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createSession",
            base_url().await
        ))
        .json(&json!({
            "identifier": handle,
            "password": new_password
        }))
        .send()
        .await
        .expect("Failed to try new password");
    assert_eq!(login_new.status(), StatusCode::OK, "New password should work");
}

#[tokio::test]
async fn test_change_password_wrong_current() {
    let client = client();
    let (_, jwt) = setup_new_user("change-pw-wrong").await;
    let res = client
        .post(format!(
            "{}/xrpc/com.tranquil.account.changePassword",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&json!({
            "currentPassword": "wrong-password",
            "newPassword": "new-password-123"
        }))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"].as_str(), Some("InvalidPassword"));
}

#[tokio::test]
async fn test_change_password_too_short() {
    let client = client();
    let ts = chrono::Utc::now().timestamp_millis();
    let handle = format!("change-pw-short-{}.test", ts);
    let email = format!("change-pw-short-{}@test.com", ts);
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
    let did = create_body["did"].as_str().unwrap();
    let jwt = verify_new_account(&client, did).await;
    let res = client
        .post(format!(
            "{}/xrpc/com.tranquil.account.changePassword",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&json!({
            "currentPassword": password,
            "newPassword": "short"
        }))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.unwrap();
    assert!(body["message"].as_str().unwrap().contains("8 characters"));
}

#[tokio::test]
async fn test_change_password_empty_current() {
    let client = client();
    let (_, jwt) = setup_new_user("change-pw-empty").await;
    let res = client
        .post(format!(
            "{}/xrpc/com.tranquil.account.changePassword",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&json!({
            "currentPassword": "",
            "newPassword": "new-password-123"
        }))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_change_password_empty_new() {
    let client = client();
    let (_, jwt) = setup_new_user("change-pw-emptynew").await;
    let res = client
        .post(format!(
            "{}/xrpc/com.tranquil.account.changePassword",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&json!({
            "currentPassword": "e2e-password-123",
            "newPassword": ""
        }))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_change_password_requires_auth() {
    let client = client();
    let res = client
        .post(format!(
            "{}/xrpc/com.tranquil.account.changePassword",
            base_url().await
        ))
        .json(&json!({
            "currentPassword": "old",
            "newPassword": "new-password-123"
        }))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}
