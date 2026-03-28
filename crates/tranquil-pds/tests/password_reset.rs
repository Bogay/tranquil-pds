mod common;
mod helpers;
use helpers::verify_new_account;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tranquil_db_traits::CommsType;

#[tokio::test]
async fn test_request_password_reset_creates_code() {
    let client = common::client();
    let base_url = common::base_url().await;
    let repos = common::get_test_repos().await;
    let handle = format!("pr{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let email = format!("{}@example.com", handle);
    let payload = json!({
        "handle": handle,
        "email": email,
        "password": "Oldpass123!"
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url
        ))
        .json(&payload)
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(res.status(), StatusCode::OK);
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestPasswordReset",
            base_url
        ))
        .json(&json!({"email": email}))
        .send()
        .await
        .expect("Failed to request password reset");
    assert_eq!(res.status(), StatusCode::OK);
    let info = repos
        .user
        .get_password_reset_info(&email)
        .await
        .expect("failed to look up user")
        .expect("user not found");
    assert!(info.code.is_some());
    assert!(info.expires_at.is_some());
    let code = info.code.unwrap();
    assert!(code.contains('-'));
    assert_eq!(code.len(), 11);
}

#[tokio::test]
async fn test_request_password_reset_unknown_email_returns_ok() {
    let client = common::client();
    let base_url = common::base_url().await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestPasswordReset",
            base_url
        ))
        .json(&json!({"email": "nonexistent@example.com"}))
        .send()
        .await
        .expect("Failed to request password reset");
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_reset_password_with_valid_token() {
    let client = common::client();
    let base_url = common::base_url().await;
    let repos = common::get_test_repos().await;
    let handle = format!("pr2{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let email = format!("{}@example.com", handle);
    let old_password = "Oldpass123!";
    let new_password = "Newpass456!";
    let payload = json!({
        "handle": handle,
        "email": email,
        "password": old_password
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url
        ))
        .json(&payload)
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let did = body["did"].as_str().unwrap();
    let _ = verify_new_account(&client, did).await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestPasswordReset",
            base_url
        ))
        .json(&json!({"email": email}))
        .send()
        .await
        .expect("Failed to request password reset");
    assert_eq!(res.status(), StatusCode::OK);
    let info = repos
        .user
        .get_password_reset_info(&email)
        .await
        .expect("failed to look up user")
        .expect("user not found");
    let token = info.code.expect("No reset code");
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.resetPassword",
            base_url
        ))
        .json(&json!({
            "token": token,
            "password": new_password
        }))
        .send()
        .await
        .expect("Failed to reset password");
    assert_eq!(res.status(), StatusCode::OK);
    let info = repos
        .user
        .get_password_reset_info(&email)
        .await
        .expect("failed to look up user")
        .expect("user not found");
    assert!(info.code.is_none());
    assert!(info.expires_at.is_none());
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createSession",
            base_url
        ))
        .json(&json!({
            "identifier": handle,
            "password": new_password
        }))
        .send()
        .await
        .expect("Failed to login");
    assert_eq!(res.status(), StatusCode::OK);
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createSession",
            base_url
        ))
        .json(&json!({
            "identifier": handle,
            "password": old_password
        }))
        .send()
        .await
        .expect("Failed to login attempt");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_reset_password_with_invalid_token() {
    let client = common::client();
    let base_url = common::base_url().await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.resetPassword",
            base_url
        ))
        .json(&json!({
            "token": "invalid-token",
            "password": "Newpass123!"
        }))
        .send()
        .await
        .expect("Failed to reset password");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["error"], "InvalidToken");
}

#[tokio::test]
async fn test_reset_password_with_expired_token() {
    let client = common::client();
    let base_url = common::base_url().await;
    let repos = common::get_test_repos().await;
    let handle = format!("pr3{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let email = format!("{}@example.com", handle);
    let payload = json!({
        "handle": handle,
        "email": email,
        "password": "Oldpass123!"
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url
        ))
        .json(&payload)
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(res.status(), StatusCode::OK);
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestPasswordReset",
            base_url
        ))
        .json(&json!({"email": email}))
        .send()
        .await
        .expect("Failed to request password reset");
    assert_eq!(res.status(), StatusCode::OK);
    let info = repos
        .user
        .get_password_reset_info(&email)
        .await
        .expect("failed to look up user")
        .expect("user not found");
    let token = info.code.expect("No reset code");
    repos
        .user
        .expire_password_reset_code(&email)
        .await
        .expect("Failed to expire token");
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.resetPassword",
            base_url
        ))
        .json(&json!({
            "token": token,
            "password": "Newpass123!"
        }))
        .send()
        .await
        .expect("Failed to reset password");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["error"], "ExpiredToken");
}

#[tokio::test]
async fn test_reset_password_invalidates_sessions() {
    let client = common::client();
    let base_url = common::base_url().await;
    let repos = common::get_test_repos().await;
    let handle = format!("pr4{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let email = format!("{}@example.com", handle);
    let payload = json!({
        "handle": handle,
        "email": email,
        "password": "Oldpass123!"
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url
        ))
        .json(&payload)
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    let did = body["did"].as_str().expect("No did");
    let original_token = verify_new_account(&client, did).await;
    let res = client
        .get(format!("{}/xrpc/com.atproto.server.getSession", base_url))
        .bearer_auth(&original_token)
        .send()
        .await
        .expect("Failed to get session");
    assert_eq!(res.status(), StatusCode::OK);
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestPasswordReset",
            base_url
        ))
        .json(&json!({"email": email}))
        .send()
        .await
        .expect("Failed to request password reset");
    assert_eq!(res.status(), StatusCode::OK);
    let info = repos
        .user
        .get_password_reset_info(&email)
        .await
        .expect("failed to look up user")
        .expect("user not found");
    let token = info.code.expect("No reset code");
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.resetPassword",
            base_url
        ))
        .json(&json!({
            "token": token,
            "password": "Newpass123!"
        }))
        .send()
        .await
        .expect("Failed to reset password");
    assert_eq!(res.status(), StatusCode::OK);
    let res = client
        .get(format!("{}/xrpc/com.atproto.server.getSession", base_url))
        .bearer_auth(&original_token)
        .send()
        .await
        .expect("Failed to get session");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_request_password_reset_empty_email() {
    let client = common::client();
    let base_url = common::base_url().await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestPasswordReset",
            base_url
        ))
        .json(&json!({"email": ""}))
        .send()
        .await
        .expect("Failed to request password reset");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn test_reset_password_creates_notification() {
    let repos = common::get_test_repos().await;
    let client = common::client();
    let base_url = common::base_url().await;
    let handle = format!("pr5{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let email = format!("{}@example.com", handle);
    let payload = json!({
        "handle": handle,
        "email": email,
        "password": "Oldpass123!"
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url
        ))
        .json(&payload)
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(res.status(), StatusCode::OK);
    let user = repos
        .user
        .get_by_email(&email)
        .await
        .expect("failed to look up user")
        .expect("user not found");
    let initial_count = repos
        .infra
        .count_comms_by_type(user.id, CommsType::PasswordReset)
        .await
        .expect("Failed to count");
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestPasswordReset",
            base_url
        ))
        .json(&json!({"email": email}))
        .send()
        .await
        .expect("Failed to request password reset");
    assert_eq!(res.status(), StatusCode::OK);
    let final_count = repos
        .infra
        .count_comms_by_type(user.id, CommsType::PasswordReset)
        .await
        .expect("Failed to count");
    assert_eq!(final_count - initial_count, 1);
}
