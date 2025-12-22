mod common;
mod helpers;
use common::*;
use helpers::*;
use reqwest::StatusCode;
use serde_json::{Value, json};

#[tokio::test]
async fn test_list_sessions_returns_current_session() {
    let client = client();
    let (did, jwt) = setup_new_user("list-sessions").await;
    let res = client
        .get(format!(
            "{}/xrpc/com.tranquil.account.listSessions",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let sessions = body["sessions"]
        .as_array()
        .expect("sessions should be array");
    assert!(!sessions.is_empty(), "Should have at least one session");
    let current = sessions
        .iter()
        .find(|s| s["isCurrent"].as_bool() == Some(true));
    assert!(current.is_some(), "Should have a current session marked");
    let session = current.unwrap();
    assert!(session["id"].as_str().is_some(), "Session should have id");
    assert!(
        session["createdAt"].as_str().is_some(),
        "Session should have createdAt"
    );
    assert!(
        session["expiresAt"].as_str().is_some(),
        "Session should have expiresAt"
    );
    let _ = did;
}

#[tokio::test]
async fn test_list_sessions_multiple_sessions() {
    let client = client();
    let ts = chrono::Utc::now().timestamp_millis();
    let handle = format!("multi-list-{}.test", ts);
    let email = format!("multi-list-{}@test.com", ts);
    let password = "Testpass123!";
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
    let jwt1 = verify_new_account(&client, did).await;
    let login_payload = json!({
        "identifier": handle,
        "password": password
    });
    let login_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createSession",
            base_url().await
        ))
        .json(&login_payload)
        .send()
        .await
        .expect("Failed to login");
    assert_eq!(login_res.status(), StatusCode::OK);
    let login_body: Value = login_res.json().await.unwrap();
    let jwt2 = login_body["accessJwt"].as_str().unwrap();
    let list_res = client
        .get(format!(
            "{}/xrpc/com.tranquil.account.listSessions",
            base_url().await
        ))
        .bearer_auth(jwt2)
        .send()
        .await
        .expect("Failed to list sessions");
    assert_eq!(list_res.status(), StatusCode::OK);
    let list_body: Value = list_res.json().await.unwrap();
    let sessions = list_body["sessions"].as_array().unwrap();
    assert!(
        sessions.len() >= 2,
        "Should have at least 2 sessions, got {}",
        sessions.len()
    );
    let _ = jwt1;
}

#[tokio::test]
async fn test_list_sessions_requires_auth() {
    let client = client();
    let res = client
        .get(format!(
            "{}/xrpc/com.tranquil.account.listSessions",
            base_url().await
        ))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_revoke_session_success() {
    let client = client();
    let ts = chrono::Utc::now().timestamp_millis();
    let handle = format!("revoke-sess-{}.test", ts);
    let email = format!("revoke-sess-{}@test.com", ts);
    let password = "Testpass123!";
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
    let jwt1 = verify_new_account(&client, did).await;
    let login_payload = json!({
        "identifier": handle,
        "password": password
    });
    let login_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createSession",
            base_url().await
        ))
        .json(&login_payload)
        .send()
        .await
        .expect("Failed to login");
    assert_eq!(login_res.status(), StatusCode::OK);
    let login_body: Value = login_res.json().await.unwrap();
    let jwt2 = login_body["accessJwt"].as_str().unwrap();
    let list_res = client
        .get(format!(
            "{}/xrpc/com.tranquil.account.listSessions",
            base_url().await
        ))
        .bearer_auth(jwt2)
        .send()
        .await
        .expect("Failed to list sessions");
    let list_body: Value = list_res.json().await.unwrap();
    let sessions = list_body["sessions"].as_array().unwrap();
    let other_session = sessions
        .iter()
        .find(|s| s["isCurrent"].as_bool() != Some(true));
    assert!(
        other_session.is_some(),
        "Should have another session to revoke"
    );
    let session_id = other_session.unwrap()["id"].as_str().unwrap();
    let revoke_res = client
        .post(format!(
            "{}/xrpc/com.tranquil.account.revokeSession",
            base_url().await
        ))
        .bearer_auth(jwt2)
        .json(&json!({"sessionId": session_id}))
        .send()
        .await
        .expect("Failed to revoke session");
    assert_eq!(revoke_res.status(), StatusCode::OK);
    let list_after_res = client
        .get(format!(
            "{}/xrpc/com.tranquil.account.listSessions",
            base_url().await
        ))
        .bearer_auth(jwt2)
        .send()
        .await
        .expect("Failed to list sessions after revoke");
    let list_after_body: Value = list_after_res.json().await.unwrap();
    let sessions_after = list_after_body["sessions"].as_array().unwrap();
    let revoked_still_exists = sessions_after
        .iter()
        .any(|s| s["id"].as_str() == Some(session_id));
    assert!(
        !revoked_still_exists,
        "Revoked session should not appear in list"
    );
    let _ = jwt1;
}

#[tokio::test]
async fn test_revoke_session_invalid_id() {
    let client = client();
    let (_, jwt) = setup_new_user("revoke-invalid").await;
    let res = client
        .post(format!(
            "{}/xrpc/com.tranquil.account.revokeSession",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&json!({"sessionId": "not-a-number"}))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_revoke_session_not_found() {
    let client = client();
    let (_, jwt) = setup_new_user("revoke-notfound").await;
    let res = client
        .post(format!(
            "{}/xrpc/com.tranquil.account.revokeSession",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&json!({"sessionId": "999999999"}))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_revoke_session_requires_auth() {
    let client = client();
    let res = client
        .post(format!(
            "{}/xrpc/com.tranquil.account.revokeSession",
            base_url().await
        ))
        .json(&json!({"sessionId": "1"}))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}
