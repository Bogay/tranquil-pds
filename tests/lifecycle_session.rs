mod common;
mod helpers;
use chrono::Utc;
use common::*;
use helpers::*;
use reqwest::StatusCode;
use serde_json::{Value, json};

#[tokio::test]
async fn test_session_lifecycle_wrong_password() {
    let client = client();
    let (_, _) = setup_new_user("session-wrong-pw").await;
    let login_payload = json!({
        "identifier": format!("session-wrong-pw-{}.test", Utc::now().timestamp_millis()),
        "password": "wrong-password"
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createSession",
            base_url().await
        ))
        .json(&login_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert!(
        res.status() == StatusCode::UNAUTHORIZED || res.status() == StatusCode::BAD_REQUEST,
        "Expected 401 or 400 for wrong password, got {}",
        res.status()
    );
}

#[tokio::test]
async fn test_session_lifecycle_multiple_sessions() {
    let client = client();
    let ts = Utc::now().timestamp_millis();
    let handle = format!("multi-session-{}.test", ts);
    let email = format!("multi-session-{}@test.com", ts);
    let password = "Multisession123!";
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
    let _ = verify_new_account(&client, did).await;
    let login_payload = json!({
        "identifier": handle,
        "password": password
    });
    let session1_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createSession",
            base_url().await
        ))
        .json(&login_payload)
        .send()
        .await
        .expect("Failed session 1");
    assert_eq!(session1_res.status(), StatusCode::OK);
    let session1: Value = session1_res.json().await.unwrap();
    let jwt1 = session1["accessJwt"].as_str().unwrap();
    let session2_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createSession",
            base_url().await
        ))
        .json(&login_payload)
        .send()
        .await
        .expect("Failed session 2");
    assert_eq!(session2_res.status(), StatusCode::OK);
    let session2: Value = session2_res.json().await.unwrap();
    let jwt2 = session2["accessJwt"].as_str().unwrap();
    assert_ne!(jwt1, jwt2, "Sessions should have different tokens");
    let get1 = client
        .get(format!(
            "{}/xrpc/com.atproto.server.getSession",
            base_url().await
        ))
        .bearer_auth(jwt1)
        .send()
        .await
        .expect("Failed getSession 1");
    assert_eq!(get1.status(), StatusCode::OK);
    let get2 = client
        .get(format!(
            "{}/xrpc/com.atproto.server.getSession",
            base_url().await
        ))
        .bearer_auth(jwt2)
        .send()
        .await
        .expect("Failed getSession 2");
    assert_eq!(get2.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_session_lifecycle_refresh_invalidates_old() {
    let client = client();
    let ts = Utc::now().timestamp_millis();
    let handle = format!("refresh-inv-{}.test", ts);
    let email = format!("refresh-inv-{}@test.com", ts);
    let password = "Refresh123inv!";
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
    let create_body: Value = create_res.json().await.unwrap();
    let did = create_body["did"].as_str().unwrap();
    let _ = verify_new_account(&client, did).await;
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
        .expect("Failed login");
    let login_body: Value = login_res.json().await.unwrap();
    let refresh_jwt = login_body["refreshJwt"].as_str().unwrap().to_string();
    let refresh_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.refreshSession",
            base_url().await
        ))
        .bearer_auth(&refresh_jwt)
        .send()
        .await
        .expect("Failed first refresh");
    assert_eq!(refresh_res.status(), StatusCode::OK);
    let refresh_body: Value = refresh_res.json().await.unwrap();
    let new_refresh_jwt = refresh_body["refreshJwt"].as_str().unwrap();
    assert_ne!(refresh_jwt, new_refresh_jwt, "Refresh tokens should differ");
    let reuse_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.refreshSession",
            base_url().await
        ))
        .bearer_auth(&refresh_jwt)
        .send()
        .await
        .expect("Failed reuse attempt");
    assert!(
        reuse_res.status() == StatusCode::UNAUTHORIZED
            || reuse_res.status() == StatusCode::BAD_REQUEST,
        "Old refresh token should be invalid after use"
    );
}

#[tokio::test]
async fn test_app_password_lifecycle() {
    let client = client();
    let ts = Utc::now().timestamp_millis();
    let handle = format!("apppass-{}.test", ts);
    let email = format!("apppass-{}@test.com", ts);
    let password = "Apppass123!";
    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
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
    let account: Value = create_res.json().await.unwrap();
    let did = account["did"].as_str().unwrap();
    let jwt = verify_new_account(&client, did).await;
    let create_app_pass_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAppPassword",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&json!({ "name": "Test App" }))
        .send()
        .await
        .expect("Failed to create app password");
    assert_eq!(create_app_pass_res.status(), StatusCode::OK);
    let app_pass: Value = create_app_pass_res.json().await.unwrap();
    let app_password = app_pass["password"].as_str().unwrap().to_string();
    assert_eq!(app_pass["name"], "Test App");
    let list_res = client
        .get(format!(
            "{}/xrpc/com.atproto.server.listAppPasswords",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("Failed to list app passwords");
    assert_eq!(list_res.status(), StatusCode::OK);
    let list_body: Value = list_res.json().await.unwrap();
    let passwords = list_body["passwords"].as_array().unwrap();
    assert_eq!(passwords.len(), 1);
    assert_eq!(passwords[0]["name"], "Test App");
    let login_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createSession",
            base_url().await
        ))
        .json(&json!({
            "identifier": handle,
            "password": app_password
        }))
        .send()
        .await
        .expect("Failed to login with app password");
    assert_eq!(
        login_res.status(),
        StatusCode::OK,
        "App password login should work"
    );
    let revoke_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.revokeAppPassword",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&json!({ "name": "Test App" }))
        .send()
        .await
        .expect("Failed to revoke app password");
    assert_eq!(revoke_res.status(), StatusCode::OK);
    let login_after_revoke = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createSession",
            base_url().await
        ))
        .json(&json!({
            "identifier": handle,
            "password": app_password
        }))
        .send()
        .await
        .expect("Failed to attempt login after revoke");
    assert!(
        login_after_revoke.status() == StatusCode::UNAUTHORIZED
            || login_after_revoke.status() == StatusCode::BAD_REQUEST,
        "Revoked app password should not work"
    );
    let list_after_revoke = client
        .get(format!(
            "{}/xrpc/com.atproto.server.listAppPasswords",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("Failed to list after revoke");
    let list_after: Value = list_after_revoke.json().await.unwrap();
    let passwords_after = list_after["passwords"].as_array().unwrap();
    assert_eq!(passwords_after.len(), 0, "No app passwords should remain");
}

#[tokio::test]
async fn test_app_password_duplicate_name() {
    let client = client();
    let base = base_url().await;
    let (jwt, _did) = create_account_and_login(&client).await;
    let create_res = client
        .post(format!("{}/xrpc/com.atproto.server.createAppPassword", base))
        .bearer_auth(&jwt)
        .json(&json!({ "name": "My App" }))
        .send()
        .await
        .expect("Failed to create app password");
    assert_eq!(create_res.status(), StatusCode::OK);
    let duplicate_res = client
        .post(format!("{}/xrpc/com.atproto.server.createAppPassword", base))
        .bearer_auth(&jwt)
        .json(&json!({ "name": "My App" }))
        .send()
        .await
        .expect("Failed to attempt duplicate");
    assert_eq!(
        duplicate_res.status(),
        StatusCode::BAD_REQUEST,
        "Duplicate app password name should fail"
    );
    let body: Value = duplicate_res.json().await.unwrap();
    assert_eq!(body["error"], "DuplicateAppPassword");
}

#[tokio::test]
async fn test_app_password_revoke_nonexistent() {
    let client = client();
    let base = base_url().await;
    let (jwt, _did) = create_account_and_login(&client).await;
    let revoke_res = client
        .post(format!("{}/xrpc/com.atproto.server.revokeAppPassword", base))
        .bearer_auth(&jwt)
        .json(&json!({ "name": "Does Not Exist" }))
        .send()
        .await
        .expect("Failed to revoke");
    assert_eq!(
        revoke_res.status(),
        StatusCode::OK,
        "Revoking non-existent app password should succeed silently"
    );
}

#[tokio::test]
async fn test_app_password_revoke_invalidates_sessions() {
    let client = client();
    let base = base_url().await;
    let ts = Utc::now().timestamp_millis();
    let handle = format!("apppass-inv-{}.test", ts);
    let email = format!("apppass-inv-{}@test.com", ts);
    let password = "ApppassInv123!";
    let create_res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": password
        }))
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(create_res.status(), StatusCode::OK);
    let account: Value = create_res.json().await.unwrap();
    let did = account["did"].as_str().unwrap();
    let main_jwt = verify_new_account(&client, did).await;
    let create_app_res = client
        .post(format!("{}/xrpc/com.atproto.server.createAppPassword", base))
        .bearer_auth(&main_jwt)
        .json(&json!({ "name": "Session Test App" }))
        .send()
        .await
        .expect("Failed to create app password");
    assert_eq!(create_app_res.status(), StatusCode::OK);
    let app_pass: Value = create_app_res.json().await.unwrap();
    let app_password = app_pass["password"].as_str().unwrap();
    let app_session_res = client
        .post(format!("{}/xrpc/com.atproto.server.createSession", base))
        .json(&json!({
            "identifier": handle,
            "password": app_password
        }))
        .send()
        .await
        .expect("Failed to login with app password");
    assert_eq!(app_session_res.status(), StatusCode::OK);
    let app_session: Value = app_session_res.json().await.unwrap();
    let app_jwt = app_session["accessJwt"].as_str().unwrap();
    let get_session_res = client
        .get(format!("{}/xrpc/com.atproto.server.getSession", base))
        .bearer_auth(app_jwt)
        .send()
        .await
        .expect("Failed to get session");
    assert_eq!(
        get_session_res.status(),
        StatusCode::OK,
        "App password session should be valid before revocation"
    );
    let revoke_res = client
        .post(format!("{}/xrpc/com.atproto.server.revokeAppPassword", base))
        .bearer_auth(&main_jwt)
        .json(&json!({ "name": "Session Test App" }))
        .send()
        .await
        .expect("Failed to revoke app password");
    assert_eq!(revoke_res.status(), StatusCode::OK);
    let get_session_after = client
        .get(format!("{}/xrpc/com.atproto.server.getSession", base))
        .bearer_auth(app_jwt)
        .send()
        .await
        .expect("Failed to check session after revoke");
    assert!(
        get_session_after.status() == StatusCode::UNAUTHORIZED
            || get_session_after.status() == StatusCode::BAD_REQUEST,
        "Session created with revoked app password should be invalid, got {}",
        get_session_after.status()
    );
    let main_session_res = client
        .get(format!("{}/xrpc/com.atproto.server.getSession", base))
        .bearer_auth(&main_jwt)
        .send()
        .await
        .expect("Failed to check main session");
    assert_eq!(
        main_session_res.status(),
        StatusCode::OK,
        "Main session should still be valid after revoking app password"
    );
}

#[tokio::test]
async fn test_account_deactivation_lifecycle() {
    let client = client();
    let ts = Utc::now().timestamp_millis();
    let handle = format!("deactivate-{}.test", ts);
    let email = format!("deactivate-{}@test.com", ts);
    let password = "Deactivate123!";
    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
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
    let account: Value = create_res.json().await.unwrap();
    let did = account["did"].as_str().unwrap().to_string();
    let jwt = verify_new_account(&client, &did).await;
    let (post_uri, _) = create_post(&client, &did, &jwt, "Post before deactivation").await;
    let post_rkey = post_uri.split('/').last().unwrap();
    let status_before = client
        .get(format!(
            "{}/xrpc/com.atproto.server.checkAccountStatus",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("Failed to check status");
    assert_eq!(status_before.status(), StatusCode::OK);
    let status_body: Value = status_before.json().await.unwrap();
    assert_eq!(status_body["activated"], true);
    let deactivate_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.deactivateAccount",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&json!({}))
        .send()
        .await
        .expect("Failed to deactivate");
    assert_eq!(deactivate_res.status(), StatusCode::OK);
    let get_post_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkey", post_rkey),
        ])
        .send()
        .await
        .expect("Failed to get post while deactivated");
    assert_eq!(
        get_post_res.status(),
        StatusCode::OK,
        "Records should still be readable"
    );
    let activate_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.activateAccount",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&json!({}))
        .send()
        .await
        .expect("Failed to reactivate");
    assert_eq!(activate_res.status(), StatusCode::OK);
    let status_after_activate = client
        .get(format!(
            "{}/xrpc/com.atproto.server.checkAccountStatus",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("Failed to check status after activate");
    assert_eq!(status_after_activate.status(), StatusCode::OK);
    let (new_post_uri, _) = create_post(&client, &did, &jwt, "Post after reactivation").await;
    assert!(
        !new_post_uri.is_empty(),
        "Should be able to post after reactivation"
    );
}

#[tokio::test]
async fn test_service_auth_lifecycle() {
    let client = client();
    let (did, jwt) = setup_new_user("service-auth-test").await;
    let service_auth_res = client
        .get(format!(
            "{}/xrpc/com.atproto.server.getServiceAuth",
            base_url().await
        ))
        .query(&[
            ("aud", "did:web:api.bsky.app"),
            ("lxm", "com.atproto.repo.uploadBlob"),
        ])
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("Failed to get service auth");
    assert_eq!(service_auth_res.status(), StatusCode::OK);
    let auth_body: Value = service_auth_res.json().await.unwrap();
    let service_token = auth_body["token"].as_str().expect("No token in response");
    let parts: Vec<&str> = service_token.split('.').collect();
    assert_eq!(parts.len(), 3, "Service token should be a valid JWT");
    use base64::Engine;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("Failed to decode JWT payload");
    let claims: Value = serde_json::from_slice(&payload_bytes).expect("Invalid JWT payload");
    assert_eq!(claims["iss"], did);
    assert_eq!(claims["aud"], "did:web:api.bsky.app");
    assert_eq!(claims["lxm"], "com.atproto.repo.uploadBlob");
}

#[tokio::test]
async fn test_request_account_delete() {
    let client = client();
    let (did, jwt) = setup_new_user("request-delete-test").await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestAccountDelete",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("Failed to request account deletion");
    assert_eq!(res.status(), StatusCode::OK);
    let db_url = get_db_connection_string().await;
    let pool = sqlx::PgPool::connect(&db_url)
        .await
        .expect("Failed to connect to test DB");
    let row = sqlx::query!(
        "SELECT token, expires_at FROM account_deletion_requests WHERE did = $1",
        did
    )
    .fetch_optional(&pool)
    .await
    .expect("Failed to query DB");
    assert!(row.is_some(), "Deletion token should exist in DB");
    let row = row.unwrap();
    assert!(!row.token.is_empty(), "Token should not be empty");
    assert!(row.expires_at > Utc::now(), "Token should not be expired");
}
