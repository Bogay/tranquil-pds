mod common;

use common::{base_url, client, create_account_and_login, get_test_repos};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tranquil_db_traits::CommsType;
use tranquil_types::Did;

async fn enable_totp_for_user(did: &str) {
    let repos = get_test_repos().await;
    repos
        .user
        .enable_totp_verified(&Did::new(did.to_string()).unwrap(), &[0u8; 20])
        .await
        .unwrap();
}

async fn set_allow_legacy_login(did: &str, allow: bool) {
    let repos = get_test_repos().await;
    repos
        .user
        .update_legacy_login(&Did::new(did.to_string()).unwrap(), allow)
        .await
        .unwrap();
}

async fn get_2fa_code_from_queue(did: &str) -> Option<String> {
    let repos = get_test_repos().await;
    let parsed_did = Did::new(did.to_string()).unwrap();
    let user_id = repos
        .user
        .get_id_by_did(&parsed_did)
        .await
        .expect("DB error")
        .expect("User not found");

    let comms = repos
        .infra
        .get_latest_comms_for_user(user_id, CommsType::TwoFactorCode, 1)
        .await
        .ok()?;

    comms.first().and_then(|c| {
        c.body
            .lines()
            .find(|line: &&str| line.chars().all(|c: char| c.is_ascii_digit()) && line.len() == 8)
            .map(|s: &str| s.to_string())
            .or_else(|| {
                c.body
                    .split_whitespace()
                    .find(|word: &&str| {
                        word.chars().all(|c: char| c.is_ascii_digit()) && word.len() == 8
                    })
                    .map(|s: &str| s.to_string())
            })
    })
}

async fn clear_2fa_challenges_for_user(did: &str) {
    let repos = get_test_repos().await;
    let parsed_did = Did::new(did.to_string()).unwrap();
    let user_id = repos
        .user
        .get_id_by_did(&parsed_did)
        .await
        .expect("DB error")
        .expect("User not found");

    let _ = repos
        .infra
        .delete_comms_by_type_for_user(user_id, CommsType::TwoFactorCode)
        .await;
}

async fn set_email_auth_factor(did: &str, enabled: bool) {
    let repos = get_test_repos().await;
    let parsed_did = Did::new(did.to_string()).unwrap();
    let user_id = repos
        .user
        .get_id_by_did(&parsed_did)
        .await
        .expect("DB error")
        .expect("User not found");

    repos
        .infra
        .upsert_account_preference(user_id, "email_auth_factor", serde_json::json!(enabled))
        .await
        .expect("Failed to set email_auth_factor");
}

async fn get_handle(did: &str) -> String {
    let repos = get_test_repos().await;
    repos
        .user
        .get_handle_by_did(&Did::new(did.to_string()).unwrap())
        .await
        .expect("DB error")
        .expect("Handle not found")
        .to_string()
}

#[tokio::test]
async fn test_legacy_2fa_auth_factor_required() {
    let client = client();
    let base = base_url().await;
    let (_token, did) = create_account_and_login(&client).await;

    enable_totp_for_user(&did).await;
    set_allow_legacy_login(&did, true).await;

    let handle = get_handle(&did).await;

    let login_payload = json!({
        "identifier": handle,
        "password": "Testpass123!"
    });
    let resp = client
        .post(format!("{}/xrpc/com.atproto.server.createSession", base))
        .json(&login_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "AuthFactorTokenRequired");
    assert!(
        body["message"]
            .as_str()
            .unwrap_or("")
            .contains("sign-in code")
    );
}

#[tokio::test]
async fn test_legacy_2fa_valid_code_succeeds() {
    let client = client();
    let base = base_url().await;
    let (_token, did) = create_account_and_login(&client).await;

    enable_totp_for_user(&did).await;
    set_allow_legacy_login(&did, true).await;
    clear_2fa_challenges_for_user(&did).await;

    let handle = get_handle(&did).await;

    let login_payload = json!({
        "identifier": handle,
        "password": "Testpass123!"
    });
    let resp = client
        .post(format!("{}/xrpc/com.atproto.server.createSession", base))
        .json(&login_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    let code = get_2fa_code_from_queue(&did)
        .await
        .expect("2FA code should be in queue");

    let login_with_code = json!({
        "identifier": handle,
        "password": "Testpass123!",
        "authFactorToken": code
    });
    let resp = client
        .post(format!("{}/xrpc/com.atproto.server.createSession", base))
        .json(&login_with_code)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert!(body.get("accessJwt").is_some());
    assert!(body.get("refreshJwt").is_some());
    assert_eq!(body["did"], did);
}

#[tokio::test]
async fn test_legacy_2fa_invalid_code_rejected() {
    let client = client();
    let base = base_url().await;
    let (_token, did) = create_account_and_login(&client).await;

    enable_totp_for_user(&did).await;
    set_allow_legacy_login(&did, true).await;
    clear_2fa_challenges_for_user(&did).await;

    let handle = get_handle(&did).await;

    let resp = client
        .post(format!("{}/xrpc/com.atproto.server.createSession", base))
        .json(&json!({
            "identifier": handle,
            "password": "Testpass123!"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let login_with_bad_code = json!({
        "identifier": handle,
        "password": "Testpass123!",
        "authFactorToken": "00000000"
    });
    let resp = client
        .post(format!("{}/xrpc/com.atproto.server.createSession", base))
        .json(&login_with_bad_code)
        .send()
        .await
        .unwrap();

    let status = resp.status();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Expected 400, got {}. Response: {:?}",
        status,
        body
    );
    assert_eq!(body["error"], "InvalidCode");
}

#[tokio::test]
async fn test_legacy_2fa_blocked_when_disabled() {
    let client = client();
    let base = base_url().await;
    let (_token, did) = create_account_and_login(&client).await;

    enable_totp_for_user(&did).await;
    set_allow_legacy_login(&did, false).await;

    let handle = get_handle(&did).await;

    let login_payload = json!({
        "identifier": handle,
        "password": "Testpass123!"
    });
    let resp = client
        .post(format!("{}/xrpc/com.atproto.server.createSession", base))
        .json(&login_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "MfaRequired");
}

#[tokio::test]
async fn test_legacy_2fa_no_totp_no_challenge() {
    let client = client();
    let base = base_url().await;
    let (_token, did) = create_account_and_login(&client).await;

    let handle = get_handle(&did).await;

    let login_payload = json!({
        "identifier": handle,
        "password": "Testpass123!"
    });
    let resp = client
        .post(format!("{}/xrpc/com.atproto.server.createSession", base))
        .json(&login_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert!(body.get("accessJwt").is_some());
}

#[tokio::test]
async fn test_legacy_2fa_code_consumed_after_use() {
    let client = client();
    let base = base_url().await;
    let (_token, did) = create_account_and_login(&client).await;

    enable_totp_for_user(&did).await;
    set_allow_legacy_login(&did, true).await;
    clear_2fa_challenges_for_user(&did).await;

    let handle = get_handle(&did).await;

    let resp = client
        .post(format!("{}/xrpc/com.atproto.server.createSession", base))
        .json(&json!({
            "identifier": handle,
            "password": "Testpass123!"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    let code = get_2fa_code_from_queue(&did)
        .await
        .expect("2FA code should be in queue");

    let resp = client
        .post(format!("{}/xrpc/com.atproto.server.createSession", base))
        .json(&json!({
            "identifier": handle,
            "password": "Testpass123!",
            "authFactorToken": code
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    clear_2fa_challenges_for_user(&did).await;
    let resp = client
        .post(format!("{}/xrpc/com.atproto.server.createSession", base))
        .json(&json!({
            "identifier": handle,
            "password": "Testpass123!"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "AuthFactorTokenRequired");

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    let new_code = get_2fa_code_from_queue(&did)
        .await
        .expect("New 2FA code should be in queue");

    let resp = client
        .post(format!("{}/xrpc/com.atproto.server.createSession", base))
        .json(&json!({
            "identifier": handle,
            "password": "Testpass123!",
            "authFactorToken": code
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Expected 400 for old code, got {}. Response: {:?}",
        status,
        body
    );
    assert_eq!(body["error"], "InvalidCode");

    let resp = client
        .post(format!("{}/xrpc/com.atproto.server.createSession", base))
        .json(&json!({
            "identifier": handle,
            "password": "Testpass123!",
            "authFactorToken": new_code
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_email_auth_factor_requires_code() {
    let client = client();
    let base = base_url().await;
    let (_token, did) = create_account_and_login(&client).await;

    set_email_auth_factor(&did, true).await;
    clear_2fa_challenges_for_user(&did).await;

    let handle = get_handle(&did).await;

    let login_payload = json!({
        "identifier": handle,
        "password": "Testpass123!"
    });
    let resp = client
        .post(format!("{}/xrpc/com.atproto.server.createSession", base))
        .json(&login_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "AuthFactorTokenRequired");

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    let code = get_2fa_code_from_queue(&did)
        .await
        .expect("2FA code should be in queue");

    let login_with_code = json!({
        "identifier": handle,
        "password": "Testpass123!",
        "authFactorToken": code
    });
    let resp = client
        .post(format!("{}/xrpc/com.atproto.server.createSession", base))
        .json(&login_with_code)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert!(body.get("accessJwt").is_some());
    assert_eq!(body["emailAuthFactor"], true);
}

#[tokio::test]
async fn test_email_auth_factor_disabled_no_challenge() {
    let client = client();
    let base = base_url().await;
    let (_token, did) = create_account_and_login(&client).await;

    set_email_auth_factor(&did, false).await;

    let handle = get_handle(&did).await;

    let login_payload = json!({
        "identifier": handle,
        "password": "Testpass123!"
    });
    let resp = client
        .post(format!("{}/xrpc/com.atproto.server.createSession", base))
        .json(&login_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert!(body.get("accessJwt").is_some());
}
