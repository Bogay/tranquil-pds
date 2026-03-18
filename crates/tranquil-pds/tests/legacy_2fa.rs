mod common;

use common::{base_url, client, create_account_and_login, get_test_db_pool};
use reqwest::StatusCode;
use serde_json::{Value, json};

async fn enable_totp_for_user(did: &str) {
    let pool = get_test_db_pool().await;
    let secret = vec![0u8; 20];
    sqlx::query(
        r#"INSERT INTO user_totp (did, secret_encrypted, encryption_version, verified, created_at)
           VALUES ($1, $2, 1, TRUE, NOW())
           ON CONFLICT (did) DO UPDATE SET verified = TRUE"#,
    )
    .bind(did)
    .bind(&secret)
    .execute(pool)
    .await
    .expect("Failed to enable TOTP");
}

async fn set_allow_legacy_login(did: &str, allow: bool) {
    let pool = get_test_db_pool().await;
    sqlx::query("UPDATE users SET allow_legacy_login = $1 WHERE did = $2")
        .bind(allow)
        .bind(did)
        .execute(pool)
        .await
        .expect("Failed to set allow_legacy_login");
}

async fn get_2fa_code_from_queue(did: &str) -> Option<String> {
    let pool = get_test_db_pool().await;
    let row: Option<(String,)> = sqlx::query_as(
        r#"SELECT body FROM comms_queue
           WHERE user_id = (SELECT id FROM users WHERE did = $1)
           AND comms_type = 'two_factor_code'
           ORDER BY created_at DESC LIMIT 1"#,
    )
    .bind(did)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    row.and_then(|(body,)| {
        body.lines()
            .find(|line: &&str| line.chars().all(|c: char| c.is_ascii_digit()) && line.len() == 8)
            .map(|s: &str| s.to_string())
            .or_else(|| {
                body.split_whitespace()
                    .find(|word: &&str| {
                        word.chars().all(|c: char| c.is_ascii_digit()) && word.len() == 8
                    })
                    .map(|s: &str| s.to_string())
            })
    })
}

async fn clear_2fa_challenges_for_user(did: &str) {
    let pool = get_test_db_pool().await;
    let _ = sqlx::query(
        "DELETE FROM comms_queue WHERE user_id = (SELECT id FROM users WHERE did = $1) AND comms_type = 'two_factor_code'",
    )
    .bind(did)
    .execute(pool)
    .await;
}

async fn set_email_auth_factor(did: &str, enabled: bool) {
    let pool = get_test_db_pool().await;
    let user_id: uuid::Uuid =
        sqlx::query_scalar::<_, uuid::Uuid>("SELECT id FROM users WHERE did = $1")
            .bind(did)
            .fetch_one(pool)
            .await
            .expect("Failed to get user id");
    let pool = get_test_db_pool().await;
    let _ = sqlx::query(
        "DELETE FROM account_preferences WHERE user_id = $1 AND name = 'email_auth_factor'",
    )
    .bind(user_id)
    .execute(pool)
    .await;
    let pool = get_test_db_pool().await;
    sqlx::query(
        "INSERT INTO account_preferences (user_id, name, value_json) VALUES ($1, 'email_auth_factor', $2::jsonb)",
    )
    .bind(user_id)
    .bind(serde_json::json!(enabled))
    .execute(pool)
    .await
    .expect("Failed to set email_auth_factor");
}

#[tokio::test]
async fn test_legacy_2fa_auth_factor_required() {
    let client = client();
    let base = base_url().await;
    let (_token, did) = create_account_and_login(&client).await;

    enable_totp_for_user(&did).await;
    set_allow_legacy_login(&did, true).await;

    let pool = get_test_db_pool().await;
    let handle: String = sqlx::query_scalar::<_, String>("SELECT handle FROM users WHERE did = $1")
        .bind(&did)
        .fetch_one(pool)
        .await
        .expect("Failed to get handle");

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

    let pool = get_test_db_pool().await;
    let handle: String = sqlx::query_scalar::<_, String>("SELECT handle FROM users WHERE did = $1")
        .bind(&did)
        .fetch_one(pool)
        .await
        .expect("Failed to get handle");

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

    let pool = get_test_db_pool().await;
    let handle: String = sqlx::query_scalar::<_, String>("SELECT handle FROM users WHERE did = $1")
        .bind(&did)
        .fetch_one(pool)
        .await
        .expect("Failed to get handle");

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

    let pool = get_test_db_pool().await;
    let handle: String = sqlx::query_scalar::<_, String>("SELECT handle FROM users WHERE did = $1")
        .bind(&did)
        .fetch_one(pool)
        .await
        .expect("Failed to get handle");

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

    let pool = get_test_db_pool().await;
    let handle: String = sqlx::query_scalar::<_, String>("SELECT handle FROM users WHERE did = $1")
        .bind(&did)
        .fetch_one(pool)
        .await
        .expect("Failed to get handle");

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

    let pool = get_test_db_pool().await;
    let handle: String = sqlx::query_scalar::<_, String>("SELECT handle FROM users WHERE did = $1")
        .bind(&did)
        .fetch_one(pool)
        .await
        .expect("Failed to get handle");

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

    let pool = get_test_db_pool().await;
    let handle: String = sqlx::query_scalar::<_, String>("SELECT handle FROM users WHERE did = $1")
        .bind(&did)
        .fetch_one(pool)
        .await
        .expect("Failed to get handle");

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

    let pool = get_test_db_pool().await;
    let handle: String = sqlx::query_scalar::<_, String>("SELECT handle FROM users WHERE did = $1")
        .bind(&did)
        .fetch_one(pool)
        .await
        .expect("Failed to get handle");

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
