mod common;
use common::{base_url, client, create_account_and_login, get_db_connection_string};
use serde_json::{Value, json};
use sqlx::PgPool;
use tranquil_pds::comms::{CommsType, NewComms, enqueue_comms};

async fn get_pool() -> PgPool {
    let conn_str = get_db_connection_string().await;
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&conn_str)
        .await
        .expect("Failed to connect to test database")
}

#[tokio::test]
async fn test_get_notification_history() {
    let client = client();
    let base = base_url().await;
    let pool = get_pool().await;
    let (token, did) = create_account_and_login(&client).await;

    let user_id: uuid::Uuid = sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did)
        .fetch_one(&pool)
        .await
        .expect("User not found");

    for i in 0..3 {
        let comms = NewComms::email(
            user_id,
            CommsType::Welcome,
            "test@example.com".to_string(),
            format!("Subject {}", i),
            format!("Body {}", i),
        );
        enqueue_comms(&pool, comms)
            .await
            .expect("Failed to enqueue");
    }

    let resp = client
        .get(format!(
            "{}/xrpc/com.tranquil.account.getNotificationHistory",
            base
        ))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let notifications = body["notifications"].as_array().unwrap();
    assert_eq!(notifications.len(), 5);

    assert_eq!(notifications[0]["subject"], "Subject 2");
    assert_eq!(notifications[1]["subject"], "Subject 1");
    assert_eq!(notifications[2]["subject"], "Subject 0");
}

#[tokio::test]
async fn test_verify_channel_discord() {
    let client = client();
    let base = base_url().await;
    let (token, did) = create_account_and_login(&client).await;

    let prefs = json!({
        "discordId": "123456789"
    });
    let resp = client
        .post(format!(
            "{}/xrpc/com.tranquil.account.updateNotificationPrefs",
            base
        ))
        .header("Authorization", format!("Bearer {}", token))
        .json(&prefs)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["verificationRequired"]
            .as_array()
            .unwrap()
            .contains(&json!("discord"))
    );

    let pool = get_pool().await;
    let user_id: uuid::Uuid = sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did)
        .fetch_one(&pool)
        .await
        .expect("User not found");

    let code: String = sqlx::query_scalar!(
        "SELECT code FROM channel_verifications WHERE user_id = $1 AND channel = 'discord'",
        user_id
    )
    .fetch_one(&pool)
    .await
    .expect("Verification code not found");

    let input = json!({
        "channel": "discord",
        "code": code
    });
    let resp = client
        .post(format!(
            "{}/xrpc/com.tranquil.account.confirmChannelVerification",
            base
        ))
        .header("Authorization", format!("Bearer {}", token))
        .json(&input)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = client
        .get(format!(
            "{}/xrpc/com.tranquil.account.getNotificationPrefs",
            base
        ))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["discordVerified"], true);
    assert_eq!(body["discordId"], "123456789");
}

#[tokio::test]
async fn test_verify_channel_invalid_code() {
    let client = client();
    let base = base_url().await;
    let (token, _did) = create_account_and_login(&client).await;

    let prefs = json!({
        "telegramUsername": "testuser"
    });
    let resp = client
        .post(format!(
            "{}/xrpc/com.tranquil.account.updateNotificationPrefs",
            base
        ))
        .header("Authorization", format!("Bearer {}", token))
        .json(&prefs)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let input = json!({
        "channel": "telegram",
        "code": "000000"
    });
    let resp = client
        .post(format!(
            "{}/xrpc/com.tranquil.account.confirmChannelVerification",
            base
        ))
        .header("Authorization", format!("Bearer {}", token))
        .json(&input)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_verify_channel_not_set() {
    let client = client();
    let base = base_url().await;
    let (token, _did) = create_account_and_login(&client).await;

    let input = json!({
        "channel": "signal",
        "code": "123456"
    });
    let resp = client
        .post(format!(
            "{}/xrpc/com.tranquil.account.confirmChannelVerification",
            base
        ))
        .header("Authorization", format!("Bearer {}", token))
        .json(&input)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_update_email_via_notification_prefs() {
    let client = client();
    let base = base_url().await;
    let pool = get_pool().await;
    let (token, did) = create_account_and_login(&client).await;

    let unique_email = format!("newemail_{}@example.com", uuid::Uuid::new_v4());
    let prefs = json!({
        "email": unique_email
    });
    let resp = client
        .post(format!(
            "{}/xrpc/com.tranquil.account.updateNotificationPrefs",
            base
        ))
        .header("Authorization", format!("Bearer {}", token))
        .json(&prefs)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["verificationRequired"]
            .as_array()
            .unwrap()
            .contains(&json!("email"))
    );

    let user_id: uuid::Uuid = sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did)
        .fetch_one(&pool)
        .await
        .expect("User not found");

    let code: String = sqlx::query_scalar!(
        "SELECT code FROM channel_verifications WHERE user_id = $1 AND channel = 'email'",
        user_id
    )
    .fetch_one(&pool)
    .await
    .expect("Verification code not found");

    let input = json!({
        "channel": "email",
        "code": code
    });
    let resp = client
        .post(format!(
            "{}/xrpc/com.tranquil.account.confirmChannelVerification",
            base
        ))
        .header("Authorization", format!("Bearer {}", token))
        .json(&input)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = client
        .get(format!(
            "{}/xrpc/com.tranquil.account.getNotificationPrefs",
            base
        ))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["email"], unique_email);
}
