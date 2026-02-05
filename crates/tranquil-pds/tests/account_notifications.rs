mod common;
use common::{base_url, client, create_account_and_login, get_test_db_pool};
use serde_json::{Value, json};

#[tokio::test]
async fn test_get_notification_history() {
    let client = client();
    let base = base_url().await;
    let pool = get_test_db_pool().await;
    let (token, did) = create_account_and_login(&client).await;

    let user_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM users WHERE did = $1")
        .bind(&did)
        .fetch_one(pool)
        .await
        .expect("User not found");

    for i in 0..3 {
        sqlx::query(
            r#"INSERT INTO comms_queue (user_id, channel, comms_type, recipient, subject, body)
               VALUES ($1, 'email', 'welcome', $2, $3, $4)"#,
        )
        .bind(user_id)
        .bind("test@example.com")
        .bind(format!("Subject {}", i))
        .bind(format!("Body {}", i))
        .execute(pool)
        .await
        .expect("Failed to enqueue");
    }

    let resp = client
        .get(format!("{}/xrpc/_account.getNotificationHistory", base))
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
    let (token, _did) = create_account_and_login(&client).await;

    let prefs = json!({
        "discordUsername": "testuser123"
    });
    let resp = client
        .post(format!("{}/xrpc/_account.updateNotificationPrefs", base))
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

    let resp = client
        .get(format!("{}/xrpc/_account.getNotificationPrefs", base))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["discordVerified"], false);
    assert_eq!(body["discordUsername"], "testuser123");
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
        .post(format!("{}/xrpc/_account.updateNotificationPrefs", base))
        .header("Authorization", format!("Bearer {}", token))
        .json(&prefs)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let input = json!({
        "channel": "telegram",
        "identifier": "testuser",
        "code": "XXXX-XXXX-XXXX-XXXX"
    });
    let resp = client
        .post(format!("{}/xrpc/_account.confirmChannelVerification", base))
        .header("Authorization", format!("Bearer {}", token))
        .json(&input)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status() == 400 || resp.status() == 422,
        "Expected 400 or 422, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_verify_channel_not_set() {
    let client = client();
    let base = base_url().await;
    let (token, _did) = create_account_and_login(&client).await;

    let input = json!({
        "channel": "signal",
        "identifier": "123456",
        "code": "XXXX-XXXX-XXXX-XXXX"
    });
    let resp = client
        .post(format!("{}/xrpc/_account.confirmChannelVerification", base))
        .header("Authorization", format!("Bearer {}", token))
        .json(&input)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status() == 400 || resp.status() == 422,
        "Expected 400 or 422, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_update_email_via_notification_prefs() {
    let client = client();
    let base = base_url().await;
    let pool = get_test_db_pool().await;
    let (token, did) = create_account_and_login(&client).await;

    let unique_email = format!("newemail_{}@example.com", uuid::Uuid::new_v4());
    let prefs = json!({
        "email": unique_email
    });
    let resp = client
        .post(format!("{}/xrpc/_account.updateNotificationPrefs", base))
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

    let user_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM users WHERE did = $1")
        .bind(&did)
        .fetch_one(pool)
        .await
        .expect("User not found");

    let body_text: String = sqlx::query_scalar(
        "SELECT body FROM comms_queue WHERE user_id = $1 AND comms_type = 'email_update' ORDER BY created_at DESC LIMIT 1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .expect("Verification code not found");

    let code = body_text
        .lines()
        .skip_while(|line| !line.contains("verification code"))
        .nth(1)
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .unwrap_or_else(|| {
            body_text
                .lines()
                .find(|line| {
                    let trimmed = line.trim();
                    trimmed.len() == 11 && trimmed.chars().nth(5) == Some('-')
                })
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        });

    let input = json!({
        "channel": "email",
        "identifier": unique_email,
        "code": code
    });
    let resp = client
        .post(format!("{}/xrpc/_account.confirmChannelVerification", base))
        .header("Authorization", format!("Bearer {}", token))
        .json(&input)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = client
        .get(format!("{}/xrpc/_account.getNotificationPrefs", base))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["email"], unique_email);
}
