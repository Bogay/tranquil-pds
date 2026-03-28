mod common;
use common::{base_url, client, create_account_and_login, get_test_repos};
use serde_json::{Value, json};
use tranquil_db_traits::{CommsChannel, CommsType};
use tranquil_types::Did;

#[tokio::test]
async fn test_get_notification_history() {
    let client = client();
    let base = base_url().await;
    let repos = get_test_repos().await;
    let (token, did) = create_account_and_login(&client).await;

    let user_id = repos
        .user
        .get_id_by_did(&Did::new(did).unwrap())
        .await
        .expect("DB error")
        .expect("User not found");

    for i in 0..3 {
        repos
            .infra
            .enqueue_comms(
                Some(user_id),
                CommsChannel::Email,
                CommsType::Welcome,
                "test@example.com",
                Some(&format!("Subject {}", i)),
                &format!("Body {}", i),
                None,
            )
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
    assert_eq!(resp.status(), 400);
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
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_update_email_via_notification_prefs() {
    let client = client();
    let base = base_url().await;
    let repos = get_test_repos().await;
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

    let user_id = repos
        .user
        .get_id_by_did(&Did::new(did).unwrap())
        .await
        .expect("DB error")
        .expect("User not found");

    let comms = repos
        .infra
        .get_latest_comms_for_user(user_id, CommsType::EmailUpdate, 1)
        .await
        .expect("DB error");
    let body_text = comms
        .first()
        .map(|c| c.body.clone())
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
