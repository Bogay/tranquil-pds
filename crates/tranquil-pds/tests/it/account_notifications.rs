use crate::common::{base_url, client, create_account_and_login, get_test_repos, user_id_of};
use serde_json::{Value, json};
use tranquil_db_traits::{CommsChannel, CommsType};
use tranquil_types::{Did, Recipient};

type Repos = tranquil_db::PostgresRepositories;

async fn set_prefs(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    prefs: serde_json::Value,
) -> reqwest::Response {
    client
        .post(format!("{}/xrpc/_account.updateNotificationPrefs", base))
        .header("Authorization", format!("Bearer {}", token))
        .json(&prefs)
        .send()
        .await
        .unwrap()
}

async fn confirm_channel(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    channel: &str,
    id: &str,
    code: &str,
) -> reqwest::Response {
    client
        .post(format!("{}/xrpc/_account.confirmChannelVerification", base))
        .header("Authorization", format!("Bearer {}", token))
        .json(&json!({"channel": channel, "identifier": id, "code": code}))
        .send()
        .await
        .unwrap()
}

async fn latest_notices(
    repos: &Repos,
    user_id: uuid::Uuid,
    n: i64,
) -> Vec<tranquil_db_traits::QueuedComms> {
    repos
        .infra
        .get_latest_comms_for_user(user_id, CommsType::ChannelVerified, n)
        .await
        .expect("DB error")
}

#[tokio::test]
async fn test_get_notification_history() {
    let client = client();
    let base = base_url().await;
    let repos = get_test_repos().await;
    let (token, did) = create_account_and_login(&client).await;

    let user_id = user_id_of(repos, &Did::new(did).unwrap()).await;

    for i in 0..3 {
        repos
            .infra
            .enqueue_comms(
                Some(user_id),
                &Recipient::new(CommsChannel::Email, "test@nel.pet").unwrap(),
                CommsType::Welcome,
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

    let resp = set_prefs(
        &client,
        base,
        &token,
        json!({ "discordUsername": "testuser123" }),
    )
    .await;
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

    let resp = set_prefs(
        &client,
        base,
        &token,
        json!({ "telegramUsername": "testuser" }),
    )
    .await;
    assert_eq!(resp.status(), 200);

    let resp = confirm_channel(
        &client,
        base,
        &token,
        "telegram",
        "testuser",
        "XXXX-XXXX-XXXX-XXXX",
    )
    .await;
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_channel_verified_notice_delivers_over_email_until_chat_id_is_stored() {
    let client = client();
    let base = base_url().await;
    let repos = get_test_repos().await;
    let (token, did) = create_account_and_login(&client).await;
    let did = Did::new(did).unwrap();
    let user_id = user_id_of(repos, &did).await;

    let id = "10987654321";
    let resp = set_prefs(&client, base, &token, json!({ "telegramUsername": id })).await;
    assert_eq!(resp.status(), 200);

    let code = |did: &Did| {
        tranquil_pds::auth::verification_token::generate_channel_update_token(
            did,
            CommsChannel::Telegram,
            id,
        )
    };
    let resp = confirm_channel(&client, base, &token, "telegram", id, &code(&did)).await;
    assert_eq!(resp.status(), 200);

    let snapshot = |notices: &[tranquil_db_traits::QueuedComms]| {
        notices
            .iter()
            .map(|notice| (notice.channel, notice.recipient.clone()))
            .collect::<Vec<_>>()
    };
    let notices = latest_notices(repos, user_id, 5).await;
    assert!(
        notices
            .iter()
            .all(|notice| notice.channel != CommsChannel::Telegram),
        "Telegram identifier entered the queue as a chat ID: {:?}",
        snapshot(&notices)
    );
    assert!(
        notices
            .iter()
            .any(|notice| notice.channel == CommsChannel::Email),
        "The notice should fall back to email: {:?}",
        snapshot(&notices)
    );

    repos
        .user
        .store_telegram_chat_id(
            &tranquil_types::TelegramUsername::new(id).unwrap(),
            10987654321,
            None,
        )
        .await
        .expect("DB error")
        .expect("The Telegram username didn't match a user");

    let resp = confirm_channel(&client, base, &token, "telegram", id, &code(&did)).await;
    assert_eq!(resp.status(), 200);

    let notices = latest_notices(repos, user_id, 10).await;
    assert!(
        notices
            .iter()
            .any(|notice| notice.channel == CommsChannel::Telegram
                && notice.recipient == "10987654321"),
        "A stored chat ID should receive the notice: {:?}",
        snapshot(&notices)
    );
}

#[tokio::test]
async fn test_verify_channel_not_set() {
    let client = client();
    let base = base_url().await;
    let (token, _did) = create_account_and_login(&client).await;

    let resp = confirm_channel(
        &client,
        base,
        &token,
        "signal",
        "123456",
        "XXXX-XXXX-XXXX-XXXX",
    )
    .await;
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_update_email_via_notification_prefs() {
    let client = client();
    let base = base_url().await;
    let repos = get_test_repos().await;
    let (token, did) = create_account_and_login(&client).await;

    let unique_email = format!("newemail_{}@jola.dev", uuid::Uuid::new_v4());
    let resp = set_prefs(&client, base, &token, json!({ "email": unique_email })).await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["verificationRequired"]
            .as_array()
            .unwrap()
            .contains(&json!("email"))
    );

    let user_id = user_id_of(repos, &Did::new(did).unwrap()).await;

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

    let resp = confirm_channel(&client, base, &token, "email", &unique_email, &code).await;
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
