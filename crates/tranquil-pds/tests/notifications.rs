mod common;
use tranquil_db_traits::{CommsChannel, CommsStatus, CommsType};
use tranquil_types::Did;

#[tokio::test]
async fn test_enqueue_comms() {
    let repos = common::get_test_repos().await;
    let (_, did) = common::create_account_and_login(&common::client()).await;
    let user_id = repos
        .user
        .get_id_by_did(&Did::new(did).unwrap())
        .await
        .expect("DB error")
        .expect("User not found");
    repos
        .infra
        .enqueue_comms(
            Some(user_id),
            CommsChannel::Email,
            CommsType::Welcome,
            "test@example.com",
            Some("Test Subject"),
            "Test body",
            None,
        )
        .await
        .expect("Failed to enqueue comms");
    let comms = repos
        .infra
        .get_latest_comms_for_user(user_id, CommsType::Welcome, 1)
        .await
        .expect("DB error");
    let row = comms.first().expect("Comms not found");
    assert_eq!(row.user_id, Some(user_id));
    assert_eq!(row.recipient, "test@example.com");
    assert_eq!(row.subject.as_deref(), Some("Test Subject"));
    assert_eq!(row.body, "Test body");
    assert_eq!(row.channel, CommsChannel::Email);
    assert_eq!(row.comms_type, CommsType::Welcome);
    assert_eq!(row.status, CommsStatus::Pending);
}

#[tokio::test]
async fn test_comms_queue_status_index() {
    let repos = common::get_test_repos().await;
    let (_, did) = common::create_account_and_login(&common::client()).await;
    let user_id = repos
        .user
        .get_id_by_did(&Did::new(did).unwrap())
        .await
        .expect("DB error")
        .expect("User not found");
    let initial_count = repos
        .infra
        .count_comms_by_type(user_id, CommsType::PasswordReset)
        .await
        .expect("Failed to count");
    for i in 0..5 {
        let recipient = format!("test{}@example.com", i);
        repos
            .infra
            .enqueue_comms(
                Some(user_id),
                CommsChannel::Email,
                CommsType::PasswordReset,
                &recipient,
                Some("Test"),
                "Body",
                None,
            )
            .await
            .expect("Failed to enqueue");
    }
    let final_count = repos
        .infra
        .count_comms_by_type(user_id, CommsType::PasswordReset)
        .await
        .expect("Failed to count");
    assert_eq!(final_count - initial_count, 5);
}
