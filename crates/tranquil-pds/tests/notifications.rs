mod common;
use sqlx::Row;
use tranquil_pds::comms::{CommsChannel, CommsStatus, CommsType};

#[tokio::test]
async fn test_enqueue_comms() {
    let pool = common::get_test_db_pool().await;
    let (_, did) = common::create_account_and_login(&common::client()).await;
    let user_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM users WHERE did = $1")
        .bind(&did)
        .fetch_one(pool)
        .await
        .expect("User not found");
    let comms_id: uuid::Uuid = sqlx::query_scalar(
        r#"INSERT INTO comms_queue (user_id, channel, comms_type, recipient, subject, body)
           VALUES ($1, 'email', 'welcome', $2, $3, $4)
           RETURNING id"#,
    )
    .bind(user_id)
    .bind("test@example.com")
    .bind("Test Subject")
    .bind("Test body")
    .fetch_one(pool)
    .await
    .expect("Failed to enqueue comms");
    let row = sqlx::query(
        r#"
        SELECT id, user_id, recipient, subject, body, channel, comms_type, status
        FROM comms_queue
        WHERE id = $1
        "#,
    )
    .bind(comms_id)
    .fetch_one(pool)
    .await
    .expect("Comms not found");
    let row_user_id: uuid::Uuid = row.get("user_id");
    let row_recipient: String = row.get("recipient");
    let row_subject: Option<String> = row.get("subject");
    let row_body: String = row.get("body");
    let row_channel: CommsChannel = row.get("channel");
    let row_comms_type: CommsType = row.get("comms_type");
    let row_status: CommsStatus = row.get("status");
    assert_eq!(row_user_id, user_id);
    assert_eq!(row_recipient, "test@example.com");
    assert_eq!(row_subject.as_deref(), Some("Test Subject"));
    assert_eq!(row_body, "Test body");
    assert_eq!(row_channel, CommsChannel::Email);
    assert_eq!(row_comms_type, CommsType::Welcome);
    assert_eq!(row_status, CommsStatus::Pending);
}

#[tokio::test]
async fn test_comms_queue_status_index() {
    let pool = common::get_test_db_pool().await;
    let (_, did) = common::create_account_and_login(&common::client()).await;
    let user_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM users WHERE did = $1")
        .bind(&did)
        .fetch_one(pool)
        .await
        .expect("User not found");
    let initial_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM comms_queue WHERE status = 'pending' AND user_id = $1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .expect("Failed to count");
    let inserts = (0..5).map(|i| {
        sqlx::query(
            r#"INSERT INTO comms_queue (user_id, channel, comms_type, recipient, subject, body)
               VALUES ($1, 'email', 'password_reset', $2, $3, $4)"#,
        )
        .bind(user_id)
        .bind(format!("test{}@example.com", i))
        .bind("Test")
        .bind("Body")
        .execute(pool)
    });
    futures::future::try_join_all(inserts)
        .await
        .expect("Failed to enqueue");
    let final_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM comms_queue WHERE status = 'pending' AND user_id = $1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .expect("Failed to count");
    assert_eq!(final_count - initial_count, 5);
}
