mod common;
use bspds::comms::{
    CommsChannel, CommsStatus, CommsType, NewComms, enqueue_comms, enqueue_welcome,
};
use sqlx::PgPool;

async fn get_pool() -> PgPool {
    let conn_str = common::get_db_connection_string().await;
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&conn_str)
        .await
        .expect("Failed to connect to test database")
}

#[tokio::test]
async fn test_enqueue_comms() {
    let pool = get_pool().await;
    let (_, did) = common::create_account_and_login(&common::client()).await;
    let user_id: uuid::Uuid = sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did)
        .fetch_one(&pool)
        .await
        .expect("User not found");
    let item = NewComms::email(
        user_id,
        CommsType::Welcome,
        "test@example.com".to_string(),
        "Test Subject".to_string(),
        "Test body".to_string(),
    );
    let comms_id = enqueue_comms(&pool, item)
        .await
        .expect("Failed to enqueue comms");
    let row = sqlx::query!(
        r#"
        SELECT
            id, user_id, recipient, subject, body,
            channel as "channel: CommsChannel",
            comms_type as "comms_type: CommsType",
            status as "status: CommsStatus"
        FROM comms_queue
        WHERE id = $1
        "#,
        comms_id
    )
    .fetch_one(&pool)
    .await
    .expect("Comms not found");
    assert_eq!(row.user_id, user_id);
    assert_eq!(row.recipient, "test@example.com");
    assert_eq!(row.subject.as_deref(), Some("Test Subject"));
    assert_eq!(row.body, "Test body");
    assert_eq!(row.channel, CommsChannel::Email);
    assert_eq!(row.comms_type, CommsType::Welcome);
    assert_eq!(row.status, CommsStatus::Pending);
}

#[tokio::test]
async fn test_enqueue_welcome() {
    let pool = get_pool().await;
    let (_, did) = common::create_account_and_login(&common::client()).await;
    let user_row = sqlx::query!("SELECT id, email, handle FROM users WHERE did = $1", did)
        .fetch_one(&pool)
        .await
        .expect("User not found");
    let comms_id = enqueue_welcome(&pool, user_row.id, "example.com")
        .await
        .expect("Failed to enqueue welcome comms");
    let row = sqlx::query!(
        r#"
        SELECT
            recipient, subject, body,
            comms_type as "comms_type: CommsType"
        FROM comms_queue
        WHERE id = $1
        "#,
        comms_id
    )
    .fetch_one(&pool)
    .await
    .expect("Comms not found");
    assert_eq!(Some(row.recipient), user_row.email);
    assert_eq!(row.subject.as_deref(), Some("Welcome to example.com"));
    assert!(row.body.contains(&format!("@{}", user_row.handle)));
    assert_eq!(row.comms_type, CommsType::Welcome);
}

#[tokio::test]
async fn test_comms_queue_status_index() {
    let pool = get_pool().await;
    let (_, did) = common::create_account_and_login(&common::client()).await;
    let user_id: uuid::Uuid = sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did)
        .fetch_one(&pool)
        .await
        .expect("User not found");
    let initial_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM comms_queue WHERE status = 'pending' AND user_id = $1",
        user_id
    )
    .fetch_one(&pool)
    .await
    .expect("Failed to count")
    .unwrap_or(0);
    for i in 0..5 {
        let item = NewComms::email(
            user_id,
            CommsType::PasswordReset,
            format!("test{}@example.com", i),
            "Test".to_string(),
            "Body".to_string(),
        );
        enqueue_comms(&pool, item)
            .await
            .expect("Failed to enqueue");
    }
    let final_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM comms_queue WHERE status = 'pending' AND user_id = $1",
        user_id
    )
    .fetch_one(&pool)
    .await
    .expect("Failed to count")
    .unwrap_or(0);
    assert_eq!(final_count - initial_count, 5);
}
