mod common;

use bspds::notifications::{
    enqueue_notification, enqueue_welcome_email, NewNotification, NotificationChannel,
    NotificationStatus, NotificationType,
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
async fn test_enqueue_notification() {
    let pool = get_pool().await;

    let (_, did) = common::create_account_and_login(&common::client()).await;

    let user_id: uuid::Uuid = sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did)
        .fetch_one(&pool)
        .await
        .expect("User not found");

    let notification = NewNotification::email(
        user_id,
        NotificationType::Welcome,
        "test@example.com".to_string(),
        "Test Subject".to_string(),
        "Test body".to_string(),
    );

    let notification_id = enqueue_notification(&pool, notification)
        .await
        .expect("Failed to enqueue notification");

    let row = sqlx::query!(
        r#"
        SELECT
            id, user_id, recipient, subject, body,
            channel as "channel: NotificationChannel",
            notification_type as "notification_type: NotificationType",
            status as "status: NotificationStatus"
        FROM notification_queue
        WHERE id = $1
        "#,
        notification_id
    )
    .fetch_one(&pool)
    .await
    .expect("Notification not found");

    assert_eq!(row.user_id, user_id);
    assert_eq!(row.recipient, "test@example.com");
    assert_eq!(row.subject.as_deref(), Some("Test Subject"));
    assert_eq!(row.body, "Test body");
    assert_eq!(row.channel, NotificationChannel::Email);
    assert_eq!(row.notification_type, NotificationType::Welcome);
    assert_eq!(row.status, NotificationStatus::Pending);
}

#[tokio::test]
async fn test_enqueue_welcome_email() {
    let pool = get_pool().await;

    let (_, did) = common::create_account_and_login(&common::client()).await;

    let user_id: uuid::Uuid = sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did)
        .fetch_one(&pool)
        .await
        .expect("User not found");

    let notification_id = enqueue_welcome_email(&pool, user_id, "user@example.com", "testhandle", "example.com")
        .await
        .expect("Failed to enqueue welcome email");

    let row = sqlx::query!(
        r#"
        SELECT
            recipient, subject, body,
            notification_type as "notification_type: NotificationType"
        FROM notification_queue
        WHERE id = $1
        "#,
        notification_id
    )
    .fetch_one(&pool)
    .await
    .expect("Notification not found");

    assert_eq!(row.recipient, "user@example.com");
    assert_eq!(row.subject.as_deref(), Some("Welcome to example.com"));
    assert!(row.body.contains("@testhandle"));
    assert_eq!(row.notification_type, NotificationType::Welcome);
}

#[tokio::test]
async fn test_notification_queue_status_index() {
    let pool = get_pool().await;

    let (_, did) = common::create_account_and_login(&common::client()).await;

    let user_id: uuid::Uuid = sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did)
        .fetch_one(&pool)
        .await
        .expect("User not found");

    let initial_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM notification_queue WHERE status = 'pending' AND user_id = $1",
        user_id
    )
    .fetch_one(&pool)
    .await
    .expect("Failed to count")
    .unwrap_or(0);

    for i in 0..5 {
        let notification = NewNotification::email(
            user_id,
            NotificationType::PasswordReset,
            format!("test{}@example.com", i),
            "Test".to_string(),
            "Body".to_string(),
        );
        enqueue_notification(&pool, notification)
            .await
            .expect("Failed to enqueue");
    }

    let final_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM notification_queue WHERE status = 'pending' AND user_id = $1",
        user_id
    )
    .fetch_one(&pool)
    .await
    .expect("Failed to count")
    .unwrap_or(0);

    assert_eq!(final_count - initial_count, 5);
}
