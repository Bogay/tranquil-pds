use sqlx::PgPool;

use super::super::{DeviceData, OAuthError};

pub async fn create_device(
    pool: &PgPool,
    device_id: &str,
    data: &DeviceData,
) -> Result<(), OAuthError> {
    sqlx::query!(
        r#"
        INSERT INTO oauth_device (id, session_id, user_agent, ip_address, last_seen_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
        device_id,
        data.session_id,
        data.user_agent,
        data.ip_address,
        data.last_seen_at,
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_device(pool: &PgPool, device_id: &str) -> Result<Option<DeviceData>, OAuthError> {
    let row = sqlx::query!(
        r#"
        SELECT session_id, user_agent, ip_address, last_seen_at
        FROM oauth_device
        WHERE id = $1
        "#,
        device_id
    )
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| DeviceData {
        session_id: r.session_id,
        user_agent: r.user_agent,
        ip_address: r.ip_address,
        last_seen_at: r.last_seen_at,
    }))
}

pub async fn update_device_last_seen(
    pool: &PgPool,
    device_id: &str,
) -> Result<(), OAuthError> {
    sqlx::query!(
        r#"
        UPDATE oauth_device
        SET last_seen_at = NOW()
        WHERE id = $1
        "#,
        device_id
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn delete_device(pool: &PgPool, device_id: &str) -> Result<(), OAuthError> {
    sqlx::query!(
        r#"
        DELETE FROM oauth_device WHERE id = $1
        "#,
        device_id
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn upsert_account_device(
    pool: &PgPool,
    did: &str,
    device_id: &str,
) -> Result<(), OAuthError> {
    sqlx::query!(
        r#"
        INSERT INTO oauth_account_device (did, device_id, created_at, updated_at)
        VALUES ($1, $2, NOW(), NOW())
        ON CONFLICT (did, device_id) DO UPDATE SET updated_at = NOW()
        "#,
        did,
        device_id
    )
    .execute(pool)
    .await?;

    Ok(())
}
