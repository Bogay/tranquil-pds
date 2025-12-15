use chrono::{DateTime, Utc};
use sqlx::PgPool;
use super::super::{DeviceData, OAuthError};

pub struct DeviceAccountRow {
    pub did: String,
    pub handle: String,
    pub email: Option<String>,
    pub last_used_at: DateTime<Utc>,
}

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

pub async fn get_device_accounts(
    pool: &PgPool,
    device_id: &str,
) -> Result<Vec<DeviceAccountRow>, OAuthError> {
    let rows = sqlx::query!(
        r#"
        SELECT u.did, u.handle, u.email, ad.updated_at as last_used_at
        FROM oauth_account_device ad
        JOIN users u ON u.did = ad.did
        WHERE ad.device_id = $1
          AND u.deactivated_at IS NULL
          AND u.takedown_ref IS NULL
        ORDER BY ad.updated_at DESC
        "#,
        device_id
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| DeviceAccountRow {
            did: r.did,
            handle: r.handle,
            email: r.email,
            last_used_at: r.last_used_at,
        })
        .collect())
}

pub async fn verify_account_on_device(
    pool: &PgPool,
    device_id: &str,
    did: &str,
) -> Result<bool, OAuthError> {
    let row = sqlx::query!(
        r#"
        SELECT 1 as exists
        FROM oauth_account_device ad
        JOIN users u ON u.did = ad.did
        WHERE ad.device_id = $1
          AND ad.did = $2
          AND u.deactivated_at IS NULL
          AND u.takedown_ref IS NULL
        "#,
        device_id,
        did
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}
