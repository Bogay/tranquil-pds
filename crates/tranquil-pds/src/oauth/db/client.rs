use super::super::{AuthorizedClientData, OAuthError};
use super::helpers::{from_json, to_json};
use sqlx::PgPool;

pub async fn upsert_authorized_client(
    pool: &PgPool,
    did: &str,
    client_id: &str,
    data: &AuthorizedClientData,
) -> Result<(), OAuthError> {
    let data_json = to_json(data)?;
    sqlx::query!(
        r#"
        INSERT INTO oauth_authorized_client (did, client_id, created_at, updated_at, data)
        VALUES ($1, $2, NOW(), NOW(), $3)
        ON CONFLICT (did, client_id) DO UPDATE SET updated_at = NOW(), data = $3
        "#,
        did,
        client_id,
        data_json
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_authorized_client(
    pool: &PgPool,
    did: &str,
    client_id: &str,
) -> Result<Option<AuthorizedClientData>, OAuthError> {
    let row = sqlx::query_scalar!(
        r#"
        SELECT data FROM oauth_authorized_client
        WHERE did = $1 AND client_id = $2
        "#,
        did,
        client_id
    )
    .fetch_optional(pool)
    .await?;
    match row {
        Some(v) => Ok(Some(from_json(v)?)),
        None => Ok(None),
    }
}
