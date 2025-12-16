use super::super::{OAuthError, TokenData};
use super::helpers::{from_json, to_json};
use chrono::{DateTime, Utc};
use sqlx::PgPool;

pub async fn create_token(pool: &PgPool, data: &TokenData) -> Result<i32, OAuthError> {
    let client_auth_json = to_json(&data.client_auth)?;
    let parameters_json = to_json(&data.parameters)?;
    let row = sqlx::query!(
        r#"
        INSERT INTO oauth_token
            (did, token_id, created_at, updated_at, expires_at, client_id, client_auth,
             device_id, parameters, details, code, current_refresh_token, scope)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        RETURNING id
        "#,
        data.did,
        data.token_id,
        data.created_at,
        data.updated_at,
        data.expires_at,
        data.client_id,
        client_auth_json,
        data.device_id,
        parameters_json,
        data.details,
        data.code,
        data.current_refresh_token,
        data.scope,
    )
    .fetch_one(pool)
    .await?;
    Ok(row.id)
}

pub async fn get_token_by_id(
    pool: &PgPool,
    token_id: &str,
) -> Result<Option<TokenData>, OAuthError> {
    let row = sqlx::query!(
        r#"
        SELECT did, token_id, created_at, updated_at, expires_at, client_id, client_auth,
               device_id, parameters, details, code, current_refresh_token, scope
        FROM oauth_token
        WHERE token_id = $1
        "#,
        token_id
    )
    .fetch_optional(pool)
    .await?;
    match row {
        Some(r) => Ok(Some(TokenData {
            did: r.did,
            token_id: r.token_id,
            created_at: r.created_at,
            updated_at: r.updated_at,
            expires_at: r.expires_at,
            client_id: r.client_id,
            client_auth: from_json(r.client_auth)?,
            device_id: r.device_id,
            parameters: from_json(r.parameters)?,
            details: r.details,
            code: r.code,
            current_refresh_token: r.current_refresh_token,
            scope: r.scope,
        })),
        None => Ok(None),
    }
}

pub async fn get_token_by_refresh_token(
    pool: &PgPool,
    refresh_token: &str,
) -> Result<Option<(i32, TokenData)>, OAuthError> {
    let row = sqlx::query!(
        r#"
        SELECT id, did, token_id, created_at, updated_at, expires_at, client_id, client_auth,
               device_id, parameters, details, code, current_refresh_token, scope
        FROM oauth_token
        WHERE current_refresh_token = $1
        "#,
        refresh_token
    )
    .fetch_optional(pool)
    .await?;
    match row {
        Some(r) => Ok(Some((
            r.id,
            TokenData {
                did: r.did,
                token_id: r.token_id,
                created_at: r.created_at,
                updated_at: r.updated_at,
                expires_at: r.expires_at,
                client_id: r.client_id,
                client_auth: from_json(r.client_auth)?,
                device_id: r.device_id,
                parameters: from_json(r.parameters)?,
                details: r.details,
                code: r.code,
                current_refresh_token: r.current_refresh_token,
                scope: r.scope,
            },
        ))),
        None => Ok(None),
    }
}

pub async fn rotate_token(
    pool: &PgPool,
    old_db_id: i32,
    new_token_id: &str,
    new_refresh_token: &str,
    new_expires_at: DateTime<Utc>,
) -> Result<(), OAuthError> {
    let mut tx = pool.begin().await?;
    let old_refresh = sqlx::query_scalar!(
        r#"
        SELECT current_refresh_token FROM oauth_token WHERE id = $1
        "#,
        old_db_id
    )
    .fetch_one(&mut *tx)
    .await?;
    if let Some(old_rt) = old_refresh {
        sqlx::query!(
            r#"
            INSERT INTO oauth_used_refresh_token (refresh_token, token_id)
            VALUES ($1, $2)
            "#,
            old_rt,
            old_db_id
        )
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query!(
        r#"
        UPDATE oauth_token
        SET token_id = $2, current_refresh_token = $3, expires_at = $4, updated_at = NOW()
        WHERE id = $1
        "#,
        old_db_id,
        new_token_id,
        new_refresh_token,
        new_expires_at
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn check_refresh_token_used(
    pool: &PgPool,
    refresh_token: &str,
) -> Result<Option<i32>, OAuthError> {
    let row = sqlx::query_scalar!(
        r#"
        SELECT token_id FROM oauth_used_refresh_token WHERE refresh_token = $1
        "#,
        refresh_token
    )
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn delete_token(pool: &PgPool, token_id: &str) -> Result<(), OAuthError> {
    sqlx::query!(
        r#"
        DELETE FROM oauth_token WHERE token_id = $1
        "#,
        token_id
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete_token_family(pool: &PgPool, db_id: i32) -> Result<(), OAuthError> {
    sqlx::query!(
        r#"
        DELETE FROM oauth_token WHERE id = $1
        "#,
        db_id
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_tokens_for_user(pool: &PgPool, did: &str) -> Result<Vec<TokenData>, OAuthError> {
    let rows = sqlx::query!(
        r#"
        SELECT did, token_id, created_at, updated_at, expires_at, client_id, client_auth,
               device_id, parameters, details, code, current_refresh_token, scope
        FROM oauth_token
        WHERE did = $1
        "#,
        did
    )
    .fetch_all(pool)
    .await?;
    let mut tokens = Vec::with_capacity(rows.len());
    for r in rows {
        tokens.push(TokenData {
            did: r.did,
            token_id: r.token_id,
            created_at: r.created_at,
            updated_at: r.updated_at,
            expires_at: r.expires_at,
            client_id: r.client_id,
            client_auth: from_json(r.client_auth)?,
            device_id: r.device_id,
            parameters: from_json(r.parameters)?,
            details: r.details,
            code: r.code,
            current_refresh_token: r.current_refresh_token,
            scope: r.scope,
        });
    }
    Ok(tokens)
}

pub async fn count_tokens_for_user(pool: &PgPool, did: &str) -> Result<i64, OAuthError> {
    let count = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) as "count!" FROM oauth_token WHERE did = $1
        "#,
        did
    )
    .fetch_one(pool)
    .await?;
    Ok(count)
}

pub async fn delete_oldest_tokens_for_user(
    pool: &PgPool,
    did: &str,
    keep_count: i64,
) -> Result<u64, OAuthError> {
    let result = sqlx::query!(
        r#"
        DELETE FROM oauth_token
        WHERE id IN (
            SELECT id FROM oauth_token
            WHERE did = $1
            ORDER BY updated_at ASC
            OFFSET $2
        )
        "#,
        did,
        keep_count
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

const MAX_TOKENS_PER_USER: i64 = 100;

pub async fn enforce_token_limit_for_user(pool: &PgPool, did: &str) -> Result<(), OAuthError> {
    let count = count_tokens_for_user(pool, did).await?;
    if count > MAX_TOKENS_PER_USER {
        let to_keep = MAX_TOKENS_PER_USER - 1;
        delete_oldest_tokens_for_user(pool, did, to_keep).await?;
    }
    Ok(())
}
