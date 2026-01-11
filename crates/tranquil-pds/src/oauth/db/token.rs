use super::super::{OAuthError, RefreshTokenState, TokenData};
use super::helpers::{from_json, to_json};
use chrono::{DateTime, Utc};
use sqlx::PgPool;

pub enum RefreshTokenLookup {
    Valid {
        db_id: i32,
        token_data: TokenData,
    },
    InGracePeriod {
        db_id: i32,
        token_data: TokenData,
        rotated_at: DateTime<Utc>,
    },
    Used {
        original_token_id: i32,
    },
    Expired {
        db_id: i32,
    },
    NotFound,
}

impl RefreshTokenLookup {
    pub fn state(&self) -> RefreshTokenState {
        match self {
            RefreshTokenLookup::Valid { .. } => RefreshTokenState::Valid,
            RefreshTokenLookup::InGracePeriod { rotated_at, .. } => {
                RefreshTokenState::InGracePeriod {
                    rotated_at: *rotated_at,
                }
            }
            RefreshTokenLookup::Used { .. } => RefreshTokenState::Used { at: Utc::now() },
            RefreshTokenLookup::Expired { .. } => RefreshTokenState::Expired,
            RefreshTokenLookup::NotFound => RefreshTokenState::Revoked,
        }
    }
}

pub async fn lookup_refresh_token(
    pool: &PgPool,
    refresh_token: &str,
) -> Result<RefreshTokenLookup, OAuthError> {
    if let Some(token_id) = check_refresh_token_used(pool, refresh_token).await? {
        if let Some((db_id, token_data)) =
            get_token_by_previous_refresh_token(pool, refresh_token).await?
        {
            let rotated_at = token_data.updated_at;
            return Ok(RefreshTokenLookup::InGracePeriod {
                db_id,
                token_data,
                rotated_at,
            });
        }
        return Ok(RefreshTokenLookup::Used {
            original_token_id: token_id,
        });
    }

    match get_token_by_refresh_token(pool, refresh_token).await? {
        Some((db_id, token_data)) => {
            if token_data.expires_at < Utc::now() {
                Ok(RefreshTokenLookup::Expired { db_id })
            } else {
                Ok(RefreshTokenLookup::Valid { db_id, token_data })
            }
        }
        None => Ok(RefreshTokenLookup::NotFound),
    }
}

pub async fn create_token(pool: &PgPool, data: &TokenData) -> Result<i32, OAuthError> {
    let client_auth_json = to_json(&data.client_auth)?;
    let parameters_json = to_json(&data.parameters)?;
    let row = sqlx::query!(
        r#"
        INSERT INTO oauth_token
            (did, token_id, created_at, updated_at, expires_at, client_id, client_auth,
             device_id, parameters, details, code, current_refresh_token, scope, controller_did)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
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
        data.controller_did,
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
               device_id, parameters, details, code, current_refresh_token, scope, controller_did
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
            controller_did: r.controller_did,
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
               device_id, parameters, details, code, current_refresh_token, scope, controller_did
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
                controller_did: r.controller_did,
            },
        ))),
        None => Ok(None),
    }
}

pub async fn rotate_token(
    pool: &PgPool,
    old_db_id: i32,
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
    if let Some(ref old_rt) = old_refresh {
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
        SET current_refresh_token = $2, expires_at = $3, updated_at = NOW(),
            previous_refresh_token = $4, rotated_at = NOW()
        WHERE id = $1
        "#,
        old_db_id,
        new_refresh_token,
        new_expires_at,
        old_refresh
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

const REFRESH_GRACE_PERIOD_SECS: i64 = 60;

pub async fn get_token_by_previous_refresh_token(
    pool: &PgPool,
    refresh_token: &str,
) -> Result<Option<(i32, TokenData)>, OAuthError> {
    let grace_cutoff = Utc::now() - chrono::Duration::seconds(REFRESH_GRACE_PERIOD_SECS);
    let row = sqlx::query!(
        r#"
        SELECT id, did, token_id, created_at, updated_at, expires_at, client_id, client_auth,
               device_id, parameters, details, code, current_refresh_token, scope, controller_did
        FROM oauth_token
        WHERE previous_refresh_token = $1 AND rotated_at > $2
        "#,
        refresh_token,
        grace_cutoff
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
                controller_did: r.controller_did,
            },
        ))),
        None => Ok(None),
    }
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
               device_id, parameters, details, code, current_refresh_token, scope, controller_did
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
            controller_did: r.controller_did,
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

pub async fn revoke_tokens_for_client(
    pool: &PgPool,
    did: &str,
    client_id: &str,
) -> Result<u64, OAuthError> {
    let result = sqlx::query!(
        "DELETE FROM oauth_token WHERE did = $1 AND client_id = $2",
        did,
        client_id
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

pub async fn revoke_tokens_for_controller(
    pool: &PgPool,
    delegated_did: &str,
    controller_did: &str,
) -> Result<u64, OAuthError> {
    let result = sqlx::query!(
        "DELETE FROM oauth_token WHERE did = $1 AND controller_did = $2",
        delegated_did,
        controller_did
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
