use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Serialize};
use sqlx::PgPool;

use super::{
    AuthorizationRequestParameters, ClientAuth, DeviceData, OAuthError, RequestData, TokenData,
    AuthorizedClientData,
};

fn to_json<T: Serialize>(value: &T) -> Result<serde_json::Value, OAuthError> {
    serde_json::to_value(value).map_err(|e| {
        tracing::error!("JSON serialization error: {}", e);
        OAuthError::ServerError("Internal serialization error".to_string())
    })
}

fn from_json<T: DeserializeOwned>(value: serde_json::Value) -> Result<T, OAuthError> {
    serde_json::from_value(value).map_err(|e| {
        tracing::error!("JSON deserialization error: {}", e);
        OAuthError::ServerError("Internal data corruption".to_string())
    })
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

pub async fn create_authorization_request(
    pool: &PgPool,
    request_id: &str,
    data: &RequestData,
) -> Result<(), OAuthError> {
    let client_auth_json = match &data.client_auth {
        Some(ca) => Some(to_json(ca)?),
        None => None,
    };
    let parameters_json = to_json(&data.parameters)?;

    sqlx::query!(
        r#"
        INSERT INTO oauth_authorization_request
            (id, did, device_id, client_id, client_auth, parameters, expires_at, code)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
        request_id,
        data.did,
        data.device_id,
        data.client_id,
        client_auth_json,
        parameters_json,
        data.expires_at,
        data.code,
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_authorization_request(
    pool: &PgPool,
    request_id: &str,
) -> Result<Option<RequestData>, OAuthError> {
    let row = sqlx::query!(
        r#"
        SELECT did, device_id, client_id, client_auth, parameters, expires_at, code
        FROM oauth_authorization_request
        WHERE id = $1
        "#,
        request_id
    )
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => {
            let client_auth: Option<ClientAuth> = match r.client_auth {
                Some(v) => Some(from_json(v)?),
                None => None,
            };
            let parameters: AuthorizationRequestParameters = from_json(r.parameters)?;

            Ok(Some(RequestData {
                client_id: r.client_id,
                client_auth,
                parameters,
                expires_at: r.expires_at,
                did: r.did,
                device_id: r.device_id,
                code: r.code,
            }))
        }
        None => Ok(None),
    }
}

pub async fn update_authorization_request(
    pool: &PgPool,
    request_id: &str,
    did: &str,
    device_id: Option<&str>,
    code: &str,
) -> Result<(), OAuthError> {
    sqlx::query!(
        r#"
        UPDATE oauth_authorization_request
        SET did = $2, device_id = $3, code = $4
        WHERE id = $1
        "#,
        request_id,
        did,
        device_id,
        code
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn consume_authorization_request_by_code(
    pool: &PgPool,
    code: &str,
) -> Result<Option<RequestData>, OAuthError> {
    let row = sqlx::query!(
        r#"
        DELETE FROM oauth_authorization_request
        WHERE code = $1
        RETURNING did, device_id, client_id, client_auth, parameters, expires_at, code
        "#,
        code
    )
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => {
            let client_auth: Option<ClientAuth> = match r.client_auth {
                Some(v) => Some(from_json(v)?),
                None => None,
            };
            let parameters: AuthorizationRequestParameters = from_json(r.parameters)?;

            Ok(Some(RequestData {
                client_id: r.client_id,
                client_auth,
                parameters,
                expires_at: r.expires_at,
                did: r.did,
                device_id: r.device_id,
                code: r.code,
            }))
        }
        None => Ok(None),
    }
}

pub async fn delete_authorization_request(
    pool: &PgPool,
    request_id: &str,
) -> Result<(), OAuthError> {
    sqlx::query!(
        r#"
        DELETE FROM oauth_authorization_request WHERE id = $1
        "#,
        request_id
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn delete_expired_authorization_requests(pool: &PgPool) -> Result<u64, OAuthError> {
    let result = sqlx::query!(
        r#"
        DELETE FROM oauth_authorization_request
        WHERE expires_at < NOW()
        "#
    )
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

pub async fn create_token(
    pool: &PgPool,
    data: &TokenData,
) -> Result<i32, OAuthError> {
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

pub async fn list_tokens_for_user(
    pool: &PgPool,
    did: &str,
) -> Result<Vec<TokenData>, OAuthError> {
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

pub async fn check_and_record_dpop_jti(
    pool: &PgPool,
    jti: &str,
) -> Result<bool, OAuthError> {
    let result = sqlx::query!(
        r#"
        INSERT INTO oauth_dpop_jti (jti)
        VALUES ($1)
        ON CONFLICT (jti) DO NOTHING
        "#,
        jti
    )
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn cleanup_expired_dpop_jtis(
    pool: &PgPool,
    max_age_secs: i64,
) -> Result<u64, OAuthError> {
    let result = sqlx::query!(
        r#"
        DELETE FROM oauth_dpop_jti
        WHERE created_at < NOW() - INTERVAL '1 second' * $1
        "#,
        max_age_secs as f64
    )
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
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
