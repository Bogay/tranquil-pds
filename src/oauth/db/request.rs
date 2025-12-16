use super::super::{AuthorizationRequestParameters, ClientAuth, OAuthError, RequestData};
use super::helpers::{from_json, to_json};
use sqlx::PgPool;

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
