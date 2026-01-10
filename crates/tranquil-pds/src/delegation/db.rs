use crate::types::Handle;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationGrant {
    pub id: Uuid,
    pub delegated_did: String,
    pub controller_did: String,
    pub granted_scopes: String,
    pub granted_at: DateTime<Utc>,
    pub granted_by: String,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatedAccountInfo {
    pub did: String,
    pub handle: Handle,
    pub granted_scopes: String,
    pub granted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControllerInfo {
    pub did: String,
    pub handle: Handle,
    pub granted_scopes: String,
    pub granted_at: DateTime<Utc>,
    pub is_active: bool,
}

pub async fn is_delegated_account(pool: &PgPool, did: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query_scalar!(
        r#"SELECT account_type::text = 'delegated' as "is_delegated!" FROM users WHERE did = $1"#,
        did
    )
    .fetch_optional(pool)
    .await?;

    Ok(result.unwrap_or(false))
}

pub async fn create_delegation(
    pool: &PgPool,
    delegated_did: &str,
    controller_did: &str,
    granted_scopes: &str,
    granted_by: &str,
) -> Result<Uuid, sqlx::Error> {
    let id = sqlx::query_scalar!(
        r#"
        INSERT INTO account_delegations (delegated_did, controller_did, granted_scopes, granted_by)
        VALUES ($1, $2, $3, $4)
        RETURNING id
        "#,
        delegated_did,
        controller_did,
        granted_scopes,
        granted_by
    )
    .fetch_one(pool)
    .await?;

    Ok(id)
}

pub async fn revoke_delegation(
    pool: &PgPool,
    delegated_did: &str,
    controller_did: &str,
    revoked_by: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        r#"
        UPDATE account_delegations
        SET revoked_at = NOW(), revoked_by = $1
        WHERE delegated_did = $2 AND controller_did = $3 AND revoked_at IS NULL
        "#,
        revoked_by,
        delegated_did,
        controller_did
    )
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn update_delegation_scopes(
    pool: &PgPool,
    delegated_did: &str,
    controller_did: &str,
    new_scopes: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        r#"
        UPDATE account_delegations
        SET granted_scopes = $1
        WHERE delegated_did = $2 AND controller_did = $3 AND revoked_at IS NULL
        "#,
        new_scopes,
        delegated_did,
        controller_did
    )
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn get_delegation(
    pool: &PgPool,
    delegated_did: &str,
    controller_did: &str,
) -> Result<Option<DelegationGrant>, sqlx::Error> {
    let grant = sqlx::query_as!(
        DelegationGrant,
        r#"
        SELECT id, delegated_did, controller_did, granted_scopes,
               granted_at, granted_by, revoked_at, revoked_by
        FROM account_delegations
        WHERE delegated_did = $1 AND controller_did = $2 AND revoked_at IS NULL
        "#,
        delegated_did,
        controller_did
    )
    .fetch_optional(pool)
    .await?;

    Ok(grant)
}

pub async fn get_delegations_for_account(
    pool: &PgPool,
    delegated_did: &str,
) -> Result<Vec<ControllerInfo>, sqlx::Error> {
    let controllers = sqlx::query_as!(
        ControllerInfo,
        r#"
        SELECT
            u.did,
            u.handle,
            d.granted_scopes,
            d.granted_at,
            (u.deactivated_at IS NULL AND u.takedown_ref IS NULL) as "is_active!"
        FROM account_delegations d
        JOIN users u ON u.did = d.controller_did
        WHERE d.delegated_did = $1 AND d.revoked_at IS NULL
        ORDER BY d.granted_at DESC
        "#,
        delegated_did
    )
    .fetch_all(pool)
    .await?;

    Ok(controllers)
}

pub async fn get_accounts_controlled_by(
    pool: &PgPool,
    controller_did: &str,
) -> Result<Vec<DelegatedAccountInfo>, sqlx::Error> {
    let accounts = sqlx::query_as!(
        DelegatedAccountInfo,
        r#"
        SELECT
            u.did,
            u.handle,
            d.granted_scopes,
            d.granted_at
        FROM account_delegations d
        JOIN users u ON u.did = d.delegated_did
        WHERE d.controller_did = $1
          AND d.revoked_at IS NULL
          AND u.deactivated_at IS NULL
          AND u.takedown_ref IS NULL
        ORDER BY d.granted_at DESC
        "#,
        controller_did
    )
    .fetch_all(pool)
    .await?;

    Ok(accounts)
}

pub async fn get_active_controllers_for_account(
    pool: &PgPool,
    delegated_did: &str,
) -> Result<Vec<ControllerInfo>, sqlx::Error> {
    let controllers = sqlx::query_as!(
        ControllerInfo,
        r#"
        SELECT
            u.did,
            u.handle,
            d.granted_scopes,
            d.granted_at,
            true as "is_active!"
        FROM account_delegations d
        JOIN users u ON u.did = d.controller_did
        WHERE d.delegated_did = $1
          AND d.revoked_at IS NULL
          AND u.deactivated_at IS NULL
          AND u.takedown_ref IS NULL
        ORDER BY d.granted_at DESC
        "#,
        delegated_did
    )
    .fetch_all(pool)
    .await?;

    Ok(controllers)
}

pub async fn count_active_controllers(
    pool: &PgPool,
    delegated_did: &str,
) -> Result<i64, sqlx::Error> {
    let count = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) as "count!"
        FROM account_delegations d
        JOIN users u ON u.did = d.controller_did
        WHERE d.delegated_did = $1
          AND d.revoked_at IS NULL
          AND u.deactivated_at IS NULL
          AND u.takedown_ref IS NULL
        "#,
        delegated_did
    )
    .fetch_one(pool)
    .await?;

    Ok(count)
}

pub async fn has_any_controllers(pool: &PgPool, did: &str) -> Result<bool, sqlx::Error> {
    let exists = sqlx::query_scalar!(
        r#"SELECT EXISTS(
            SELECT 1 FROM account_delegations
            WHERE delegated_did = $1 AND revoked_at IS NULL
        ) as "exists!""#,
        did
    )
    .fetch_one(pool)
    .await?;

    Ok(exists)
}

pub async fn controls_any_accounts(pool: &PgPool, did: &str) -> Result<bool, sqlx::Error> {
    let exists = sqlx::query_scalar!(
        r#"SELECT EXISTS(
            SELECT 1 FROM account_delegations
            WHERE controller_did = $1 AND revoked_at IS NULL
        ) as "exists!""#,
        did
    )
    .fetch_one(pool)
    .await?;

    Ok(exists)
}
