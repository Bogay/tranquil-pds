use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "delegation_action_type", rename_all = "snake_case")]
pub enum DelegationActionType {
    GrantCreated,
    GrantRevoked,
    ScopesModified,
    TokenIssued,
    RepoWrite,
    BlobUpload,
    AccountAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub delegated_did: String,
    pub actor_did: String,
    pub controller_did: Option<String>,
    pub action_type: DelegationActionType,
    pub action_details: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[allow(clippy::too_many_arguments)]
pub async fn log_delegation_action(
    pool: &PgPool,
    delegated_did: &str,
    actor_did: &str,
    controller_did: Option<&str>,
    action_type: DelegationActionType,
    action_details: Option<serde_json::Value>,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
) -> Result<Uuid, sqlx::Error> {
    let id = sqlx::query_scalar!(
        r#"
        INSERT INTO delegation_audit_log
            (delegated_did, actor_did, controller_did, action_type, action_details, ip_address, user_agent)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id
        "#,
        delegated_did,
        actor_did,
        controller_did,
        action_type as DelegationActionType,
        action_details,
        ip_address,
        user_agent
    )
    .fetch_one(pool)
    .await?;

    Ok(id)
}

pub async fn get_audit_log_for_account(
    pool: &PgPool,
    delegated_did: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<AuditLogEntry>, sqlx::Error> {
    let entries = sqlx::query_as!(
        AuditLogEntry,
        r#"
        SELECT
            id,
            delegated_did,
            actor_did,
            controller_did,
            action_type as "action_type: DelegationActionType",
            action_details,
            ip_address,
            user_agent,
            created_at
        FROM delegation_audit_log
        WHERE delegated_did = $1
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
        "#,
        delegated_did,
        limit,
        offset
    )
    .fetch_all(pool)
    .await?;

    Ok(entries)
}

pub async fn get_audit_log_by_controller(
    pool: &PgPool,
    controller_did: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<AuditLogEntry>, sqlx::Error> {
    let entries = sqlx::query_as!(
        AuditLogEntry,
        r#"
        SELECT
            id,
            delegated_did,
            actor_did,
            controller_did,
            action_type as "action_type: DelegationActionType",
            action_details,
            ip_address,
            user_agent,
            created_at
        FROM delegation_audit_log
        WHERE controller_did = $1
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
        "#,
        controller_did,
        limit,
        offset
    )
    .fetch_all(pool)
    .await?;

    Ok(entries)
}

pub async fn count_audit_log_entries(
    pool: &PgPool,
    delegated_did: &str,
) -> Result<i64, sqlx::Error> {
    let count = sqlx::query_scalar!(
        r#"SELECT COUNT(*) as "count!" FROM delegation_audit_log WHERE delegated_did = $1"#,
        delegated_did
    )
    .fetch_one(pool)
    .await?;

    Ok(count)
}
