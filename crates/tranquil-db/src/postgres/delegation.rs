use async_trait::async_trait;
use sqlx::PgPool;
use tranquil_db_traits::{
    AuditLogEntry, ControllerInfo, DbError, DelegatedAccountInfo, DelegationActionType,
    DelegationGrant, DelegationRepository,
};
use tranquil_types::Did;
use uuid::Uuid;

use super::user::map_sqlx_error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "delegation_action_type", rename_all = "snake_case")]
pub enum PgDelegationActionType {
    GrantCreated,
    GrantRevoked,
    ScopesModified,
    TokenIssued,
    RepoWrite,
    BlobUpload,
    AccountAction,
}

impl From<DelegationActionType> for PgDelegationActionType {
    fn from(t: DelegationActionType) -> Self {
        match t {
            DelegationActionType::GrantCreated => Self::GrantCreated,
            DelegationActionType::GrantRevoked => Self::GrantRevoked,
            DelegationActionType::ScopesModified => Self::ScopesModified,
            DelegationActionType::TokenIssued => Self::TokenIssued,
            DelegationActionType::RepoWrite => Self::RepoWrite,
            DelegationActionType::BlobUpload => Self::BlobUpload,
            DelegationActionType::AccountAction => Self::AccountAction,
        }
    }
}

impl From<PgDelegationActionType> for DelegationActionType {
    fn from(t: PgDelegationActionType) -> Self {
        match t {
            PgDelegationActionType::GrantCreated => Self::GrantCreated,
            PgDelegationActionType::GrantRevoked => Self::GrantRevoked,
            PgDelegationActionType::ScopesModified => Self::ScopesModified,
            PgDelegationActionType::TokenIssued => Self::TokenIssued,
            PgDelegationActionType::RepoWrite => Self::RepoWrite,
            PgDelegationActionType::BlobUpload => Self::BlobUpload,
            PgDelegationActionType::AccountAction => Self::AccountAction,
        }
    }
}

pub struct PostgresDelegationRepository {
    pool: PgPool,
}

impl PostgresDelegationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DelegationRepository for PostgresDelegationRepository {
    async fn is_delegated_account(&self, did: &Did) -> Result<bool, DbError> {
        let result = sqlx::query_scalar!(
            r#"SELECT account_type::text = 'delegated' as "is_delegated!" FROM users WHERE did = $1"#,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.unwrap_or(false))
    }

    async fn create_delegation(
        &self,
        delegated_did: &Did,
        controller_did: &Did,
        granted_scopes: &str,
        granted_by: &Did,
    ) -> Result<Uuid, DbError> {
        let id = sqlx::query_scalar!(
            r#"
            INSERT INTO account_delegations (delegated_did, controller_did, granted_scopes, granted_by)
            VALUES ($1, $2, $3, $4)
            RETURNING id
            "#,
            delegated_did.as_str(),
            controller_did.as_str(),
            granted_scopes,
            granted_by.as_str()
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(id)
    }

    async fn revoke_delegation(
        &self,
        delegated_did: &Did,
        controller_did: &Did,
        revoked_by: &Did,
    ) -> Result<bool, DbError> {
        let result = sqlx::query!(
            r#"
            UPDATE account_delegations
            SET revoked_at = NOW(), revoked_by = $1
            WHERE delegated_did = $2 AND controller_did = $3 AND revoked_at IS NULL
            "#,
            revoked_by.as_str(),
            delegated_did.as_str(),
            controller_did.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.rows_affected() > 0)
    }

    async fn update_delegation_scopes(
        &self,
        delegated_did: &Did,
        controller_did: &Did,
        new_scopes: &str,
    ) -> Result<bool, DbError> {
        let result = sqlx::query!(
            r#"
            UPDATE account_delegations
            SET granted_scopes = $1
            WHERE delegated_did = $2 AND controller_did = $3 AND revoked_at IS NULL
            "#,
            new_scopes,
            delegated_did.as_str(),
            controller_did.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.rows_affected() > 0)
    }

    async fn get_delegation(
        &self,
        delegated_did: &Did,
        controller_did: &Did,
    ) -> Result<Option<DelegationGrant>, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT id, delegated_did, controller_did, granted_scopes,
                   granted_at, granted_by, revoked_at, revoked_by
            FROM account_delegations
            WHERE delegated_did = $1 AND controller_did = $2 AND revoked_at IS NULL
            "#,
            delegated_did.as_str(),
            controller_did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| DelegationGrant {
            id: r.id,
            delegated_did: r.delegated_did.into(),
            controller_did: r.controller_did.into(),
            granted_scopes: r.granted_scopes,
            granted_at: r.granted_at,
            granted_by: r.granted_by.into(),
            revoked_at: r.revoked_at,
            revoked_by: r.revoked_by.map(Into::into),
        }))
    }

    async fn get_delegations_for_account(
        &self,
        delegated_did: &Did,
    ) -> Result<Vec<ControllerInfo>, DbError> {
        let rows = sqlx::query!(
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
            delegated_did.as_str()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(rows
            .into_iter()
            .map(|r| ControllerInfo {
                did: r.did.into(),
                handle: r.handle.into(),
                granted_scopes: r.granted_scopes,
                granted_at: r.granted_at,
                is_active: r.is_active,
            })
            .collect())
    }

    async fn get_accounts_controlled_by(
        &self,
        controller_did: &Did,
    ) -> Result<Vec<DelegatedAccountInfo>, DbError> {
        let rows = sqlx::query!(
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
            controller_did.as_str()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(rows
            .into_iter()
            .map(|r| DelegatedAccountInfo {
                did: r.did.into(),
                handle: r.handle.into(),
                granted_scopes: r.granted_scopes,
                granted_at: r.granted_at,
            })
            .collect())
    }

    async fn get_active_controllers_for_account(
        &self,
        delegated_did: &Did,
    ) -> Result<Vec<ControllerInfo>, DbError> {
        let rows = sqlx::query!(
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
            delegated_did.as_str()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(rows
            .into_iter()
            .map(|r| ControllerInfo {
                did: r.did.into(),
                handle: r.handle.into(),
                granted_scopes: r.granted_scopes,
                granted_at: r.granted_at,
                is_active: r.is_active,
            })
            .collect())
    }

    async fn count_active_controllers(&self, delegated_did: &Did) -> Result<i64, DbError> {
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
            delegated_did.as_str()
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(count)
    }

    async fn has_any_controllers(&self, did: &Did) -> Result<bool, DbError> {
        let exists = sqlx::query_scalar!(
            r#"SELECT EXISTS(
                SELECT 1 FROM account_delegations
                WHERE delegated_did = $1 AND revoked_at IS NULL
            ) as "exists!""#,
            did.as_str()
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(exists)
    }

    async fn controls_any_accounts(&self, did: &Did) -> Result<bool, DbError> {
        let exists = sqlx::query_scalar!(
            r#"SELECT EXISTS(
                SELECT 1 FROM account_delegations
                WHERE controller_did = $1 AND revoked_at IS NULL
            ) as "exists!""#,
            did.as_str()
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(exists)
    }

    async fn log_delegation_action(
        &self,
        delegated_did: &Did,
        actor_did: &Did,
        controller_did: Option<&Did>,
        action_type: DelegationActionType,
        action_details: Option<serde_json::Value>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Uuid, DbError> {
        let pg_action_type: PgDelegationActionType = action_type.into();
        let controller_did_str = controller_did.map(|d| d.as_str());
        let id = sqlx::query_scalar!(
            r#"
            INSERT INTO delegation_audit_log
                (delegated_did, actor_did, controller_did, action_type, action_details, ip_address, user_agent)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id
            "#,
            delegated_did.as_str(),
            actor_did.as_str(),
            controller_did_str,
            pg_action_type as PgDelegationActionType,
            action_details,
            ip_address,
            user_agent
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(id)
    }

    async fn get_audit_log_for_account(
        &self,
        delegated_did: &Did,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditLogEntry>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT
                id,
                delegated_did,
                actor_did,
                controller_did,
                action_type as "action_type: PgDelegationActionType",
                action_details,
                ip_address,
                user_agent,
                created_at
            FROM delegation_audit_log
            WHERE delegated_did = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
            delegated_did.as_str(),
            limit,
            offset
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(rows
            .into_iter()
            .map(|r| AuditLogEntry {
                id: r.id,
                delegated_did: r.delegated_did.into(),
                actor_did: r.actor_did.into(),
                controller_did: r.controller_did.map(Into::into),
                action_type: r.action_type.into(),
                action_details: r.action_details,
                ip_address: r.ip_address,
                user_agent: r.user_agent,
                created_at: r.created_at,
            })
            .collect())
    }

    async fn get_audit_log_by_controller(
        &self,
        controller_did: &Did,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditLogEntry>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT
                id,
                delegated_did,
                actor_did,
                controller_did,
                action_type as "action_type: PgDelegationActionType",
                action_details,
                ip_address,
                user_agent,
                created_at
            FROM delegation_audit_log
            WHERE controller_did = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
            controller_did.as_str(),
            limit,
            offset
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(rows
            .into_iter()
            .map(|r| AuditLogEntry {
                id: r.id,
                delegated_did: r.delegated_did.into(),
                actor_did: r.actor_did.into(),
                controller_did: r.controller_did.map(Into::into),
                action_type: r.action_type.into(),
                action_details: r.action_details,
                ip_address: r.ip_address,
                user_agent: r.user_agent,
                created_at: r.created_at,
            })
            .collect())
    }

    async fn count_audit_log_entries(&self, delegated_did: &Did) -> Result<i64, DbError> {
        let count = sqlx::query_scalar!(
            r#"SELECT COUNT(*) as "count!" FROM delegation_audit_log WHERE delegated_did = $1"#,
            delegated_did.as_str()
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(count)
    }
}
