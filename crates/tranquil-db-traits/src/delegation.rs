use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tranquil_types::{Did, Handle};
use uuid::Uuid;

use crate::DbError;
use crate::scope::DbScope;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationGrant {
    pub id: Uuid,
    pub delegated_did: Did,
    pub controller_did: Did,
    pub granted_scopes: DbScope,
    pub granted_at: DateTime<Utc>,
    pub granted_by: Did,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<Did>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegatedAccountInfo {
    pub did: Did,
    pub handle: Handle,
    pub granted_scopes: DbScope,
    pub granted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ControllerInfo {
    pub did: Did,
    pub handle: Option<Handle>,
    pub granted_scopes: DbScope,
    pub granted_at: DateTime<Utc>,
    pub is_active: bool,
    pub is_local: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[serde(rename_all = "camelCase")]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub delegated_did: Did,
    pub actor_did: Did,
    pub controller_did: Option<Did>,
    pub action_type: DelegationActionType,
    pub action_details: Option<serde_json::Value>,
    #[serde(skip_serializing)]
    pub ip_address: Option<String>,
    #[serde(skip_serializing)]
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[async_trait]
pub trait DelegationRepository: Send + Sync {
    async fn is_delegated_account(&self, did: &Did) -> Result<bool, DbError>;

    async fn create_delegation(
        &self,
        delegated_did: &Did,
        controller_did: &Did,
        granted_scopes: &DbScope,
        granted_by: &Did,
    ) -> Result<Uuid, DbError>;

    async fn revoke_delegation(
        &self,
        delegated_did: &Did,
        controller_did: &Did,
        revoked_by: &Did,
    ) -> Result<bool, DbError>;

    async fn update_delegation_scopes(
        &self,
        delegated_did: &Did,
        controller_did: &Did,
        new_scopes: &DbScope,
    ) -> Result<bool, DbError>;

    async fn get_delegation(
        &self,
        delegated_did: &Did,
        controller_did: &Did,
    ) -> Result<Option<DelegationGrant>, DbError>;

    async fn get_delegations_for_account(
        &self,
        delegated_did: &Did,
    ) -> Result<Vec<ControllerInfo>, DbError>;

    async fn get_accounts_controlled_by(
        &self,
        controller_did: &Did,
    ) -> Result<Vec<DelegatedAccountInfo>, DbError>;

    async fn count_active_controllers(&self, delegated_did: &Did) -> Result<i64, DbError>;

    async fn controls_any_accounts(&self, did: &Did) -> Result<bool, DbError>;

    #[allow(clippy::too_many_arguments)]
    async fn log_delegation_action(
        &self,
        delegated_did: &Did,
        actor_did: &Did,
        controller_did: Option<&Did>,
        action_type: DelegationActionType,
        action_details: Option<serde_json::Value>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Uuid, DbError>;

    async fn get_audit_log_for_account(
        &self,
        delegated_did: &Did,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditLogEntry>, DbError>;

    async fn count_audit_log_entries(&self, delegated_did: &Did) -> Result<i64, DbError>;
}
