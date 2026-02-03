use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tranquil_types::{CidLink, Did, Handle};
use uuid::Uuid;

use crate::DbError;
use crate::invite_code::{InviteCodeError, ValidatedInviteCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InviteCodeSortOrder {
    #[default]
    Recent,
    Usage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum InviteCodeState {
    #[default]
    Active,
    Disabled,
}

impl InviteCodeState {
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn is_disabled(self) -> bool {
        matches!(self, Self::Disabled)
    }
}

impl From<bool> for InviteCodeState {
    fn from(disabled: bool) -> Self {
        if disabled {
            Self::Disabled
        } else {
            Self::Active
        }
    }
}

impl From<Option<bool>> for InviteCodeState {
    fn from(disabled: Option<bool>) -> Self {
        Self::from(disabled.unwrap_or(false))
    }
}

impl From<InviteCodeState> for bool {
    fn from(state: InviteCodeState) -> Self {
        matches!(state, InviteCodeState::Disabled)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "lowercase")]
#[sqlx(type_name = "comms_channel", rename_all = "snake_case")]
pub enum CommsChannel {
    Email,
    Discord,
    Telegram,
    Signal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "comms_type", rename_all = "snake_case")]
pub enum CommsType {
    Welcome,
    EmailVerification,
    PasswordReset,
    EmailUpdate,
    AccountDeletion,
    AdminEmail,
    PlcOperation,
    TwoFactorCode,
    PasskeyRecovery,
    LegacyLoginAlert,
    MigrationVerification,
    ChannelVerification,
    ChannelVerified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "comms_status", rename_all = "snake_case")]
pub enum CommsStatus {
    Pending,
    Processing,
    Sent,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedComms {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub channel: CommsChannel,
    pub comms_type: CommsType,
    pub status: CommsStatus,
    pub recipient: String,
    pub subject: Option<String>,
    pub body: String,
    pub metadata: Option<serde_json::Value>,
    pub attempts: i32,
    pub max_attempts: i32,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub scheduled_for: DateTime<Utc>,
    pub processed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteCodeInfo {
    pub code: String,
    pub available_uses: i32,
    pub state: InviteCodeState,
    pub for_account: Option<Did>,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<Did>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteCodeUse {
    pub code: String,
    pub used_by_did: Did,
    pub used_by_handle: Option<Handle>,
    pub used_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteCodeRow {
    pub code: String,
    pub available_uses: i32,
    pub disabled: Option<bool>,
    pub created_by_user: Uuid,
    pub created_at: DateTime<Utc>,
}

impl InviteCodeRow {
    pub fn state(&self) -> InviteCodeState {
        InviteCodeState::from(self.disabled)
    }
}

#[derive(Debug, Clone)]
pub struct ReservedSigningKey {
    pub id: Uuid,
    pub private_key_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DeletionRequest {
    pub did: Did,
    pub expires_at: DateTime<Utc>,
}

#[async_trait]
pub trait InfraRepository: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    async fn enqueue_comms(
        &self,
        user_id: Option<Uuid>,
        channel: CommsChannel,
        comms_type: CommsType,
        recipient: &str,
        subject: Option<&str>,
        body: &str,
        metadata: Option<serde_json::Value>,
    ) -> Result<Uuid, DbError>;

    async fn fetch_pending_comms(
        &self,
        now: DateTime<Utc>,
        batch_size: i64,
    ) -> Result<Vec<QueuedComms>, DbError>;

    async fn mark_comms_sent(&self, id: Uuid) -> Result<(), DbError>;

    async fn mark_comms_failed(&self, id: Uuid, error: &str) -> Result<(), DbError>;

    async fn create_invite_code(
        &self,
        code: &str,
        use_count: i32,
        for_account: Option<&Did>,
    ) -> Result<bool, DbError>;

    async fn create_invite_codes_batch(
        &self,
        codes: &[String],
        use_count: i32,
        created_by_user: Uuid,
        for_account: Option<&Did>,
    ) -> Result<(), DbError>;

    async fn get_invite_code_available_uses(&self, code: &str) -> Result<Option<i32>, DbError>;

    async fn validate_invite_code<'a>(
        &self,
        code: &'a str,
    ) -> Result<ValidatedInviteCode<'a>, InviteCodeError>;

    async fn decrement_invite_code_uses(
        &self,
        code: &ValidatedInviteCode<'_>,
    ) -> Result<(), DbError>;

    async fn record_invite_code_use(
        &self,
        code: &ValidatedInviteCode<'_>,
        used_by_user: Uuid,
    ) -> Result<(), DbError>;

    async fn get_invite_codes_for_account(
        &self,
        for_account: &Did,
    ) -> Result<Vec<InviteCodeInfo>, DbError>;

    async fn get_invite_code_uses(&self, code: &str) -> Result<Vec<InviteCodeUse>, DbError>;

    async fn disable_invite_codes_by_code(&self, codes: &[String]) -> Result<(), DbError>;

    async fn disable_invite_codes_by_account(&self, accounts: &[Did]) -> Result<(), DbError>;

    async fn list_invite_codes(
        &self,
        cursor: Option<&str>,
        limit: i64,
        sort: InviteCodeSortOrder,
    ) -> Result<Vec<InviteCodeRow>, DbError>;

    async fn get_user_dids_by_ids(&self, user_ids: &[Uuid]) -> Result<Vec<(Uuid, Did)>, DbError>;

    async fn get_invite_code_uses_batch(
        &self,
        codes: &[String],
    ) -> Result<Vec<InviteCodeUse>, DbError>;

    async fn get_invites_created_by_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<InviteCodeInfo>, DbError>;

    async fn get_invite_code_info(&self, code: &str) -> Result<Option<InviteCodeInfo>, DbError>;

    async fn get_invite_codes_by_users(
        &self,
        user_ids: &[Uuid],
    ) -> Result<Vec<(Uuid, InviteCodeInfo)>, DbError>;

    async fn get_invite_code_used_by_user(&self, user_id: Uuid) -> Result<Option<String>, DbError>;

    async fn delete_invite_code_uses_by_user(&self, user_id: Uuid) -> Result<(), DbError>;

    async fn delete_invite_codes_by_user(&self, user_id: Uuid) -> Result<(), DbError>;

    async fn reserve_signing_key(
        &self,
        did: Option<&Did>,
        public_key_did_key: &str,
        private_key_bytes: &[u8],
        expires_at: DateTime<Utc>,
    ) -> Result<Uuid, DbError>;

    async fn get_reserved_signing_key(
        &self,
        public_key_did_key: &str,
    ) -> Result<Option<ReservedSigningKey>, DbError>;

    async fn mark_signing_key_used(&self, key_id: Uuid) -> Result<(), DbError>;

    async fn create_deletion_request(
        &self,
        token: &str,
        did: &Did,
        expires_at: DateTime<Utc>,
    ) -> Result<(), DbError>;

    async fn get_deletion_request(&self, token: &str) -> Result<Option<DeletionRequest>, DbError>;

    async fn delete_deletion_request(&self, token: &str) -> Result<(), DbError>;

    async fn delete_deletion_requests_by_did(&self, did: &Did) -> Result<(), DbError>;

    async fn upsert_account_preference(
        &self,
        user_id: Uuid,
        name: &str,
        value_json: serde_json::Value,
    ) -> Result<(), DbError>;

    async fn insert_account_preference_if_not_exists(
        &self,
        user_id: Uuid,
        name: &str,
        value_json: serde_json::Value,
    ) -> Result<(), DbError>;

    async fn get_server_config(&self, key: &str) -> Result<Option<String>, DbError>;

    async fn health_check(&self) -> Result<bool, DbError>;

    async fn insert_report(
        &self,
        id: i64,
        reason_type: &str,
        reason: Option<&str>,
        subject_json: serde_json::Value,
        reported_by_did: &Did,
        created_at: DateTime<Utc>,
    ) -> Result<(), DbError>;

    async fn delete_plc_tokens_for_user(&self, user_id: Uuid) -> Result<(), DbError>;

    async fn insert_plc_token(
        &self,
        user_id: Uuid,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), DbError>;

    async fn get_plc_token_expiry(
        &self,
        user_id: Uuid,
        token: &str,
    ) -> Result<Option<DateTime<Utc>>, DbError>;

    async fn delete_plc_token(&self, user_id: Uuid, token: &str) -> Result<(), DbError>;

    async fn get_account_preferences(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<(String, serde_json::Value)>, DbError>;

    async fn replace_namespace_preferences(
        &self,
        user_id: Uuid,
        namespace: &str,
        preferences: Vec<(String, serde_json::Value)>,
    ) -> Result<(), DbError>;

    async fn get_notification_history(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<NotificationHistoryRow>, DbError>;

    async fn get_server_configs(&self, keys: &[&str]) -> Result<Vec<(String, String)>, DbError>;

    async fn upsert_server_config(&self, key: &str, value: &str) -> Result<(), DbError>;

    async fn delete_server_config(&self, key: &str) -> Result<(), DbError>;

    async fn get_blob_storage_key_by_cid(&self, cid: &CidLink) -> Result<Option<String>, DbError>;

    async fn delete_blob_by_cid(&self, cid: &CidLink) -> Result<(), DbError>;

    async fn get_admin_account_info_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<AdminAccountInfo>, DbError>;

    async fn get_admin_account_infos_by_dids(
        &self,
        dids: &[Did],
    ) -> Result<Vec<AdminAccountInfo>, DbError>;

    async fn get_invite_code_uses_by_users(
        &self,
        user_ids: &[Uuid],
    ) -> Result<Vec<(Uuid, String)>, DbError>;
}

#[derive(Debug, Clone)]
pub struct NotificationHistoryRow {
    pub created_at: DateTime<Utc>,
    pub channel: CommsChannel,
    pub comms_type: CommsType,
    pub status: CommsStatus,
    pub subject: Option<String>,
    pub body: String,
}

#[derive(Debug, Clone)]
pub struct AdminAccountInfo {
    pub id: Uuid,
    pub did: Did,
    pub handle: Handle,
    pub email: Option<String>,
    pub created_at: DateTime<Utc>,
    pub invites_disabled: bool,
    pub email_verified: bool,
    pub deactivated_at: Option<DateTime<Utc>>,
}
