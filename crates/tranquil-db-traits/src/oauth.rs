use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tranquil_oauth::{AuthorizedClientData, DeviceData, RequestData, TokenData};
use tranquil_types::{
    AuthorizationCode, ClientId, DPoPProofId, DeviceId, Did, Handle, RefreshToken, RequestId,
    TokenId,
};
use uuid::Uuid;

use crate::DbError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopePreference {
    pub scope: String,
    pub granted: bool,
}

#[derive(Debug, Clone)]
pub struct DeviceAccountRow {
    pub did: Did,
    pub handle: Handle,
    pub email: Option<String>,
    pub last_used_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct TwoFactorChallenge {
    pub id: Uuid,
    pub did: Did,
    pub request_uri: String,
    pub code: String,
    pub attempts: i32,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct TrustedDeviceRow {
    pub id: String,
    pub user_agent: Option<String>,
    pub friendly_name: Option<String>,
    pub trusted_at: Option<DateTime<Utc>>,
    pub trusted_until: Option<DateTime<Utc>>,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct DeviceTrustInfo {
    pub trusted_at: Option<DateTime<Utc>>,
    pub trusted_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct OAuthSessionListItem {
    pub id: i32,
    pub token_id: TokenId,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub client_id: ClientId,
}

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
    pub fn state(&self) -> &'static str {
        match self {
            Self::Valid { .. } => "valid",
            Self::InGracePeriod { .. } => "grace_period",
            Self::Used { .. } => "used",
            Self::Expired { .. } => "expired",
            Self::NotFound => "not_found",
        }
    }
}

#[async_trait]
pub trait OAuthRepository: Send + Sync {
    async fn create_token(&self, data: &TokenData) -> Result<i32, DbError>;
    async fn get_token_by_id(&self, token_id: &TokenId) -> Result<Option<TokenData>, DbError>;
    async fn get_token_by_refresh_token(
        &self,
        refresh_token: &RefreshToken,
    ) -> Result<Option<(i32, TokenData)>, DbError>;
    async fn get_token_by_previous_refresh_token(
        &self,
        refresh_token: &RefreshToken,
    ) -> Result<Option<(i32, TokenData)>, DbError>;
    async fn rotate_token(
        &self,
        old_db_id: i32,
        new_refresh_token: &RefreshToken,
        new_expires_at: DateTime<Utc>,
    ) -> Result<(), DbError>;
    async fn check_refresh_token_used(
        &self,
        refresh_token: &RefreshToken,
    ) -> Result<Option<i32>, DbError>;
    async fn delete_token(&self, token_id: &TokenId) -> Result<(), DbError>;
    async fn delete_token_family(&self, db_id: i32) -> Result<(), DbError>;
    async fn list_tokens_for_user(&self, did: &Did) -> Result<Vec<TokenData>, DbError>;
    async fn count_tokens_for_user(&self, did: &Did) -> Result<i64, DbError>;
    async fn delete_oldest_tokens_for_user(
        &self,
        did: &Did,
        keep_count: i64,
    ) -> Result<u64, DbError>;
    async fn revoke_tokens_for_client(
        &self,
        did: &Did,
        client_id: &ClientId,
    ) -> Result<u64, DbError>;
    async fn revoke_tokens_for_controller(
        &self,
        delegated_did: &Did,
        controller_did: &Did,
    ) -> Result<u64, DbError>;

    async fn create_authorization_request(
        &self,
        request_id: &RequestId,
        data: &RequestData,
    ) -> Result<(), DbError>;
    async fn get_authorization_request(
        &self,
        request_id: &RequestId,
    ) -> Result<Option<RequestData>, DbError>;
    async fn set_authorization_did(
        &self,
        request_id: &RequestId,
        did: &Did,
        device_id: Option<&DeviceId>,
    ) -> Result<(), DbError>;
    async fn update_authorization_request(
        &self,
        request_id: &RequestId,
        did: &Did,
        device_id: Option<&DeviceId>,
        code: &AuthorizationCode,
    ) -> Result<(), DbError>;
    async fn consume_authorization_request_by_code(
        &self,
        code: &AuthorizationCode,
    ) -> Result<Option<RequestData>, DbError>;
    async fn delete_authorization_request(&self, request_id: &RequestId) -> Result<(), DbError>;
    async fn delete_expired_authorization_requests(&self) -> Result<u64, DbError>;
    async fn mark_request_authenticated(
        &self,
        request_id: &RequestId,
        did: &Did,
        device_id: Option<&DeviceId>,
    ) -> Result<(), DbError>;
    async fn update_request_scope(
        &self,
        request_id: &RequestId,
        scope: &str,
    ) -> Result<(), DbError>;
    async fn set_controller_did(
        &self,
        request_id: &RequestId,
        controller_did: &Did,
    ) -> Result<(), DbError>;
    async fn set_request_did(&self, request_id: &RequestId, did: &Did) -> Result<(), DbError>;

    async fn create_device(&self, device_id: &DeviceId, data: &DeviceData) -> Result<(), DbError>;
    async fn get_device(&self, device_id: &DeviceId) -> Result<Option<DeviceData>, DbError>;
    async fn update_device_last_seen(&self, device_id: &DeviceId) -> Result<(), DbError>;
    async fn delete_device(&self, device_id: &DeviceId) -> Result<(), DbError>;
    async fn upsert_account_device(&self, did: &Did, device_id: &DeviceId) -> Result<(), DbError>;
    async fn get_device_accounts(
        &self,
        device_id: &DeviceId,
    ) -> Result<Vec<DeviceAccountRow>, DbError>;
    async fn verify_account_on_device(
        &self,
        device_id: &DeviceId,
        did: &Did,
    ) -> Result<bool, DbError>;

    async fn check_and_record_dpop_jti(&self, jti: &DPoPProofId) -> Result<bool, DbError>;
    async fn cleanup_expired_dpop_jtis(&self, max_age_secs: i64) -> Result<u64, DbError>;

    async fn create_2fa_challenge(
        &self,
        did: &Did,
        request_uri: &RequestId,
    ) -> Result<TwoFactorChallenge, DbError>;
    async fn get_2fa_challenge(
        &self,
        request_uri: &RequestId,
    ) -> Result<Option<TwoFactorChallenge>, DbError>;
    async fn increment_2fa_attempts(&self, id: Uuid) -> Result<i32, DbError>;
    async fn delete_2fa_challenge(&self, id: Uuid) -> Result<(), DbError>;
    async fn delete_2fa_challenge_by_request_uri(
        &self,
        request_uri: &RequestId,
    ) -> Result<(), DbError>;
    async fn cleanup_expired_2fa_challenges(&self) -> Result<u64, DbError>;
    async fn check_user_2fa_enabled(&self, did: &Did) -> Result<bool, DbError>;

    async fn get_scope_preferences(
        &self,
        did: &Did,
        client_id: &ClientId,
    ) -> Result<Vec<ScopePreference>, DbError>;
    async fn upsert_scope_preferences(
        &self,
        did: &Did,
        client_id: &ClientId,
        prefs: &[ScopePreference],
    ) -> Result<(), DbError>;
    async fn delete_scope_preferences(
        &self,
        did: &Did,
        client_id: &ClientId,
    ) -> Result<(), DbError>;

    async fn upsert_authorized_client(
        &self,
        did: &Did,
        client_id: &ClientId,
        data: &AuthorizedClientData,
    ) -> Result<(), DbError>;
    async fn get_authorized_client(
        &self,
        did: &Did,
        client_id: &ClientId,
    ) -> Result<Option<AuthorizedClientData>, DbError>;

    async fn list_trusted_devices(&self, did: &Did) -> Result<Vec<TrustedDeviceRow>, DbError>;
    async fn get_device_trust_info(
        &self,
        device_id: &DeviceId,
        did: &Did,
    ) -> Result<Option<DeviceTrustInfo>, DbError>;
    async fn device_belongs_to_user(
        &self,
        device_id: &DeviceId,
        did: &Did,
    ) -> Result<bool, DbError>;
    async fn revoke_device_trust(&self, device_id: &DeviceId) -> Result<(), DbError>;
    async fn update_device_friendly_name(
        &self,
        device_id: &DeviceId,
        friendly_name: Option<&str>,
    ) -> Result<(), DbError>;
    async fn trust_device(
        &self,
        device_id: &DeviceId,
        trusted_at: DateTime<Utc>,
        trusted_until: DateTime<Utc>,
    ) -> Result<(), DbError>;
    async fn extend_device_trust(
        &self,
        device_id: &DeviceId,
        trusted_until: DateTime<Utc>,
    ) -> Result<(), DbError>;

    async fn list_sessions_by_did(&self, did: &Did) -> Result<Vec<OAuthSessionListItem>, DbError>;
    async fn delete_session_by_id(&self, session_id: i32, did: &Did) -> Result<u64, DbError>;
    async fn delete_sessions_by_did(&self, did: &Did) -> Result<u64, DbError>;
    async fn delete_sessions_by_did_except(
        &self,
        did: &Did,
        except_token_id: &TokenId,
    ) -> Result<u64, DbError>;
}
