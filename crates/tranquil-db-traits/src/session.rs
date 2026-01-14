use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tranquil_types::Did;
use uuid::Uuid;

use crate::DbError;

#[derive(Debug, Clone)]
pub struct SessionToken {
    pub id: i32,
    pub did: Did,
    pub access_jti: String,
    pub refresh_jti: String,
    pub access_expires_at: DateTime<Utc>,
    pub refresh_expires_at: DateTime<Utc>,
    pub legacy_login: bool,
    pub mfa_verified: bool,
    pub scope: Option<String>,
    pub controller_did: Option<Did>,
    pub app_password_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct SessionTokenCreate {
    pub did: Did,
    pub access_jti: String,
    pub refresh_jti: String,
    pub access_expires_at: DateTime<Utc>,
    pub refresh_expires_at: DateTime<Utc>,
    pub legacy_login: bool,
    pub mfa_verified: bool,
    pub scope: Option<String>,
    pub controller_did: Option<Did>,
    pub app_password_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SessionForRefresh {
    pub id: i32,
    pub did: Did,
    pub scope: Option<String>,
    pub controller_did: Option<Did>,
    pub key_bytes: Vec<u8>,
    pub encryption_version: i32,
}

#[derive(Debug, Clone)]
pub struct SessionListItem {
    pub id: i32,
    pub access_jti: String,
    pub created_at: DateTime<Utc>,
    pub refresh_expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct AppPasswordRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub privileged: bool,
    pub scopes: Option<String>,
    pub created_by_controller_did: Option<Did>,
}

#[derive(Debug, Clone)]
pub struct AppPasswordCreate {
    pub user_id: Uuid,
    pub name: String,
    pub password_hash: String,
    pub privileged: bool,
    pub scopes: Option<String>,
    pub created_by_controller_did: Option<Did>,
}

#[derive(Debug, Clone)]
pub struct SessionMfaStatus {
    pub legacy_login: bool,
    pub mfa_verified: bool,
    pub last_reauth_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub enum RefreshSessionResult {
    Success,
    TokenAlreadyUsed,
    ConcurrentRefresh,
}

#[derive(Debug, Clone)]
pub struct SessionRefreshData {
    pub old_refresh_jti: String,
    pub session_id: i32,
    pub new_access_jti: String,
    pub new_refresh_jti: String,
    pub new_access_expires_at: DateTime<Utc>,
    pub new_refresh_expires_at: DateTime<Utc>,
}

#[async_trait]
pub trait SessionRepository: Send + Sync {
    async fn create_session(&self, data: &SessionTokenCreate) -> Result<i32, DbError>;

    async fn get_session_by_access_jti(
        &self,
        access_jti: &str,
    ) -> Result<Option<SessionToken>, DbError>;

    async fn get_session_for_refresh(
        &self,
        refresh_jti: &str,
    ) -> Result<Option<SessionForRefresh>, DbError>;

    async fn update_session_tokens(
        &self,
        session_id: i32,
        new_access_jti: &str,
        new_refresh_jti: &str,
        new_access_expires_at: DateTime<Utc>,
        new_refresh_expires_at: DateTime<Utc>,
    ) -> Result<(), DbError>;

    async fn delete_session_by_access_jti(&self, access_jti: &str) -> Result<u64, DbError>;

    async fn delete_session_by_id(&self, session_id: i32) -> Result<u64, DbError>;

    async fn delete_sessions_by_did(&self, did: &Did) -> Result<u64, DbError>;

    async fn delete_sessions_by_did_except_jti(
        &self,
        did: &Did,
        except_jti: &str,
    ) -> Result<u64, DbError>;

    async fn list_sessions_by_did(&self, did: &Did) -> Result<Vec<SessionListItem>, DbError>;

    async fn get_session_access_jti_by_id(
        &self,
        session_id: i32,
        did: &Did,
    ) -> Result<Option<String>, DbError>;

    async fn delete_sessions_by_app_password(
        &self,
        did: &Did,
        app_password_name: &str,
    ) -> Result<u64, DbError>;

    async fn get_session_jtis_by_app_password(
        &self,
        did: &Did,
        app_password_name: &str,
    ) -> Result<Vec<String>, DbError>;

    async fn check_refresh_token_used(&self, refresh_jti: &str) -> Result<Option<i32>, DbError>;

    async fn mark_refresh_token_used(
        &self,
        refresh_jti: &str,
        session_id: i32,
    ) -> Result<bool, DbError>;

    async fn list_app_passwords(&self, user_id: Uuid) -> Result<Vec<AppPasswordRecord>, DbError>;

    async fn get_app_passwords_for_login(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<AppPasswordRecord>, DbError>;

    async fn get_app_password_by_name(
        &self,
        user_id: Uuid,
        name: &str,
    ) -> Result<Option<AppPasswordRecord>, DbError>;

    async fn create_app_password(&self, data: &AppPasswordCreate) -> Result<Uuid, DbError>;

    async fn delete_app_password(&self, user_id: Uuid, name: &str) -> Result<u64, DbError>;

    async fn delete_app_passwords_by_controller(
        &self,
        did: &Did,
        controller_did: &Did,
    ) -> Result<u64, DbError>;

    async fn get_last_reauth_at(&self, did: &Did) -> Result<Option<DateTime<Utc>>, DbError>;

    async fn update_last_reauth(&self, did: &Did) -> Result<DateTime<Utc>, DbError>;

    async fn get_session_mfa_status(&self, did: &Did) -> Result<Option<SessionMfaStatus>, DbError>;

    async fn update_mfa_verified(&self, did: &Did) -> Result<(), DbError>;

    async fn get_app_password_hashes_by_did(&self, did: &Did) -> Result<Vec<String>, DbError>;

    async fn refresh_session_atomic(
        &self,
        data: &SessionRefreshData,
    ) -> Result<RefreshSessionResult, DbError>;
}
