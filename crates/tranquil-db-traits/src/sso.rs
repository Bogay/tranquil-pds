use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tranquil_types::Did;
use uuid::Uuid;

use crate::DbError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "sso_provider_type", rename_all = "lowercase")]
pub enum SsoProviderType {
    Github,
    Discord,
    Google,
    Gitlab,
    Oidc,
    Apple,
}

impl SsoProviderType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Discord => "discord",
            Self::Google => "google",
            Self::Gitlab => "gitlab",
            Self::Oidc => "oidc",
            Self::Apple => "apple",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "github" => Some(Self::Github),
            "discord" => Some(Self::Discord),
            "google" => Some(Self::Google),
            "gitlab" => Some(Self::Gitlab),
            "oidc" => Some(Self::Oidc),
            "apple" => Some(Self::Apple),
            _ => None,
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Github => "GitHub",
            Self::Discord => "Discord",
            Self::Google => "Google",
            Self::Gitlab => "GitLab",
            Self::Oidc => "SSO",
            Self::Apple => "Apple",
        }
    }

    pub fn icon_name(&self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Discord => "discord",
            Self::Google => "google",
            Self::Gitlab => "gitlab",
            Self::Oidc => "oidc",
            Self::Apple => "apple",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExternalIdentity {
    pub id: Uuid,
    pub did: Did,
    pub provider: SsoProviderType,
    pub provider_user_id: String,
    pub provider_username: Option<String>,
    pub provider_email: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct SsoAuthState {
    pub state: String,
    pub request_uri: String,
    pub provider: SsoProviderType,
    pub action: String,
    pub nonce: Option<String>,
    pub code_verifier: Option<String>,
    pub did: Option<Did>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct SsoPendingRegistration {
    pub token: String,
    pub request_uri: String,
    pub provider: SsoProviderType,
    pub provider_user_id: String,
    pub provider_username: Option<String>,
    pub provider_email: Option<String>,
    pub provider_email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[async_trait]
pub trait SsoRepository: Send + Sync {
    async fn create_external_identity(
        &self,
        did: &Did,
        provider: SsoProviderType,
        provider_user_id: &str,
        provider_username: Option<&str>,
        provider_email: Option<&str>,
    ) -> Result<Uuid, DbError>;

    async fn get_external_identity_by_provider(
        &self,
        provider: SsoProviderType,
        provider_user_id: &str,
    ) -> Result<Option<ExternalIdentity>, DbError>;

    async fn get_external_identities_by_did(
        &self,
        did: &Did,
    ) -> Result<Vec<ExternalIdentity>, DbError>;

    async fn update_external_identity_login(
        &self,
        id: Uuid,
        provider_username: Option<&str>,
        provider_email: Option<&str>,
    ) -> Result<(), DbError>;

    async fn delete_external_identity(&self, id: Uuid, did: &Did) -> Result<bool, DbError>;

    #[allow(clippy::too_many_arguments)]
    async fn create_sso_auth_state(
        &self,
        state: &str,
        request_uri: &str,
        provider: SsoProviderType,
        action: &str,
        nonce: Option<&str>,
        code_verifier: Option<&str>,
        did: Option<&Did>,
    ) -> Result<(), DbError>;

    async fn consume_sso_auth_state(&self, state: &str) -> Result<Option<SsoAuthState>, DbError>;

    async fn cleanup_expired_sso_auth_states(&self) -> Result<u64, DbError>;

    #[allow(clippy::too_many_arguments)]
    async fn create_pending_registration(
        &self,
        token: &str,
        request_uri: &str,
        provider: SsoProviderType,
        provider_user_id: &str,
        provider_username: Option<&str>,
        provider_email: Option<&str>,
        provider_email_verified: bool,
    ) -> Result<(), DbError>;

    async fn get_pending_registration(
        &self,
        token: &str,
    ) -> Result<Option<SsoPendingRegistration>, DbError>;

    async fn consume_pending_registration(
        &self,
        token: &str,
    ) -> Result<Option<SsoPendingRegistration>, DbError>;

    async fn cleanup_expired_pending_registrations(&self) -> Result<u64, DbError>;
}
