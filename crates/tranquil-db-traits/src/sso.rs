use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tranquil_types::Did;
use uuid::Uuid;

use crate::DbError;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExternalUserId(String);

impl ExternalUserId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl std::fmt::Display for ExternalUserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for ExternalUserId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<ExternalUserId> for String {
    fn from(id: ExternalUserId) -> Self {
        id.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExternalUsername(String);

impl ExternalUsername {
    pub fn new(username: impl Into<String>) -> Self {
        Self(username.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl std::fmt::Display for ExternalUsername {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for ExternalUsername {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<ExternalUsername> for String {
    fn from(username: ExternalUsername) -> Self {
        username.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExternalEmail(String);

impl ExternalEmail {
    pub fn new(email: impl Into<String>) -> Self {
        Self(email.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl std::fmt::Display for ExternalEmail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for ExternalEmail {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<ExternalEmail> for String {
    fn from(email: ExternalEmail) -> Self {
        email.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "sso_provider_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum SsoProviderType {
    Github,
    Discord,
    Google,
    Gitlab,
    Oidc,
    Apple,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum SsoAction {
    Login,
    Link,
    Register,
}

impl SsoAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Link => "link",
            Self::Register => "register",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "login" => Some(Self::Login),
            "link" => Some(Self::Link),
            "register" => Some(Self::Register),
            _ => None,
        }
    }
}

impl std::fmt::Display for SsoAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for SsoProviderType {
    type Err = InvalidSsoProviderType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(InvalidSsoProviderType)
    }
}

#[derive(Debug, Clone)]
pub struct InvalidSsoProviderType;

impl std::fmt::Display for InvalidSsoProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid SSO provider type")
    }
}

impl std::error::Error for InvalidSsoProviderType {}

impl std::str::FromStr for SsoAction {
    type Err = InvalidSsoAction;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(InvalidSsoAction)
    }
}

#[derive(Debug, Clone)]
pub struct InvalidSsoAction;

impl std::fmt::Display for InvalidSsoAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid SSO action")
    }
}

impl std::error::Error for InvalidSsoAction {}

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
        match s {
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
    pub provider_user_id: ExternalUserId,
    pub provider_username: Option<ExternalUsername>,
    pub provider_email: Option<ExternalEmail>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct SsoAuthState {
    pub state: String,
    pub request_uri: String,
    pub provider: SsoProviderType,
    pub action: SsoAction,
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
    pub provider_user_id: ExternalUserId,
    pub provider_username: Option<ExternalUsername>,
    pub provider_email: Option<ExternalEmail>,
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
        action: SsoAction,
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
