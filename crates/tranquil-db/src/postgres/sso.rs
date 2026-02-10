use async_trait::async_trait;
use chrono::Utc;
use sqlx::PgPool;
use tranquil_db_traits::{
    DbError, ExternalEmail, ExternalIdentity, ExternalUserId, ExternalUsername, SsoAction,
    SsoAuthState, SsoPendingRegistration, SsoProviderType, SsoRepository,
};
use tranquil_types::Did;
use uuid::Uuid;

use super::user::map_sqlx_error;

pub struct PostgresSsoRepository {
    pool: PgPool,
}

impl PostgresSsoRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SsoRepository for PostgresSsoRepository {
    async fn create_external_identity(
        &self,
        did: &Did,
        provider: SsoProviderType,
        provider_user_id: &str,
        provider_username: Option<&str>,
        provider_email: Option<&str>,
    ) -> Result<Uuid, DbError> {
        let id = sqlx::query_scalar!(
            r#"
            INSERT INTO external_identities (did, provider, provider_user_id, provider_username, provider_email)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
            "#,
            did.as_str(),
            provider as SsoProviderType,
            provider_user_id,
            provider_username,
            provider_email,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(id)
    }

    async fn get_external_identity_by_provider(
        &self,
        provider: SsoProviderType,
        provider_user_id: &str,
    ) -> Result<Option<ExternalIdentity>, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT id, did, provider as "provider: SsoProviderType", provider_user_id,
                   provider_username, provider_email, created_at, updated_at, last_login_at
            FROM external_identities
            WHERE provider = $1 AND provider_user_id = $2
            "#,
            provider as SsoProviderType,
            provider_user_id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        row.map(|r| {
            Ok(ExternalIdentity {
                id: r.id,
                did: r.did.parse().map_err(|_| DbError::CorruptData("DID"))?,
                provider: r.provider,
                provider_user_id: ExternalUserId::from(r.provider_user_id),
                provider_username: r.provider_username.map(ExternalUsername::from),
                provider_email: r.provider_email.map(ExternalEmail::from),
                created_at: r.created_at,
                updated_at: r.updated_at,
                last_login_at: r.last_login_at,
            })
        })
        .transpose()
    }

    async fn get_external_identities_by_did(
        &self,
        did: &Did,
    ) -> Result<Vec<ExternalIdentity>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, did, provider as "provider: SsoProviderType", provider_user_id,
                   provider_username, provider_email, created_at, updated_at, last_login_at
            FROM external_identities
            WHERE did = $1
            ORDER BY created_at ASC
            "#,
            did.as_str(),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        rows.into_iter()
            .map(|r| {
                Ok(ExternalIdentity {
                    id: r.id,
                    did: r.did.parse().map_err(|_| DbError::CorruptData("DID"))?,
                    provider: r.provider,
                    provider_user_id: ExternalUserId::from(r.provider_user_id),
                    provider_username: r.provider_username.map(ExternalUsername::from),
                    provider_email: r.provider_email.map(ExternalEmail::from),
                    created_at: r.created_at,
                    updated_at: r.updated_at,
                    last_login_at: r.last_login_at,
                })
            })
            .collect()
    }

    async fn update_external_identity_login(
        &self,
        id: Uuid,
        provider_username: Option<&str>,
        provider_email: Option<&str>,
    ) -> Result<(), DbError> {
        sqlx::query!(
            r#"
            UPDATE external_identities
            SET provider_username = COALESCE($2, provider_username),
                provider_email = COALESCE($3, provider_email),
                last_login_at = NOW(),
                updated_at = NOW()
            WHERE id = $1
            "#,
            id,
            provider_username,
            provider_email,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn delete_external_identity(&self, id: Uuid, did: &Did) -> Result<bool, DbError> {
        let result = sqlx::query!(
            r#"
            DELETE FROM external_identities
            WHERE id = $1 AND did = $2
            "#,
            id,
            did.as_str(),
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.rows_affected() > 0)
    }

    async fn create_sso_auth_state(
        &self,
        state: &str,
        request_uri: &str,
        provider: SsoProviderType,
        action: SsoAction,
        nonce: Option<&str>,
        code_verifier: Option<&str>,
        did: Option<&Did>,
    ) -> Result<(), DbError> {
        sqlx::query!(
            r#"
            INSERT INTO sso_auth_state (state, request_uri, provider, action, nonce, code_verifier, did)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            state,
            request_uri,
            provider as SsoProviderType,
            action.as_str(),
            nonce,
            code_verifier,
            did.map(|d| d.as_str()),
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn consume_sso_auth_state(&self, state: &str) -> Result<Option<SsoAuthState>, DbError> {
        let row = sqlx::query!(
            r#"
            DELETE FROM sso_auth_state
            WHERE state = $1 AND expires_at > NOW()
            RETURNING state, request_uri, provider as "provider: SsoProviderType", action,
                      nonce, code_verifier, did, created_at, expires_at
            "#,
            state,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        row.map(|r| {
            let action: SsoAction = r
                .action
                .parse()
                .map_err(|_| DbError::CorruptData("sso_action"))?;
            Ok(SsoAuthState {
                state: r.state,
                request_uri: r.request_uri,
                provider: r.provider,
                action,
                nonce: r.nonce,
                code_verifier: r.code_verifier,
                did: r
                    .did
                    .map(|d| d.parse::<Did>())
                    .transpose()
                    .map_err(|_| DbError::CorruptData("DID"))?,
                created_at: r.created_at,
                expires_at: r.expires_at,
            })
        })
        .transpose()
    }

    async fn cleanup_expired_sso_auth_states(&self) -> Result<u64, DbError> {
        let result = sqlx::query!(
            r#"
            DELETE FROM sso_auth_state
            WHERE expires_at < $1
            "#,
            Utc::now(),
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.rows_affected())
    }

    async fn create_pending_registration(
        &self,
        token: &str,
        request_uri: &str,
        provider: SsoProviderType,
        provider_user_id: &str,
        provider_username: Option<&str>,
        provider_email: Option<&str>,
        provider_email_verified: bool,
    ) -> Result<(), DbError> {
        sqlx::query!(
            r#"
            INSERT INTO sso_pending_registration (token, request_uri, provider, provider_user_id, provider_username, provider_email, provider_email_verified)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            token,
            request_uri,
            provider as SsoProviderType,
            provider_user_id,
            provider_username,
            provider_email,
            provider_email_verified,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn get_pending_registration(
        &self,
        token: &str,
    ) -> Result<Option<SsoPendingRegistration>, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT token, request_uri, provider as "provider: SsoProviderType",
                   provider_user_id, provider_username, provider_email, provider_email_verified,
                   created_at, expires_at
            FROM sso_pending_registration
            WHERE token = $1 AND expires_at > NOW()
            "#,
            token,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| SsoPendingRegistration {
            token: r.token,
            request_uri: r.request_uri,
            provider: r.provider,
            provider_user_id: ExternalUserId::from(r.provider_user_id),
            provider_username: r.provider_username.map(ExternalUsername::from),
            provider_email: r.provider_email.map(ExternalEmail::from),
            provider_email_verified: r.provider_email_verified,
            created_at: r.created_at,
            expires_at: r.expires_at,
        }))
    }

    async fn consume_pending_registration(
        &self,
        token: &str,
    ) -> Result<Option<SsoPendingRegistration>, DbError> {
        let row = sqlx::query!(
            r#"
            DELETE FROM sso_pending_registration
            WHERE token = $1 AND expires_at > NOW()
            RETURNING token, request_uri, provider as "provider: SsoProviderType",
                      provider_user_id, provider_username, provider_email, provider_email_verified,
                      created_at, expires_at
            "#,
            token,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| SsoPendingRegistration {
            token: r.token,
            request_uri: r.request_uri,
            provider: r.provider,
            provider_user_id: ExternalUserId::from(r.provider_user_id),
            provider_username: r.provider_username.map(ExternalUsername::from),
            provider_email: r.provider_email.map(ExternalEmail::from),
            provider_email_verified: r.provider_email_verified,
            created_at: r.created_at,
            expires_at: r.expires_at,
        }))
    }

    async fn cleanup_expired_pending_registrations(&self) -> Result<u64, DbError> {
        let result = sqlx::query!(
            r#"
            DELETE FROM sso_pending_registration
            WHERE expires_at < $1
            "#,
            Utc::now(),
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.rows_affected())
    }
}
