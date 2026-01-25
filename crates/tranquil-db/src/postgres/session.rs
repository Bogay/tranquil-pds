use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tranquil_db_traits::{
    AppPasswordCreate, AppPasswordPrivilege, AppPasswordRecord, DbError, LoginType,
    RefreshSessionResult, SessionForRefresh, SessionId, SessionListItem, SessionMfaStatus,
    SessionRefreshData, SessionRepository, SessionToken, SessionTokenCreate,
};
use tranquil_types::Did;
use uuid::Uuid;

use super::user::map_sqlx_error;

pub struct PostgresSessionRepository {
    pool: PgPool,
}

impl PostgresSessionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SessionRepository for PostgresSessionRepository {
    async fn create_session(&self, data: &SessionTokenCreate) -> Result<SessionId, DbError> {
        let row = sqlx::query!(
            r#"
            INSERT INTO session_tokens
                (did, access_jti, refresh_jti, access_expires_at, refresh_expires_at,
                 legacy_login, mfa_verified, scope, controller_did, app_password_name)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id
            "#,
            data.did.as_str(),
            data.access_jti,
            data.refresh_jti,
            data.access_expires_at,
            data.refresh_expires_at,
            bool::from(data.login_type),
            data.mfa_verified,
            data.scope,
            data.controller_did.as_ref().map(|d| d.as_str()),
            data.app_password_name
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(SessionId::new(row.id))
    }

    async fn get_session_by_access_jti(
        &self,
        access_jti: &str,
    ) -> Result<Option<SessionToken>, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT id, did, access_jti, refresh_jti, access_expires_at, refresh_expires_at,
                   legacy_login, mfa_verified, scope, controller_did, app_password_name,
                   created_at, updated_at
            FROM session_tokens
            WHERE access_jti = $1
            "#,
            access_jti
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| SessionToken {
            id: SessionId::new(r.id),
            did: Did::from(r.did),
            access_jti: r.access_jti,
            refresh_jti: r.refresh_jti,
            access_expires_at: r.access_expires_at,
            refresh_expires_at: r.refresh_expires_at,
            login_type: LoginType::from(r.legacy_login),
            mfa_verified: r.mfa_verified,
            scope: r.scope,
            controller_did: r.controller_did.map(Did::from),
            app_password_name: r.app_password_name,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
    }

    async fn get_session_for_refresh(
        &self,
        refresh_jti: &str,
    ) -> Result<Option<SessionForRefresh>, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT st.id, st.did, st.scope, st.controller_did, k.key_bytes, k.encryption_version
            FROM session_tokens st
            JOIN users u ON st.did = u.did
            JOIN user_keys k ON u.id = k.user_id
            WHERE st.refresh_jti = $1 AND st.refresh_expires_at > NOW()
            "#,
            refresh_jti
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| SessionForRefresh {
            id: SessionId::new(r.id),
            did: Did::from(r.did),
            scope: r.scope,
            controller_did: r.controller_did.map(Did::from),
            key_bytes: r.key_bytes,
            encryption_version: r.encryption_version.unwrap_or(0),
        }))
    }

    async fn update_session_tokens(
        &self,
        session_id: SessionId,
        new_access_jti: &str,
        new_refresh_jti: &str,
        new_access_expires_at: DateTime<Utc>,
        new_refresh_expires_at: DateTime<Utc>,
    ) -> Result<(), DbError> {
        sqlx::query!(
            r#"
            UPDATE session_tokens
            SET access_jti = $1, refresh_jti = $2, access_expires_at = $3,
                refresh_expires_at = $4, updated_at = NOW()
            WHERE id = $5
            "#,
            new_access_jti,
            new_refresh_jti,
            new_access_expires_at,
            new_refresh_expires_at,
            session_id.as_i32()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn delete_session_by_access_jti(&self, access_jti: &str) -> Result<u64, DbError> {
        let result = sqlx::query!(
            "DELETE FROM session_tokens WHERE access_jti = $1",
            access_jti
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.rows_affected())
    }

    async fn delete_session_by_id(&self, session_id: SessionId) -> Result<u64, DbError> {
        let result = sqlx::query!(
            "DELETE FROM session_tokens WHERE id = $1",
            session_id.as_i32()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.rows_affected())
    }

    async fn delete_sessions_by_did(&self, did: &Did) -> Result<u64, DbError> {
        let result = sqlx::query!("DELETE FROM session_tokens WHERE did = $1", did.as_str())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(result.rows_affected())
    }

    async fn delete_sessions_by_did_except_jti(
        &self,
        did: &Did,
        except_jti: &str,
    ) -> Result<u64, DbError> {
        let result = sqlx::query!(
            "DELETE FROM session_tokens WHERE did = $1 AND access_jti != $2",
            did.as_str(),
            except_jti
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.rows_affected())
    }

    async fn list_sessions_by_did(&self, did: &Did) -> Result<Vec<SessionListItem>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, access_jti, created_at, refresh_expires_at
            FROM session_tokens
            WHERE did = $1 AND refresh_expires_at > NOW()
            ORDER BY created_at DESC
            "#,
            did.as_str()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(rows
            .into_iter()
            .map(|r| SessionListItem {
                id: SessionId::new(r.id),
                access_jti: r.access_jti,
                created_at: r.created_at,
                refresh_expires_at: r.refresh_expires_at,
            })
            .collect())
    }

    async fn get_session_access_jti_by_id(
        &self,
        session_id: SessionId,
        did: &Did,
    ) -> Result<Option<String>, DbError> {
        let row = sqlx::query_scalar!(
            "SELECT access_jti FROM session_tokens WHERE id = $1 AND did = $2",
            session_id.as_i32(),
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row)
    }

    async fn delete_sessions_by_app_password(
        &self,
        did: &Did,
        app_password_name: &str,
    ) -> Result<u64, DbError> {
        let result = sqlx::query!(
            "DELETE FROM session_tokens WHERE did = $1 AND app_password_name = $2",
            did.as_str(),
            app_password_name
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.rows_affected())
    }

    async fn get_session_jtis_by_app_password(
        &self,
        did: &Did,
        app_password_name: &str,
    ) -> Result<Vec<String>, DbError> {
        let rows = sqlx::query_scalar!(
            "SELECT access_jti FROM session_tokens WHERE did = $1 AND app_password_name = $2",
            did.as_str(),
            app_password_name
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(rows)
    }

    async fn check_refresh_token_used(
        &self,
        refresh_jti: &str,
    ) -> Result<Option<SessionId>, DbError> {
        let row = sqlx::query_scalar!(
            "SELECT session_id FROM used_refresh_tokens WHERE refresh_jti = $1",
            refresh_jti
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(SessionId::new))
    }

    async fn mark_refresh_token_used(
        &self,
        refresh_jti: &str,
        session_id: SessionId,
    ) -> Result<bool, DbError> {
        let result = sqlx::query!(
            r#"
            INSERT INTO used_refresh_tokens (refresh_jti, session_id)
            VALUES ($1, $2)
            ON CONFLICT (refresh_jti) DO NOTHING
            "#,
            refresh_jti,
            session_id.as_i32()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.rows_affected() > 0)
    }

    async fn list_app_passwords(&self, user_id: Uuid) -> Result<Vec<AppPasswordRecord>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, user_id, name, password_hash, created_at, privileged, scopes, created_by_controller_did
            FROM app_passwords
            WHERE user_id = $1
            ORDER BY created_at DESC
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(rows
            .into_iter()
            .map(|r| AppPasswordRecord {
                id: r.id,
                user_id: r.user_id,
                name: r.name,
                password_hash: r.password_hash,
                created_at: r.created_at,
                privilege: AppPasswordPrivilege::from(r.privileged),
                scopes: r.scopes,
                created_by_controller_did: r.created_by_controller_did.map(Did::from),
            })
            .collect())
    }

    async fn get_app_passwords_for_login(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<AppPasswordRecord>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, user_id, name, password_hash, created_at, privileged, scopes, created_by_controller_did
            FROM app_passwords
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT 20
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(rows
            .into_iter()
            .map(|r| AppPasswordRecord {
                id: r.id,
                user_id: r.user_id,
                name: r.name,
                password_hash: r.password_hash,
                created_at: r.created_at,
                privilege: AppPasswordPrivilege::from(r.privileged),
                scopes: r.scopes,
                created_by_controller_did: r.created_by_controller_did.map(Did::from),
            })
            .collect())
    }

    async fn get_app_password_by_name(
        &self,
        user_id: Uuid,
        name: &str,
    ) -> Result<Option<AppPasswordRecord>, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT id, user_id, name, password_hash, created_at, privileged, scopes, created_by_controller_did
            FROM app_passwords
            WHERE user_id = $1 AND name = $2
            "#,
            user_id,
            name
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| AppPasswordRecord {
            id: r.id,
            user_id: r.user_id,
            name: r.name,
            password_hash: r.password_hash,
            created_at: r.created_at,
            privilege: AppPasswordPrivilege::from(r.privileged),
            scopes: r.scopes,
            created_by_controller_did: r.created_by_controller_did.map(Did::from),
        }))
    }

    async fn create_app_password(&self, data: &AppPasswordCreate) -> Result<Uuid, DbError> {
        let row = sqlx::query!(
            r#"
            INSERT INTO app_passwords (user_id, name, password_hash, privileged, scopes, created_by_controller_did)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            "#,
            data.user_id,
            data.name,
            data.password_hash,
            bool::from(data.privilege),
            data.scopes,
            data.created_by_controller_did.as_ref().map(|d| d.as_str())
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.id)
    }

    async fn delete_app_password(&self, user_id: Uuid, name: &str) -> Result<u64, DbError> {
        let result = sqlx::query!(
            "DELETE FROM app_passwords WHERE user_id = $1 AND name = $2",
            user_id,
            name
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.rows_affected())
    }

    async fn delete_app_passwords_by_controller(
        &self,
        did: &Did,
        controller_did: &Did,
    ) -> Result<u64, DbError> {
        let result = sqlx::query!(
            r#"DELETE FROM app_passwords
               WHERE user_id = (SELECT id FROM users WHERE did = $1)
               AND created_by_controller_did = $2"#,
            did.as_str(),
            controller_did.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.rows_affected())
    }

    async fn get_last_reauth_at(&self, did: &Did) -> Result<Option<DateTime<Utc>>, DbError> {
        let row = sqlx::query_scalar!(
            r#"SELECT last_reauth_at FROM session_tokens
               WHERE did = $1 ORDER BY created_at DESC LIMIT 1"#,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.flatten())
    }

    async fn update_last_reauth(&self, did: &Did) -> Result<DateTime<Utc>, DbError> {
        let now = Utc::now();
        sqlx::query!(
            "UPDATE session_tokens SET last_reauth_at = $1, mfa_verified = TRUE WHERE did = $2",
            now,
            did.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(now)
    }

    async fn get_session_mfa_status(&self, did: &Did) -> Result<Option<SessionMfaStatus>, DbError> {
        let row = sqlx::query!(
            r#"SELECT legacy_login, mfa_verified, last_reauth_at FROM session_tokens
               WHERE did = $1 ORDER BY created_at DESC LIMIT 1"#,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| SessionMfaStatus {
            login_type: LoginType::from(r.legacy_login),
            mfa_verified: r.mfa_verified,
            last_reauth_at: r.last_reauth_at,
        }))
    }

    async fn update_mfa_verified(&self, did: &Did) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE session_tokens SET mfa_verified = TRUE, last_reauth_at = NOW() WHERE did = $1",
            did.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn get_app_password_hashes_by_did(&self, did: &Did) -> Result<Vec<String>, DbError> {
        let rows = sqlx::query_scalar!(
            r#"SELECT ap.password_hash FROM app_passwords ap
               JOIN users u ON ap.user_id = u.id
               WHERE u.did = $1"#,
            did.as_str()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(rows)
    }

    async fn refresh_session_atomic(
        &self,
        data: &SessionRefreshData,
    ) -> Result<RefreshSessionResult, DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;

        if let Ok(Some(session_id)) = sqlx::query_scalar!(
            "SELECT session_id FROM used_refresh_tokens WHERE refresh_jti = $1 FOR UPDATE",
            data.old_refresh_jti
        )
        .fetch_optional(&mut *tx)
        .await
        {
            let _ = sqlx::query!("DELETE FROM session_tokens WHERE id = $1", session_id)
                .execute(&mut *tx)
                .await;
            tx.commit().await.map_err(map_sqlx_error)?;
            return Ok(RefreshSessionResult::TokenAlreadyUsed);
        }

        let result = sqlx::query!(
            "INSERT INTO used_refresh_tokens (refresh_jti, session_id) VALUES ($1, $2) ON CONFLICT (refresh_jti) DO NOTHING",
            data.old_refresh_jti,
            data.session_id.as_i32()
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;

        if result.rows_affected() == 0 {
            let _ = sqlx::query!(
                "DELETE FROM session_tokens WHERE id = $1",
                data.session_id.as_i32()
            )
            .execute(&mut *tx)
            .await;
            tx.commit().await.map_err(map_sqlx_error)?;
            return Ok(RefreshSessionResult::ConcurrentRefresh);
        }

        sqlx::query!(
            "UPDATE session_tokens SET access_jti = $1, refresh_jti = $2, access_expires_at = $3, refresh_expires_at = $4, updated_at = NOW() WHERE id = $5",
            data.new_access_jti,
            data.new_refresh_jti,
            data.new_access_expires_at,
            data.new_refresh_expires_at,
            data.session_id.as_i32()
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;

        tx.commit().await.map_err(map_sqlx_error)?;
        Ok(RefreshSessionResult::Success)
    }
}
