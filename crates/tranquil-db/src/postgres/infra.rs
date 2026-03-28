use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tranquil_db_traits::{
    AdminAccountInfo, CommsChannel, CommsStatus, CommsType, DbError, DeletionRequest,
    DeletionRequestWithToken, InfraRepository, InviteCodeError, InviteCodeInfo, InviteCodeRow,
    InviteCodeSortOrder, InviteCodeState, InviteCodeUse, NotificationHistoryRow, PlcTokenInfo,
    QueuedComms, ReservedSigningKey, ReservedSigningKeyFull, ValidatedInviteCode,
};
use tranquil_types::{CidLink, Did, Handle};
use uuid::Uuid;

use super::user::map_sqlx_error;

pub struct PostgresInfraRepository {
    pool: PgPool,
}

impl PostgresInfraRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl InfraRepository for PostgresInfraRepository {
    async fn enqueue_comms(
        &self,
        user_id: Option<Uuid>,
        channel: CommsChannel,
        comms_type: CommsType,
        recipient: &str,
        subject: Option<&str>,
        body: &str,
        metadata: Option<serde_json::Value>,
    ) -> Result<Uuid, DbError> {
        let id = sqlx::query_scalar!(
            r#"INSERT INTO comms_queue
               (user_id, channel, comms_type, recipient, subject, body, metadata)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               RETURNING id"#,
            user_id,
            channel as CommsChannel,
            comms_type as CommsType,
            recipient,
            subject,
            body,
            metadata
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(id)
    }

    async fn fetch_pending_comms(
        &self,
        now: DateTime<Utc>,
        batch_size: i64,
    ) -> Result<Vec<QueuedComms>, DbError> {
        let results = sqlx::query_as!(
            QueuedComms,
            r#"UPDATE comms_queue
               SET status = 'processing', updated_at = NOW()
               WHERE id IN (
                   SELECT id FROM comms_queue
                   WHERE status = 'pending'
                     AND scheduled_for <= $1
                     AND attempts < max_attempts
                   ORDER BY scheduled_for ASC
                   LIMIT $2
                   FOR UPDATE SKIP LOCKED
               )
               RETURNING
                   id, user_id,
                   channel as "channel: CommsChannel",
                   comms_type as "comms_type: CommsType",
                   status as "status: CommsStatus",
                   recipient, subject, body, metadata,
                   attempts, max_attempts, last_error,
                   created_at, updated_at, scheduled_for, processed_at"#,
            now,
            batch_size
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(results)
    }

    async fn mark_comms_sent(&self, id: Uuid) -> Result<(), DbError> {
        sqlx::query!(
            r#"UPDATE comms_queue
               SET status = 'sent', processed_at = NOW(), updated_at = NOW()
               WHERE id = $1"#,
            id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn mark_comms_failed(&self, id: Uuid, error: &str) -> Result<(), DbError> {
        sqlx::query!(
            r#"UPDATE comms_queue
               SET
                   status = CASE
                       WHEN attempts + 1 >= max_attempts THEN 'failed'::comms_status
                       ELSE 'pending'::comms_status
                   END,
                   attempts = attempts + 1,
                   last_error = $2,
                   updated_at = NOW(),
                   scheduled_for = NOW() + (INTERVAL '1 minute' * (attempts + 1))
               WHERE id = $1"#,
            id,
            error
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn create_invite_code(
        &self,
        code: &str,
        use_count: i32,
        for_account: Option<&Did>,
    ) -> Result<bool, DbError> {
        let for_account_str = for_account.map(|d| d.as_str());
        let result = sqlx::query!(
            r#"INSERT INTO invite_codes (code, available_uses, created_by_user, for_account)
               SELECT $1, $2, id, $3 FROM users WHERE is_admin = true LIMIT 1"#,
            code,
            use_count,
            for_account_str
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.rows_affected() > 0)
    }

    async fn create_invite_codes_batch(
        &self,
        codes: &[String],
        use_count: i32,
        created_by_user: Uuid,
        for_account: Option<&Did>,
    ) -> Result<(), DbError> {
        let for_account_str = for_account.map(|d| d.as_str());
        sqlx::query!(
            r#"INSERT INTO invite_codes (code, available_uses, created_by_user, for_account)
               SELECT code, $2, $3, $4 FROM UNNEST($1::text[]) AS t(code)"#,
            codes,
            use_count,
            created_by_user,
            for_account_str
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn get_invite_code_available_uses(&self, code: &str) -> Result<Option<i32>, DbError> {
        let result = sqlx::query_scalar!(
            "SELECT available_uses FROM invite_codes WHERE code = $1 FOR UPDATE",
            code
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result)
    }

    async fn validate_invite_code<'a>(
        &self,
        code: &'a str,
    ) -> Result<ValidatedInviteCode<'a>, InviteCodeError> {
        let result = sqlx::query!(
            r#"SELECT available_uses, COALESCE(disabled, false) as "disabled!" FROM invite_codes WHERE code = $1"#,
            code
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| InviteCodeError::DatabaseError(map_sqlx_error(e)))?;

        match result {
            None => Err(InviteCodeError::NotFound),
            Some(row) if row.disabled => Err(InviteCodeError::Disabled),
            Some(row) if row.available_uses <= 0 => Err(InviteCodeError::ExhaustedUses),
            Some(_) => Ok(ValidatedInviteCode::new_validated(code)),
        }
    }

    async fn decrement_invite_code_uses(
        &self,
        code: &ValidatedInviteCode<'_>,
    ) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE invite_codes SET available_uses = available_uses - 1 WHERE code = $1",
            code.code()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn record_invite_code_use(
        &self,
        code: &ValidatedInviteCode<'_>,
        used_by_user: Uuid,
    ) -> Result<(), DbError> {
        sqlx::query!(
            "INSERT INTO invite_code_uses (code, used_by_user) VALUES ($1, $2)",
            code.code(),
            used_by_user
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn get_invite_codes_for_account(
        &self,
        for_account: &Did,
    ) -> Result<Vec<InviteCodeInfo>, DbError> {
        let results = sqlx::query!(
            r#"SELECT
                   ic.code,
                   ic.available_uses,
                   ic.created_at,
                   ic.disabled,
                   ic.for_account,
                   (SELECT COUNT(*) FROM invite_code_uses icu WHERE icu.code = ic.code)::int as "use_count!"
               FROM invite_codes ic
               WHERE ic.for_account = $1
               ORDER BY ic.created_at DESC"#,
            for_account.as_str()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(results
            .into_iter()
            .map(|r| InviteCodeInfo {
                code: r.code,
                available_uses: r.available_uses,
                state: InviteCodeState::from_optional_disabled_flag(r.disabled),
                for_account: Some(Did::from(r.for_account)),
                created_at: r.created_at,
                created_by: None,
            })
            .collect())
    }

    async fn get_invite_code_uses(&self, code: &str) -> Result<Vec<InviteCodeUse>, DbError> {
        let results = sqlx::query!(
            r#"SELECT u.did, u.handle, icu.used_at
               FROM invite_code_uses icu
               JOIN users u ON icu.used_by_user = u.id
               WHERE icu.code = $1
               ORDER BY icu.used_at DESC"#,
            code
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(results
            .into_iter()
            .map(|r| InviteCodeUse {
                code: code.to_string(),
                used_by_did: Did::from(r.did),
                used_by_handle: Some(Handle::from(r.handle)),
                used_at: r.used_at,
            })
            .collect())
    }

    async fn disable_invite_codes_by_code(&self, codes: &[String]) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE invite_codes SET disabled = TRUE WHERE code = ANY($1)",
            codes
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn disable_invite_codes_by_account(&self, accounts: &[Did]) -> Result<(), DbError> {
        let accounts_str: Vec<&str> = accounts.iter().map(|d| d.as_str()).collect();
        sqlx::query!(
            r#"UPDATE invite_codes SET disabled = TRUE
               WHERE created_by_user IN (SELECT id FROM users WHERE did = ANY($1))"#,
            &accounts_str as &[&str]
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn list_invite_codes(
        &self,
        cursor: Option<&str>,
        limit: i64,
        sort: InviteCodeSortOrder,
    ) -> Result<Vec<InviteCodeRow>, DbError> {
        let results = match (cursor, sort) {
            (Some(cursor_code), InviteCodeSortOrder::Recent) => sqlx::query_as!(
                InviteCodeRow,
                r#"SELECT ic.code, ic.available_uses, ic.disabled, ic.created_by_user, ic.created_at
                       FROM invite_codes ic
                       WHERE ic.created_at < (SELECT created_at FROM invite_codes WHERE code = $1)
                       ORDER BY created_at DESC
                       LIMIT $2"#,
                cursor_code,
                limit
            )
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?,
            (None, InviteCodeSortOrder::Recent) => sqlx::query_as!(
                InviteCodeRow,
                r#"SELECT ic.code, ic.available_uses, ic.disabled, ic.created_by_user, ic.created_at
                       FROM invite_codes ic
                       ORDER BY created_at DESC
                       LIMIT $1"#,
                limit
            )
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?,
            (Some(cursor_code), InviteCodeSortOrder::Usage) => sqlx::query_as!(
                InviteCodeRow,
                r#"SELECT ic.code, ic.available_uses, ic.disabled, ic.created_by_user, ic.created_at
                       FROM invite_codes ic
                       WHERE ic.created_at < (SELECT created_at FROM invite_codes WHERE code = $1)
                       ORDER BY available_uses DESC
                       LIMIT $2"#,
                cursor_code,
                limit
            )
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?,
            (None, InviteCodeSortOrder::Usage) => sqlx::query_as!(
                InviteCodeRow,
                r#"SELECT ic.code, ic.available_uses, ic.disabled, ic.created_by_user, ic.created_at
                       FROM invite_codes ic
                       ORDER BY available_uses DESC
                       LIMIT $1"#,
                limit
            )
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?,
        };

        Ok(results)
    }

    async fn get_user_dids_by_ids(&self, user_ids: &[Uuid]) -> Result<Vec<(Uuid, Did)>, DbError> {
        let results = sqlx::query!("SELECT id, did FROM users WHERE id = ANY($1)", user_ids)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(results
            .into_iter()
            .map(|r| (r.id, Did::from(r.did)))
            .collect())
    }

    async fn get_invite_code_uses_batch(
        &self,
        codes: &[String],
    ) -> Result<Vec<InviteCodeUse>, DbError> {
        let results = sqlx::query!(
            r#"SELECT icu.code, u.did, icu.used_at
               FROM invite_code_uses icu
               JOIN users u ON icu.used_by_user = u.id
               WHERE icu.code = ANY($1)
               ORDER BY icu.used_at DESC"#,
            codes
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(results
            .into_iter()
            .map(|r| InviteCodeUse {
                code: r.code,
                used_by_did: Did::from(r.did),
                used_by_handle: None,
                used_at: r.used_at,
            })
            .collect())
    }

    async fn get_invites_created_by_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<InviteCodeInfo>, DbError> {
        let results = sqlx::query!(
            r#"SELECT ic.code, ic.available_uses, ic.disabled, ic.for_account, ic.created_at, u.did as created_by
               FROM invite_codes ic
               JOIN users u ON ic.created_by_user = u.id
               WHERE ic.created_by_user = $1"#,
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(results
            .into_iter()
            .map(|r| InviteCodeInfo {
                code: r.code,
                available_uses: r.available_uses,
                state: InviteCodeState::from_optional_disabled_flag(r.disabled),
                for_account: Some(Did::from(r.for_account)),
                created_at: r.created_at,
                created_by: Some(Did::from(r.created_by)),
            })
            .collect())
    }

    async fn get_invite_code_info(&self, code: &str) -> Result<Option<InviteCodeInfo>, DbError> {
        let result = sqlx::query!(
            r#"SELECT ic.code, ic.available_uses, ic.disabled, ic.for_account, ic.created_at, u.did as created_by
               FROM invite_codes ic
               JOIN users u ON ic.created_by_user = u.id
               WHERE ic.code = $1"#,
            code
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.map(|r| InviteCodeInfo {
            code: r.code,
            available_uses: r.available_uses,
            state: InviteCodeState::from_optional_disabled_flag(r.disabled),
            for_account: Some(Did::from(r.for_account)),
            created_at: r.created_at,
            created_by: Some(Did::from(r.created_by)),
        }))
    }

    async fn get_invite_codes_by_users(
        &self,
        user_ids: &[Uuid],
    ) -> Result<Vec<(Uuid, InviteCodeInfo)>, DbError> {
        let results = sqlx::query!(
            r#"SELECT ic.code, ic.available_uses, ic.disabled, ic.for_account, ic.created_at,
                      ic.created_by_user, u.did as created_by
               FROM invite_codes ic
               JOIN users u ON ic.created_by_user = u.id
               WHERE ic.created_by_user = ANY($1)"#,
            user_ids
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(results
            .into_iter()
            .map(|r| {
                (
                    r.created_by_user,
                    InviteCodeInfo {
                        code: r.code,
                        available_uses: r.available_uses,
                        state: InviteCodeState::from_optional_disabled_flag(r.disabled),
                        for_account: Some(Did::from(r.for_account)),
                        created_at: r.created_at,
                        created_by: Some(Did::from(r.created_by)),
                    },
                )
            })
            .collect())
    }

    async fn get_invite_code_used_by_user(&self, user_id: Uuid) -> Result<Option<String>, DbError> {
        let result = sqlx::query_scalar!(
            "SELECT code FROM invite_code_uses WHERE used_by_user = $1",
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result)
    }

    async fn delete_invite_code_uses_by_user(&self, user_id: Uuid) -> Result<(), DbError> {
        sqlx::query!(
            "DELETE FROM invite_code_uses WHERE used_by_user = $1",
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn delete_invite_codes_by_user(&self, user_id: Uuid) -> Result<(), DbError> {
        sqlx::query!(
            "DELETE FROM invite_codes WHERE created_by_user = $1",
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn reserve_signing_key(
        &self,
        did: Option<&Did>,
        public_key_did_key: &str,
        private_key_bytes: &[u8],
        expires_at: DateTime<Utc>,
    ) -> Result<Uuid, DbError> {
        let did_str = did.map(|d| d.as_str());
        let id = sqlx::query_scalar!(
            r#"INSERT INTO reserved_signing_keys (did, public_key_did_key, private_key_bytes, expires_at)
               VALUES ($1, $2, $3, $4)
               RETURNING id"#,
            did_str,
            public_key_did_key,
            private_key_bytes,
            expires_at
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(id)
    }

    async fn get_reserved_signing_key(
        &self,
        public_key_did_key: &str,
    ) -> Result<Option<ReservedSigningKey>, DbError> {
        let result = sqlx::query!(
            r#"SELECT id, private_key_bytes
               FROM reserved_signing_keys
               WHERE public_key_did_key = $1
                 AND used_at IS NULL
                 AND expires_at > NOW()
               FOR UPDATE"#,
            public_key_did_key
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.map(|r| ReservedSigningKey {
            id: r.id,
            private_key_bytes: r.private_key_bytes,
        }))
    }

    async fn mark_signing_key_used(&self, key_id: Uuid) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE reserved_signing_keys SET used_at = NOW() WHERE id = $1",
            key_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn create_deletion_request(
        &self,
        token: &str,
        did: &Did,
        expires_at: DateTime<Utc>,
    ) -> Result<(), DbError> {
        sqlx::query!(
            "INSERT INTO account_deletion_requests (token, did, expires_at) VALUES ($1, $2, $3)",
            token,
            did.as_str(),
            expires_at
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn get_deletion_request(&self, token: &str) -> Result<Option<DeletionRequest>, DbError> {
        let result = sqlx::query!(
            "SELECT did, expires_at FROM account_deletion_requests WHERE token = $1",
            token
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.map(|r| DeletionRequest {
            did: Did::from(r.did),
            expires_at: r.expires_at,
        }))
    }

    async fn delete_deletion_request(&self, token: &str) -> Result<(), DbError> {
        sqlx::query!(
            "DELETE FROM account_deletion_requests WHERE token = $1",
            token
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn delete_deletion_requests_by_did(&self, did: &Did) -> Result<(), DbError> {
        sqlx::query!(
            "DELETE FROM account_deletion_requests WHERE did = $1",
            did.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn upsert_account_preference(
        &self,
        user_id: Uuid,
        name: &str,
        value_json: serde_json::Value,
    ) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;

        sqlx::query!(
            r#"DELETE FROM account_preferences WHERE user_id = $1 AND name = $2"#,
            user_id,
            name
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;

        sqlx::query!(
            r#"INSERT INTO account_preferences (user_id, name, value_json) VALUES ($1, $2, $3)"#,
            user_id,
            name,
            value_json
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;

        tx.commit().await.map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn insert_account_preference_if_not_exists(
        &self,
        user_id: Uuid,
        name: &str,
        value_json: serde_json::Value,
    ) -> Result<(), DbError> {
        sqlx::query!(
            r#"INSERT INTO account_preferences (user_id, name, value_json) VALUES ($1, $2, $3)
               ON CONFLICT (user_id, name) DO NOTHING"#,
            user_id,
            name,
            value_json
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn get_server_config(&self, key: &str) -> Result<Option<String>, DbError> {
        let row = sqlx::query_scalar!("SELECT value FROM server_config WHERE key = $1", key)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(row)
    }

    async fn health_check(&self) -> Result<bool, DbError> {
        sqlx::query_scalar!("SELECT 1 as one")
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(true)
    }

    async fn insert_report(
        &self,
        id: i64,
        reason_type: &str,
        reason: Option<&str>,
        subject_json: serde_json::Value,
        reported_by_did: &Did,
        created_at: DateTime<Utc>,
    ) -> Result<(), DbError> {
        sqlx::query!(
            "INSERT INTO reports (id, reason_type, reason, subject_json, reported_by_did, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
            id,
            reason_type,
            reason,
            subject_json,
            reported_by_did.as_str(),
            created_at
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn delete_plc_tokens_for_user(&self, user_id: Uuid) -> Result<(), DbError> {
        sqlx::query!(
            "DELETE FROM plc_operation_tokens WHERE user_id = $1 OR expires_at < NOW()",
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn insert_plc_token(
        &self,
        user_id: Uuid,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), DbError> {
        sqlx::query!(
            "INSERT INTO plc_operation_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
            user_id,
            token,
            expires_at
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn get_plc_token_expiry(
        &self,
        user_id: Uuid,
        token: &str,
    ) -> Result<Option<DateTime<Utc>>, DbError> {
        let expiry = sqlx::query_scalar!(
            "SELECT expires_at FROM plc_operation_tokens WHERE user_id = $1 AND token = $2",
            user_id,
            token
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(expiry)
    }

    async fn delete_plc_token(&self, user_id: Uuid, token: &str) -> Result<(), DbError> {
        sqlx::query!(
            "DELETE FROM plc_operation_tokens WHERE user_id = $1 AND token = $2",
            user_id,
            token
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn get_account_preferences(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<(String, serde_json::Value)>, DbError> {
        let rows = sqlx::query!(
            "SELECT name, value_json FROM account_preferences WHERE user_id = $1",
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(rows.into_iter().map(|r| (r.name, r.value_json)).collect())
    }

    async fn replace_namespace_preferences(
        &self,
        user_id: Uuid,
        namespace: &str,
        preferences: Vec<(String, serde_json::Value)>,
    ) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;

        let like_pattern = format!("{}.%", namespace);
        sqlx::query!(
            "DELETE FROM account_preferences WHERE user_id = $1 AND (name = $2 OR name LIKE $3)",
            user_id,
            namespace,
            like_pattern
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;

        for (name, value_json) in preferences {
            sqlx::query!(
                "INSERT INTO account_preferences (user_id, name, value_json) VALUES ($1, $2, $3)",
                user_id,
                name,
                value_json
            )
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        }

        tx.commit().await.map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn get_notification_history(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<NotificationHistoryRow>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT
                created_at,
                channel as "channel: CommsChannel",
                comms_type as "comms_type: CommsType",
                status as "status: CommsStatus",
                subject,
                body
            FROM comms_queue
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
            user_id,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(rows
            .into_iter()
            .map(|r| NotificationHistoryRow {
                created_at: r.created_at,
                channel: r.channel,
                comms_type: r.comms_type,
                status: r.status,
                subject: r.subject,
                body: r.body,
            })
            .collect())
    }

    async fn get_server_configs(&self, keys: &[&str]) -> Result<Vec<(String, String)>, DbError> {
        let keys_vec: Vec<String> = keys.iter().map(|s| s.to_string()).collect();
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT key, value FROM server_config WHERE key = ANY($1)")
                .bind(&keys_vec)
                .fetch_all(&self.pool)
                .await
                .map_err(map_sqlx_error)?;

        Ok(rows)
    }

    async fn upsert_server_config(&self, key: &str, value: &str) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO server_config (key, value, updated_at) VALUES ($1, $2, NOW())
             ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn delete_server_config(&self, key: &str) -> Result<(), DbError> {
        sqlx::query("DELETE FROM server_config WHERE key = $1")
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn get_blob_storage_key_by_cid(&self, cid: &CidLink) -> Result<Option<String>, DbError> {
        let result =
            sqlx::query_scalar!("SELECT storage_key FROM blobs WHERE cid = $1", cid.as_str())
                .fetch_optional(&self.pool)
                .await
                .map_err(map_sqlx_error)?;

        Ok(result)
    }

    async fn delete_blob_by_cid(&self, cid: &CidLink) -> Result<(), DbError> {
        sqlx::query!("DELETE FROM blobs WHERE cid = $1", cid.as_str())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn get_admin_account_info_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<AdminAccountInfo>, DbError> {
        let result = sqlx::query!(
            r#"
            SELECT id, did, handle, email, created_at, invites_disabled, email_verified, deactivated_at
            FROM users
            WHERE did = $1
            "#,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.map(|r| AdminAccountInfo {
            id: r.id,
            did: Did::from(r.did),
            handle: Handle::from(r.handle),
            email: r.email,
            created_at: r.created_at,
            invites_disabled: r.invites_disabled.unwrap_or(false),
            email_verified: r.email_verified,
            deactivated_at: r.deactivated_at,
        }))
    }

    async fn get_admin_account_infos_by_dids(
        &self,
        dids: &[Did],
    ) -> Result<Vec<AdminAccountInfo>, DbError> {
        let dids_str: Vec<&str> = dids.iter().map(|d| d.as_str()).collect();
        let results = sqlx::query!(
            r#"
            SELECT id, did, handle, email, created_at, invites_disabled, email_verified, deactivated_at
            FROM users
            WHERE did = ANY($1)
            "#,
            &dids_str as &[&str]
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(results
            .into_iter()
            .map(|r| AdminAccountInfo {
                id: r.id,
                did: Did::from(r.did),
                handle: Handle::from(r.handle),
                email: r.email,
                created_at: r.created_at,
                invites_disabled: r.invites_disabled.unwrap_or(false),
                email_verified: r.email_verified,
                deactivated_at: r.deactivated_at,
            })
            .collect())
    }

    async fn get_invite_code_uses_by_users(
        &self,
        user_ids: &[Uuid],
    ) -> Result<Vec<(Uuid, String)>, DbError> {
        let results = sqlx::query!(
            r#"
            SELECT used_by_user, code
            FROM invite_code_uses
            WHERE used_by_user = ANY($1)
            "#,
            user_ids
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(results
            .into_iter()
            .map(|r| (r.used_by_user, r.code))
            .collect())
    }

    async fn get_deletion_request_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<DeletionRequestWithToken>, DbError> {
        let row = sqlx::query!(
            r#"SELECT token, did, expires_at FROM account_deletion_requests WHERE did = $1"#,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| DeletionRequestWithToken {
            token: r.token,
            did: Did::new(r.did).expect("valid DID in database"),
            expires_at: r.expires_at,
        }))
    }

    async fn get_latest_comms_for_user(
        &self,
        user_id: Uuid,
        comms_type: CommsType,
        limit: i64,
    ) -> Result<Vec<QueuedComms>, DbError> {
        let results = sqlx::query_as!(
            QueuedComms,
            r#"SELECT
                id, user_id,
                channel as "channel: CommsChannel",
                comms_type as "comms_type: CommsType",
                status as "status: CommsStatus",
                recipient, subject, body, metadata,
                attempts, max_attempts, last_error,
                created_at, updated_at, scheduled_for, processed_at
            FROM comms_queue
            WHERE user_id = $1 AND comms_type = $2
            ORDER BY created_at DESC
            LIMIT $3"#,
            user_id,
            comms_type as CommsType,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(results)
    }

    async fn count_comms_by_type(
        &self,
        user_id: Uuid,
        comms_type: CommsType,
    ) -> Result<i64, DbError> {
        let count = sqlx::query_scalar!(
            r#"SELECT COUNT(*) as "count!" FROM comms_queue WHERE user_id = $1 AND comms_type = $2"#,
            user_id,
            comms_type as CommsType
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(count)
    }

    async fn delete_comms_by_type_for_user(
        &self,
        user_id: Uuid,
        comms_type: CommsType,
    ) -> Result<u64, DbError> {
        let result = sqlx::query!(
            "DELETE FROM comms_queue WHERE user_id = $1 AND comms_type = $2",
            user_id,
            comms_type as CommsType
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.rows_affected())
    }

    async fn expire_deletion_request(&self, token: &str) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE account_deletion_requests SET expires_at = NOW() - INTERVAL '1 hour' WHERE token = $1",
            token
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn get_reserved_signing_key_full(
        &self,
        public_key_did_key: &str,
    ) -> Result<Option<ReservedSigningKeyFull>, DbError> {
        let row = sqlx::query!(
            r#"SELECT id, did, public_key_did_key, private_key_bytes, expires_at, used_at
            FROM reserved_signing_keys WHERE public_key_did_key = $1"#,
            public_key_did_key
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| ReservedSigningKeyFull {
            id: r.id,
            did: r.did.map(|d| Did::new(d).expect("valid DID in database")),
            public_key_did_key: r.public_key_did_key,
            private_key_bytes: r.private_key_bytes,
            expires_at: r.expires_at,
            used_at: r.used_at,
        }))
    }

    async fn get_plc_tokens_by_did(&self, did: &Did) -> Result<Vec<PlcTokenInfo>, DbError> {
        let results = sqlx::query!(
            r#"SELECT t.token, t.expires_at
            FROM plc_operation_tokens t
            JOIN users u ON t.user_id = u.id
            WHERE u.did = $1"#,
            did.as_str()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(results
            .into_iter()
            .map(|r| PlcTokenInfo {
                token: r.token,
                expires_at: r.expires_at,
            })
            .collect())
    }

    async fn count_plc_tokens_by_did(&self, did: &Did) -> Result<i64, DbError> {
        let count = sqlx::query_scalar!(
            r#"SELECT COUNT(*) as "count!"
            FROM plc_operation_tokens t
            JOIN users u ON t.user_id = u.id
            WHERE u.did = $1"#,
            did.as_str()
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(count)
    }
}
