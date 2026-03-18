use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tranquil_types::{Did, Handle};
use uuid::Uuid;

use tranquil_db_traits::{
    AccountSearchResult, AccountType, ChannelVerificationStatus, CommsChannel, DbError,
    DidWebOverrides, NotificationPrefs, OAuthTokenWithUser, PasswordResetResult, SsoProviderType,
    StoredBackupCode, StoredPasskey, TotpRecord, TotpRecordState, User2faStatus, UserAuthInfo,
    UserCommsPrefs, UserConfirmSignup, UserDidWebInfo, UserEmailInfo, UserForDeletion,
    UserForDidDoc, UserForDidDocBuild, UserForPasskeyRecovery, UserForPasskeySetup,
    UserForRecovery, UserForVerification, UserIdAndHandle, UserIdAndPasswordHash,
    UserIdHandleEmail, UserInfoForAuth, UserKeyInfo, UserKeyWithId, UserLegacyLoginPref,
    UserLoginCheck, UserLoginFull, UserLoginInfo, UserPasswordInfo, UserRepository,
    UserResendVerification, UserResetCodeInfo, UserRow, UserSessionInfo, UserStatus,
    UserVerificationInfo, UserWithKey, WebauthnChallengeType,
};

pub struct PostgresUserRepository {
    pool: PgPool,
}

impl PostgresUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

pub(crate) fn map_sqlx_error(e: sqlx::Error) -> DbError {
    match e {
        sqlx::Error::RowNotFound => DbError::NotFound,
        sqlx::Error::Database(db_err) => {
            let msg = db_err.message().to_string();
            if db_err.is_unique_violation() || db_err.is_foreign_key_violation() {
                DbError::Constraint(msg)
            } else {
                DbError::Query(msg)
            }
        }
        sqlx::Error::PoolTimedOut => DbError::Connection("Pool timed out".into()),
        _ => DbError::Other(e.to_string()),
    }
}

#[async_trait]
impl UserRepository for PostgresUserRepository {
    async fn get_by_did(&self, did: &Did) -> Result<Option<UserRow>, DbError> {
        let row = sqlx::query!(
            r#"SELECT id, did, handle, email, created_at, deactivated_at, takedown_ref, is_admin
               FROM users WHERE did = $1"#,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| UserRow {
            id: r.id,
            did: Did::from(r.did),
            handle: Handle::from(r.handle),
            email: r.email,
            created_at: r.created_at,
            deactivated_at: r.deactivated_at,
            takedown_ref: r.takedown_ref,
            is_admin: r.is_admin,
        }))
    }

    async fn get_by_handle(&self, handle: &Handle) -> Result<Option<UserRow>, DbError> {
        let row = sqlx::query!(
            r#"SELECT id, did, handle, email, created_at, deactivated_at, takedown_ref, is_admin
               FROM users WHERE handle = $1"#,
            handle.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| UserRow {
            id: r.id,
            did: Did::from(r.did),
            handle: Handle::from(r.handle),
            email: r.email,
            created_at: r.created_at,
            deactivated_at: r.deactivated_at,
            takedown_ref: r.takedown_ref,
            is_admin: r.is_admin,
        }))
    }

    async fn get_with_key_by_did(&self, did: &Did) -> Result<Option<UserWithKey>, DbError> {
        let row = sqlx::query!(
            r#"SELECT u.id, u.did, u.handle, u.email, u.deactivated_at, u.takedown_ref, u.is_admin,
                      k.key_bytes, k.encryption_version
               FROM users u
               JOIN user_keys k ON u.id = k.user_id
               WHERE u.did = $1"#,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| UserWithKey {
            id: r.id,
            did: Did::from(r.did),
            handle: Handle::from(r.handle),
            email: r.email,
            deactivated_at: r.deactivated_at,
            takedown_ref: r.takedown_ref,
            is_admin: r.is_admin,
            key_bytes: r.key_bytes,
            encryption_version: r.encryption_version,
        }))
    }

    async fn get_status_by_did(&self, did: &Did) -> Result<Option<UserStatus>, DbError> {
        let row = sqlx::query!(
            "SELECT deactivated_at, takedown_ref, is_admin FROM users WHERE did = $1",
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| UserStatus {
            deactivated_at: r.deactivated_at,
            takedown_ref: r.takedown_ref,
            is_admin: r.is_admin,
        }))
    }

    async fn count_users(&self) -> Result<i64, DbError> {
        let row = sqlx::query_scalar!("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(row.unwrap_or(0))
    }

    async fn get_session_access_expiry(
        &self,
        did: &Did,
        access_jti: &str,
    ) -> Result<Option<DateTime<Utc>>, DbError> {
        let row = sqlx::query!(
            "SELECT access_expires_at FROM session_tokens WHERE did = $1 AND access_jti = $2",
            did.as_str(),
            access_jti
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| r.access_expires_at))
    }

    async fn get_oauth_token_with_user(
        &self,
        token_id: &str,
    ) -> Result<Option<OAuthTokenWithUser>, DbError> {
        let row = sqlx::query!(
            r#"SELECT t.did, t.expires_at, u.deactivated_at, u.takedown_ref, u.is_admin,
                      k.key_bytes as "key_bytes?", k.encryption_version as "encryption_version?"
               FROM oauth_token t
               JOIN users u ON t.did = u.did
               LEFT JOIN user_keys k ON u.id = k.user_id
               WHERE t.token_id = $1"#,
            token_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| OAuthTokenWithUser {
            did: Did::from(r.did),
            expires_at: r.expires_at,
            deactivated_at: r.deactivated_at,
            takedown_ref: r.takedown_ref,
            is_admin: r.is_admin,
            key_bytes: r.key_bytes,
            encryption_version: r.encryption_version,
        }))
    }

    async fn get_user_info_by_did(&self, did: &Did) -> Result<Option<UserInfoForAuth>, DbError> {
        let row = sqlx::query!(
            r#"SELECT u.deactivated_at, u.takedown_ref, u.is_admin,
                      k.key_bytes as "key_bytes?", k.encryption_version as "encryption_version?"
               FROM users u
               LEFT JOIN user_keys k ON u.id = k.user_id
               WHERE u.did = $1"#,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| UserInfoForAuth {
            deactivated_at: r.deactivated_at,
            takedown_ref: r.takedown_ref,
            is_admin: r.is_admin,
            key_bytes: r.key_bytes,
            encryption_version: r.encryption_version,
        }))
    }

    async fn get_any_admin_user_id(&self) -> Result<Option<Uuid>, DbError> {
        let row = sqlx::query_scalar!("SELECT id FROM users WHERE is_admin = true LIMIT 1")
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(row)
    }

    async fn set_invites_disabled(&self, did: &Did, disabled: bool) -> Result<bool, DbError> {
        let result = sqlx::query!(
            "UPDATE users SET invites_disabled = $2 WHERE did = $1",
            did.as_str(),
            disabled
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn search_accounts(
        &self,
        cursor_did: Option<&Did>,
        email_filter: Option<&str>,
        handle_filter: Option<&str>,
        limit: i64,
    ) -> Result<Vec<AccountSearchResult>, DbError> {
        let cursor_str = cursor_did.map(|d| d.as_str());
        let rows = sqlx::query!(
            r#"SELECT did, handle, email, created_at, email_verified, deactivated_at, invites_disabled
               FROM users
               WHERE ($1::text IS NULL OR did > $1)
                 AND ($2::text IS NULL OR email ILIKE $2)
                 AND ($3::text IS NULL OR handle ILIKE $3)
               ORDER BY did ASC
               LIMIT $4"#,
            cursor_str,
            email_filter,
            handle_filter,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(rows
            .into_iter()
            .map(|r| AccountSearchResult {
                did: Did::from(r.did),
                handle: Handle::from(r.handle),
                email: r.email,
                created_at: r.created_at,
                email_verified: r.email_verified,
                deactivated_at: r.deactivated_at,
                invites_disabled: r.invites_disabled,
            })
            .collect())
    }

    async fn get_auth_info_by_did(&self, did: &Did) -> Result<Option<UserAuthInfo>, DbError> {
        let row = sqlx::query!(
            r#"SELECT id, did, password_hash, deactivated_at, takedown_ref,
                      email_verified, discord_verified, telegram_verified, signal_verified
               FROM users
               WHERE did = $1"#,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(row.map(|r| UserAuthInfo {
            id: r.id,
            did: Did::from(r.did),
            password_hash: r.password_hash,
            deactivated_at: r.deactivated_at,
            takedown_ref: r.takedown_ref,
            channel_verification: ChannelVerificationStatus::from_db_row(
                r.email_verified,
                r.discord_verified,
                r.telegram_verified,
                r.signal_verified,
            ),
        }))
    }

    async fn get_by_email(&self, email: &str) -> Result<Option<UserForVerification>, DbError> {
        let row = sqlx::query!(
            r#"SELECT id, did, email, email_verified, handle
               FROM users
               WHERE LOWER(email) = $1"#,
            email
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(row.map(|r| UserForVerification {
            id: r.id,
            did: Did::from(r.did),
            email: r.email,
            email_verified: r.email_verified,
            handle: Handle::from(r.handle),
        }))
    }

    async fn get_comms_prefs(&self, user_id: Uuid) -> Result<Option<UserCommsPrefs>, DbError> {
        let row = sqlx::query!(
            r#"SELECT email, handle, preferred_comms_channel as "preferred_channel!: CommsChannel", preferred_locale, telegram_chat_id, discord_id, signal_username
               FROM users WHERE id = $1"#,
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(row.map(|r| UserCommsPrefs {
            email: r.email,
            handle: Handle::from(r.handle),
            preferred_channel: r.preferred_channel,
            preferred_locale: r.preferred_locale,
            telegram_chat_id: r.telegram_chat_id,
            discord_id: r.discord_id,
            signal_username: r.signal_username,
        }))
    }

    async fn get_id_by_did(&self, did: &Did) -> Result<Option<Uuid>, DbError> {
        let id = sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(id)
    }

    async fn get_user_key_by_id(&self, user_id: Uuid) -> Result<Option<UserKeyInfo>, DbError> {
        let row = sqlx::query!(
            "SELECT key_bytes, encryption_version FROM user_keys WHERE user_id = $1",
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(row.map(|r| UserKeyInfo {
            key_bytes: r.key_bytes,
            encryption_version: r.encryption_version,
        }))
    }

    async fn get_id_and_handle_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserIdAndHandle>, DbError> {
        let row = sqlx::query!("SELECT id, handle FROM users WHERE did = $1", did.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(row.map(|r| UserIdAndHandle {
            id: r.id,
            handle: Handle::from(r.handle),
        }))
    }

    async fn get_did_web_info_by_handle(
        &self,
        handle: &Handle,
    ) -> Result<Option<UserDidWebInfo>, DbError> {
        let row = sqlx::query!(
            "SELECT id, did, migrated_to_pds FROM users WHERE handle = $1",
            handle.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(row.map(|r| UserDidWebInfo {
            id: r.id,
            did: Did::from(r.did),
            migrated_to_pds: r.migrated_to_pds,
        }))
    }

    async fn get_did_web_overrides(
        &self,
        user_id: Uuid,
    ) -> Result<Option<DidWebOverrides>, DbError> {
        let row = sqlx::query!(
            "SELECT verification_methods, also_known_as FROM did_web_overrides WHERE user_id = $1",
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(row.map(|r| DidWebOverrides {
            verification_methods: r.verification_methods,
            also_known_as: r.also_known_as,
        }))
    }

    async fn get_handle_by_did(&self, did: &Did) -> Result<Option<Handle>, DbError> {
        let handle = sqlx::query_scalar!("SELECT handle FROM users WHERE did = $1", did.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(handle.map(Handle::from))
    }

    async fn check_handle_exists(
        &self,
        handle: &Handle,
        exclude_user_id: Uuid,
    ) -> Result<bool, DbError> {
        let exists = sqlx::query_scalar!(
            "SELECT EXISTS(SELECT 1 FROM users WHERE handle = $1 AND id != $2) as \"exists!\"",
            handle.as_str(),
            exclude_user_id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(exists)
    }

    async fn update_handle(&self, user_id: Uuid, handle: &Handle) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE users SET handle = $1 WHERE id = $2",
            handle.as_str(),
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn get_user_with_key_by_did(&self, did: &Did) -> Result<Option<UserKeyWithId>, DbError> {
        let row = sqlx::query!(
            r#"SELECT u.id, uk.key_bytes, uk.encryption_version
               FROM users u
               JOIN user_keys uk ON u.id = uk.user_id
               WHERE u.did = $1"#,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(row.map(|r| UserKeyWithId {
            id: r.id,
            key_bytes: r.key_bytes,
            encryption_version: r.encryption_version,
        }))
    }

    async fn is_account_migrated(&self, did: &Did) -> Result<bool, DbError> {
        let row = sqlx::query!(
            r#"SELECT (migrated_to_pds IS NOT NULL AND deactivated_at IS NOT NULL) as "migrated!: bool" FROM users WHERE did = $1"#,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(row.map(|r| r.migrated).unwrap_or(false))
    }

    async fn has_verified_comms_channel(&self, did: &Did) -> Result<bool, DbError> {
        let row = sqlx::query!(
            r#"SELECT
                email_verified,
                discord_verified,
                telegram_verified,
                signal_verified
            FROM users
            WHERE did = $1"#,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(row
            .map(|r| {
                r.email_verified || r.discord_verified || r.telegram_verified || r.signal_verified
            })
            .unwrap_or(false))
    }

    async fn get_id_by_handle(&self, handle: &Handle) -> Result<Option<Uuid>, DbError> {
        let id = sqlx::query_scalar!("SELECT id FROM users WHERE handle = $1", handle.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(id)
    }

    async fn get_email_info_by_did(&self, did: &Did) -> Result<Option<UserEmailInfo>, DbError> {
        let row = sqlx::query!(
            "SELECT id, handle, email, email_verified FROM users WHERE did = $1",
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(row.map(|r| UserEmailInfo {
            id: r.id,
            handle: Handle::from(r.handle),
            email: r.email,
            email_verified: r.email_verified,
        }))
    }

    async fn check_email_exists(
        &self,
        email: &str,
        exclude_user_id: Uuid,
    ) -> Result<bool, DbError> {
        let row = sqlx::query!(
            "SELECT 1 as one FROM users WHERE LOWER(email) = $1 AND id != $2",
            email.to_lowercase(),
            exclude_user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(row.is_some())
    }

    async fn update_email(&self, user_id: Uuid, email: &str) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE users SET email = $1, email_verified = FALSE, updated_at = NOW() WHERE id = $2",
            email,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn set_email_verified(&self, user_id: Uuid, verified: bool) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE users SET email_verified = $1, updated_at = NOW() WHERE id = $2",
            verified,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn check_email_verified_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<bool>, DbError> {
        let row = sqlx::query_scalar!(
            "SELECT email_verified FROM users WHERE did = $1 OR email = $1 OR handle = $1",
            identifier
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(row)
    }

    async fn check_channel_verified_by_did(
        &self,
        did: &Did,
        channel: CommsChannel,
    ) -> Result<Option<bool>, DbError> {
        let row = sqlx::query!(
            r#"SELECT
                email_verified,
                discord_verified,
                telegram_verified,
                signal_verified
            FROM users
            WHERE did = $1"#,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| match channel {
            CommsChannel::Email => r.email_verified,
            CommsChannel::Discord => r.discord_verified,
            CommsChannel::Telegram => r.telegram_verified,
            CommsChannel::Signal => r.signal_verified,
        }))
    }

    async fn admin_update_email(&self, did: &Did, email: &str) -> Result<u64, DbError> {
        let result = sqlx::query!(
            "UPDATE users SET email = $1 WHERE did = $2",
            email,
            did.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(result.rows_affected())
    }

    async fn admin_update_handle(&self, did: &Did, handle: &Handle) -> Result<u64, DbError> {
        let result = sqlx::query!(
            "UPDATE users SET handle = $1 WHERE did = $2",
            handle.as_str(),
            did.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(result.rows_affected())
    }

    async fn admin_update_password(&self, did: &Did, password_hash: &str) -> Result<u64, DbError> {
        let result = sqlx::query!(
            "UPDATE users SET password_hash = $1 WHERE did = $2",
            password_hash,
            did.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(result.rows_affected())
    }

    async fn get_notification_prefs(
        &self,
        did: &Did,
    ) -> Result<Option<NotificationPrefs>, DbError> {
        let row = sqlx::query!(
            r#"SELECT
                email,
                preferred_comms_channel as "preferred_channel!: CommsChannel",
                discord_id,
                discord_username,
                discord_verified,
                telegram_username,
                telegram_verified,
                telegram_chat_id,
                signal_username,
                signal_verified
            FROM users WHERE did = $1"#,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(row.map(|r| NotificationPrefs {
            email: r.email.unwrap_or_default(),
            preferred_channel: r.preferred_channel,
            discord_id: r.discord_id,
            discord_username: r.discord_username,
            discord_verified: r.discord_verified,
            telegram_username: r.telegram_username,
            telegram_verified: r.telegram_verified,
            telegram_chat_id: r.telegram_chat_id,
            signal_username: r.signal_username,
            signal_verified: r.signal_verified,
        }))
    }

    async fn get_id_handle_email_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserIdHandleEmail>, DbError> {
        let row = sqlx::query!(
            "SELECT id, handle, email FROM users WHERE did = $1",
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(row.map(|r| UserIdHandleEmail {
            id: r.id,
            handle: Handle::from(r.handle),
            email: r.email,
        }))
    }

    async fn update_preferred_comms_channel(
        &self,
        did: &Did,
        channel: CommsChannel,
    ) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE users SET preferred_comms_channel = $1, updated_at = NOW() WHERE did = $2",
            channel as CommsChannel,
            did.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn clear_discord(&self, user_id: Uuid) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE users SET discord_id = NULL, discord_username = NULL, discord_verified = FALSE, updated_at = NOW() WHERE id = $1",
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn clear_telegram(&self, user_id: Uuid) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE users SET telegram_username = NULL, telegram_verified = FALSE, telegram_chat_id = NULL, updated_at = NOW() WHERE id = $1",
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn clear_signal(&self, user_id: Uuid) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE users SET signal_username = NULL, signal_verified = FALSE, updated_at = NOW() WHERE id = $1",
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn get_verification_info(
        &self,
        did: &Did,
    ) -> Result<Option<UserVerificationInfo>, DbError> {
        let row = sqlx::query!(
            r#"SELECT id, handle, email, email_verified, discord_verified, telegram_verified, signal_verified
               FROM users WHERE did = $1"#,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(row.map(|r| UserVerificationInfo {
            id: r.id,
            handle: Handle::from(r.handle),
            email: r.email,
            channel_verification: ChannelVerificationStatus::from_db_row(
                r.email_verified,
                r.discord_verified,
                r.telegram_verified,
                r.signal_verified,
            ),
        }))
    }

    async fn verify_email_channel(&self, user_id: Uuid, email: &str) -> Result<bool, DbError> {
        sqlx::query!(
            "UPDATE users SET email = $1, email_verified = TRUE, updated_at = NOW() WHERE id = $2",
            email,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(true)
    }

    async fn verify_discord_channel(&self, user_id: Uuid, discord_id: &str) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE users SET discord_id = $1, discord_verified = TRUE, updated_at = NOW() WHERE id = $2",
            discord_id,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn verify_telegram_channel(
        &self,
        user_id: Uuid,
        telegram_username: &str,
    ) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE users SET telegram_username = $1, telegram_verified = TRUE, updated_at = NOW() WHERE id = $2",
            telegram_username,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn verify_signal_channel(
        &self,
        user_id: Uuid,
        signal_username: &str,
    ) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE users SET signal_username = $1, signal_verified = TRUE, updated_at = NOW() WHERE id = $2",
            signal_username,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn set_email_verified_flag(&self, user_id: Uuid) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE users SET email_verified = TRUE WHERE id = $1",
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn set_discord_verified_flag(&self, user_id: Uuid) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE users SET discord_verified = TRUE WHERE id = $1",
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn set_telegram_verified_flag(&self, user_id: Uuid) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE users SET telegram_verified = TRUE WHERE id = $1",
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn set_signal_verified_flag(&self, user_id: Uuid) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE users SET signal_verified = TRUE WHERE id = $1",
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn has_totp_enabled(&self, did: &Did) -> Result<bool, DbError> {
        let row = sqlx::query_scalar!(
            "SELECT verified FROM user_totp WHERE did = $1",
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(matches!(row, Some(true)))
    }

    async fn has_passkeys(&self, did: &Did) -> Result<bool, DbError> {
        let count = sqlx::query_scalar!(
            "SELECT COUNT(*) as count FROM passkeys WHERE did = $1",
            did.as_str()
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(count.unwrap_or(0) > 0)
    }

    async fn get_password_hash_by_did(&self, did: &Did) -> Result<Option<String>, DbError> {
        let row = sqlx::query_scalar!(
            "SELECT password_hash FROM users WHERE did = $1",
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.flatten())
    }

    async fn get_passkeys_for_user(&self, did: &Did) -> Result<Vec<StoredPasskey>, DbError> {
        let rows = sqlx::query!(
            r#"SELECT id, did, credential_id, public_key, sign_count, created_at, last_used,
                      friendly_name, aaguid, transports
               FROM passkeys WHERE did = $1 ORDER BY created_at DESC"#,
            did.as_str()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(rows
            .into_iter()
            .map(|r| StoredPasskey {
                id: r.id,
                did: Did::from(r.did),
                credential_id: r.credential_id,
                public_key: r.public_key,
                sign_count: r.sign_count,
                created_at: r.created_at,
                last_used: r.last_used,
                friendly_name: r.friendly_name,
                aaguid: r.aaguid,
                transports: r.transports,
            })
            .collect())
    }

    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<StoredPasskey>, DbError> {
        let row = sqlx::query!(
            r#"SELECT id, did, credential_id, public_key, sign_count, created_at, last_used,
                      friendly_name, aaguid, transports
               FROM passkeys WHERE credential_id = $1"#,
            credential_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| StoredPasskey {
            id: r.id,
            did: Did::from(r.did),
            credential_id: r.credential_id,
            public_key: r.public_key,
            sign_count: r.sign_count,
            created_at: r.created_at,
            last_used: r.last_used,
            friendly_name: r.friendly_name,
            aaguid: r.aaguid,
            transports: r.transports,
        }))
    }

    async fn save_passkey(
        &self,
        did: &Did,
        credential_id: &[u8],
        public_key: &[u8],
        friendly_name: Option<&str>,
    ) -> Result<Uuid, DbError> {
        let id = Uuid::new_v4();
        let aaguid: Option<Vec<u8>> = None;
        sqlx::query!(
            r#"INSERT INTO passkeys (id, did, credential_id, public_key, sign_count, friendly_name, aaguid)
               VALUES ($1, $2, $3, $4, 0, $5, $6)"#,
            id,
            did.as_str(),
            credential_id,
            public_key,
            friendly_name,
            aaguid,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(id)
    }

    async fn update_passkey_counter(
        &self,
        credential_id: &[u8],
        new_counter: i32,
    ) -> Result<bool, DbError> {
        let stored = self.get_passkey_by_credential_id(credential_id).await?;
        let Some(stored) = stored else {
            return Err(DbError::NotFound);
        };

        if new_counter > 0 && new_counter <= stored.sign_count {
            return Ok(false);
        }

        sqlx::query!(
            "UPDATE passkeys SET sign_count = $1, last_used = NOW() WHERE credential_id = $2",
            new_counter,
            credential_id,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(true)
    }

    async fn delete_passkey(&self, id: Uuid, did: &Did) -> Result<bool, DbError> {
        let result = sqlx::query!(
            "DELETE FROM passkeys WHERE id = $1 AND did = $2",
            id,
            did.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.rows_affected() > 0)
    }

    async fn update_passkey_name(&self, id: Uuid, did: &Did, name: &str) -> Result<bool, DbError> {
        let result = sqlx::query!(
            "UPDATE passkeys SET friendly_name = $1 WHERE id = $2 AND did = $3",
            name,
            id,
            did.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.rows_affected() > 0)
    }

    async fn save_webauthn_challenge(
        &self,
        did: &Did,
        challenge_type: WebauthnChallengeType,
        state_json: &str,
    ) -> Result<Uuid, DbError> {
        let id = Uuid::new_v4();
        let challenge = id.as_bytes().to_vec();
        let expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);
        sqlx::query!(
            r#"INSERT INTO webauthn_challenges (id, did, challenge, challenge_type, state_json, expires_at)
               VALUES ($1, $2, $3, $4, $5, $6)"#,
            id,
            did.as_str(),
            challenge,
            challenge_type.as_str(),
            state_json,
            expires_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(id)
    }

    async fn load_webauthn_challenge(
        &self,
        did: &Did,
        challenge_type: WebauthnChallengeType,
    ) -> Result<Option<String>, DbError> {
        let row = sqlx::query_scalar!(
            r#"SELECT state_json FROM webauthn_challenges
               WHERE did = $1 AND challenge_type = $2 AND expires_at > NOW()
               ORDER BY created_at DESC LIMIT 1"#,
            did.as_str(),
            challenge_type.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row)
    }

    async fn delete_webauthn_challenge(
        &self,
        did: &Did,
        challenge_type: WebauthnChallengeType,
    ) -> Result<(), DbError> {
        sqlx::query!(
            "DELETE FROM webauthn_challenges WHERE did = $1 AND challenge_type = $2",
            did.as_str(),
            challenge_type.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn get_totp_record(&self, did: &Did) -> Result<Option<TotpRecord>, DbError> {
        let row = sqlx::query!(
            "SELECT secret_encrypted, encryption_version, verified FROM user_totp WHERE did = $1",
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| TotpRecord {
            secret_encrypted: r.secret_encrypted,
            encryption_version: r.encryption_version,
            verified: r.verified,
        }))
    }

    async fn get_totp_record_state(&self, did: &Did) -> Result<Option<TotpRecordState>, DbError> {
        self.get_totp_record(did)
            .await
            .map(|opt| opt.map(TotpRecordState::from))
    }

    async fn upsert_totp_secret(
        &self,
        did: &Did,
        secret_encrypted: &[u8],
        encryption_version: i32,
    ) -> Result<(), DbError> {
        sqlx::query!(
            r#"INSERT INTO user_totp (did, secret_encrypted, encryption_version, verified, created_at)
               VALUES ($1, $2, $3, false, NOW())
               ON CONFLICT (did) DO UPDATE SET
                   secret_encrypted = $2,
                   encryption_version = $3,
                   verified = false,
                   created_at = NOW(),
                   last_used = NULL"#,
            did.as_str(),
            secret_encrypted,
            encryption_version
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn set_totp_verified(&self, did: &Did) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE user_totp SET verified = true, last_used = NOW() WHERE did = $1",
            did.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn update_totp_last_used(&self, did: &Did) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE user_totp SET last_used = NOW() WHERE did = $1",
            did.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn delete_totp(&self, did: &Did) -> Result<(), DbError> {
        sqlx::query!("DELETE FROM user_totp WHERE did = $1", did.as_str())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn get_unused_backup_codes(&self, did: &Did) -> Result<Vec<StoredBackupCode>, DbError> {
        let rows = sqlx::query!(
            "SELECT id, code_hash FROM backup_codes WHERE did = $1 AND used_at IS NULL",
            did.as_str()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(rows
            .into_iter()
            .map(|r| StoredBackupCode {
                id: r.id,
                code_hash: r.code_hash,
            })
            .collect())
    }

    async fn mark_backup_code_used(&self, code_id: Uuid) -> Result<bool, DbError> {
        let result = sqlx::query!(
            "UPDATE backup_codes SET used_at = NOW() WHERE id = $1",
            code_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.rows_affected() > 0)
    }

    async fn count_unused_backup_codes(&self, did: &Did) -> Result<i64, DbError> {
        let row = sqlx::query!(
            "SELECT COUNT(*) as count FROM backup_codes WHERE did = $1 AND used_at IS NULL",
            did.as_str()
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.count.unwrap_or(0))
    }

    async fn delete_backup_codes(&self, did: &Did) -> Result<u64, DbError> {
        let result = sqlx::query!("DELETE FROM backup_codes WHERE did = $1", did.as_str())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(result.rows_affected())
    }

    async fn insert_backup_codes(&self, did: &Did, code_hashes: &[String]) -> Result<(), DbError> {
        sqlx::query!(
            r#"
            INSERT INTO backup_codes (did, code_hash, created_at)
            SELECT $1, hash, NOW() FROM UNNEST($2::text[]) AS t(hash)
            "#,
            did.as_str(),
            code_hashes
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn enable_totp_with_backup_codes(
        &self,
        did: &Did,
        code_hashes: &[String],
    ) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;

        sqlx::query!(
            "UPDATE user_totp SET verified = true, last_used = NOW() WHERE did = $1",
            did.as_str()
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;

        sqlx::query!("DELETE FROM backup_codes WHERE did = $1", did.as_str())
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;

        sqlx::query!(
            r#"
            INSERT INTO backup_codes (did, code_hash, created_at)
            SELECT $1, hash, NOW() FROM UNNEST($2::text[]) AS t(hash)
            "#,
            did.as_str(),
            code_hashes
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;

        tx.commit().await.map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn delete_totp_and_backup_codes(&self, did: &Did) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;

        sqlx::query!("DELETE FROM user_totp WHERE did = $1", did.as_str())
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;

        sqlx::query!("DELETE FROM backup_codes WHERE did = $1", did.as_str())
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;

        tx.commit().await.map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn replace_backup_codes(&self, did: &Did, code_hashes: &[String]) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;

        sqlx::query!("DELETE FROM backup_codes WHERE did = $1", did.as_str())
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;

        sqlx::query!(
            r#"
            INSERT INTO backup_codes (did, code_hash, created_at)
            SELECT $1, hash, NOW() FROM UNNEST($2::text[]) AS t(hash)
            "#,
            did.as_str(),
            code_hashes
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;

        tx.commit().await.map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn get_login_check_by_handle_or_email(
        &self,
        identifier: &str,
    ) -> Result<Option<UserLoginCheck>, DbError> {
        sqlx::query!(
            "SELECT did, password_hash FROM users WHERE handle = $1 OR email = $1",
            identifier
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)
        .map(|opt| {
            opt.map(|r| UserLoginCheck {
                did: Did::from(r.did),
                password_hash: r.password_hash,
            })
        })
    }

    async fn get_login_info_by_handle_or_email(
        &self,
        identifier: &str,
    ) -> Result<Option<UserLoginInfo>, DbError> {
        sqlx::query!(
            r#"
            SELECT id, did, email, password_hash, password_required, two_factor_enabled,
                   preferred_comms_channel as "preferred_comms_channel!: CommsChannel",
                   deactivated_at, takedown_ref,
                   email_verified, discord_verified, telegram_verified, signal_verified,
                   account_type as "account_type!: AccountType"
            FROM users
            WHERE handle = $1 OR email = $1
            "#,
            identifier
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)
        .map(|opt| {
            opt.map(|row| UserLoginInfo {
                id: row.id,
                did: Did::from(row.did),
                email: row.email,
                password_hash: row.password_hash,
                password_required: row.password_required,
                two_factor_enabled: row.two_factor_enabled,
                preferred_comms_channel: row.preferred_comms_channel,
                deactivated_at: row.deactivated_at,
                takedown_ref: row.takedown_ref,
                channel_verification: ChannelVerificationStatus::from_db_row(
                    row.email_verified,
                    row.discord_verified,
                    row.telegram_verified,
                    row.signal_verified,
                ),
                account_type: row.account_type,
            })
        })
    }

    async fn get_2fa_status_by_did(&self, did: &Did) -> Result<Option<User2faStatus>, DbError> {
        sqlx::query!(
            r#"
            SELECT id, two_factor_enabled,
                   preferred_comms_channel as "preferred_comms_channel!: CommsChannel",
                   email_verified, discord_verified, telegram_verified, signal_verified
            FROM users
            WHERE did = $1
            "#,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)
        .map(|opt| {
            opt.map(|row| User2faStatus {
                id: row.id,
                two_factor_enabled: row.two_factor_enabled,
                preferred_comms_channel: row.preferred_comms_channel,
                channel_verification: ChannelVerificationStatus::from_db_row(
                    row.email_verified,
                    row.discord_verified,
                    row.telegram_verified,
                    row.signal_verified,
                ),
            })
        })
    }

    async fn get_session_info_by_did(&self, did: &Did) -> Result<Option<UserSessionInfo>, DbError> {
        sqlx::query!(
            r#"
            SELECT u.handle, u.email, u.email_verified, u.is_admin, u.deactivated_at, u.takedown_ref,
                   u.preferred_locale,
                   u.preferred_comms_channel as "preferred_comms_channel!: CommsChannel",
                   u.discord_verified, u.telegram_verified, u.signal_verified,
                   u.migrated_to_pds, u.migrated_at,
                   (SELECT verified FROM user_totp WHERE did = u.did) as totp_enabled,
                   COALESCE((SELECT (value_json)::boolean FROM account_preferences WHERE user_id = u.id AND name = 'email_auth_factor' ORDER BY created_at DESC LIMIT 1), false) as "email_2fa_enabled!"
            FROM users u
            WHERE u.did = $1
            "#,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)
        .map(|opt| {
            opt.map(|row| UserSessionInfo {
                handle: Handle::from(row.handle),
                email: row.email,
                is_admin: row.is_admin,
                deactivated_at: row.deactivated_at,
                takedown_ref: row.takedown_ref,
                preferred_locale: row.preferred_locale,
                preferred_comms_channel: row.preferred_comms_channel,
                channel_verification: ChannelVerificationStatus::from_db_row(
                    row.email_verified,
                    row.discord_verified,
                    row.telegram_verified,
                    row.signal_verified,
                ),
                migrated_to_pds: row.migrated_to_pds,
                migrated_at: row.migrated_at,
                totp_enabled: row.totp_enabled.unwrap_or(false),
                email_2fa_enabled: row.email_2fa_enabled,
            })
        })
    }

    async fn get_legacy_login_pref(
        &self,
        did: &Did,
    ) -> Result<Option<UserLegacyLoginPref>, DbError> {
        sqlx::query!(
            r#"
            SELECT u.allow_legacy_login,
                   (EXISTS(SELECT 1 FROM user_totp t WHERE t.did = u.did AND t.verified = TRUE) OR
                    EXISTS(SELECT 1 FROM passkeys p WHERE p.did = u.did)) as "has_mfa!"
            FROM users u
            WHERE u.did = $1
            "#,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)
        .map(|opt| {
            opt.map(|row| UserLegacyLoginPref {
                allow_legacy_login: row.allow_legacy_login,
                has_mfa: row.has_mfa,
            })
        })
    }

    async fn update_legacy_login(&self, did: &Did, allow: bool) -> Result<bool, DbError> {
        let result = sqlx::query!(
            "UPDATE users SET allow_legacy_login = $1 WHERE did = $2 RETURNING did",
            allow,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(result.is_some())
    }

    async fn update_locale(&self, did: &Did, locale: &str) -> Result<bool, DbError> {
        let result = sqlx::query!(
            "UPDATE users SET preferred_locale = $1 WHERE did = $2 RETURNING did",
            locale,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(result.is_some())
    }

    async fn get_login_full_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<UserLoginFull>, DbError> {
        sqlx::query!(
            r#"SELECT
                u.id, u.did, u.handle, u.password_hash, u.email, u.deactivated_at, u.takedown_ref,
                u.email_verified, u.discord_verified, u.telegram_verified, u.signal_verified,
                u.allow_legacy_login, u.migrated_to_pds,
                u.preferred_comms_channel as "preferred_comms_channel: CommsChannel",
                k.key_bytes, k.encryption_version,
                (SELECT verified FROM user_totp WHERE did = u.did) as totp_enabled,
                COALESCE((SELECT (value_json)::boolean FROM account_preferences WHERE user_id = u.id AND name = 'email_auth_factor' ORDER BY created_at DESC LIMIT 1), false) as "email_2fa_enabled!"
            FROM users u
            JOIN user_keys k ON u.id = k.user_id
            WHERE u.handle = $1 OR u.email = $1 OR u.did = $1"#,
            identifier
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)
        .map(|opt| {
            opt.map(|row| UserLoginFull {
                id: row.id,
                did: Did::from(row.did),
                handle: Handle::from(row.handle),
                password_hash: row.password_hash,
                email: row.email,
                deactivated_at: row.deactivated_at,
                takedown_ref: row.takedown_ref,
                channel_verification: ChannelVerificationStatus::from_db_row(
                    row.email_verified,
                    row.discord_verified,
                    row.telegram_verified,
                    row.signal_verified,
                ),
                allow_legacy_login: row.allow_legacy_login,
                migrated_to_pds: row.migrated_to_pds,
                preferred_comms_channel: row.preferred_comms_channel,
                key_bytes: row.key_bytes,
                encryption_version: row.encryption_version,
                totp_enabled: row.totp_enabled.unwrap_or(false),
                email_2fa_enabled: row.email_2fa_enabled,
            })
        })
    }

    async fn get_confirm_signup_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserConfirmSignup>, DbError> {
        sqlx::query!(
            r#"SELECT
                u.id, u.did, u.handle, u.email,
                u.preferred_comms_channel as "channel: CommsChannel",
                u.discord_username, u.telegram_username, u.signal_username,
                k.key_bytes, k.encryption_version
            FROM users u
            JOIN user_keys k ON u.id = k.user_id
            WHERE u.did = $1"#,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)
        .map(|opt| {
            opt.map(|row| UserConfirmSignup {
                id: row.id,
                did: Did::from(row.did),
                handle: Handle::from(row.handle),
                email: row.email,
                channel: row.channel,
                discord_username: row.discord_username,
                telegram_username: row.telegram_username,
                signal_username: row.signal_username,
                key_bytes: row.key_bytes,
                encryption_version: row.encryption_version,
            })
        })
    }

    async fn get_resend_verification_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserResendVerification>, DbError> {
        sqlx::query!(
            r#"SELECT
                id, handle, email,
                preferred_comms_channel as "channel: CommsChannel",
                discord_username, telegram_username, signal_username,
                email_verified, discord_verified, telegram_verified, signal_verified
            FROM users
            WHERE did = $1"#,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)
        .map(|opt| {
            opt.map(|row| UserResendVerification {
                id: row.id,
                handle: Handle::from(row.handle),
                email: row.email,
                channel: row.channel,
                discord_username: row.discord_username,
                telegram_username: row.telegram_username,
                signal_username: row.signal_username,
                channel_verification: ChannelVerificationStatus::from_db_row(
                    row.email_verified,
                    row.discord_verified,
                    row.telegram_verified,
                    row.signal_verified,
                ),
            })
        })
    }

    async fn set_channel_verified(&self, did: &Did, channel: CommsChannel) -> Result<(), DbError> {
        let column = match channel {
            CommsChannel::Email => "email_verified",
            CommsChannel::Discord => "discord_verified",
            CommsChannel::Telegram => "telegram_verified",
            CommsChannel::Signal => "signal_verified",
        };
        let query = format!("UPDATE users SET {} = TRUE WHERE did = $1", column);
        sqlx::query(&query)
            .bind(did.as_str())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn get_id_by_email_or_handle(
        &self,
        email: &str,
        handle: &str,
    ) -> Result<Option<Uuid>, DbError> {
        sqlx::query_scalar!(
            "SELECT id FROM users WHERE LOWER(email) = $1 OR handle = $2",
            email,
            handle
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)
    }

    async fn count_accounts_by_email(&self, email: &str) -> Result<i64, DbError> {
        sqlx::query_scalar!(
            "SELECT COUNT(*) FROM users WHERE LOWER(email) = LOWER($1) AND deactivated_at IS NULL",
            email
        )
        .fetch_one(&self.pool)
        .await
        .map(|c| c.unwrap_or(0))
        .map_err(map_sqlx_error)
    }

    async fn count_accounts_by_comms_identifier(
        &self,
        channel: CommsChannel,
        identifier: &str,
    ) -> Result<i64, DbError> {
        let query = match channel {
            CommsChannel::Email => {
                "SELECT COUNT(*) FROM users WHERE LOWER(email) = LOWER($1) AND deactivated_at IS NULL"
            }
            CommsChannel::Discord => {
                "SELECT COUNT(*) FROM users WHERE LOWER(discord_username) = LOWER($1) AND deactivated_at IS NULL"
            }
            CommsChannel::Telegram => {
                "SELECT COUNT(*) FROM users WHERE LOWER(telegram_username) = LOWER($1) AND deactivated_at IS NULL"
            }
            CommsChannel::Signal => {
                "SELECT COUNT(*) FROM users WHERE signal_username = $1 AND deactivated_at IS NULL"
            }
        };
        sqlx::query_scalar(query)
            .bind(identifier)
            .fetch_one(&self.pool)
            .await
            .map(|c: Option<i64>| c.unwrap_or(0))
            .map_err(map_sqlx_error)
    }

    async fn get_handles_by_email(&self, email: &str) -> Result<Vec<Handle>, DbError> {
        sqlx::query_scalar!(
            "SELECT handle FROM users WHERE LOWER(email) = LOWER($1) AND deactivated_at IS NULL ORDER BY created_at DESC",
            email
        )
        .fetch_all(&self.pool)
        .await
        .map(|handles| handles.into_iter().map(Handle::from).collect())
        .map_err(map_sqlx_error)
    }

    async fn set_password_reset_code(
        &self,
        user_id: Uuid,
        code: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE users SET password_reset_code = $1, password_reset_code_expires_at = $2 WHERE id = $3",
            code,
            expires_at,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn get_user_by_reset_code(
        &self,
        code: &str,
    ) -> Result<Option<UserResetCodeInfo>, DbError> {
        sqlx::query!(
            "SELECT id, did, preferred_comms_channel as \"preferred_comms_channel: CommsChannel\", password_reset_code_expires_at FROM users WHERE password_reset_code = $1",
            code
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)
        .map(|opt| {
            opt.map(|row| UserResetCodeInfo {
                id: row.id,
                did: Did::from(row.did),
                preferred_comms_channel: row.preferred_comms_channel,
                expires_at: row.password_reset_code_expires_at,
            })
        })
    }

    async fn clear_password_reset_code(&self, user_id: Uuid) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE users SET password_reset_code = NULL, password_reset_code_expires_at = NULL WHERE id = $1",
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn get_id_and_password_hash_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserIdAndPasswordHash>, DbError> {
        sqlx::query!(
            "SELECT id, password_hash FROM users WHERE did = $1",
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)
        .map(|opt| {
            opt.and_then(|row| {
                row.password_hash.map(|hash| UserIdAndPasswordHash {
                    id: row.id,
                    password_hash: hash,
                })
            })
        })
    }

    async fn update_password_hash(
        &self,
        user_id: Uuid,
        password_hash: &str,
    ) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE users SET password_hash = $1 WHERE id = $2",
            password_hash,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn reset_password_with_sessions(
        &self,
        user_id: Uuid,
        password_hash: &str,
    ) -> Result<PasswordResetResult, DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;

        sqlx::query!(
            "UPDATE users SET password_hash = $1, password_reset_code = NULL, password_reset_code_expires_at = NULL, password_required = TRUE WHERE id = $2",
            password_hash,
            user_id
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;

        let user_did = sqlx::query_scalar!("SELECT did FROM users WHERE id = $1", user_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;

        let session_jtis: Vec<String> = sqlx::query_scalar!(
            "SELECT access_jti FROM session_tokens WHERE did = $1",
            user_did
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;

        sqlx::query!("DELETE FROM session_tokens WHERE did = $1", user_did)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;

        tx.commit().await.map_err(map_sqlx_error)?;

        Ok(PasswordResetResult {
            did: Did::from(user_did),
            session_jtis,
        })
    }

    async fn activate_account(&self, did: &Did) -> Result<bool, DbError> {
        let result = sqlx::query!(
            "UPDATE users SET deactivated_at = NULL WHERE did = $1",
            did.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn deactivate_account(
        &self,
        did: &Did,
        delete_after: Option<DateTime<Utc>>,
    ) -> Result<bool, DbError> {
        let result = sqlx::query!(
            "UPDATE users SET deactivated_at = NOW(), delete_after = $2 WHERE did = $1",
            did.as_str(),
            delete_after
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn has_password_by_did(&self, did: &Did) -> Result<Option<bool>, DbError> {
        sqlx::query_scalar!(
            "SELECT password_hash IS NOT NULL as has_password FROM users WHERE did = $1",
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)
        .map(|opt| opt.flatten())
    }

    async fn get_password_info_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserPasswordInfo>, DbError> {
        sqlx::query!(
            "SELECT id, password_hash FROM users WHERE did = $1",
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)
        .map(|opt| {
            opt.map(|row| UserPasswordInfo {
                id: row.id,
                password_hash: row.password_hash,
            })
        })
    }

    async fn remove_user_password(&self, user_id: Uuid) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE users SET password_hash = NULL, password_required = FALSE WHERE id = $1",
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn set_new_user_password(
        &self,
        user_id: Uuid,
        password_hash: &str,
    ) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE users SET password_hash = $1, password_required = TRUE WHERE id = $2",
            password_hash,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn is_account_active_by_did(&self, did: &Did) -> Result<Option<bool>, DbError> {
        sqlx::query_scalar!(
            "SELECT deactivated_at IS NULL as is_active FROM users WHERE did = $1",
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)
        .map(|opt| opt.flatten())
    }

    async fn get_user_for_deletion(&self, did: &Did) -> Result<Option<UserForDeletion>, DbError> {
        sqlx::query!(
            "SELECT id, password_hash, handle FROM users WHERE did = $1",
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)
        .map(|opt| {
            opt.map(|row| UserForDeletion {
                id: row.id,
                password_hash: row.password_hash,
                handle: Handle::from(row.handle),
            })
        })
    }

    async fn get_user_key_by_did(&self, did: &Did) -> Result<Option<UserKeyInfo>, DbError> {
        sqlx::query!(
            r#"SELECT uk.key_bytes, uk.encryption_version
               FROM user_keys uk
               JOIN users u ON uk.user_id = u.id
               WHERE u.did = $1"#,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)
        .map(|opt| {
            opt.map(|row| UserKeyInfo {
                key_bytes: row.key_bytes,
                encryption_version: row.encryption_version,
            })
        })
    }

    async fn delete_account_complete(&self, user_id: Uuid, did: &Did) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
        sqlx::query!("DELETE FROM session_tokens WHERE did = $1", did.as_str())
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        sqlx::query!("DELETE FROM records WHERE repo_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        sqlx::query!("DELETE FROM repos WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        sqlx::query!("DELETE FROM blobs WHERE created_by_user = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        sqlx::query!("DELETE FROM user_keys WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        sqlx::query!("DELETE FROM app_passwords WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        sqlx::query!(
            "DELETE FROM account_deletion_requests WHERE did = $1",
            did.as_str()
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;
        sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        tx.commit().await.map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn set_user_takedown(
        &self,
        did: &Did,
        takedown_ref: Option<&str>,
    ) -> Result<bool, DbError> {
        let result = sqlx::query!(
            "UPDATE users SET takedown_ref = $1 WHERE did = $2",
            takedown_ref,
            did.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn admin_delete_account_complete(&self, user_id: Uuid, did: &Did) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
        sqlx::query!("DELETE FROM session_tokens WHERE did = $1", did.as_str())
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        sqlx::query!(
            "DELETE FROM used_refresh_tokens WHERE session_id IN (SELECT id FROM session_tokens WHERE did = $1)",
            did.as_str()
        )
        .execute(&mut *tx)
        .await
        .ok();
        sqlx::query!("DELETE FROM records WHERE repo_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        sqlx::query!("DELETE FROM repos WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        sqlx::query!("DELETE FROM blobs WHERE created_by_user = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        sqlx::query!("DELETE FROM app_passwords WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        sqlx::query!(
            "DELETE FROM invite_code_uses WHERE used_by_user = $1",
            user_id
        )
        .execute(&mut *tx)
        .await
        .ok();
        sqlx::query!(
            "DELETE FROM invite_codes WHERE created_by_user = $1",
            user_id
        )
        .execute(&mut *tx)
        .await
        .ok();
        sqlx::query!("DELETE FROM user_keys WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        tx.commit().await.map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn get_user_for_did_doc(&self, did: &Did) -> Result<Option<UserForDidDoc>, DbError> {
        let row = sqlx::query!(
            "SELECT id, handle, deactivated_at FROM users WHERE did = $1",
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| UserForDidDoc {
            id: r.id,
            handle: Handle::from(r.handle),
            deactivated_at: r.deactivated_at,
        }))
    }

    async fn get_user_for_did_doc_build(
        &self,
        did: &Did,
    ) -> Result<Option<UserForDidDocBuild>, DbError> {
        let row = sqlx::query!(
            "SELECT id, handle, migrated_to_pds FROM users WHERE did = $1",
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| UserForDidDocBuild {
            id: r.id,
            handle: Handle::from(r.handle),
            migrated_to_pds: r.migrated_to_pds,
        }))
    }

    async fn upsert_did_web_overrides(
        &self,
        user_id: Uuid,
        verification_methods: Option<serde_json::Value>,
        also_known_as: Option<Vec<String>>,
    ) -> Result<(), DbError> {
        let now = chrono::Utc::now();
        sqlx::query!(
            r#"
            INSERT INTO did_web_overrides (user_id, verification_methods, also_known_as, updated_at)
            VALUES ($1, COALESCE($2, '[]'::jsonb), COALESCE($3, '{}'::text[]), $4)
            ON CONFLICT (user_id) DO UPDATE SET
                verification_methods = CASE WHEN $2 IS NOT NULL THEN $2 ELSE did_web_overrides.verification_methods END,
                also_known_as = CASE WHEN $3 IS NOT NULL THEN $3 ELSE did_web_overrides.also_known_as END,
                updated_at = $4
            "#,
            user_id,
            verification_methods,
            also_known_as.as_deref(),
            now
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn update_migrated_to_pds(&self, did: &Did, endpoint: &str) -> Result<(), DbError> {
        let now = chrono::Utc::now();
        sqlx::query!(
            "UPDATE users SET migrated_to_pds = $1, migrated_at = $2 WHERE did = $3",
            endpoint,
            now,
            did.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn get_user_for_passkey_setup(
        &self,
        did: &Did,
    ) -> Result<Option<UserForPasskeySetup>, DbError> {
        let row = sqlx::query!(
            r#"SELECT id, handle, recovery_token, recovery_token_expires_at, password_required
               FROM users WHERE did = $1"#,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| UserForPasskeySetup {
            id: r.id,
            handle: Handle::from(r.handle),
            recovery_token: r.recovery_token,
            recovery_token_expires_at: r.recovery_token_expires_at,
            password_required: r.password_required,
        }))
    }

    async fn get_user_for_passkey_recovery(
        &self,
        identifier: &str,
        normalized_handle: &str,
    ) -> Result<Option<UserForPasskeyRecovery>, DbError> {
        let row = sqlx::query!(
            "SELECT id, did, handle, password_required FROM users WHERE LOWER(email) = $1 OR handle = $2",
            identifier,
            normalized_handle
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| UserForPasskeyRecovery {
            id: r.id,
            did: Did::from(r.did),
            handle: Handle::from(r.handle),
            password_required: r.password_required,
        }))
    }

    async fn set_recovery_token(
        &self,
        did: &Did,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE users SET recovery_token = $1, recovery_token_expires_at = $2 WHERE did = $3",
            token_hash,
            expires_at,
            did.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn get_user_for_recovery(&self, did: &Did) -> Result<Option<UserForRecovery>, DbError> {
        let row = sqlx::query!(
            "SELECT id, did, preferred_comms_channel as \"preferred_comms_channel: CommsChannel\", recovery_token, recovery_token_expires_at FROM users WHERE did = $1",
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| UserForRecovery {
            id: r.id,
            did: Did::from(r.did),
            preferred_comms_channel: r.preferred_comms_channel,
            recovery_token: r.recovery_token,
            recovery_token_expires_at: r.recovery_token_expires_at,
        }))
    }

    async fn get_accounts_scheduled_for_deletion(
        &self,
        limit: i64,
    ) -> Result<Vec<tranquil_db_traits::ScheduledDeletionAccount>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, did, handle
            FROM users
            WHERE delete_after IS NOT NULL
              AND delete_after < NOW()
              AND deactivated_at IS NOT NULL
            LIMIT $1
            "#,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(rows
            .into_iter()
            .map(|r| tranquil_db_traits::ScheduledDeletionAccount {
                id: r.id,
                did: Did::from(r.did),
                handle: Handle::from(r.handle),
            })
            .collect())
    }

    async fn delete_account_with_firehose(&self, user_id: Uuid, did: &Did) -> Result<i64, DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;

        sqlx::query!("DELETE FROM blobs WHERE created_by_user = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;

        sqlx::query!("DELETE FROM record_blobs WHERE repo_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;

        sqlx::query!("DELETE FROM records WHERE repo_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;

        sqlx::query!("DELETE FROM repos WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;

        sqlx::query!("DELETE FROM user_blocks WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;

        sqlx::query!("DELETE FROM user_keys WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;

        sqlx::query!("DELETE FROM session_tokens WHERE did = $1", did.as_str())
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;

        sqlx::query!("DELETE FROM app_passwords WHERE user_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;

        sqlx::query!("DELETE FROM passkeys WHERE did = $1", did.as_str())
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;

        sqlx::query!("DELETE FROM user_totp WHERE did = $1", did.as_str())
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;

        sqlx::query!("DELETE FROM backup_codes WHERE did = $1", did.as_str())
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;

        sqlx::query!(
            "DELETE FROM webauthn_challenges WHERE did = $1",
            did.as_str()
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;

        sqlx::query!(
            "DELETE FROM account_deletion_requests WHERE did = $1",
            did.as_str()
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;

        sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;

        let account_seq: i64 = sqlx::query_scalar!(
            r#"
            INSERT INTO repo_seq (did, event_type, active, status)
            VALUES ($1, 'account', false, 'deleted')
            RETURNING seq
            "#,
            did.as_str()
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;

        sqlx::query!(
            "DELETE FROM repo_seq WHERE did = $1 AND seq != $2",
            did.as_str(),
            account_seq
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;

        tx.commit().await.map_err(map_sqlx_error)?;

        sqlx::query(&format!("NOTIFY repo_updates, '{}'", account_seq))
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(account_seq)
    }

    async fn create_password_account(
        &self,
        input: &tranquil_db_traits::CreatePasswordAccountInput,
    ) -> Result<
        tranquil_db_traits::CreatePasswordAccountResult,
        tranquil_db_traits::CreateAccountError,
    > {
        tracing::info!(did = %input.did, handle = %input.handle, "create_password_account: starting transaction");
        let mut tx = self.pool.begin().await.map_err(|e: sqlx::Error| {
            tracing::error!(
                "create_password_account: failed to begin transaction: {}",
                e
            );
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        let is_first_user: bool = sqlx::query_scalar!("SELECT COUNT(*) as count FROM users")
            .fetch_one(&mut *tx)
            .await
            .map(|c| c.unwrap_or(0) == 0)
            .unwrap_or(false);

        let user_insert: Result<(uuid::Uuid,), _> = sqlx::query_as(
            r#"INSERT INTO users (
                handle, email, did, password_hash,
                preferred_comms_channel,
                discord_username, telegram_username, signal_username,
                is_admin, deactivated_at, email_verified
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, FALSE) RETURNING id"#,
        )
        .bind(input.handle.as_str())
        .bind(&input.email)
        .bind(input.did.as_str())
        .bind(&input.password_hash)
        .bind(input.preferred_comms_channel)
        .bind(&input.discord_username)
        .bind(&input.telegram_username)
        .bind(&input.signal_username)
        .bind(is_first_user)
        .bind(input.deactivated_at)
        .fetch_one(&mut *tx)
        .await;

        let user_id = match user_insert {
            Ok((id,)) => {
                tracing::info!(did = %input.did, user_id = %id, "create_password_account: user row inserted");
                id
            }
            Err(e) => {
                tracing::error!(did = %input.did, error = %e, "create_password_account: user insert failed");
                if let Some(db_err) = e.as_database_error()
                    && db_err.code().as_deref() == Some("23505")
                {
                    let constraint = db_err.constraint().unwrap_or("");
                    if constraint.contains("handle") {
                        return Err(tranquil_db_traits::CreateAccountError::HandleTaken);
                    } else if constraint.contains("email") {
                        return Err(tranquil_db_traits::CreateAccountError::EmailTaken);
                    } else if constraint.contains("did") {
                        return Err(tranquil_db_traits::CreateAccountError::DidExists);
                    }
                }
                return Err(tranquil_db_traits::CreateAccountError::Database(
                    e.to_string(),
                ));
            }
        };

        sqlx::query!(
            "INSERT INTO user_keys (user_id, key_bytes, encryption_version, encrypted_at) VALUES ($1, $2, $3, NOW())",
            user_id,
            &input.encrypted_key_bytes[..],
            input.encryption_version
        )
        .execute(&mut *tx)
        .await
        .map_err(|e: sqlx::Error| tranquil_db_traits::CreateAccountError::Database(e.to_string()))?;

        if let Some(key_id) = input.reserved_key_id {
            sqlx::query!(
                "UPDATE reserved_signing_keys SET used_at = NOW() WHERE id = $1",
                key_id
            )
            .execute(&mut *tx)
            .await
            .map_err(|e: sqlx::Error| {
                tranquil_db_traits::CreateAccountError::Database(e.to_string())
            })?;
        }

        sqlx::query!(
            "INSERT INTO repos (user_id, repo_root_cid, repo_rev) VALUES ($1, $2, $3)",
            user_id,
            input.commit_cid,
            input.repo_rev
        )
        .execute(&mut *tx)
        .await
        .map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        sqlx::query(
            r#"
            INSERT INTO user_blocks (user_id, block_cid, repo_rev)
            SELECT $1, block_cid, $3 FROM UNNEST($2::bytea[]) AS t(block_cid)
            ON CONFLICT (user_id, block_cid) DO NOTHING
            "#,
        )
        .bind(user_id)
        .bind(&input.genesis_block_cids)
        .bind(&input.repo_rev)
        .execute(&mut *tx)
        .await
        .map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        if let Some(code) = &input.invite_code {
            let _ = sqlx::query!(
                "UPDATE invite_codes SET available_uses = available_uses - 1 WHERE code = $1",
                code
            )
            .execute(&mut *tx)
            .await;

            let _ = sqlx::query!(
                "INSERT INTO invite_code_uses (code, used_by_user) VALUES ($1, $2)",
                code,
                user_id
            )
            .execute(&mut *tx)
            .await;
        }

        if let Some(birthdate_pref) = &input.birthdate_pref {
            let _ = sqlx::query!(
                "INSERT INTO account_preferences (user_id, name, value_json) VALUES ($1, $2, $3)",
                user_id,
                "app.bsky.actor.defs#personalDetailsPref",
                birthdate_pref
            )
            .execute(&mut *tx)
            .await;
        }

        tracing::info!(did = %input.did, user_id = %user_id, "create_password_account: committing transaction");
        tx.commit().await.map_err(|e: sqlx::Error| {
            tracing::error!(did = %input.did, user_id = %user_id, error = %e, "create_password_account: commit failed");
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;
        tracing::info!(did = %input.did, user_id = %user_id, "create_password_account: transaction committed successfully");

        Ok(tranquil_db_traits::CreatePasswordAccountResult {
            user_id,
            is_admin: is_first_user,
        })
    }

    async fn create_delegated_account(
        &self,
        input: &tranquil_db_traits::CreateDelegatedAccountInput,
    ) -> Result<uuid::Uuid, tranquil_db_traits::CreateAccountError> {
        let mut tx = self.pool.begin().await.map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        let user_insert: Result<(uuid::Uuid,), _> = sqlx::query_as(
            r#"INSERT INTO users (
                handle, email, did, password_hash, password_required,
                account_type, preferred_comms_channel
            ) VALUES ($1, $2, $3, NULL, FALSE, 'delegated'::account_type, 'email'::comms_channel) RETURNING id"#,
        )
        .bind(input.handle.as_str())
        .bind(&input.email)
        .bind(input.did.as_str())
        .fetch_one(&mut *tx)
        .await;

        let user_id = match user_insert {
            Ok((id,)) => id,
            Err(e) => {
                if let Some(db_err) = e.as_database_error()
                    && db_err.code().as_deref() == Some("23505")
                {
                    let constraint = db_err.constraint().unwrap_or("");
                    if constraint.contains("handle") {
                        return Err(tranquil_db_traits::CreateAccountError::HandleTaken);
                    } else if constraint.contains("email") {
                        return Err(tranquil_db_traits::CreateAccountError::EmailTaken);
                    }
                }
                return Err(tranquil_db_traits::CreateAccountError::Database(
                    e.to_string(),
                ));
            }
        };

        sqlx::query!(
            "INSERT INTO user_keys (user_id, key_bytes, encryption_version, encrypted_at) VALUES ($1, $2, $3, NOW())",
            user_id,
            &input.encrypted_key_bytes[..],
            input.encryption_version
        )
        .execute(&mut *tx)
        .await
        .map_err(|e: sqlx::Error| tranquil_db_traits::CreateAccountError::Database(e.to_string()))?;

        sqlx::query!(
            r#"INSERT INTO account_delegations (delegated_did, controller_did, granted_scopes, granted_by)
               VALUES ($1, $2, $3, $4)"#,
            input.did.as_str(),
            input.controller_did.as_str(),
            &input.controller_scopes,
            input.controller_did.as_str()
        )
        .execute(&mut *tx)
        .await
        .map_err(|e: sqlx::Error| tranquil_db_traits::CreateAccountError::Database(e.to_string()))?;

        sqlx::query!(
            "INSERT INTO repos (user_id, repo_root_cid, repo_rev) VALUES ($1, $2, $3)",
            user_id,
            input.commit_cid,
            input.repo_rev
        )
        .execute(&mut *tx)
        .await
        .map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        sqlx::query(
            r#"
            INSERT INTO user_blocks (user_id, block_cid, repo_rev)
            SELECT $1, block_cid, $3 FROM UNNEST($2::bytea[]) AS t(block_cid)
            ON CONFLICT (user_id, block_cid) DO NOTHING
            "#,
        )
        .bind(user_id)
        .bind(&input.genesis_block_cids)
        .bind(&input.repo_rev)
        .execute(&mut *tx)
        .await
        .map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        if let Some(code) = &input.invite_code {
            let _ = sqlx::query!(
                "UPDATE invite_codes SET available_uses = available_uses - 1 WHERE code = $1",
                code
            )
            .execute(&mut *tx)
            .await;

            let _ = sqlx::query!(
                "INSERT INTO invite_code_uses (code, used_by_user) VALUES ($1, $2)",
                code,
                user_id
            )
            .execute(&mut *tx)
            .await;
        }

        tx.commit().await.map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        Ok(user_id)
    }

    async fn create_passkey_account(
        &self,
        input: &tranquil_db_traits::CreatePasskeyAccountInput,
    ) -> Result<
        tranquil_db_traits::CreatePasswordAccountResult,
        tranquil_db_traits::CreateAccountError,
    > {
        let mut tx = self.pool.begin().await.map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        let is_first_user: bool = sqlx::query_scalar!("SELECT COUNT(*) as count FROM users")
            .fetch_one(&mut *tx)
            .await
            .map(|c| c.unwrap_or(0) == 0)
            .unwrap_or(false);

        let user_insert: Result<(uuid::Uuid,), _> = sqlx::query_as(
            r#"INSERT INTO users (
                handle, email, did, password_hash, password_required,
                preferred_comms_channel,
                discord_username, telegram_username, signal_username,
                recovery_token, recovery_token_expires_at,
                is_admin, deactivated_at
            ) VALUES ($1, $2, $3, NULL, FALSE, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id"#,
        )
        .bind(input.handle.as_str())
        .bind(&input.email)
        .bind(input.did.as_str())
        .bind(input.preferred_comms_channel)
        .bind(&input.discord_username)
        .bind(&input.telegram_username)
        .bind(&input.signal_username)
        .bind(&input.setup_token_hash)
        .bind(input.setup_expires_at)
        .bind(is_first_user)
        .bind(input.deactivated_at)
        .fetch_one(&mut *tx)
        .await;

        let user_id = match user_insert {
            Ok((id,)) => id,
            Err(e) => {
                if let Some(db_err) = e.as_database_error()
                    && db_err.code().as_deref() == Some("23505")
                {
                    let constraint = db_err.constraint().unwrap_or("");
                    if constraint.contains("handle") {
                        return Err(tranquil_db_traits::CreateAccountError::HandleTaken);
                    } else if constraint.contains("email") {
                        return Err(tranquil_db_traits::CreateAccountError::EmailTaken);
                    }
                }
                return Err(tranquil_db_traits::CreateAccountError::Database(
                    e.to_string(),
                ));
            }
        };

        sqlx::query!(
            "INSERT INTO user_keys (user_id, key_bytes, encryption_version, encrypted_at) VALUES ($1, $2, $3, NOW())",
            user_id,
            &input.encrypted_key_bytes[..],
            input.encryption_version
        )
        .execute(&mut *tx)
        .await
        .map_err(|e: sqlx::Error| tranquil_db_traits::CreateAccountError::Database(e.to_string()))?;

        if let Some(key_id) = input.reserved_key_id {
            sqlx::query!(
                "UPDATE reserved_signing_keys SET used_at = NOW() WHERE id = $1",
                key_id
            )
            .execute(&mut *tx)
            .await
            .map_err(|e: sqlx::Error| {
                tranquil_db_traits::CreateAccountError::Database(e.to_string())
            })?;
        }

        sqlx::query!(
            "INSERT INTO repos (user_id, repo_root_cid, repo_rev) VALUES ($1, $2, $3)",
            user_id,
            input.commit_cid,
            input.repo_rev
        )
        .execute(&mut *tx)
        .await
        .map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        sqlx::query(
            r#"
            INSERT INTO user_blocks (user_id, block_cid, repo_rev)
            SELECT $1, block_cid, $3 FROM UNNEST($2::bytea[]) AS t(block_cid)
            ON CONFLICT (user_id, block_cid) DO NOTHING
            "#,
        )
        .bind(user_id)
        .bind(&input.genesis_block_cids)
        .bind(&input.repo_rev)
        .execute(&mut *tx)
        .await
        .map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        if let Some(code) = &input.invite_code {
            let _ = sqlx::query!(
                "UPDATE invite_codes SET available_uses = available_uses - 1 WHERE code = $1",
                code
            )
            .execute(&mut *tx)
            .await;

            let _ = sqlx::query!(
                "INSERT INTO invite_code_uses (code, used_by_user) VALUES ($1, $2)",
                code,
                user_id
            )
            .execute(&mut *tx)
            .await;
        }

        if let Some(birthdate_pref) = &input.birthdate_pref {
            let _ = sqlx::query!(
                "INSERT INTO account_preferences (user_id, name, value_json) VALUES ($1, $2, $3)",
                user_id,
                "app.bsky.actor.defs#personalDetailsPref",
                birthdate_pref
            )
            .execute(&mut *tx)
            .await;
        }

        tx.commit().await.map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        Ok(tranquil_db_traits::CreatePasswordAccountResult {
            user_id,
            is_admin: is_first_user,
        })
    }

    async fn create_sso_account(
        &self,
        input: &tranquil_db_traits::CreateSsoAccountInput,
    ) -> Result<
        tranquil_db_traits::CreatePasswordAccountResult,
        tranquil_db_traits::CreateAccountError,
    > {
        let mut tx = self.pool.begin().await.map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        let token_consumed: Option<(String,)> = sqlx::query_as(
            r#"
            DELETE FROM sso_pending_registration
            WHERE token = $1 AND expires_at > NOW()
            RETURNING token
            "#,
        )
        .bind(&input.pending_registration_token)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        if token_consumed.is_none() {
            return Err(tranquil_db_traits::CreateAccountError::InvalidToken);
        }

        let is_first_user: bool = sqlx::query_scalar!("SELECT COUNT(*) as count FROM users")
            .fetch_one(&mut *tx)
            .await
            .map(|c| c.unwrap_or(0) == 0)
            .unwrap_or(false);

        let user_insert: Result<(uuid::Uuid,), _> = sqlx::query_as(
            r#"INSERT INTO users (
                handle, email, did, password_hash, password_required,
                preferred_comms_channel, discord_username, telegram_username, signal_username,
                is_admin
            ) VALUES ($1, $2, $3, NULL, FALSE, $4, $5, $6, $7, $8) RETURNING id"#,
        )
        .bind(input.handle.as_str())
        .bind(&input.email)
        .bind(input.did.as_str())
        .bind(input.preferred_comms_channel)
        .bind(&input.discord_username)
        .bind(&input.telegram_username)
        .bind(&input.signal_username)
        .bind(is_first_user)
        .fetch_one(&mut *tx)
        .await;

        let user_id = match user_insert {
            Ok((id,)) => id,
            Err(e) => {
                if let Some(db_err) = e.as_database_error()
                    && db_err.code().as_deref() == Some("23505")
                {
                    let constraint = db_err.constraint().unwrap_or("");
                    if constraint.contains("handle") {
                        return Err(tranquil_db_traits::CreateAccountError::HandleTaken);
                    } else if constraint.contains("email") {
                        return Err(tranquil_db_traits::CreateAccountError::EmailTaken);
                    }
                }
                return Err(tranquil_db_traits::CreateAccountError::Database(
                    e.to_string(),
                ));
            }
        };

        sqlx::query!(
            "INSERT INTO user_keys (user_id, key_bytes, encryption_version, encrypted_at) VALUES ($1, $2, $3, NOW())",
            user_id,
            &input.encrypted_key_bytes[..],
            input.encryption_version
        )
        .execute(&mut *tx)
        .await
        .map_err(|e: sqlx::Error| tranquil_db_traits::CreateAccountError::Database(e.to_string()))?;

        sqlx::query!(
            "INSERT INTO repos (user_id, repo_root_cid, repo_rev) VALUES ($1, $2, $3)",
            user_id,
            input.commit_cid,
            input.repo_rev
        )
        .execute(&mut *tx)
        .await
        .map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        sqlx::query(
            r#"
            INSERT INTO user_blocks (user_id, block_cid, repo_rev)
            SELECT $1, block_cid, $3 FROM UNNEST($2::bytea[]) AS t(block_cid)
            ON CONFLICT (user_id, block_cid) DO NOTHING
            "#,
        )
        .bind(user_id)
        .bind(&input.genesis_block_cids)
        .bind(&input.repo_rev)
        .execute(&mut *tx)
        .await
        .map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        if let Some(code) = &input.invite_code {
            let _ = sqlx::query!(
                "UPDATE invite_codes SET available_uses = available_uses - 1 WHERE code = $1",
                code
            )
            .execute(&mut *tx)
            .await;

            let _ = sqlx::query!(
                "INSERT INTO invite_code_uses (code, used_by_user) VALUES ($1, $2)",
                code,
                user_id
            )
            .execute(&mut *tx)
            .await;
        }

        if let Some(birthdate_pref) = &input.birthdate_pref {
            let _ = sqlx::query!(
                "INSERT INTO account_preferences (user_id, name, value_json) VALUES ($1, $2, $3)",
                user_id,
                "app.bsky.actor.defs#personalDetailsPref",
                birthdate_pref
            )
            .execute(&mut *tx)
            .await;
        }

        sqlx::query!(
            r#"
            INSERT INTO external_identities (did, provider, provider_user_id, provider_username, provider_email, provider_email_verified)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            input.did.as_str(),
            input.sso_provider as SsoProviderType,
            &input.sso_provider_user_id,
            input.sso_provider_username.as_deref(),
            input.sso_provider_email.as_deref(),
            input.sso_provider_email_verified,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        tx.commit().await.map_err(|e: sqlx::Error| {
            tranquil_db_traits::CreateAccountError::Database(e.to_string())
        })?;

        Ok(tranquil_db_traits::CreatePasswordAccountResult {
            user_id,
            is_admin: is_first_user,
        })
    }

    async fn reactivate_migration_account(
        &self,
        input: &tranquil_db_traits::MigrationReactivationInput,
    ) -> Result<
        tranquil_db_traits::ReactivatedAccountInfo,
        tranquil_db_traits::MigrationReactivationError,
    > {
        let mut tx =
            self.pool.begin().await.map_err(|e| {
                tranquil_db_traits::MigrationReactivationError::Database(e.to_string())
            })?;

        let existing: Option<(uuid::Uuid, String, Option<chrono::DateTime<chrono::Utc>>)> =
            sqlx::query_as(
                "SELECT id, handle, deactivated_at FROM users WHERE did = $1 FOR UPDATE",
            )
            .bind(input.did.as_str())
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| tranquil_db_traits::MigrationReactivationError::Database(e.to_string()))?;

        let (account_id, old_handle, deactivated_at) =
            existing.ok_or(tranquil_db_traits::MigrationReactivationError::NotFound)?;

        if deactivated_at.is_none() {
            return Err(tranquil_db_traits::MigrationReactivationError::NotDeactivated);
        }

        let update_result: Result<_, sqlx::Error> = if let Some(ref new_email) = input.new_email {
            sqlx::query(
                "UPDATE users SET handle = $1, email = $2, email_verified = false WHERE id = $3",
            )
            .bind(input.new_handle.as_str())
            .bind(new_email)
            .bind(account_id)
            .execute(&mut *tx)
            .await
        } else {
            sqlx::query("UPDATE users SET handle = $1 WHERE id = $2")
                .bind(input.new_handle.as_str())
                .bind(account_id)
                .execute(&mut *tx)
                .await
        };

        if let Err(e) = update_result {
            if let Some(db_err) = e.as_database_error()
                && db_err
                    .constraint()
                    .map(|c| c.contains("handle"))
                    .unwrap_or(false)
            {
                return Err(tranquil_db_traits::MigrationReactivationError::HandleTaken);
            }
            return Err(tranquil_db_traits::MigrationReactivationError::Database(
                e.to_string(),
            ));
        }

        tx.commit()
            .await
            .map_err(|e| tranquil_db_traits::MigrationReactivationError::Database(e.to_string()))?;

        Ok(tranquil_db_traits::ReactivatedAccountInfo {
            user_id: account_id,
            old_handle: Handle::from(old_handle),
        })
    }

    async fn check_handle_available_for_new_account(
        &self,
        handle: &Handle,
    ) -> Result<bool, DbError> {
        let exists: Option<(i32,)> = sqlx::query_as(
            r#"
            SELECT 1 FROM users WHERE handle = $1 AND deactivated_at IS NULL
            UNION ALL
            SELECT 1 FROM handle_reservations WHERE handle = $1 AND expires_at > NOW()
            LIMIT 1
            "#,
        )
        .bind(handle.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(exists.is_none())
    }

    async fn reserve_handle(&self, handle: &Handle, reserved_by: &str) -> Result<bool, DbError> {
        sqlx::query!("DELETE FROM handle_reservations WHERE expires_at <= NOW()")
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        let result = sqlx::query!(
            r#"
            INSERT INTO handle_reservations (handle, reserved_by)
            SELECT $1, $2
            WHERE NOT EXISTS (
                SELECT 1 FROM users WHERE handle = $1 AND deactivated_at IS NULL
            )
            AND NOT EXISTS (
                SELECT 1 FROM handle_reservations WHERE handle = $1 AND expires_at > NOW()
            )
            "#,
            handle.as_str(),
            reserved_by,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.rows_affected() > 0)
    }

    async fn release_handle_reservation(&self, handle: &Handle) -> Result<(), DbError> {
        sqlx::query!(
            "DELETE FROM handle_reservations WHERE handle = $1",
            handle.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn cleanup_expired_handle_reservations(&self) -> Result<u64, DbError> {
        let result = sqlx::query!("DELETE FROM handle_reservations WHERE expires_at <= NOW()")
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(result.rows_affected())
    }

    async fn check_and_consume_invite_code(&self, code: &str) -> Result<bool, DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;

        let invite = sqlx::query!(
            "SELECT available_uses FROM invite_codes WHERE code = $1 FOR UPDATE",
            code
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;

        let Some(row) = invite else {
            return Ok(false);
        };

        if row.available_uses <= 0 {
            return Ok(false);
        }

        sqlx::query!(
            "UPDATE invite_codes SET available_uses = available_uses - 1 WHERE code = $1",
            code
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;

        tx.commit().await.map_err(map_sqlx_error)?;

        Ok(true)
    }

    async fn complete_passkey_setup(
        &self,
        input: &tranquil_db_traits::CompletePasskeySetupInput,
    ) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;

        sqlx::query!(
            "INSERT INTO app_passwords (user_id, name, password_hash, privileged) VALUES ($1, $2, $3, FALSE)",
            input.user_id,
            input.app_password_name,
            input.app_password_hash
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;

        sqlx::query!(
            "UPDATE users SET recovery_token = NULL, recovery_token_expires_at = NULL WHERE did = $1",
            input.did.as_str()
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;

        tx.commit().await.map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn recover_passkey_account(
        &self,
        input: &tranquil_db_traits::RecoverPasskeyAccountInput,
    ) -> Result<tranquil_db_traits::RecoverPasskeyAccountResult, DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;

        sqlx::query!(
            "UPDATE users SET password_hash = $1, password_required = TRUE, recovery_token = NULL, recovery_token_expires_at = NULL WHERE did = $2",
            input.password_hash,
            input.did.as_str()
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;

        let deleted = sqlx::query!("DELETE FROM passkeys WHERE did = $1", input.did.as_str())
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;

        tx.commit().await.map_err(map_sqlx_error)?;

        Ok(tranquil_db_traits::RecoverPasskeyAccountResult {
            passkeys_deleted: deleted.rows_affected(),
        })
    }

    async fn set_unverified_telegram(
        &self,
        user_id: Uuid,
        telegram_username: &str,
    ) -> Result<(), DbError> {
        sqlx::query!(
            r#"UPDATE users SET
                telegram_username = $1,
                telegram_verified = CASE WHEN LOWER(telegram_username) = LOWER($1) THEN telegram_verified ELSE FALSE END,
                telegram_chat_id = CASE WHEN LOWER(telegram_username) = LOWER($1) THEN telegram_chat_id ELSE NULL END,
                updated_at = NOW()
            WHERE id = $2"#,
            telegram_username,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn set_unverified_signal(
        &self,
        user_id: Uuid,
        signal_username: &str,
    ) -> Result<(), DbError> {
        sqlx::query!(
            r#"UPDATE users SET
                signal_username = $1,
                signal_verified = CASE WHEN LOWER(signal_username) = LOWER($1) THEN signal_verified ELSE FALSE END,
                updated_at = NOW()
            WHERE id = $2"#,
            signal_username,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn set_unverified_discord(
        &self,
        user_id: Uuid,
        discord_username: &str,
    ) -> Result<(), DbError> {
        sqlx::query!(
            r#"UPDATE users SET
                discord_username = $1,
                discord_verified = CASE WHEN LOWER(discord_username) = LOWER($1) THEN discord_verified ELSE FALSE END,
                discord_id = CASE WHEN LOWER(discord_username) = LOWER($1) THEN discord_id ELSE NULL END,
                updated_at = NOW()
            WHERE id = $2"#,
            discord_username,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn store_discord_user_id(
        &self,
        discord_username: &str,
        discord_id: &str,
        handle: Option<&str>,
    ) -> Result<Option<Uuid>, DbError> {
        let result = match handle {
            Some(h) => sqlx::query_scalar!(
                "UPDATE users SET discord_id = $2, discord_verified = TRUE, updated_at = NOW() WHERE LOWER(discord_username) = LOWER($1) AND discord_username IS NOT NULL AND handle = $3 RETURNING id",
                discord_username,
                discord_id,
                h
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?,
            None => {
                let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;

                let matching: Vec<uuid::Uuid> = match sqlx::query_scalar!(
                    "SELECT id FROM users WHERE LOWER(discord_username) = LOWER($1) AND discord_username IS NOT NULL AND deactivated_at IS NULL FOR UPDATE NOWAIT",
                    discord_username
                )
                .fetch_all(&mut *tx)
                .await
                {
                    Ok(ids) => ids,
                    Err(sqlx::Error::Database(ref db_err))
                        if db_err.code().as_deref() == Some("55P03") =>
                    {
                        return Err(DbError::LockContention);
                    }
                    Err(e) => return Err(map_sqlx_error(e)),
                };

                let result = match matching.len() {
                    0 => None,
                    1 => {
                        sqlx::query_scalar!(
                            "UPDATE users SET discord_id = $2, discord_verified = TRUE, updated_at = NOW() WHERE id = $1 RETURNING id",
                            matching[0],
                            discord_id
                        )
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(map_sqlx_error)?
                    }
                    _ => {
                        tx.rollback().await.ok();
                        return Err(DbError::Ambiguous(
                            "Multiple accounts use this Discord username. Type: /start your-handle.example.com".to_string(),
                        ));
                    }
                };

                tx.commit().await.map_err(map_sqlx_error)?;
                result
            }
        };
        Ok(result)
    }

    async fn store_telegram_chat_id(
        &self,
        telegram_username: &str,
        chat_id: i64,
        handle: Option<&str>,
    ) -> Result<Option<Uuid>, DbError> {
        let result = match handle {
            Some(h) => sqlx::query_scalar!(
                "UPDATE users SET telegram_chat_id = $2, telegram_verified = TRUE, updated_at = NOW() WHERE LOWER(telegram_username) = LOWER($1) AND telegram_username IS NOT NULL AND handle = $3 RETURNING id",
                telegram_username,
                chat_id,
                h
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?,
            None => sqlx::query_scalar!(
                r#"UPDATE users SET telegram_chat_id = $2, telegram_verified = TRUE, updated_at = NOW()
                WHERE id = (
                    SELECT id FROM users
                    WHERE LOWER(telegram_username) = LOWER($1) AND telegram_username IS NOT NULL AND deactivated_at IS NULL
                    LIMIT 1
                ) RETURNING id"#,
                telegram_username,
                chat_id
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?,
        };
        Ok(result)
    }

    async fn get_telegram_chat_id(&self, user_id: Uuid) -> Result<Option<i64>, DbError> {
        let row = sqlx::query_scalar!("SELECT telegram_chat_id FROM users WHERE id = $1", user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(row.flatten())
    }
}
