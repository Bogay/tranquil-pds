use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tranquil_db_traits::{
    BackupForDeletion, BackupRepository, BackupRow, BackupStorageInfo, BlobExportInfo, DbError,
    OldBackupInfo, UserBackupInfo,
};
use tranquil_types::Did;
use uuid::Uuid;

use super::user::map_sqlx_error;

pub struct PostgresBackupRepository {
    pool: PgPool,
}

impl PostgresBackupRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl BackupRepository for PostgresBackupRepository {
    async fn get_user_backup_status(&self, did: &Did) -> Result<Option<(Uuid, bool)>, DbError> {
        let result = sqlx::query!(
            "SELECT id, backup_enabled FROM users WHERE did = $1",
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.map(|r| (r.id, r.backup_enabled)))
    }

    async fn list_backups_for_user(&self, user_id: Uuid) -> Result<Vec<BackupRow>, DbError> {
        let results = sqlx::query_as!(
            BackupRow,
            r#"
            SELECT id, repo_rev, repo_root_cid, block_count, size_bytes, created_at
            FROM account_backups
            WHERE user_id = $1
            ORDER BY created_at DESC
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(results)
    }

    async fn get_backup_storage_info(
        &self,
        backup_id: Uuid,
        did: &Did,
    ) -> Result<Option<BackupStorageInfo>, DbError> {
        let result = sqlx::query!(
            r#"
            SELECT ab.storage_key, ab.repo_rev
            FROM account_backups ab
            JOIN users u ON u.id = ab.user_id
            WHERE ab.id = $1 AND u.did = $2
            "#,
            backup_id,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.map(|r| BackupStorageInfo {
            storage_key: r.storage_key,
            repo_rev: r.repo_rev,
        }))
    }

    async fn get_user_for_backup(&self, did: &Did) -> Result<Option<UserBackupInfo>, DbError> {
        let result = sqlx::query!(
            r#"
            SELECT u.id, u.did, u.backup_enabled, u.deactivated_at, r.repo_root_cid, r.repo_rev
            FROM users u
            JOIN repos r ON r.user_id = u.id
            WHERE u.did = $1
            "#,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.map(|r| UserBackupInfo {
            id: r.id,
            did: r.did.into(),
            backup_enabled: r.backup_enabled,
            deactivated_at: r.deactivated_at,
            repo_root_cid: r.repo_root_cid,
            repo_rev: r.repo_rev,
        }))
    }

    async fn insert_backup(
        &self,
        user_id: Uuid,
        storage_key: &str,
        repo_root_cid: &str,
        repo_rev: &str,
        block_count: i32,
        size_bytes: i64,
    ) -> Result<Uuid, DbError> {
        let id = sqlx::query_scalar!(
            r#"
            INSERT INTO account_backups (user_id, storage_key, repo_root_cid, repo_rev, block_count, size_bytes)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (storage_key) DO UPDATE SET created_at = NOW()
            RETURNING id
            "#,
            user_id,
            storage_key,
            repo_root_cid,
            repo_rev,
            block_count,
            size_bytes
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(id)
    }

    async fn get_old_backups(
        &self,
        user_id: Uuid,
        retention_offset: i64,
    ) -> Result<Vec<OldBackupInfo>, DbError> {
        let results = sqlx::query!(
            r#"
            SELECT id, storage_key
            FROM account_backups
            WHERE user_id = $1
            ORDER BY created_at DESC
            OFFSET $2
            "#,
            user_id,
            retention_offset
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(results
            .into_iter()
            .map(|r| OldBackupInfo {
                id: r.id,
                storage_key: r.storage_key,
            })
            .collect())
    }

    async fn delete_backup(&self, backup_id: Uuid) -> Result<(), DbError> {
        sqlx::query!("DELETE FROM account_backups WHERE id = $1", backup_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn get_backup_for_deletion(
        &self,
        backup_id: Uuid,
        did: &Did,
    ) -> Result<Option<BackupForDeletion>, DbError> {
        let result = sqlx::query!(
            r#"
            SELECT ab.id, ab.storage_key, u.deactivated_at
            FROM account_backups ab
            JOIN users u ON u.id = ab.user_id
            WHERE ab.id = $1 AND u.did = $2
            "#,
            backup_id,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.map(|r| BackupForDeletion {
            id: r.id,
            storage_key: r.storage_key,
            deactivated_at: r.deactivated_at,
        }))
    }

    async fn get_user_deactivated_status(
        &self,
        did: &Did,
    ) -> Result<Option<Option<DateTime<Utc>>>, DbError> {
        let result = sqlx::query!(
            "SELECT deactivated_at FROM users WHERE did = $1",
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.map(|r| r.deactivated_at))
    }

    async fn update_backup_enabled(&self, did: &Did, enabled: bool) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE users SET backup_enabled = $1 WHERE did = $2",
            enabled,
            did.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn get_user_id_by_did(&self, did: &Did) -> Result<Option<Uuid>, DbError> {
        let result = sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(result)
    }

    async fn get_blobs_for_export(&self, user_id: Uuid) -> Result<Vec<BlobExportInfo>, DbError> {
        let results = sqlx::query!(
            r#"
            SELECT DISTINCT b.cid, b.storage_key, b.mime_type
            FROM blobs b
            JOIN record_blobs rb ON rb.blob_cid = b.cid
            WHERE rb.repo_id = $1
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(results
            .into_iter()
            .map(|r| BlobExportInfo {
                cid: r.cid,
                storage_key: r.storage_key,
                mime_type: r.mime_type,
            })
            .collect())
    }

    async fn get_users_needing_backup(
        &self,
        backup_interval_secs: i64,
        limit: i64,
    ) -> Result<Vec<UserBackupInfo>, DbError> {
        let results = sqlx::query!(
            r#"
            SELECT u.id, u.did, u.backup_enabled, u.deactivated_at, r.repo_root_cid, r.repo_rev
            FROM users u
            JOIN repos r ON r.user_id = u.id
            WHERE u.backup_enabled = true
              AND u.deactivated_at IS NULL
              AND (
                NOT EXISTS (
                  SELECT 1 FROM account_backups ab WHERE ab.user_id = u.id
                )
                OR (
                  SELECT MAX(ab.created_at) FROM account_backups ab WHERE ab.user_id = u.id
                ) < NOW() - make_interval(secs => $1)
              )
            LIMIT $2
            "#,
            backup_interval_secs as f64,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(results
            .into_iter()
            .map(|r| UserBackupInfo {
                id: r.id,
                did: r.did.into(),
                backup_enabled: r.backup_enabled,
                deactivated_at: r.deactivated_at,
                repo_root_cid: r.repo_root_cid,
                repo_rev: r.repo_rev,
            })
            .collect())
    }
}
