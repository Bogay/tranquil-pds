use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tranquil_types::Did;
use uuid::Uuid;

use crate::DbError;

#[derive(Debug, Clone)]
pub struct BackupRow {
    pub id: Uuid,
    pub repo_rev: String,
    pub repo_root_cid: String,
    pub block_count: i32,
    pub size_bytes: i64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct BackupStorageInfo {
    pub storage_key: String,
    pub repo_rev: String,
}

#[derive(Debug, Clone)]
pub struct BackupForDeletion {
    pub id: Uuid,
    pub storage_key: String,
    pub deactivated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct OldBackupInfo {
    pub id: Uuid,
    pub storage_key: String,
}

#[derive(Debug, Clone)]
pub struct UserBackupInfo {
    pub id: Uuid,
    pub did: Did,
    pub backup_enabled: bool,
    pub deactivated_at: Option<DateTime<Utc>>,
    pub repo_root_cid: String,
    pub repo_rev: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BlobExportInfo {
    pub cid: String,
    pub storage_key: String,
    pub mime_type: String,
}

#[async_trait]
pub trait BackupRepository: Send + Sync {
    async fn get_user_backup_status(&self, did: &Did) -> Result<Option<(Uuid, bool)>, DbError>;

    async fn list_backups_for_user(&self, user_id: Uuid) -> Result<Vec<BackupRow>, DbError>;

    async fn get_backup_storage_info(
        &self,
        backup_id: Uuid,
        did: &Did,
    ) -> Result<Option<BackupStorageInfo>, DbError>;

    async fn get_user_for_backup(&self, did: &Did) -> Result<Option<UserBackupInfo>, DbError>;

    async fn insert_backup(
        &self,
        user_id: Uuid,
        storage_key: &str,
        repo_root_cid: &str,
        repo_rev: &str,
        block_count: i32,
        size_bytes: i64,
    ) -> Result<Uuid, DbError>;

    async fn get_old_backups(
        &self,
        user_id: Uuid,
        retention_offset: i64,
    ) -> Result<Vec<OldBackupInfo>, DbError>;

    async fn delete_backup(&self, backup_id: Uuid) -> Result<(), DbError>;

    async fn get_backup_for_deletion(
        &self,
        backup_id: Uuid,
        did: &Did,
    ) -> Result<Option<BackupForDeletion>, DbError>;

    async fn get_user_deactivated_status(
        &self,
        did: &Did,
    ) -> Result<Option<Option<DateTime<Utc>>>, DbError>;

    async fn update_backup_enabled(&self, did: &Did, enabled: bool) -> Result<(), DbError>;

    async fn get_user_id_by_did(&self, did: &Did) -> Result<Option<Uuid>, DbError>;

    async fn get_blobs_for_export(&self, user_id: Uuid) -> Result<Vec<BlobExportInfo>, DbError>;

    async fn get_users_needing_backup(
        &self,
        backup_interval_secs: i64,
        limit: i64,
    ) -> Result<Vec<UserBackupInfo>, DbError>;
}
