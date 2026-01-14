use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tranquil_types::{AtUri, CidLink, Did};
use uuid::Uuid;

use crate::DbError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobMetadata {
    pub storage_key: String,
    pub mime_type: String,
    pub size_bytes: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobWithTakedown {
    pub cid: CidLink,
    pub takedown_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobForExport {
    pub cid: CidLink,
    pub storage_key: String,
    pub mime_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingBlobInfo {
    pub blob_cid: CidLink,
    pub record_uri: AtUri,
}

#[async_trait]
pub trait BlobRepository: Send + Sync {
    async fn insert_blob(
        &self,
        cid: &CidLink,
        mime_type: &str,
        size_bytes: i64,
        created_by_user: Uuid,
        storage_key: &str,
    ) -> Result<Option<CidLink>, DbError>;

    async fn get_blob_metadata(&self, cid: &CidLink) -> Result<Option<BlobMetadata>, DbError>;

    async fn get_blob_with_takedown(
        &self,
        cid: &CidLink,
    ) -> Result<Option<BlobWithTakedown>, DbError>;

    async fn get_blob_storage_key(&self, cid: &CidLink) -> Result<Option<String>, DbError>;

    async fn list_blobs_by_user(
        &self,
        user_id: Uuid,
        cursor: Option<&str>,
        limit: i64,
    ) -> Result<Vec<CidLink>, DbError>;

    async fn list_blobs_since_rev(
        &self,
        did: &Did,
        since: &str,
    ) -> Result<Vec<CidLink>, DbError>;

    async fn count_blobs_by_user(&self, user_id: Uuid) -> Result<i64, DbError>;

    async fn sum_blob_storage(&self) -> Result<i64, DbError>;

    async fn update_blob_takedown(
        &self,
        cid: &CidLink,
        takedown_ref: Option<&str>,
    ) -> Result<bool, DbError>;

    async fn delete_blob_by_cid(&self, cid: &CidLink) -> Result<bool, DbError>;

    async fn delete_blobs_by_user(&self, user_id: Uuid) -> Result<u64, DbError>;

    async fn get_blob_storage_keys_by_user(&self, user_id: Uuid) -> Result<Vec<String>, DbError>;

    async fn insert_record_blobs(
        &self,
        repo_id: Uuid,
        record_uris: &[AtUri],
        blob_cids: &[CidLink],
    ) -> Result<(), DbError>;

    async fn list_missing_blobs(
        &self,
        repo_id: Uuid,
        cursor: Option<&str>,
        limit: i64,
    ) -> Result<Vec<MissingBlobInfo>, DbError>;

    async fn count_distinct_record_blobs(&self, repo_id: Uuid) -> Result<i64, DbError>;

    async fn get_blobs_for_export(&self, repo_id: Uuid) -> Result<Vec<BlobForExport>, DbError>;
}
