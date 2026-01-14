use async_trait::async_trait;
use sqlx::PgPool;
use tranquil_db_traits::{
    BlobForExport, BlobMetadata, BlobRepository, BlobWithTakedown, DbError, MissingBlobInfo,
};
use tranquil_types::{AtUri, CidLink, Did};
use uuid::Uuid;

use super::user::map_sqlx_error;

pub struct PostgresBlobRepository {
    pool: PgPool,
}

impl PostgresBlobRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl BlobRepository for PostgresBlobRepository {
    async fn insert_blob(
        &self,
        cid: &CidLink,
        mime_type: &str,
        size_bytes: i64,
        created_by_user: Uuid,
        storage_key: &str,
    ) -> Result<Option<CidLink>, DbError> {
        let result = sqlx::query_scalar!(
            r#"INSERT INTO blobs (cid, mime_type, size_bytes, created_by_user, storage_key)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (cid) DO NOTHING RETURNING cid"#,
            cid.as_str(),
            mime_type,
            size_bytes,
            created_by_user,
            storage_key
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.map(CidLink::from))
    }

    async fn get_blob_metadata(&self, cid: &CidLink) -> Result<Option<BlobMetadata>, DbError> {
        let result = sqlx::query!(
            "SELECT storage_key, mime_type, size_bytes FROM blobs WHERE cid = $1",
            cid.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.map(|r| BlobMetadata {
            storage_key: r.storage_key,
            mime_type: r.mime_type,
            size_bytes: r.size_bytes,
        }))
    }

    async fn get_blob_with_takedown(
        &self,
        cid: &CidLink,
    ) -> Result<Option<BlobWithTakedown>, DbError> {
        let result = sqlx::query!(
            "SELECT cid, takedown_ref FROM blobs WHERE cid = $1",
            cid.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.map(|r| BlobWithTakedown {
            cid: CidLink::from(r.cid),
            takedown_ref: r.takedown_ref,
        }))
    }

    async fn get_blob_storage_key(&self, cid: &CidLink) -> Result<Option<String>, DbError> {
        let result = sqlx::query_scalar!(
            "SELECT storage_key FROM blobs WHERE cid = $1",
            cid.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result)
    }

    async fn list_blobs_by_user(
        &self,
        user_id: Uuid,
        cursor: Option<&str>,
        limit: i64,
    ) -> Result<Vec<CidLink>, DbError> {
        let cursor_val = cursor.unwrap_or("");
        let results = sqlx::query_scalar!(
            r#"SELECT cid FROM blobs
               WHERE created_by_user = $1 AND cid > $2
               ORDER BY cid ASC
               LIMIT $3"#,
            user_id,
            cursor_val,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(results.into_iter().map(CidLink::from).collect())
    }

    async fn list_blobs_since_rev(
        &self,
        did: &Did,
        since: &str,
    ) -> Result<Vec<CidLink>, DbError> {
        let results = sqlx::query_scalar!(
            r#"SELECT DISTINCT unnest(blobs) as "cid!"
               FROM repo_seq
               WHERE did = $1 AND rev > $2 AND blobs IS NOT NULL"#,
            did.as_str(),
            since
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(results.into_iter().map(CidLink::from).collect())
    }

    async fn count_blobs_by_user(&self, user_id: Uuid) -> Result<i64, DbError> {
        let result = sqlx::query_scalar!(
            r#"SELECT COUNT(*) as "count!" FROM blobs WHERE created_by_user = $1"#,
            user_id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result)
    }

    async fn sum_blob_storage(&self) -> Result<i64, DbError> {
        let result = sqlx::query_scalar!(
            r#"SELECT COALESCE(SUM(size_bytes), 0)::BIGINT as "total!" FROM blobs"#
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result)
    }

    async fn update_blob_takedown(
        &self,
        cid: &CidLink,
        takedown_ref: Option<&str>,
    ) -> Result<bool, DbError> {
        let result = sqlx::query!(
            "UPDATE blobs SET takedown_ref = $1 WHERE cid = $2",
            takedown_ref,
            cid.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.rows_affected() > 0)
    }

    async fn delete_blob_by_cid(&self, cid: &CidLink) -> Result<bool, DbError> {
        let result = sqlx::query!("DELETE FROM blobs WHERE cid = $1", cid.as_str())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(result.rows_affected() > 0)
    }

    async fn delete_blobs_by_user(&self, user_id: Uuid) -> Result<u64, DbError> {
        let result = sqlx::query!("DELETE FROM blobs WHERE created_by_user = $1", user_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(result.rows_affected())
    }

    async fn get_blob_storage_keys_by_user(&self, user_id: Uuid) -> Result<Vec<String>, DbError> {
        let results = sqlx::query_scalar!(
            r#"SELECT storage_key as "storage_key!" FROM blobs WHERE created_by_user = $1"#,
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(results)
    }

    async fn insert_record_blobs(
        &self,
        repo_id: Uuid,
        record_uris: &[AtUri],
        blob_cids: &[CidLink],
    ) -> Result<(), DbError> {
        let uris_str: Vec<&str> = record_uris.iter().map(|u| u.as_str()).collect();
        let cids_str: Vec<&str> = blob_cids.iter().map(|c| c.as_str()).collect();

        sqlx::query!(
            r#"INSERT INTO record_blobs (repo_id, record_uri, blob_cid)
               SELECT $1, record_uri, blob_cid
               FROM UNNEST($2::text[], $3::text[]) AS t(record_uri, blob_cid)
               ON CONFLICT (repo_id, record_uri, blob_cid) DO NOTHING"#,
            repo_id,
            &uris_str as &[&str],
            &cids_str as &[&str]
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn list_missing_blobs(
        &self,
        repo_id: Uuid,
        cursor: Option<&str>,
        limit: i64,
    ) -> Result<Vec<MissingBlobInfo>, DbError> {
        let cursor_val = cursor.unwrap_or("");
        let results = sqlx::query!(
            r#"SELECT rb.blob_cid, rb.record_uri
               FROM record_blobs rb
               LEFT JOIN blobs b ON rb.blob_cid = b.cid
               WHERE rb.repo_id = $1 AND b.cid IS NULL AND rb.blob_cid > $2
               ORDER BY rb.blob_cid
               LIMIT $3"#,
            repo_id,
            cursor_val,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(results
            .into_iter()
            .map(|r| MissingBlobInfo {
                blob_cid: CidLink::from(r.blob_cid),
                record_uri: AtUri::from(r.record_uri),
            })
            .collect())
    }

    async fn count_distinct_record_blobs(&self, repo_id: Uuid) -> Result<i64, DbError> {
        let result = sqlx::query_scalar!(
            r#"SELECT COUNT(DISTINCT blob_cid) as "count!" FROM record_blobs WHERE repo_id = $1"#,
            repo_id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result)
    }

    async fn get_blobs_for_export(&self, repo_id: Uuid) -> Result<Vec<BlobForExport>, DbError> {
        let results = sqlx::query!(
            r#"SELECT DISTINCT b.cid, b.storage_key, b.mime_type
               FROM blobs b
               JOIN record_blobs rb ON rb.blob_cid = b.cid
               WHERE rb.repo_id = $1"#,
            repo_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(results
            .into_iter()
            .map(|r| BlobForExport {
                cid: CidLink::from(r.cid),
                storage_key: r.storage_key,
                mime_type: r.mime_type,
            })
            .collect())
    }
}
