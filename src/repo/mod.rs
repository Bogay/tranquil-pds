use bytes::Bytes;
use cid::Cid;
use jacquard_repo::error::RepoError;
use jacquard_repo::repo::CommitData;
use jacquard_repo::storage::BlockStore;
use multihash::Multihash;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

pub mod tracking;

#[derive(Clone)]
pub struct PostgresBlockStore {
    pool: PgPool,
}

impl PostgresBlockStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl BlockStore for PostgresBlockStore {
    async fn get(&self, cid: &Cid) -> Result<Option<Bytes>, RepoError> {
        crate::metrics::record_block_operation("get");
        let cid_bytes = cid.to_bytes();
        let row = sqlx::query!("SELECT data FROM blocks WHERE cid = $1", &cid_bytes)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| RepoError::storage(e))?;

        match row {
            Some(row) => Ok(Some(Bytes::from(row.data))),
            None => Ok(None),
        }
    }

    async fn put(&self, data: &[u8]) -> Result<Cid, RepoError> {
        crate::metrics::record_block_operation("put");
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let multihash = Multihash::wrap(0x12, &hash)
            .map_err(|e| RepoError::storage(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Failed to wrap multihash: {:?}", e))))?;
        let cid = Cid::new_v1(0x71, multihash);
        let cid_bytes = cid.to_bytes();

        sqlx::query!("INSERT INTO blocks (cid, data) VALUES ($1, $2) ON CONFLICT (cid) DO NOTHING", &cid_bytes, data)
            .execute(&self.pool)
            .await
            .map_err(|e| RepoError::storage(e))?;

        Ok(cid)
    }

    async fn has(&self, cid: &Cid) -> Result<bool, RepoError> {
        crate::metrics::record_block_operation("has");
        let cid_bytes = cid.to_bytes();
        let row = sqlx::query!("SELECT 1 as one FROM blocks WHERE cid = $1", &cid_bytes)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| RepoError::storage(e))?;

        Ok(row.is_some())
    }

    async fn put_many(
        &self,
        blocks: impl IntoIterator<Item = (Cid, Bytes)> + Send,
    ) -> Result<(), RepoError> {
        let blocks: Vec<_> = blocks.into_iter().collect();
        if blocks.is_empty() {
            return Ok(());
        }

        crate::metrics::record_block_operation("put_many");
        let cids: Vec<Vec<u8>> = blocks.iter().map(|(cid, _)| cid.to_bytes()).collect();
        let data: Vec<&[u8]> = blocks.iter().map(|(_, d)| d.as_ref()).collect();

        sqlx::query!(
            r#"
            INSERT INTO blocks (cid, data)
            SELECT * FROM UNNEST($1::bytea[], $2::bytea[])
            ON CONFLICT (cid) DO NOTHING
            "#,
            &cids,
            &data as &[&[u8]]
        )
        .execute(&self.pool)
        .await
        .map_err(|e| RepoError::storage(e))?;

        Ok(())
    }

    async fn get_many(&self, cids: &[Cid]) -> Result<Vec<Option<Bytes>>, RepoError> {
        if cids.is_empty() {
            return Ok(Vec::new());
        }

        crate::metrics::record_block_operation("get_many");
        let cid_bytes: Vec<Vec<u8>> = cids.iter().map(|c| c.to_bytes()).collect();

        let rows = sqlx::query!(
            "SELECT cid, data FROM blocks WHERE cid = ANY($1)",
            &cid_bytes
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| RepoError::storage(e))?;

        let found: std::collections::HashMap<Vec<u8>, Bytes> = rows
            .into_iter()
            .map(|row| (row.cid, Bytes::from(row.data)))
            .collect();

        let results = cid_bytes
            .iter()
            .map(|cid| found.get(cid).cloned())
            .collect();

        Ok(results)
    }

    async fn apply_commit(&self, commit: CommitData) -> Result<(), RepoError> {
        self.put_many(commit.blocks).await?;
        Ok(())
    }
}
