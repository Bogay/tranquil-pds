use bytes::Bytes;
use cid::Cid;
use jacquard_repo::error::RepoError;
use jacquard_repo::repo::CommitData;
use jacquard_repo::storage::BlockStore;
use multihash::Multihash;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct PostgresBlockStore {
    pool: PgPool,
}

impl PostgresBlockStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

impl PostgresBlockStore {
    pub async fn get_oldest_block_cids(&self, limit: i64) -> Result<Vec<Vec<u8>>, RepoError> {
        let rows = sqlx::query!(
            "SELECT cid FROM blocks ORDER BY created_at ASC LIMIT $1",
            limit,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(RepoError::storage)?;
        Ok(rows.into_iter().map(|r| r.cid).collect())
    }

    pub async fn delete_blocks(&self, cids: &[Vec<u8>]) -> Result<u64, RepoError> {
        match cids.is_empty() {
            true => Ok(0),
            false => {
                let result = sqlx::query!("DELETE FROM blocks WHERE cid = ANY($1)", cids,)
                    .execute(&self.pool)
                    .await
                    .map_err(RepoError::storage)?;
                Ok(result.rows_affected())
            }
        }
    }
}

impl BlockStore for PostgresBlockStore {
    async fn get(&self, cid: &Cid) -> Result<Option<Bytes>, RepoError> {
        let cid_bytes = cid.to_bytes();
        let row = sqlx::query!("SELECT data FROM blocks WHERE cid = $1", &cid_bytes)
            .fetch_optional(&self.pool)
            .await
            .map_err(RepoError::storage)?;
        match row {
            Some(row) => Ok(Some(Bytes::from(row.data))),
            None => Ok(None),
        }
    }

    async fn put(&self, data: &[u8]) -> Result<Cid, RepoError> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let multihash = Multihash::wrap(0x12, &hash).map_err(|e| {
            RepoError::storage(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to wrap multihash: {:?}", e),
            ))
        })?;
        let cid = Cid::new_v1(0x71, multihash);
        let cid_bytes = cid.to_bytes();
        sqlx::query!(
            "INSERT INTO blocks (cid, data) VALUES ($1, $2) ON CONFLICT (cid) DO NOTHING",
            &cid_bytes,
            data
        )
        .execute(&self.pool)
        .await
        .map_err(RepoError::storage)?;
        Ok(cid)
    }

    async fn has(&self, cid: &Cid) -> Result<bool, RepoError> {
        let cid_bytes = cid.to_bytes();
        let row = sqlx::query!("SELECT 1 as one FROM blocks WHERE cid = $1", &cid_bytes)
            .fetch_optional(&self.pool)
            .await
            .map_err(RepoError::storage)?;
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
        .map_err(RepoError::storage)?;
        Ok(())
    }

    async fn get_many(&self, cids: &[Cid]) -> Result<Vec<Option<Bytes>>, RepoError> {
        if cids.is_empty() {
            return Ok(Vec::new());
        }
        let cid_bytes: Vec<Vec<u8>> = cids.iter().map(|c| c.to_bytes()).collect();
        let rows = sqlx::query!(
            "SELECT cid, data FROM blocks WHERE cid = ANY($1)",
            &cid_bytes
        )
        .fetch_all(&self.pool)
        .await
        .map_err(RepoError::storage)?;
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

#[derive(Clone)]
pub struct TrackingBlockStore<S: BlockStore> {
    inner: S,
    written_cids: Arc<Mutex<Vec<Cid>>>,
    read_cids: Arc<Mutex<HashSet<Cid>>>,
}

impl<S: BlockStore + Sync> TrackingBlockStore<S> {
    pub fn new(store: S) -> Self {
        Self {
            inner: store,
            written_cids: Arc::new(Mutex::new(Vec::new())),
            read_cids: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn get_written_cids(&self) -> Vec<Cid> {
        match self.written_cids.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    pub fn get_read_cids(&self) -> Vec<Cid> {
        match self.read_cids.lock() {
            Ok(guard) => guard.iter().cloned().collect(),
            Err(poisoned) => poisoned.into_inner().iter().cloned().collect(),
        }
    }

    pub fn get_all_relevant_cids(&self) -> Vec<Cid> {
        let written = self.get_written_cids();
        let read = self.get_read_cids();
        let mut all: HashSet<Cid> = written.into_iter().collect();
        all.extend(read);
        all.into_iter().collect()
    }
}

impl<S: BlockStore + Sync> BlockStore for TrackingBlockStore<S> {
    async fn get(&self, cid: &Cid) -> Result<Option<Bytes>, RepoError> {
        let result = self.inner.get(cid).await?;
        if result.is_some() {
            match self.read_cids.lock() {
                Ok(mut guard) => {
                    guard.insert(*cid);
                }
                Err(poisoned) => {
                    poisoned.into_inner().insert(*cid);
                }
            }
        }
        Ok(result)
    }

    async fn put(&self, data: &[u8]) -> Result<Cid, RepoError> {
        let cid = self.inner.put(data).await?;
        match self.written_cids.lock() {
            Ok(mut guard) => guard.push(cid),
            Err(poisoned) => poisoned.into_inner().push(cid),
        }
        Ok(cid)
    }

    async fn has(&self, cid: &Cid) -> Result<bool, RepoError> {
        self.inner.has(cid).await
    }

    async fn put_many(
        &self,
        blocks: impl IntoIterator<Item = (Cid, Bytes)> + Send,
    ) -> Result<(), RepoError> {
        let blocks: Vec<_> = blocks.into_iter().collect();
        let cids: Vec<Cid> = blocks.iter().map(|(cid, _)| *cid).collect();
        self.inner.put_many(blocks).await?;
        match self.written_cids.lock() {
            Ok(mut guard) => guard.extend(cids),
            Err(poisoned) => poisoned.into_inner().extend(cids),
        }
        Ok(())
    }

    async fn get_many(&self, cids: &[Cid]) -> Result<Vec<Option<Bytes>>, RepoError> {
        let results = self.inner.get_many(cids).await?;
        cids.iter()
            .zip(results.iter())
            .filter(|(_, result)| result.is_some())
            .for_each(|(cid, _)| match self.read_cids.lock() {
                Ok(mut guard) => {
                    guard.insert(*cid);
                }
                Err(poisoned) => {
                    poisoned.into_inner().insert(*cid);
                }
            });
        Ok(results)
    }

    async fn apply_commit(&self, commit: CommitData) -> Result<(), RepoError> {
        self.put_many(commit.blocks).await?;
        Ok(())
    }
}
