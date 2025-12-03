use jacquard_repo::storage::BlockStore;
use jacquard_repo::error::RepoError;
use jacquard_repo::repo::CommitData;
use cid::Cid;
use sqlx::{PgPool, Row};
use bytes::Bytes;
use sha2::{Sha256, Digest};
use multihash::Multihash;

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
        let cid_bytes = cid.to_bytes();
        let row = sqlx::query("SELECT data FROM blocks WHERE cid = $1")
            .bind(cid_bytes)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| RepoError::storage(e))?;

        match row {
            Some(row) => {
                let data: Vec<u8> = row.get("data");
                Ok(Some(Bytes::from(data)))
            },
            None => Ok(None),
        }
    }

    async fn put(&self, data: &[u8]) -> Result<Cid, RepoError> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let multihash = Multihash::wrap(0x12, &hash).unwrap();
        let cid = Cid::new_v1(0x71, multihash);
        let cid_bytes = cid.to_bytes();

        sqlx::query("INSERT INTO blocks (cid, data) VALUES ($1, $2) ON CONFLICT (cid) DO NOTHING")
            .bind(cid_bytes)
            .bind(data)
            .execute(&self.pool)
            .await
            .map_err(|e| RepoError::storage(e))?;

        Ok(cid)
    }

    async fn has(&self, cid: &Cid) -> Result<bool, RepoError> {
        let cid_bytes = cid.to_bytes();
        let row = sqlx::query("SELECT 1 FROM blocks WHERE cid = $1")
            .bind(cid_bytes)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| RepoError::storage(e))?;

        Ok(row.is_some())
    }

    async fn put_many(&self, blocks: impl IntoIterator<Item = (Cid, Bytes)> + Send) -> Result<(), RepoError> {
        let blocks: Vec<_> = blocks.into_iter().collect();
        for (cid, data) in blocks {
            let cid_bytes = cid.to_bytes();
            sqlx::query("INSERT INTO blocks (cid, data) VALUES ($1, $2) ON CONFLICT (cid) DO NOTHING")
                .bind(cid_bytes)
                .bind(data.as_ref())
                .execute(&self.pool)
                .await
                .map_err(|e| RepoError::storage(e))?;
        }
        Ok(())
    }

    async fn get_many(&self, cids: &[Cid]) -> Result<Vec<Option<Bytes>>, RepoError> {
        let mut results = Vec::new();
        for cid in cids {
            results.push(self.get(cid).await?);
        }
        Ok(results)
    }

    async fn apply_commit(&self, commit: CommitData) -> Result<(), RepoError> {
        self.put_many(commit.blocks).await?;
        Ok(())
    }
}
