pub use tranquil_repo::PostgresBlockStore;

pub type TrackingBlockStore = tranquil_repo::TrackingBlockStore<AnyBlockStore>;

use bytes::Bytes;
use cid::Cid;
use jacquard_repo::error::RepoError;
use jacquard_repo::repo::CommitData;
use jacquard_repo::storage::BlockStore;
use tranquil_store::blockstore::TranquilBlockStore;

#[derive(Clone)]
pub enum AnyBlockStore {
    Postgres(PostgresBlockStore),
    TranquilStore(TranquilBlockStore),
}

impl AnyBlockStore {
    pub fn as_postgres(&self) -> Option<&PostgresBlockStore> {
        match self {
            Self::Postgres(s) => Some(s),
            Self::TranquilStore(_) => None,
        }
    }

    pub fn as_tranquil_store(&self) -> Option<&TranquilBlockStore> {
        match self {
            Self::TranquilStore(s) => Some(s),
            Self::Postgres(_) => None,
        }
    }

    pub async fn decrement_refs(&self, cids: &[Cid]) -> Result<(), RepoError> {
        match self {
            Self::Postgres(_) => Ok(()),
            Self::TranquilStore(s) => s.decrement_refs(cids).await,
        }
    }
}

impl BlockStore for AnyBlockStore {
    async fn get(&self, cid: &Cid) -> Result<Option<Bytes>, RepoError> {
        match self {
            Self::Postgres(s) => s.get(cid).await,
            Self::TranquilStore(s) => s.get(cid).await,
        }
    }

    async fn put(&self, data: &[u8]) -> Result<Cid, RepoError> {
        match self {
            Self::Postgres(s) => s.put(data).await,
            Self::TranquilStore(s) => s.put(data).await,
        }
    }

    async fn has(&self, cid: &Cid) -> Result<bool, RepoError> {
        match self {
            Self::Postgres(s) => s.has(cid).await,
            Self::TranquilStore(s) => s.has(cid).await,
        }
    }

    async fn put_many(
        &self,
        blocks: impl IntoIterator<Item = (Cid, Bytes)> + Send,
    ) -> Result<(), RepoError> {
        match self {
            Self::Postgres(s) => s.put_many(blocks).await,
            Self::TranquilStore(s) => s.put_many(blocks).await,
        }
    }

    async fn get_many(&self, cids: &[Cid]) -> Result<Vec<Option<Bytes>>, RepoError> {
        match self {
            Self::Postgres(s) => s.get_many(cids).await,
            Self::TranquilStore(s) => s.get_many(cids).await,
        }
    }

    async fn apply_commit(&self, commit: CommitData) -> Result<(), RepoError> {
        match self {
            Self::Postgres(s) => s.apply_commit(commit).await,
            Self::TranquilStore(s) => s.apply_commit(commit).await,
        }
    }
}
