use crate::repo::PostgresBlockStore;
use bytes::Bytes;
use cid::Cid;
use jacquard_repo::error::RepoError;
use jacquard_repo::repo::CommitData;
use jacquard_repo::storage::BlockStore;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct TrackingBlockStore {
    inner: PostgresBlockStore,
    written_cids: Arc<Mutex<Vec<Cid>>>,
}

impl TrackingBlockStore {
    pub fn new(store: PostgresBlockStore) -> Self {
        Self {
            inner: store,
            written_cids: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn get_written_cids(&self) -> Vec<Cid> {
        self.written_cids.lock().unwrap().clone()
    }
}

impl BlockStore for TrackingBlockStore {
    async fn get(&self, cid: &Cid) -> Result<Option<Bytes>, RepoError> {
        self.inner.get(cid).await
    }

    async fn put(&self, data: &[u8]) -> Result<Cid, RepoError> {
        let cid = self.inner.put(data).await?;
        self.written_cids.lock().unwrap().push(cid.clone());
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
        let cids: Vec<Cid> = blocks.iter().map(|(cid, _)| cid.clone()).collect();
        self.inner.put_many(blocks).await?;
        self.written_cids.lock().unwrap().extend(cids);
        Ok(())
    }

    async fn get_many(&self, cids: &[Cid]) -> Result<Vec<Option<Bytes>>, RepoError> {
        self.inner.get_many(cids).await
    }

    async fn apply_commit(&self, commit: CommitData) -> Result<(), RepoError> {
        self.put_many(commit.blocks).await?;
        Ok(())
    }
}
