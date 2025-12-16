use crate::repo::PostgresBlockStore;
use bytes::Bytes;
use cid::Cid;
use jacquard_repo::error::RepoError;
use jacquard_repo::repo::CommitData;
use jacquard_repo::storage::BlockStore;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct TrackingBlockStore {
    inner: PostgresBlockStore,
    written_cids: Arc<Mutex<Vec<Cid>>>,
    read_cids: Arc<Mutex<HashSet<Cid>>>,
}

impl TrackingBlockStore {
    pub fn new(store: PostgresBlockStore) -> Self {
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

impl BlockStore for TrackingBlockStore {
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
        for (cid, result) in cids.iter().zip(results.iter()) {
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
        }
        Ok(results)
    }

    async fn apply_commit(&self, commit: CommitData) -> Result<(), RepoError> {
        self.put_many(commit.blocks).await?;
        Ok(())
    }
}
