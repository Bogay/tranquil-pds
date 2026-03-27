use std::marker::PhantomData;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokio::sync::oneshot;
use tranquil_db_traits::{
    AccountStatus, ApplyCommitError, ApplyCommitInput, ApplyCommitResult, Backlink,
    BrokenGenesisCommit, CommitEventData, DbError, EventBlocksCids, ImportBlock, ImportRecord,
    ImportRepoError, RepoAccountInfo, RepoInfo, RepoListItem, RepoWithoutRev, SequenceNumber,
    SequencedEvent, UserNeedingRecordBlobsBackfill, UserWithoutBlocks,
};
use tranquil_types::{AtUri, CidLink, Did, Handle, Nsid, Rkey};
use uuid::Uuid;

use super::handler::{
    BacklinkRequest, BlobRequest, CommitRequest, EventRequest, HandlerPool, MetastoreRequest,
    RecordRequest, RepoRequest, UserBlockRequest,
};
use super::keys::UserHash;
use crate::io::StorageIO;

async fn recv<T>(rx: oneshot::Receiver<Result<T, DbError>>) -> Result<T, DbError> {
    rx.await
        .map_err(|_| DbError::Connection("metastore handler thread closed".to_string()))?
}

async fn recv_commit(
    rx: oneshot::Receiver<Result<ApplyCommitResult, ApplyCommitError>>,
) -> Result<ApplyCommitResult, ApplyCommitError> {
    rx.await
        .map_err(|_| ApplyCommitError::Database("metastore handler thread closed".to_string()))?
}

async fn recv_import(
    rx: oneshot::Receiver<Result<(), ImportRepoError>>,
) -> Result<(), ImportRepoError> {
    rx.await
        .map_err(|_| ImportRepoError::Database("metastore handler thread closed".to_string()))?
}

pub struct MetastoreClient<S: StorageIO> {
    pool: Arc<HandlerPool>,
    _phantom: PhantomData<S>,
}

impl<S: StorageIO> Clone for MetastoreClient<S> {
    fn clone(&self) -> Self {
        Self {
            pool: Arc::clone(&self.pool),
            _phantom: PhantomData,
        }
    }
}

impl<S: StorageIO> MetastoreClient<S> {
    pub fn new(pool: Arc<HandlerPool>) -> Self {
        Self {
            pool,
            _phantom: PhantomData,
        }
    }

    pub fn pool(&self) -> &Arc<HandlerPool> {
        &self.pool
    }

    pub async fn create_repo_full(
        &self,
        user_id: Uuid,
        did: &Did,
        handle: &Handle,
        repo_root_cid: &CidLink,
        repo_rev: &str,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Repo(RepoRequest::CreateRepoFull {
                user_id,
                did: did.clone(),
                handle: handle.clone(),
                repo_root_cid: repo_root_cid.clone(),
                repo_rev: repo_rev.to_string(),
                tx,
            }))?;
        recv(rx).await
    }
}

#[async_trait]
impl<S: StorageIO + 'static> tranquil_db_traits::RepoRepository for MetastoreClient<S> {
    async fn create_repo(
        &self,
        user_id: Uuid,
        did: &Did,
        handle: &Handle,
        repo_root_cid: &CidLink,
        repo_rev: &str,
    ) -> Result<(), DbError> {
        self.create_repo_full(user_id, did, handle, repo_root_cid, repo_rev)
            .await
    }

    async fn update_repo_status(
        &self,
        did: &Did,
        takedown: Option<bool>,
        takedown_ref: Option<&str>,
        deactivated: Option<bool>,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Repo(RepoRequest::UpdateRepoStatus {
                did: did.clone(),
                takedown,
                takedown_ref: takedown_ref.map(str::to_owned),
                deactivated,
                tx,
            }))?;
        recv(rx).await
    }

    async fn update_repo_root(
        &self,
        user_id: Uuid,
        repo_root_cid: &CidLink,
        repo_rev: &str,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Repo(RepoRequest::UpdateRepoRoot {
                user_id,
                repo_root_cid: repo_root_cid.clone(),
                repo_rev: repo_rev.to_string(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn update_repo_rev(&self, user_id: Uuid, repo_rev: &str) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Repo(RepoRequest::UpdateRepoRev {
                user_id,
                repo_rev: repo_rev.to_string(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn delete_repo(&self, user_id: Uuid) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Repo(RepoRequest::DeleteRepo {
                user_id,
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_repo_root_for_update(&self, user_id: Uuid) -> Result<Option<CidLink>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Repo(RepoRequest::GetRepoRootForUpdate {
                user_id,
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_repo(&self, user_id: Uuid) -> Result<Option<RepoInfo>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Repo(RepoRequest::GetRepo { user_id, tx }))?;
        recv(rx).await
    }

    async fn get_repo_root_by_did(&self, did: &Did) -> Result<Option<CidLink>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Repo(RepoRequest::GetRepoRootByDid {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn count_repos(&self) -> Result<i64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Repo(RepoRequest::CountRepos { tx }))?;
        recv(rx).await
    }

    async fn get_repos_without_rev(&self) -> Result<Vec<RepoWithoutRev>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Repo(RepoRequest::GetReposWithoutRev {
                tx,
            }))?;
        recv(rx).await
    }

    async fn upsert_records(
        &self,
        repo_id: Uuid,
        collections: &[Nsid],
        rkeys: &[Rkey],
        record_cids: &[CidLink],
        repo_rev: &str,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Record(RecordRequest::UpsertRecords {
                repo_id,
                collections: collections.to_vec(),
                rkeys: rkeys.to_vec(),
                record_cids: record_cids.to_vec(),
                repo_rev: repo_rev.to_string(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn delete_records(
        &self,
        repo_id: Uuid,
        collections: &[Nsid],
        rkeys: &[Rkey],
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Record(RecordRequest::DeleteRecords {
                repo_id,
                collections: collections.to_vec(),
                rkeys: rkeys.to_vec(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn delete_all_records(&self, repo_id: Uuid) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Record(RecordRequest::DeleteAllRecords {
                repo_id,
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_record_cid(
        &self,
        repo_id: Uuid,
        collection: &Nsid,
        rkey: &Rkey,
    ) -> Result<Option<CidLink>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Record(RecordRequest::GetRecordCid {
                repo_id,
                collection: collection.clone(),
                rkey: rkey.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn list_records(
        &self,
        repo_id: Uuid,
        collection: &Nsid,
        cursor: Option<&Rkey>,
        limit: i64,
        reverse: bool,
        rkey_start: Option<&Rkey>,
        rkey_end: Option<&Rkey>,
    ) -> Result<Vec<tranquil_db_traits::RecordInfo>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Record(RecordRequest::ListRecords {
                repo_id,
                collection: collection.clone(),
                cursor: cursor.cloned(),
                limit,
                reverse,
                rkey_start: rkey_start.cloned(),
                rkey_end: rkey_end.cloned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_all_records(
        &self,
        repo_id: Uuid,
    ) -> Result<Vec<tranquil_db_traits::FullRecordInfo>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Record(RecordRequest::GetAllRecords {
                repo_id,
                tx,
            }))?;
        recv(rx).await
    }

    async fn list_collections(&self, repo_id: Uuid) -> Result<Vec<Nsid>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Record(RecordRequest::ListCollections {
                repo_id,
                tx,
            }))?;
        recv(rx).await
    }

    async fn count_records(&self, repo_id: Uuid) -> Result<i64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Record(RecordRequest::CountRecords {
                repo_id,
                tx,
            }))?;
        recv(rx).await
    }

    async fn count_all_records(&self) -> Result<i64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Record(RecordRequest::CountAllRecords {
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_record_by_cid(
        &self,
        cid: &CidLink,
    ) -> Result<Option<tranquil_db_traits::RecordWithTakedown>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Record(RecordRequest::GetRecordByCid {
                cid: cid.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn set_record_takedown(
        &self,
        cid: &CidLink,
        takedown_ref: Option<&str>,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Record(RecordRequest::SetRecordTakedown {
                cid: cid.clone(),
                takedown_ref: takedown_ref.map(str::to_owned),
                scope_user: None,
                tx,
            }))?;
        recv(rx).await
    }

    async fn insert_user_blocks(
        &self,
        user_id: Uuid,
        block_cids: &[Vec<u8>],
        repo_rev: &str,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::UserBlock(
            UserBlockRequest::InsertUserBlocks {
                user_id,
                block_cids: block_cids.to_vec(),
                repo_rev: repo_rev.to_string(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn delete_user_blocks(
        &self,
        user_id: Uuid,
        block_cids: &[Vec<u8>],
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::UserBlock(
            UserBlockRequest::DeleteUserBlocks {
                user_id,
                block_cids: block_cids.to_vec(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_user_block_cids_since_rev(
        &self,
        user_id: Uuid,
        since_rev: &str,
    ) -> Result<Vec<Vec<u8>>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::UserBlock(
            UserBlockRequest::GetUserBlockCidsSinceRev {
                user_id,
                since_rev: since_rev.to_string(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn count_user_blocks(&self, user_id: Uuid) -> Result<i64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::UserBlock(
            UserBlockRequest::CountUserBlocks { user_id, tx },
        ))?;
        recv(rx).await
    }

    async fn find_unreferenced_blocks(
        &self,
        candidate_cids: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::UserBlock(
            UserBlockRequest::FindUnreferencedBlocks {
                candidate_cids: candidate_cids.to_vec(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn insert_commit_event(&self, data: &CommitEventData) -> Result<SequenceNumber, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Event(EventRequest::InsertCommitEvent {
                data: data.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn insert_identity_event(
        &self,
        did: &Did,
        handle: Option<&Handle>,
    ) -> Result<SequenceNumber, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Event(EventRequest::InsertIdentityEvent {
                did: did.clone(),
                handle: handle.cloned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn insert_account_event(
        &self,
        did: &Did,
        status: AccountStatus,
    ) -> Result<SequenceNumber, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Event(EventRequest::InsertAccountEvent {
                did: did.clone(),
                status,
                tx,
            }))?;
        recv(rx).await
    }

    async fn insert_sync_event(
        &self,
        did: &Did,
        commit_cid: &CidLink,
        rev: Option<&str>,
    ) -> Result<SequenceNumber, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Event(EventRequest::InsertSyncEvent {
                did: did.clone(),
                commit_cid: commit_cid.clone(),
                rev: rev.map(str::to_owned),
                tx,
            }))?;
        recv(rx).await
    }

    async fn insert_genesis_commit_event(
        &self,
        did: &Did,
        commit_cid: &CidLink,
        mst_root_cid: &CidLink,
        rev: &str,
    ) -> Result<SequenceNumber, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Event(
            EventRequest::InsertGenesisCommitEvent {
                did: did.clone(),
                commit_cid: commit_cid.clone(),
                mst_root_cid: mst_root_cid.clone(),
                rev: rev.to_string(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn update_seq_blocks_cids(
        &self,
        seq: SequenceNumber,
        blocks_cids: &[String],
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Event(EventRequest::UpdateSeqBlocksCids {
                seq,
                blocks_cids: blocks_cids.to_vec(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn delete_sequences_except(
        &self,
        did: &Did,
        keep_seq: SequenceNumber,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Event(
            EventRequest::DeleteSequencesExcept {
                did: did.clone(),
                keep_seq,
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_max_seq(&self) -> Result<SequenceNumber, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Event(EventRequest::GetMaxSeq { tx }))?;
        recv(rx).await
    }

    async fn get_min_seq_since(
        &self,
        since: DateTime<Utc>,
    ) -> Result<Option<SequenceNumber>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Event(EventRequest::GetMinSeqSince {
                since,
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_account_with_repo(&self, did: &Did) -> Result<Option<RepoAccountInfo>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Repo(RepoRequest::GetAccountWithRepo {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_events_since_seq(
        &self,
        since_seq: SequenceNumber,
        limit: Option<i64>,
    ) -> Result<Vec<SequencedEvent>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Event(EventRequest::GetEventsSinceSeq {
                since_seq,
                limit,
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_events_in_seq_range(
        &self,
        start_seq: SequenceNumber,
        end_seq: SequenceNumber,
    ) -> Result<Vec<SequencedEvent>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Event(EventRequest::GetEventsInSeqRange {
                start_seq,
                end_seq,
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_event_by_seq(
        &self,
        seq: SequenceNumber,
    ) -> Result<Option<SequencedEvent>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Event(EventRequest::GetEventBySeq {
                seq,
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_events_since_cursor(
        &self,
        cursor: SequenceNumber,
        limit: i64,
    ) -> Result<Vec<SequencedEvent>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Event(
            EventRequest::GetEventsSinceCursor { cursor, limit, tx },
        ))?;
        recv(rx).await
    }

    async fn get_events_since_rev(
        &self,
        did: &Did,
        since_rev: &str,
    ) -> Result<Vec<EventBlocksCids>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Event(EventRequest::GetEventsSinceRev {
                did: did.clone(),
                since_rev: since_rev.to_string(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn list_repos_paginated(
        &self,
        cursor_did: Option<&Did>,
        limit: i64,
    ) -> Result<Vec<RepoListItem>, DbError> {
        let cursor_hash = cursor_did.map(|d| UserHash::from_did(d.as_str()).raw());
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Repo(RepoRequest::ListReposPaginated {
                cursor_user_hash: cursor_hash,
                limit: usize::try_from(limit).unwrap_or(usize::MAX),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_repo_root_cid_by_user_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<CidLink>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Repo(
            RepoRequest::GetRepoRootCidByUserId { user_id, tx },
        ))?;
        recv(rx).await
    }

    async fn notify_update(&self, seq: SequenceNumber) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Event(EventRequest::NotifyUpdate {
                seq,
                tx,
            }))?;
        recv(rx).await
    }

    async fn import_repo_data(
        &self,
        user_id: Uuid,
        blocks: &[ImportBlock],
        records: &[ImportRecord],
        expected_root_cid: Option<&CidLink>,
    ) -> Result<(), ImportRepoError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Commit(Box::new(
                CommitRequest::ImportRepoData {
                    user_id,
                    blocks: blocks.to_vec(),
                    records: records.to_vec(),
                    expected_root_cid: expected_root_cid.cloned(),
                    tx,
                },
            )))
            .map_err(|e| ImportRepoError::Database(e.to_string()))?;
        recv_import(rx).await
    }

    async fn apply_commit(
        &self,
        input: ApplyCommitInput,
    ) -> Result<ApplyCommitResult, ApplyCommitError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Commit(Box::new(
                CommitRequest::ApplyCommit {
                    input: Box::new(input),
                    tx,
                },
            )))
            .map_err(|e| ApplyCommitError::Database(e.to_string()))?;
        recv_commit(rx).await
    }

    async fn get_broken_genesis_commits(&self) -> Result<Vec<BrokenGenesisCommit>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Commit(Box::new(
            CommitRequest::GetBrokenGenesisCommits { tx },
        )))?;
        recv(rx).await
    }

    async fn get_users_without_blocks(&self) -> Result<Vec<UserWithoutBlocks>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Commit(Box::new(
            CommitRequest::GetUsersWithoutBlocks { tx },
        )))?;
        recv(rx).await
    }

    async fn get_users_needing_record_blobs_backfill(
        &self,
        limit: i64,
    ) -> Result<Vec<UserNeedingRecordBlobsBackfill>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Commit(Box::new(
            CommitRequest::GetUsersNeedingRecordBlobsBackfill { limit, tx },
        )))?;
        recv(rx).await
    }

    async fn insert_record_blobs(
        &self,
        repo_id: Uuid,
        record_uris: &[AtUri],
        blob_cids: &[CidLink],
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Commit(Box::new(
            CommitRequest::InsertRecordBlobs {
                repo_id,
                record_uris: record_uris.to_vec(),
                blob_cids: blob_cids.to_vec(),
                tx,
            },
        )))?;
        recv(rx).await
    }
}

#[async_trait]
impl<S: StorageIO + 'static> tranquil_db_traits::BacklinkRepository for MetastoreClient<S> {
    async fn get_backlink_conflicts(
        &self,
        repo_id: Uuid,
        collection: &Nsid,
        backlinks: &[Backlink],
    ) -> Result<Vec<AtUri>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Backlink(
            BacklinkRequest::GetBacklinkConflicts {
                repo_id,
                collection: collection.clone(),
                backlinks: backlinks.to_vec(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn add_backlinks(&self, repo_id: Uuid, backlinks: &[Backlink]) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Backlink(BacklinkRequest::AddBacklinks {
                repo_id,
                backlinks: backlinks.to_vec(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn remove_backlinks_by_uri(&self, uri: &AtUri) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Backlink(
            BacklinkRequest::RemoveBacklinksByUri {
                uri: uri.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn remove_backlinks_by_repo(&self, repo_id: Uuid) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Backlink(
            BacklinkRequest::RemoveBacklinksByRepo { repo_id, tx },
        ))?;
        recv(rx).await
    }
}

#[async_trait]
impl<S: StorageIO + 'static> tranquil_db_traits::BlobRepository for MetastoreClient<S> {
    async fn insert_blob(
        &self,
        cid: &CidLink,
        mime_type: &str,
        size_bytes: i64,
        created_by_user: Uuid,
        storage_key: &str,
    ) -> Result<Option<CidLink>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Blob(BlobRequest::InsertBlob {
                cid: cid.clone(),
                mime_type: mime_type.to_owned(),
                size_bytes,
                created_by_user,
                storage_key: storage_key.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_blob_metadata(
        &self,
        cid: &CidLink,
    ) -> Result<Option<tranquil_db_traits::BlobMetadata>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Blob(BlobRequest::GetBlobMetadata {
                cid: cid.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_blob_with_takedown(
        &self,
        cid: &CidLink,
    ) -> Result<Option<tranquil_db_traits::BlobWithTakedown>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Blob(BlobRequest::GetBlobWithTakedown {
                cid: cid.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_blob_storage_key(&self, cid: &CidLink) -> Result<Option<String>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Blob(BlobRequest::GetBlobStorageKey {
                cid: cid.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn list_blobs_by_user(
        &self,
        user_id: Uuid,
        cursor: Option<&str>,
        limit: i64,
    ) -> Result<Vec<CidLink>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Blob(BlobRequest::ListBlobsByUser {
                user_id,
                cursor: cursor.map(str::to_owned),
                limit,
                tx,
            }))?;
        recv(rx).await
    }

    async fn list_blobs_since_rev(
        &self,
        did: &tranquil_types::Did,
        since: &str,
    ) -> Result<Vec<CidLink>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Blob(BlobRequest::ListBlobsSinceRev {
                did: did.clone(),
                since: since.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn count_blobs_by_user(&self, user_id: Uuid) -> Result<i64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Blob(BlobRequest::CountBlobsByUser {
                user_id,
                tx,
            }))?;
        recv(rx).await
    }

    async fn sum_blob_storage(&self) -> Result<i64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Blob(BlobRequest::SumBlobStorage { tx }))?;
        recv(rx).await
    }

    async fn update_blob_takedown(
        &self,
        cid: &CidLink,
        takedown_ref: Option<&str>,
    ) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Blob(BlobRequest::UpdateBlobTakedown {
                cid: cid.clone(),
                takedown_ref: takedown_ref.map(str::to_owned),
                tx,
            }))?;
        recv(rx).await
    }

    async fn delete_blob_by_cid(&self, cid: &CidLink) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Blob(BlobRequest::DeleteBlobByCid {
                cid: cid.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn delete_blobs_by_user(&self, user_id: Uuid) -> Result<u64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Blob(BlobRequest::DeleteBlobsByUser {
                user_id,
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_blob_storage_keys_by_user(&self, user_id: Uuid) -> Result<Vec<String>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Blob(
            BlobRequest::GetBlobStorageKeysByUser { user_id, tx },
        ))?;
        recv(rx).await
    }

    async fn insert_record_blobs(
        &self,
        repo_id: Uuid,
        record_uris: &[AtUri],
        blob_cids: &[CidLink],
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Commit(Box::new(
            CommitRequest::InsertRecordBlobs {
                repo_id,
                record_uris: record_uris.to_vec(),
                blob_cids: blob_cids.to_vec(),
                tx,
            },
        )))?;
        recv(rx).await
    }

    async fn list_missing_blobs(
        &self,
        repo_id: Uuid,
        cursor: Option<&str>,
        limit: i64,
    ) -> Result<Vec<tranquil_db_traits::MissingBlobInfo>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Blob(BlobRequest::ListMissingBlobs {
                repo_id,
                cursor: cursor.map(str::to_owned),
                limit,
                tx,
            }))?;
        recv(rx).await
    }

    async fn count_distinct_record_blobs(&self, repo_id: Uuid) -> Result<i64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Blob(
            BlobRequest::CountDistinctRecordBlobs { repo_id, tx },
        ))?;
        recv(rx).await
    }

    async fn get_blobs_for_export(
        &self,
        repo_id: Uuid,
    ) -> Result<Vec<tranquil_db_traits::BlobForExport>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Blob(BlobRequest::GetBlobsForExport {
                repo_id,
                tx,
            }))?;
        recv(rx).await
    }
}
