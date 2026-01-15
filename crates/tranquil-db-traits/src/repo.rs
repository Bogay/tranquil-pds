use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tranquil_types::{AtUri, CidLink, Did, Handle, Nsid, Rkey};
use uuid::Uuid;

use crate::DbError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoAccountInfo {
    pub user_id: Uuid,
    pub did: Did,
    pub deactivated_at: Option<DateTime<Utc>>,
    pub takedown_ref: Option<String>,
    pub repo_root_cid: Option<CidLink>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoInfo {
    pub user_id: Uuid,
    pub repo_root_cid: CidLink,
    pub repo_rev: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordInfo {
    pub rkey: Rkey,
    pub record_cid: CidLink,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullRecordInfo {
    pub collection: Nsid,
    pub rkey: Rkey,
    pub record_cid: CidLink,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordWithTakedown {
    pub id: Uuid,
    pub takedown_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoWithoutRev {
    pub user_id: Uuid,
    pub repo_root_cid: CidLink,
}

#[derive(Debug, Clone)]
pub struct BrokenGenesisCommit {
    pub seq: i64,
    pub did: Did,
    pub commit_cid: Option<CidLink>,
}

#[derive(Debug, Clone)]
pub struct UserWithoutBlocks {
    pub user_id: Uuid,
    pub repo_root_cid: CidLink,
    pub repo_rev: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UserNeedingRecordBlobsBackfill {
    pub user_id: Uuid,
    pub did: Did,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoSeqEvent {
    pub seq: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencedEvent {
    pub seq: i64,
    pub did: Did,
    pub created_at: DateTime<Utc>,
    pub event_type: String,
    pub commit_cid: Option<CidLink>,
    pub prev_cid: Option<CidLink>,
    pub prev_data_cid: Option<CidLink>,
    pub ops: Option<serde_json::Value>,
    pub blobs: Option<Vec<String>>,
    pub blocks_cids: Option<Vec<String>>,
    pub handle: Option<Handle>,
    pub active: Option<bool>,
    pub status: Option<String>,
    pub rev: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CommitEventData {
    pub did: Did,
    pub event_type: String,
    pub commit_cid: Option<CidLink>,
    pub prev_cid: Option<CidLink>,
    pub ops: Option<serde_json::Value>,
    pub blobs: Option<Vec<String>>,
    pub blocks_cids: Option<Vec<String>>,
    pub prev_data_cid: Option<CidLink>,
    pub rev: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventBlocksCids {
    pub blocks_cids: Option<Vec<String>>,
    pub commit_cid: Option<CidLink>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoListItem {
    pub did: Did,
    pub deactivated_at: Option<DateTime<Utc>>,
    pub takedown_ref: Option<String>,
    pub repo_root_cid: CidLink,
    pub repo_rev: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ImportBlock {
    pub cid_bytes: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ImportRecord {
    pub collection: Nsid,
    pub rkey: Rkey,
    pub record_cid: CidLink,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportRepoError {
    RepoNotFound,
    ConcurrentModification,
    Database(String),
}

#[derive(Debug, Clone)]
pub struct RecordUpsert {
    pub collection: Nsid,
    pub rkey: Rkey,
    pub cid: CidLink,
}

#[derive(Debug, Clone)]
pub struct RecordDelete {
    pub collection: Nsid,
    pub rkey: Rkey,
}

#[derive(Debug, Clone)]
pub struct ApplyCommitInput {
    pub user_id: Uuid,
    pub did: Did,
    pub expected_root_cid: Option<CidLink>,
    pub new_root_cid: CidLink,
    pub new_rev: String,
    pub new_block_cids: Vec<Vec<u8>>,
    pub obsolete_block_cids: Vec<Vec<u8>>,
    pub record_upserts: Vec<RecordUpsert>,
    pub record_deletes: Vec<RecordDelete>,
    pub commit_event: CommitEventData,
}

#[derive(Debug, Clone)]
pub struct ApplyCommitResult {
    pub seq: i64,
    pub is_account_active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyCommitError {
    RepoNotFound,
    ConcurrentModification,
    Database(String),
}

#[async_trait]
pub trait RepoRepository: Send + Sync {
    async fn create_repo(
        &self,
        user_id: Uuid,
        repo_root_cid: &CidLink,
        repo_rev: &str,
    ) -> Result<(), DbError>;

    async fn update_repo_root(
        &self,
        user_id: Uuid,
        repo_root_cid: &CidLink,
        repo_rev: &str,
    ) -> Result<(), DbError>;

    async fn update_repo_rev(&self, user_id: Uuid, repo_rev: &str) -> Result<(), DbError>;

    async fn delete_repo(&self, user_id: Uuid) -> Result<(), DbError>;

    async fn get_repo_root_for_update(&self, user_id: Uuid) -> Result<Option<CidLink>, DbError>;

    async fn get_repo(&self, user_id: Uuid) -> Result<Option<RepoInfo>, DbError>;

    async fn get_repo_root_by_did(&self, did: &Did) -> Result<Option<CidLink>, DbError>;

    async fn count_repos(&self) -> Result<i64, DbError>;

    async fn get_repos_without_rev(&self) -> Result<Vec<RepoWithoutRev>, DbError>;

    async fn upsert_records(
        &self,
        repo_id: Uuid,
        collections: &[Nsid],
        rkeys: &[Rkey],
        record_cids: &[CidLink],
        repo_rev: &str,
    ) -> Result<(), DbError>;

    async fn delete_records(
        &self,
        repo_id: Uuid,
        collections: &[Nsid],
        rkeys: &[Rkey],
    ) -> Result<(), DbError>;

    async fn delete_all_records(&self, repo_id: Uuid) -> Result<(), DbError>;

    async fn get_record_cid(
        &self,
        repo_id: Uuid,
        collection: &Nsid,
        rkey: &Rkey,
    ) -> Result<Option<CidLink>, DbError>;

    #[allow(clippy::too_many_arguments)]
    async fn list_records(
        &self,
        repo_id: Uuid,
        collection: &Nsid,
        cursor: Option<&Rkey>,
        limit: i64,
        reverse: bool,
        rkey_start: Option<&Rkey>,
        rkey_end: Option<&Rkey>,
    ) -> Result<Vec<RecordInfo>, DbError>;

    async fn get_all_records(&self, repo_id: Uuid) -> Result<Vec<FullRecordInfo>, DbError>;

    async fn list_collections(&self, repo_id: Uuid) -> Result<Vec<Nsid>, DbError>;

    async fn count_records(&self, repo_id: Uuid) -> Result<i64, DbError>;

    async fn count_all_records(&self) -> Result<i64, DbError>;

    async fn get_record_by_cid(&self, cid: &CidLink)
    -> Result<Option<RecordWithTakedown>, DbError>;

    async fn set_record_takedown(
        &self,
        cid: &CidLink,
        takedown_ref: Option<&str>,
    ) -> Result<(), DbError>;

    async fn insert_user_blocks(
        &self,
        user_id: Uuid,
        block_cids: &[Vec<u8>],
        repo_rev: &str,
    ) -> Result<(), DbError>;

    async fn delete_user_blocks(
        &self,
        user_id: Uuid,
        block_cids: &[Vec<u8>],
    ) -> Result<(), DbError>;

    async fn get_user_block_cids_since_rev(
        &self,
        user_id: Uuid,
        since_rev: &str,
    ) -> Result<Vec<Vec<u8>>, DbError>;

    async fn count_user_blocks(&self, user_id: Uuid) -> Result<i64, DbError>;

    async fn insert_commit_event(&self, data: &CommitEventData) -> Result<i64, DbError>;

    async fn insert_identity_event(
        &self,
        did: &Did,
        handle: Option<&Handle>,
    ) -> Result<i64, DbError>;

    async fn insert_account_event(
        &self,
        did: &Did,
        active: bool,
        status: Option<&str>,
    ) -> Result<i64, DbError>;

    async fn insert_sync_event(
        &self,
        did: &Did,
        commit_cid: &CidLink,
        rev: Option<&str>,
    ) -> Result<i64, DbError>;

    async fn insert_genesis_commit_event(
        &self,
        did: &Did,
        commit_cid: &CidLink,
        mst_root_cid: &CidLink,
        rev: &str,
    ) -> Result<i64, DbError>;

    async fn update_seq_blocks_cids(&self, seq: i64, blocks_cids: &[String])
    -> Result<(), DbError>;

    async fn delete_sequences_except(&self, did: &Did, keep_seq: i64) -> Result<(), DbError>;

    async fn get_max_seq(&self) -> Result<i64, DbError>;

    async fn get_min_seq_since(&self, since: DateTime<Utc>) -> Result<Option<i64>, DbError>;

    async fn get_account_with_repo(&self, did: &Did) -> Result<Option<RepoAccountInfo>, DbError>;

    async fn get_events_since_seq(
        &self,
        since_seq: i64,
        limit: Option<i64>,
    ) -> Result<Vec<SequencedEvent>, DbError>;

    async fn get_events_in_seq_range(
        &self,
        start_seq: i64,
        end_seq: i64,
    ) -> Result<Vec<SequencedEvent>, DbError>;

    async fn get_event_by_seq(&self, seq: i64) -> Result<Option<SequencedEvent>, DbError>;

    async fn get_events_since_cursor(
        &self,
        cursor: i64,
        limit: i64,
    ) -> Result<Vec<SequencedEvent>, DbError>;

    async fn get_events_since_rev(
        &self,
        did: &Did,
        since_rev: &str,
    ) -> Result<Vec<EventBlocksCids>, DbError>;

    async fn list_repos_paginated(
        &self,
        cursor_did: Option<&Did>,
        limit: i64,
    ) -> Result<Vec<RepoListItem>, DbError>;

    async fn get_repo_root_cid_by_user_id(&self, user_id: Uuid)
    -> Result<Option<CidLink>, DbError>;

    async fn notify_update(&self, seq: i64) -> Result<(), DbError>;

    async fn import_repo_data(
        &self,
        user_id: Uuid,
        blocks: &[ImportBlock],
        records: &[ImportRecord],
    ) -> Result<(), ImportRepoError>;

    async fn apply_commit(
        &self,
        input: ApplyCommitInput,
    ) -> Result<ApplyCommitResult, ApplyCommitError>;

    async fn get_broken_genesis_commits(&self) -> Result<Vec<BrokenGenesisCommit>, DbError>;

    async fn get_users_without_blocks(&self) -> Result<Vec<UserWithoutBlocks>, DbError>;

    async fn get_users_needing_record_blobs_backfill(
        &self,
        limit: i64,
    ) -> Result<Vec<UserNeedingRecordBlobsBackfill>, DbError>;

    async fn insert_record_blobs(
        &self,
        repo_id: Uuid,
        record_uris: &[AtUri],
        blob_cids: &[CidLink],
    ) -> Result<(), DbError>;
}

#[async_trait]
pub trait RepoEventNotifier: Send + Sync {
    async fn subscribe(&self) -> Result<Box<dyn RepoEventReceiver>, DbError>;
}

#[async_trait]
pub trait RepoEventReceiver: Send {
    async fn recv(&mut self) -> Option<i64>;
}
