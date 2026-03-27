use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::JoinHandle;

use chrono::{DateTime, Utc};
use tokio::sync::oneshot;
use tranquil_db_traits::{
    AccountStatus, ApplyCommitError, ApplyCommitInput, ApplyCommitResult, Backlink,
    BrokenGenesisCommit, CommitEventData, DbError, EventBlocksCids, ImportBlock, ImportRecord,
    ImportRepoError, SequenceNumber, SequencedEvent, UserNeedingRecordBlobsBackfill,
    UserWithoutBlocks,
};
use tranquil_types::{AtUri, CidLink, Did, Handle, Nsid, Rkey};
use uuid::Uuid;

use super::MetastoreError;
use super::commit_ops::CommitOps;
use super::event_ops::EventOps;
use super::keys::UserHash;
use super::record_ops::ListRecordsQuery;
use super::user_hash::UserHashMap;
use crate::blockstore::TranquilBlockStore;
use crate::eventlog::EventLogBridge;
use crate::io::StorageIO;
use crate::metastore::Metastore;

type Tx<T> = oneshot::Sender<Result<T, DbError>>;

fn metastore_to_db(e: MetastoreError) -> DbError {
    match e {
        MetastoreError::Fjall(e) => DbError::Query(e.to_string()),
        MetastoreError::Lsm(e) => DbError::Query(e.to_string()),
        MetastoreError::VersionMismatch { expected, found } => DbError::Query(format!(
            "format version mismatch: expected {expected}, found {found}"
        )),
        MetastoreError::CorruptData(msg) => DbError::CorruptData(msg),
        MetastoreError::InvalidInput(msg) => DbError::Query(msg.to_string()),
        MetastoreError::UserHashCollision {
            hash,
            existing_uuid,
            new_uuid,
        } => DbError::Constraint(format!(
            "user hash collision: {hash} maps to both {existing_uuid} and {new_uuid}"
        )),
    }
}

enum Routing {
    Sharded(u64),
    Global,
}

fn uuid_to_routing(user_hashes: &UserHashMap, user_id: &Uuid) -> Routing {
    match user_hashes.get(user_id) {
        Some(h) => Routing::Sharded(h.raw()),
        None => Routing::Sharded(user_id.as_u128() as u64),
    }
}

fn did_to_routing(did: &str) -> Routing {
    Routing::Sharded(UserHash::from_did(did).raw())
}

fn cid_to_routing(cid: &CidLink) -> Routing {
    use siphasher::sip::SipHasher24;
    use std::hash::{Hash, Hasher};
    let mut hasher = SipHasher24::new();
    cid.as_str().hash(&mut hasher);
    Routing::Sharded(hasher.finish())
}

pub enum MetastoreRequest {
    Repo(RepoRequest),
    Record(RecordRequest),
    UserBlock(UserBlockRequest),
    Event(EventRequest),
    Commit(Box<CommitRequest>),
    Backlink(BacklinkRequest),
    Blob(BlobRequest),
}

impl MetastoreRequest {
    fn routing(&self, user_hashes: &UserHashMap) -> Routing {
        match self {
            Self::Repo(r) => r.routing(user_hashes),
            Self::Record(r) => r.routing(user_hashes),
            Self::UserBlock(r) => r.routing(user_hashes),
            Self::Event(r) => r.routing(),
            Self::Commit(r) => r.routing(user_hashes),
            Self::Backlink(r) => r.routing(user_hashes),
            Self::Blob(r) => r.routing(user_hashes),
        }
    }
}

pub enum RepoRequest {
    CreateRepoFull {
        user_id: Uuid,
        did: Did,
        handle: Handle,
        repo_root_cid: CidLink,
        repo_rev: String,
        tx: Tx<()>,
    },
    UpdateRepoRoot {
        user_id: Uuid,
        repo_root_cid: CidLink,
        repo_rev: String,
        tx: Tx<()>,
    },
    UpdateRepoRev {
        user_id: Uuid,
        repo_rev: String,
        tx: Tx<()>,
    },
    DeleteRepo {
        user_id: Uuid,
        tx: Tx<()>,
    },
    GetRepoRootForUpdate {
        user_id: Uuid,
        tx: Tx<Option<CidLink>>,
    },
    GetRepo {
        user_id: Uuid,
        tx: Tx<Option<tranquil_db_traits::RepoInfo>>,
    },
    GetRepoRootByDid {
        did: Did,
        tx: Tx<Option<CidLink>>,
    },
    CountRepos {
        tx: Tx<i64>,
    },
    GetReposWithoutRev {
        tx: Tx<Vec<tranquil_db_traits::RepoWithoutRev>>,
    },
    GetRepoRootCidByUserId {
        user_id: Uuid,
        tx: Tx<Option<CidLink>>,
    },
    GetAccountWithRepo {
        did: Did,
        tx: Tx<Option<tranquil_db_traits::RepoAccountInfo>>,
    },
    ListReposPaginated {
        cursor_user_hash: Option<u64>,
        limit: usize,
        tx: Tx<Vec<tranquil_db_traits::RepoListItem>>,
    },
    UpdateRepoStatus {
        did: Did,
        takedown: Option<bool>,
        takedown_ref: Option<String>,
        deactivated: Option<bool>,
        tx: Tx<()>,
    },
}

impl RepoRequest {
    fn routing(&self, user_hashes: &UserHashMap) -> Routing {
        match self {
            Self::CreateRepoFull { did, .. } => did_to_routing(did.as_str()),
            Self::UpdateRepoRoot { user_id, .. }
            | Self::UpdateRepoRev { user_id, .. }
            | Self::DeleteRepo { user_id, .. }
            | Self::GetRepoRootForUpdate { user_id, .. }
            | Self::GetRepo { user_id, .. }
            | Self::GetRepoRootCidByUserId { user_id, .. } => uuid_to_routing(user_hashes, user_id),
            Self::GetRepoRootByDid { did, .. }
            | Self::GetAccountWithRepo { did, .. }
            | Self::UpdateRepoStatus { did, .. } => did_to_routing(did.as_str()),
            Self::CountRepos { .. }
            | Self::GetReposWithoutRev { .. }
            | Self::ListReposPaginated { .. } => Routing::Global,
        }
    }
}

pub enum RecordRequest {
    UpsertRecords {
        repo_id: Uuid,
        collections: Vec<Nsid>,
        rkeys: Vec<Rkey>,
        record_cids: Vec<CidLink>,
        repo_rev: String,
        tx: Tx<()>,
    },
    DeleteRecords {
        repo_id: Uuid,
        collections: Vec<Nsid>,
        rkeys: Vec<Rkey>,
        tx: Tx<()>,
    },
    DeleteAllRecords {
        repo_id: Uuid,
        tx: Tx<()>,
    },
    GetRecordCid {
        repo_id: Uuid,
        collection: Nsid,
        rkey: Rkey,
        tx: Tx<Option<CidLink>>,
    },
    ListRecords {
        repo_id: Uuid,
        collection: Nsid,
        cursor: Option<Rkey>,
        limit: i64,
        reverse: bool,
        rkey_start: Option<Rkey>,
        rkey_end: Option<Rkey>,
        tx: Tx<Vec<tranquil_db_traits::RecordInfo>>,
    },
    GetAllRecords {
        repo_id: Uuid,
        tx: Tx<Vec<tranquil_db_traits::FullRecordInfo>>,
    },
    ListCollections {
        repo_id: Uuid,
        tx: Tx<Vec<Nsid>>,
    },
    CountRecords {
        repo_id: Uuid,
        tx: Tx<i64>,
    },
    CountAllRecords {
        tx: Tx<i64>,
    },
    GetRecordByCid {
        cid: CidLink,
        tx: Tx<Option<tranquil_db_traits::RecordWithTakedown>>,
    },
    SetRecordTakedown {
        cid: CidLink,
        takedown_ref: Option<String>,
        scope_user: Option<Uuid>,
        tx: Tx<()>,
    },
}

impl RecordRequest {
    fn routing(&self, user_hashes: &UserHashMap) -> Routing {
        match self {
            Self::UpsertRecords { repo_id, .. }
            | Self::DeleteRecords { repo_id, .. }
            | Self::DeleteAllRecords { repo_id, .. }
            | Self::GetRecordCid { repo_id, .. }
            | Self::ListRecords { repo_id, .. }
            | Self::GetAllRecords { repo_id, .. }
            | Self::ListCollections { repo_id, .. }
            | Self::CountRecords { repo_id, .. } => uuid_to_routing(user_hashes, repo_id),
            Self::CountAllRecords { .. } | Self::GetRecordByCid { .. } => Routing::Global,
            Self::SetRecordTakedown {
                scope_user: Some(user_id),
                ..
            } => uuid_to_routing(user_hashes, user_id),
            Self::SetRecordTakedown { .. } => Routing::Global,
        }
    }
}

pub enum UserBlockRequest {
    InsertUserBlocks {
        user_id: Uuid,
        block_cids: Vec<Vec<u8>>,
        repo_rev: String,
        tx: Tx<()>,
    },
    DeleteUserBlocks {
        user_id: Uuid,
        block_cids: Vec<Vec<u8>>,
        tx: Tx<()>,
    },
    GetUserBlockCidsSinceRev {
        user_id: Uuid,
        since_rev: String,
        tx: Tx<Vec<Vec<u8>>>,
    },
    CountUserBlocks {
        user_id: Uuid,
        tx: Tx<i64>,
    },
    FindUnreferencedBlocks {
        candidate_cids: Vec<Vec<u8>>,
        tx: Tx<Vec<Vec<u8>>>,
    },
}

impl UserBlockRequest {
    fn routing(&self, user_hashes: &UserHashMap) -> Routing {
        match self {
            Self::InsertUserBlocks { user_id, .. }
            | Self::DeleteUserBlocks { user_id, .. }
            | Self::GetUserBlockCidsSinceRev { user_id, .. }
            | Self::CountUserBlocks { user_id, .. } => uuid_to_routing(user_hashes, user_id),
            Self::FindUnreferencedBlocks { .. } => Routing::Global,
        }
    }
}

pub enum EventRequest {
    InsertCommitEvent {
        data: CommitEventData,
        tx: Tx<SequenceNumber>,
    },
    InsertIdentityEvent {
        did: Did,
        handle: Option<Handle>,
        tx: Tx<SequenceNumber>,
    },
    InsertAccountEvent {
        did: Did,
        status: AccountStatus,
        tx: Tx<SequenceNumber>,
    },
    InsertSyncEvent {
        did: Did,
        commit_cid: CidLink,
        rev: Option<String>,
        tx: Tx<SequenceNumber>,
    },
    InsertGenesisCommitEvent {
        did: Did,
        commit_cid: CidLink,
        mst_root_cid: CidLink,
        rev: String,
        tx: Tx<SequenceNumber>,
    },
    UpdateSeqBlocksCids {
        seq: SequenceNumber,
        blocks_cids: Vec<String>,
        tx: Tx<()>,
    },
    DeleteSequencesExcept {
        did: Did,
        keep_seq: SequenceNumber,
        tx: Tx<()>,
    },
    GetMaxSeq {
        tx: Tx<SequenceNumber>,
    },
    GetMinSeqSince {
        since: DateTime<Utc>,
        tx: Tx<Option<SequenceNumber>>,
    },
    GetEventsSinceSeq {
        since_seq: SequenceNumber,
        limit: Option<i64>,
        tx: Tx<Vec<SequencedEvent>>,
    },
    GetEventsInSeqRange {
        start_seq: SequenceNumber,
        end_seq: SequenceNumber,
        tx: Tx<Vec<SequencedEvent>>,
    },
    GetEventBySeq {
        seq: SequenceNumber,
        tx: Tx<Option<SequencedEvent>>,
    },
    GetEventsSinceCursor {
        cursor: SequenceNumber,
        limit: i64,
        tx: Tx<Vec<SequencedEvent>>,
    },
    GetEventsSinceRev {
        did: Did,
        since_rev: String,
        tx: Tx<Vec<EventBlocksCids>>,
    },
    NotifyUpdate {
        seq: SequenceNumber,
        tx: Tx<()>,
    },
}

impl EventRequest {
    fn routing(&self) -> Routing {
        match self {
            Self::InsertCommitEvent { data, .. } => {
                Routing::Sharded(UserHash::from_did(data.did.as_str()).raw())
            }
            Self::InsertIdentityEvent { did, .. }
            | Self::InsertAccountEvent { did, .. }
            | Self::InsertSyncEvent { did, .. }
            | Self::InsertGenesisCommitEvent { did, .. }
            | Self::DeleteSequencesExcept { did, .. }
            | Self::GetEventsSinceRev { did, .. } => {
                Routing::Sharded(UserHash::from_did(did.as_str()).raw())
            }
            Self::UpdateSeqBlocksCids { .. }
            | Self::GetMaxSeq { .. }
            | Self::GetMinSeqSince { .. }
            | Self::GetEventsSinceSeq { .. }
            | Self::GetEventsInSeqRange { .. }
            | Self::GetEventBySeq { .. }
            | Self::GetEventsSinceCursor { .. }
            | Self::NotifyUpdate { .. } => Routing::Global,
        }
    }
}

pub enum CommitRequest {
    ApplyCommit {
        input: Box<ApplyCommitInput>,
        tx: oneshot::Sender<Result<ApplyCommitResult, ApplyCommitError>>,
    },
    ImportRepoData {
        user_id: Uuid,
        blocks: Vec<ImportBlock>,
        records: Vec<ImportRecord>,
        expected_root_cid: Option<CidLink>,
        tx: oneshot::Sender<Result<(), ImportRepoError>>,
    },
    GetBrokenGenesisCommits {
        tx: Tx<Vec<BrokenGenesisCommit>>,
    },
    GetUsersWithoutBlocks {
        tx: Tx<Vec<UserWithoutBlocks>>,
    },
    GetUsersNeedingRecordBlobsBackfill {
        limit: i64,
        tx: Tx<Vec<UserNeedingRecordBlobsBackfill>>,
    },
    InsertRecordBlobs {
        repo_id: Uuid,
        record_uris: Vec<AtUri>,
        blob_cids: Vec<CidLink>,
        tx: Tx<()>,
    },
}

impl CommitRequest {
    fn routing(&self, user_hashes: &UserHashMap) -> Routing {
        match self {
            Self::ApplyCommit { input, .. } => did_to_routing(input.did.as_str()),
            Self::ImportRepoData { user_id, .. }
            | Self::InsertRecordBlobs {
                repo_id: user_id, ..
            } => uuid_to_routing(user_hashes, user_id),
            Self::GetBrokenGenesisCommits { .. }
            | Self::GetUsersWithoutBlocks { .. }
            | Self::GetUsersNeedingRecordBlobsBackfill { .. } => Routing::Global,
        }
    }
}

pub enum BacklinkRequest {
    GetBacklinkConflicts {
        repo_id: Uuid,
        collection: Nsid,
        backlinks: Vec<Backlink>,
        tx: Tx<Vec<AtUri>>,
    },
    AddBacklinks {
        repo_id: Uuid,
        backlinks: Vec<Backlink>,
        tx: Tx<()>,
    },
    RemoveBacklinksByUri {
        uri: AtUri,
        tx: Tx<()>,
    },
    RemoveBacklinksByRepo {
        repo_id: Uuid,
        tx: Tx<()>,
    },
}

impl BacklinkRequest {
    fn routing(&self, user_hashes: &UserHashMap) -> Routing {
        match self {
            Self::GetBacklinkConflicts { repo_id, .. }
            | Self::AddBacklinks { repo_id, .. }
            | Self::RemoveBacklinksByRepo { repo_id, .. } => uuid_to_routing(user_hashes, repo_id),
            Self::RemoveBacklinksByUri { uri, .. } => match uri.did() {
                Some(did) => did_to_routing(did),
                None => Routing::Global,
            },
        }
    }
}

pub enum BlobRequest {
    InsertBlob {
        cid: CidLink,
        mime_type: String,
        size_bytes: i64,
        created_by_user: Uuid,
        storage_key: String,
        tx: Tx<Option<CidLink>>,
    },
    GetBlobMetadata {
        cid: CidLink,
        tx: Tx<Option<tranquil_db_traits::BlobMetadata>>,
    },
    GetBlobWithTakedown {
        cid: CidLink,
        tx: Tx<Option<tranquil_db_traits::BlobWithTakedown>>,
    },
    GetBlobStorageKey {
        cid: CidLink,
        tx: Tx<Option<String>>,
    },
    ListBlobsByUser {
        user_id: Uuid,
        cursor: Option<String>,
        limit: i64,
        tx: Tx<Vec<CidLink>>,
    },
    ListBlobsSinceRev {
        did: Did,
        since: String,
        tx: Tx<Vec<CidLink>>,
    },
    CountBlobsByUser {
        user_id: Uuid,
        tx: Tx<i64>,
    },
    SumBlobStorage {
        tx: Tx<i64>,
    },
    UpdateBlobTakedown {
        cid: CidLink,
        takedown_ref: Option<String>,
        tx: Tx<bool>,
    },
    DeleteBlobByCid {
        cid: CidLink,
        tx: Tx<bool>,
    },
    DeleteBlobsByUser {
        user_id: Uuid,
        tx: Tx<u64>,
    },
    GetBlobStorageKeysByUser {
        user_id: Uuid,
        tx: Tx<Vec<String>>,
    },
    ListMissingBlobs {
        repo_id: Uuid,
        cursor: Option<String>,
        limit: i64,
        tx: Tx<Vec<tranquil_db_traits::MissingBlobInfo>>,
    },
    CountDistinctRecordBlobs {
        repo_id: Uuid,
        tx: Tx<i64>,
    },
    GetBlobsForExport {
        repo_id: Uuid,
        tx: Tx<Vec<tranquil_db_traits::BlobForExport>>,
    },
}

impl BlobRequest {
    fn routing(&self, user_hashes: &UserHashMap) -> Routing {
        match self {
            Self::InsertBlob { cid, .. }
            | Self::UpdateBlobTakedown { cid, .. }
            | Self::DeleteBlobByCid { cid, .. } => cid_to_routing(cid),

            Self::DeleteBlobsByUser { user_id, .. } => uuid_to_routing(user_hashes, user_id),

            Self::GetBlobMetadata { .. }
            | Self::GetBlobWithTakedown { .. }
            | Self::GetBlobStorageKey { .. }
            | Self::SumBlobStorage { .. } => Routing::Global,

            Self::ListBlobsByUser { user_id, .. }
            | Self::CountBlobsByUser { user_id, .. }
            | Self::GetBlobStorageKeysByUser { user_id, .. } => {
                uuid_to_routing(user_hashes, user_id)
            }
            Self::ListMissingBlobs { repo_id, .. }
            | Self::CountDistinctRecordBlobs { repo_id, .. }
            | Self::GetBlobsForExport { repo_id, .. } => uuid_to_routing(user_hashes, repo_id),
            Self::ListBlobsSinceRev { did, .. } => did_to_routing(did.as_str()),
        }
    }
}

fn convert_repo_info(r: super::repo_ops::RepoInfo) -> tranquil_db_traits::RepoInfo {
    tranquil_db_traits::RepoInfo {
        user_id: r.user_id,
        repo_root_cid: r.repo_root_cid,
        repo_rev: r.repo_rev,
    }
}

fn convert_repo_account(
    r: super::repo_ops::RepoAccountEntry,
) -> tranquil_db_traits::RepoAccountInfo {
    tranquil_db_traits::RepoAccountInfo {
        user_id: r.user_id,
        did: r.did,
        deactivated_at: r.deactivated_at,
        takedown_ref: r.takedown_ref,
        repo_root_cid: r.repo_root_cid,
    }
}

fn convert_repo_list_entry(
    r: super::repo_ops::RepoListEntry,
) -> Result<tranquil_db_traits::RepoListItem, DbError> {
    let did = r
        .did
        .ok_or(DbError::CorruptData("repo_meta missing DID field"))?;
    Ok(tranquil_db_traits::RepoListItem {
        did: Did::from(did),
        deactivated_at: r.deactivated_at,
        takedown_ref: r.takedown_ref,
        repo_root_cid: r.repo_root_cid,
        repo_rev: r.repo_rev,
    })
}

fn convert_record_info(r: super::record_ops::RecordInfo) -> tranquil_db_traits::RecordInfo {
    tranquil_db_traits::RecordInfo {
        rkey: r.rkey,
        record_cid: r.record_cid,
    }
}

fn convert_full_record_info(
    r: super::record_ops::FullRecordInfo,
) -> tranquil_db_traits::FullRecordInfo {
    tranquil_db_traits::FullRecordInfo {
        collection: r.collection,
        rkey: r.rkey,
        record_cid: r.record_cid,
    }
}

fn convert_record_with_takedown(
    r: super::record_ops::RecordWithTakedown,
) -> tranquil_db_traits::RecordWithTakedown {
    tranquil_db_traits::RecordWithTakedown {
        id: r.id,
        takedown_ref: r.takedown_ref,
    }
}

fn convert_without_rev(
    r: super::repo_ops::RepoWithoutRevEntry,
) -> tranquil_db_traits::RepoWithoutRev {
    tranquil_db_traits::RepoWithoutRev {
        user_id: r.user_id,
        repo_root_cid: r.repo_root_cid,
    }
}

struct HandlerState<S: StorageIO> {
    metastore: Metastore,
    event_ops: EventOps<S>,
    commit_ops: CommitOps<S>,
}

fn dispatch_repo<S: StorageIO>(state: &HandlerState<S>, req: RepoRequest) {
    match req {
        RepoRequest::CreateRepoFull {
            user_id,
            did,
            handle,
            repo_root_cid,
            repo_rev,
            tx,
        } => {
            let result = state
                .metastore
                .repo_ops()
                .create_repo(
                    state.metastore.database(),
                    user_id,
                    &did,
                    &handle,
                    &repo_root_cid,
                    &repo_rev,
                )
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        RepoRequest::UpdateRepoRoot {
            user_id,
            repo_root_cid,
            repo_rev,
            tx,
        } => {
            let result = state
                .metastore
                .repo_ops()
                .update_repo_root(
                    state.metastore.database(),
                    user_id,
                    &repo_root_cid,
                    &repo_rev,
                )
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        RepoRequest::UpdateRepoRev {
            user_id,
            repo_rev,
            tx,
        } => {
            let result = state
                .metastore
                .repo_ops()
                .update_repo_rev(state.metastore.database(), user_id, &repo_rev)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        RepoRequest::DeleteRepo { user_id, tx } => {
            let result = state
                .metastore
                .repo_ops()
                .delete_repo(state.metastore.database(), user_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        RepoRequest::GetRepoRootForUpdate { user_id, tx } => {
            let result = state
                .metastore
                .repo_ops()
                .get_repo_root_for_update(user_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        RepoRequest::GetRepo { user_id, tx } => {
            let result = state
                .metastore
                .repo_ops()
                .get_repo(user_id)
                .map(|opt| opt.map(convert_repo_info))
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        RepoRequest::GetRepoRootByDid { did, tx } => {
            let result = state
                .metastore
                .repo_ops()
                .get_repo_root_by_did(&did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        RepoRequest::CountRepos { tx } => {
            let result = state
                .metastore
                .repo_ops()
                .count_repos()
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        RepoRequest::GetReposWithoutRev { tx } => {
            let result = state
                .metastore
                .repo_ops()
                .get_repos_without_rev(MAX_REPOS_WITHOUT_REV)
                .map(|v| v.into_iter().map(convert_without_rev).collect())
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        RepoRequest::GetRepoRootCidByUserId { user_id, tx } => {
            let result = state
                .metastore
                .repo_ops()
                .get_repo_root_cid_by_user_id(user_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        RepoRequest::GetAccountWithRepo { did, tx } => {
            let result = state
                .metastore
                .repo_ops()
                .get_account_with_repo(&did)
                .map(|opt| opt.map(convert_repo_account))
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        RepoRequest::ListReposPaginated {
            cursor_user_hash,
            limit,
            tx,
        } => {
            let result = state
                .metastore
                .repo_ops()
                .list_repos_paginated(cursor_user_hash, limit)
                .map_err(metastore_to_db)
                .and_then(|entries| entries.into_iter().map(convert_repo_list_entry).collect());
            let _ = tx.send(result);
        }
        RepoRequest::UpdateRepoStatus {
            did,
            takedown,
            takedown_ref,
            deactivated,
            tx,
        } => {
            let result = state
                .metastore
                .repo_ops()
                .update_repo_status(
                    state.metastore.database(),
                    &did,
                    takedown,
                    takedown_ref.as_deref(),
                    deactivated,
                )
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
    }
}

fn dispatch_record<S: StorageIO>(state: &HandlerState<S>, req: RecordRequest) {
    match req {
        RecordRequest::UpsertRecords {
            repo_id,
            collections,
            rkeys,
            record_cids,
            repo_rev,
            tx,
        } => {
            let result = (|| {
                let (user_hash, mut meta) = state
                    .metastore
                    .repo_ops()
                    .get_repo_meta(repo_id)
                    .map_err(metastore_to_db)?
                    .ok_or(DbError::Query("unknown user_id".to_string()))?;
                let writes: Vec<super::record_ops::RecordWrite<'_>> = collections
                    .iter()
                    .zip(rkeys.iter())
                    .zip(record_cids.iter())
                    .map(|((c, r), cid)| super::record_ops::RecordWrite {
                        collection: c,
                        rkey: r,
                        cid,
                    })
                    .collect();
                let mut batch = state.metastore.database().batch();
                state
                    .metastore
                    .record_ops()
                    .upsert_records(&mut batch, user_hash, &writes)
                    .map_err(metastore_to_db)?;
                meta.repo_rev = repo_rev;
                state
                    .metastore
                    .repo_ops()
                    .write_repo_meta(&mut batch, user_hash, &meta);
                batch.commit().map_err(|e| DbError::Query(e.to_string()))
            })();
            let _ = tx.send(result);
        }
        RecordRequest::DeleteRecords {
            repo_id,
            collections,
            rkeys,
            tx,
        } => {
            let result = (|| {
                let user_hash = state
                    .metastore
                    .user_hashes()
                    .get(&repo_id)
                    .ok_or(DbError::Query("unknown user_id".to_string()))?;
                let deletes: Vec<super::record_ops::RecordDelete<'_>> = collections
                    .iter()
                    .zip(rkeys.iter())
                    .map(|(c, r)| super::record_ops::RecordDelete {
                        collection: c,
                        rkey: r,
                    })
                    .collect();
                let mut batch = state.metastore.database().batch();
                state
                    .metastore
                    .record_ops()
                    .delete_records(&mut batch, user_hash, &deletes);
                batch.commit().map_err(|e| DbError::Query(e.to_string()))
            })();
            let _ = tx.send(result);
        }
        RecordRequest::DeleteAllRecords { repo_id, tx } => {
            let result = (|| {
                let user_hash = state
                    .metastore
                    .user_hashes()
                    .get(&repo_id)
                    .ok_or(DbError::Query("unknown user_id".to_string()))?;
                let mut batch = state.metastore.database().batch();
                state
                    .metastore
                    .record_ops()
                    .delete_all_records(&mut batch, user_hash)
                    .map_err(metastore_to_db)?;
                batch.commit().map_err(|e| DbError::Query(e.to_string()))
            })();
            let _ = tx.send(result);
        }
        RecordRequest::GetRecordCid {
            repo_id,
            collection,
            rkey,
            tx,
        } => {
            let result = state
                .metastore
                .record_ops()
                .get_record_cid(repo_id, &collection, &rkey)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        RecordRequest::ListRecords {
            repo_id,
            collection,
            cursor,
            limit,
            reverse,
            rkey_start,
            rkey_end,
            tx,
        } => {
            let query = ListRecordsQuery {
                user_id: repo_id,
                collection: &collection,
                cursor: cursor.as_ref(),
                limit: usize::try_from(limit).unwrap_or(usize::MAX),
                reverse,
                rkey_start: rkey_start.as_ref(),
                rkey_end: rkey_end.as_ref(),
            };
            let result = state
                .metastore
                .record_ops()
                .list_records(&query)
                .map(|v| v.into_iter().map(convert_record_info).collect())
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        RecordRequest::GetAllRecords { repo_id, tx } => {
            let result = state
                .metastore
                .record_ops()
                .get_all_records(repo_id)
                .map(|v| v.into_iter().map(convert_full_record_info).collect())
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        RecordRequest::ListCollections { repo_id, tx } => {
            let result = state
                .metastore
                .record_ops()
                .list_collections(repo_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        RecordRequest::CountRecords { repo_id, tx } => {
            let result = state
                .metastore
                .record_ops()
                .count_records(repo_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        RecordRequest::CountAllRecords { tx } => {
            let result = state
                .metastore
                .record_ops()
                .count_all_records()
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        RecordRequest::GetRecordByCid { cid, tx } => {
            let result = state
                .metastore
                .record_ops()
                .get_record_by_cid(&cid, None)
                .map(|opt| opt.map(convert_record_with_takedown))
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        RecordRequest::SetRecordTakedown {
            cid,
            takedown_ref,
            scope_user,
            tx,
        } => {
            let result = state
                .metastore
                .record_ops()
                .set_record_takedown(
                    state.metastore.database(),
                    &cid,
                    takedown_ref.as_deref(),
                    scope_user,
                )
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
    }
}

fn dispatch_user_block<S: StorageIO>(state: &HandlerState<S>, req: UserBlockRequest) {
    match req {
        UserBlockRequest::InsertUserBlocks {
            user_id,
            block_cids,
            repo_rev,
            tx,
        } => {
            let result = (|| {
                let user_hash = state
                    .metastore
                    .user_hashes()
                    .get(&user_id)
                    .ok_or(DbError::Query("unknown user_id".to_string()))?;
                let mut batch = state.metastore.database().batch();
                state
                    .metastore
                    .user_block_ops()
                    .insert_user_blocks(&mut batch, user_hash, &block_cids, &repo_rev)
                    .map_err(metastore_to_db)?;
                batch.commit().map_err(|e| DbError::Query(e.to_string()))
            })();
            let _ = tx.send(result);
        }
        UserBlockRequest::DeleteUserBlocks {
            user_id,
            block_cids,
            tx,
        } => {
            let result = (|| {
                let user_hash = state
                    .metastore
                    .user_hashes()
                    .get(&user_id)
                    .ok_or(DbError::Query("unknown user_id".to_string()))?;
                let mut batch = state.metastore.database().batch();
                state
                    .metastore
                    .user_block_ops()
                    .delete_user_blocks_by_cid(&mut batch, user_hash, &block_cids)
                    .map_err(metastore_to_db)?;
                batch.commit().map_err(|e| DbError::Query(e.to_string()))
            })();
            let _ = tx.send(result);
        }
        UserBlockRequest::GetUserBlockCidsSinceRev {
            user_id,
            since_rev,
            tx,
        } => {
            let result = state
                .metastore
                .user_block_ops()
                .get_user_block_cids_since_rev(user_id, &since_rev)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        UserBlockRequest::CountUserBlocks { user_id, tx } => {
            let result = state
                .metastore
                .user_block_ops()
                .count_user_blocks(user_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        UserBlockRequest::FindUnreferencedBlocks { candidate_cids, tx } => {
            let result = state
                .metastore
                .user_block_ops()
                .find_unreferenced(&candidate_cids);
            let _ = tx.send(Ok(result));
        }
    }
}

fn dispatch_event<S: StorageIO>(state: &HandlerState<S>, req: EventRequest) {
    match req {
        EventRequest::InsertCommitEvent { data, tx } => {
            let result = state.event_ops.insert_commit_event(&data);
            let _ = tx.send(result);
        }
        EventRequest::InsertIdentityEvent { did, handle, tx } => {
            let result = state.event_ops.insert_identity_event(&did, handle.as_ref());
            let _ = tx.send(result);
        }
        EventRequest::InsertAccountEvent { did, status, tx } => {
            let result = state.event_ops.insert_account_event(&did, status);
            let _ = tx.send(result);
        }
        EventRequest::InsertSyncEvent {
            did,
            commit_cid,
            rev,
            tx,
        } => {
            let result = state
                .event_ops
                .insert_sync_event(&did, &commit_cid, rev.as_deref());
            let _ = tx.send(result);
        }
        EventRequest::InsertGenesisCommitEvent {
            did,
            commit_cid,
            mst_root_cid,
            rev,
            tx,
        } => {
            let result =
                state
                    .event_ops
                    .insert_genesis_commit_event(&did, &commit_cid, &mst_root_cid, &rev);
            let _ = tx.send(result);
        }
        EventRequest::UpdateSeqBlocksCids {
            seq,
            blocks_cids,
            tx,
        } => {
            let result = state.event_ops.update_seq_blocks_cids(seq, &blocks_cids);
            let _ = tx.send(result);
        }
        EventRequest::DeleteSequencesExcept { did, keep_seq, tx } => {
            let result = state.event_ops.delete_sequences_except(&did, keep_seq);
            let _ = tx.send(result);
        }
        EventRequest::GetMaxSeq { tx } => {
            let _ = tx.send(Ok(state.event_ops.get_max_seq()));
        }
        EventRequest::GetMinSeqSince { since, tx } => {
            let _ = tx.send(state.event_ops.get_min_seq_since(since));
        }
        EventRequest::GetEventsSinceSeq {
            since_seq,
            limit,
            tx,
        } => {
            let _ = tx.send(state.event_ops.get_events_since_seq(since_seq, limit));
        }
        EventRequest::GetEventsInSeqRange {
            start_seq,
            end_seq,
            tx,
        } => {
            let _ = tx.send(state.event_ops.get_events_in_seq_range(start_seq, end_seq));
        }
        EventRequest::GetEventBySeq { seq, tx } => {
            let _ = tx.send(state.event_ops.get_event_by_seq(seq));
        }
        EventRequest::GetEventsSinceCursor { cursor, limit, tx } => {
            let _ = tx.send(state.event_ops.get_events_since_cursor(cursor, limit));
        }
        EventRequest::GetEventsSinceRev { did, since_rev, tx } => {
            let _ = tx.send(state.event_ops.get_events_since_rev(&did, &since_rev));
        }
        EventRequest::NotifyUpdate { seq, tx } => {
            let _ = tx.send(state.event_ops.notify_update(seq));
        }
    }
}

fn dispatch_commit<S: StorageIO>(state: &HandlerState<S>, req: CommitRequest) {
    match req {
        CommitRequest::ApplyCommit { input, tx } => {
            let _ = tx.send(state.commit_ops.apply_commit(*input));
        }
        CommitRequest::ImportRepoData {
            user_id,
            blocks,
            records,
            expected_root_cid,
            tx,
        } => {
            let _ = tx.send(state.commit_ops.import_repo_data(
                user_id,
                &blocks,
                &records,
                expected_root_cid.as_ref(),
            ));
        }
        CommitRequest::GetBrokenGenesisCommits { tx } => {
            let _ = tx.send(
                state
                    .commit_ops
                    .get_broken_genesis_commits()
                    .map_err(metastore_to_db),
            );
        }
        CommitRequest::GetUsersWithoutBlocks { tx } => {
            let _ = tx.send(
                state
                    .commit_ops
                    .get_users_without_blocks()
                    .map_err(metastore_to_db),
            );
        }
        CommitRequest::GetUsersNeedingRecordBlobsBackfill { limit, tx } => {
            let _ = tx.send(
                state
                    .commit_ops
                    .get_users_needing_record_blobs_backfill(limit)
                    .map_err(metastore_to_db),
            );
        }
        CommitRequest::InsertRecordBlobs {
            repo_id,
            record_uris,
            blob_cids,
            tx,
        } => {
            let _ = tx.send(
                state
                    .commit_ops
                    .insert_record_blobs(repo_id, &record_uris, &blob_cids)
                    .map_err(metastore_to_db),
            );
        }
    }
}

fn dispatch_backlink<S: StorageIO>(state: &HandlerState<S>, req: BacklinkRequest) {
    match req {
        BacklinkRequest::GetBacklinkConflicts {
            repo_id,
            collection,
            backlinks,
            tx,
        } => {
            let result = state
                .metastore
                .backlink_ops()
                .get_backlink_conflicts(repo_id, &collection, &backlinks)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        BacklinkRequest::AddBacklinks {
            repo_id,
            backlinks,
            tx,
        } => {
            let result = (|| {
                let user_hash = state
                    .metastore
                    .user_hashes()
                    .get(&repo_id)
                    .ok_or(DbError::Query("unknown user_id".to_string()))?;
                let mut batch = state.metastore.database().batch();
                state
                    .metastore
                    .backlink_ops()
                    .add_backlinks(&mut batch, user_hash, &backlinks)
                    .map_err(metastore_to_db)?;
                batch.commit().map_err(|e| DbError::Query(e.to_string()))
            })();
            let _ = tx.send(result);
        }
        BacklinkRequest::RemoveBacklinksByUri { uri, tx } => {
            let result = (|| {
                let did_str = uri
                    .did()
                    .ok_or(DbError::Query("backlink uri missing did".to_string()))?;
                let user_hash = UserHash::from_did(did_str);
                let mut batch = state.metastore.database().batch();
                state
                    .metastore
                    .backlink_ops()
                    .remove_backlinks_by_uri(&mut batch, user_hash, &uri)
                    .map_err(metastore_to_db)?;
                batch.commit().map_err(|e| DbError::Query(e.to_string()))
            })();
            let _ = tx.send(result);
        }
        BacklinkRequest::RemoveBacklinksByRepo { repo_id, tx } => {
            let result = (|| {
                let user_hash = state
                    .metastore
                    .user_hashes()
                    .get(&repo_id)
                    .ok_or(DbError::Query("unknown user_id".to_string()))?;
                let mut batch = state.metastore.database().batch();
                state
                    .metastore
                    .backlink_ops()
                    .remove_backlinks_by_repo(&mut batch, user_hash)
                    .map_err(metastore_to_db)?;
                batch.commit().map_err(|e| DbError::Query(e.to_string()))
            })();
            let _ = tx.send(result);
        }
    }
}

fn dispatch_blob<S: StorageIO>(state: &HandlerState<S>, req: BlobRequest) {
    match req {
        BlobRequest::InsertBlob {
            cid,
            mime_type,
            size_bytes,
            created_by_user,
            storage_key,
            tx,
        } => {
            let result = state
                .metastore
                .blob_ops()
                .insert_blob(&cid, &mime_type, size_bytes, created_by_user, &storage_key)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        BlobRequest::GetBlobMetadata { cid, tx } => {
            let result = state
                .metastore
                .blob_ops()
                .get_blob_metadata(&cid)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        BlobRequest::GetBlobWithTakedown { cid, tx } => {
            let result = state
                .metastore
                .blob_ops()
                .get_blob_with_takedown(&cid)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        BlobRequest::GetBlobStorageKey { cid, tx } => {
            let result = state
                .metastore
                .blob_ops()
                .get_blob_storage_key(&cid)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        BlobRequest::ListBlobsByUser {
            user_id,
            cursor,
            limit,
            tx,
        } => {
            let result = state
                .metastore
                .blob_ops()
                .list_blobs_by_user(
                    user_id,
                    cursor.as_deref(),
                    usize::try_from(limit).unwrap_or(usize::MAX),
                )
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        BlobRequest::ListBlobsSinceRev { did, since, tx } => {
            let result = state.event_ops.get_blob_cids_since_rev(&did, &since);
            let _ = tx.send(result);
        }
        BlobRequest::CountBlobsByUser { user_id, tx } => {
            let result = state
                .metastore
                .blob_ops()
                .count_blobs_by_user(user_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        BlobRequest::SumBlobStorage { tx } => {
            let result = state
                .metastore
                .blob_ops()
                .sum_blob_storage()
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        BlobRequest::UpdateBlobTakedown {
            cid,
            takedown_ref,
            tx,
        } => {
            let result = state
                .metastore
                .blob_ops()
                .update_blob_takedown(&cid, takedown_ref.as_deref())
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        BlobRequest::DeleteBlobByCid { cid, tx } => {
            let result = state
                .metastore
                .blob_ops()
                .delete_blob_by_cid(&cid)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        BlobRequest::DeleteBlobsByUser { user_id, tx } => {
            let result = state
                .metastore
                .blob_ops()
                .delete_blobs_by_user(user_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        BlobRequest::GetBlobStorageKeysByUser { user_id, tx } => {
            let result = state
                .metastore
                .blob_ops()
                .get_blob_storage_keys_by_user(user_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        BlobRequest::ListMissingBlobs {
            repo_id,
            cursor,
            limit,
            tx,
        } => {
            let result = state
                .metastore
                .blob_ops()
                .list_missing_blobs(
                    repo_id,
                    cursor.as_deref(),
                    usize::try_from(limit).unwrap_or(usize::MAX),
                )
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        BlobRequest::CountDistinctRecordBlobs { repo_id, tx } => {
            let result = state
                .metastore
                .blob_ops()
                .count_distinct_record_blobs(repo_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        BlobRequest::GetBlobsForExport { repo_id, tx } => {
            let result = state
                .metastore
                .blob_ops()
                .get_blobs_for_export(repo_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
    }
}

fn dispatch<S: StorageIO>(state: &HandlerState<S>, request: MetastoreRequest) {
    match request {
        MetastoreRequest::Repo(r) => dispatch_repo(state, r),
        MetastoreRequest::Record(r) => dispatch_record(state, r),
        MetastoreRequest::UserBlock(r) => dispatch_user_block(state, r),
        MetastoreRequest::Event(r) => dispatch_event(state, r),
        MetastoreRequest::Commit(r) => dispatch_commit(state, *r),
        MetastoreRequest::Backlink(r) => dispatch_backlink(state, r),
        MetastoreRequest::Blob(r) => dispatch_blob(state, r),
    }
}

fn handler_loop<S: StorageIO>(
    metastore: Metastore,
    bridge: Arc<EventLogBridge<S>>,
    blockstore: Option<TranquilBlockStore>,
    rx: flume::Receiver<MetastoreRequest>,
    thread_index: usize,
) {
    let event_ops = metastore.event_ops(Arc::clone(&bridge));
    let mut commit_ops = metastore.commit_ops(bridge);
    if let Some(bs) = blockstore {
        commit_ops = commit_ops.with_blockstore(bs);
    }
    let state = HandlerState {
        metastore,
        event_ops,
        commit_ops,
    };
    tracing::info!(thread_index, "metastore handler thread started");
    rx.iter().for_each(|req| {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| dispatch(&state, req))) {
            Ok(()) => {}
            Err(e) => {
                let msg = match e.downcast_ref::<&str>() {
                    Some(s) => (*s).to_owned(),
                    None => match e.downcast_ref::<String>() {
                        Some(s) => s.clone(),
                        None => "unknown panic payload".to_owned(),
                    },
                };
                tracing::error!(thread_index, msg, "metastore handler panic (recovered)");
            }
        }
    });
    tracing::info!(thread_index, "metastore handler thread exiting");
}

const DEFAULT_CHANNEL_BOUND: usize = 256;
const MAX_REPOS_WITHOUT_REV: usize = 10_000;

pub struct HandlerPool {
    senders: Vec<flume::Sender<MetastoreRequest>>,
    handles: Option<Vec<JoinHandle<()>>>,
    user_hashes: Arc<UserHashMap>,
    round_robin: AtomicUsize,
}

impl HandlerPool {
    pub fn spawn<S: StorageIO + 'static>(
        metastore: Metastore,
        bridge: Arc<EventLogBridge<S>>,
        blockstore: Option<TranquilBlockStore>,
        thread_count: Option<usize>,
    ) -> Self {
        let count = thread_count
            .unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(|n| n.get().max(2) / 2)
                    .unwrap_or(1)
            })
            .max(1);

        let user_hashes = Arc::clone(metastore.user_hashes());

        let (senders, handles): (Vec<_>, Vec<_>) = (0..count)
            .map(|i| {
                let (tx, rx) = flume::bounded(DEFAULT_CHANNEL_BOUND);
                let ms = metastore.clone();
                let br = Arc::clone(&bridge);
                let bs = blockstore.clone();
                let handle = std::thread::Builder::new()
                    .name(format!("metastore-{i}"))
                    .spawn(move || handler_loop(ms, br, bs, rx, i))
                    .expect("failed to spawn metastore handler thread");
                (tx, handle)
            })
            .unzip();

        Self {
            senders,
            handles: Some(handles),
            user_hashes,
            round_robin: AtomicUsize::new(0),
        }
    }

    pub fn send(&self, request: MetastoreRequest) -> Result<(), DbError> {
        let index = match request.routing(&self.user_hashes) {
            Routing::Sharded(bits) => (bits as usize) % self.senders.len(),
            Routing::Global => {
                self.round_robin.fetch_add(1, Ordering::Relaxed) % self.senders.len()
            }
        };
        self.senders[index].try_send(request).map_err(|e| match e {
            flume::TrySendError::Full(_) => {
                DbError::Query("metastore handler backpressure".to_string())
            }
            flume::TrySendError::Disconnected(_) => {
                DbError::Connection("metastore handler pool shut down".to_string())
            }
        })
    }

    pub fn thread_count(&self) -> usize {
        self.senders.len()
    }

    pub async fn shutdown(&mut self) {
        self.senders.clear();
        if let Some(handles) = self.handles.take() {
            let join_fut = tokio::task::spawn_blocking(move || {
                handles.into_iter().for_each(|h| {
                    if let Err(e) = h.join() {
                        tracing::error!("metastore handler thread panicked: {e:?}");
                    }
                });
            });
            match tokio::time::timeout(std::time::Duration::from_secs(30), join_fut).await {
                Ok(_) => tracing::info!("metastore handler threads shut down cleanly"),
                Err(_) => tracing::error!("metastore handler thread shutdown timed out after 30s"),
            }
        }
    }
}

impl Drop for HandlerPool {
    fn drop(&mut self) {
        self.senders.clear();
        if let Some(handles) = self.handles.take() {
            tracing::warn!(
                "HandlerPool dropped without calling shutdown(); blocking on thread join"
            );
            handles.into_iter().for_each(|h| {
                if let Err(e) = h.join() {
                    tracing::error!("metastore handler thread panicked: {e:?}");
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eventlog::{EventLog, EventLogConfig};
    use crate::io::RealIO;
    use crate::metastore::MetastoreConfig;
    use tranquil_types::{Did, Handle};

    struct TestHarness {
        _metastore_dir: tempfile::TempDir,
        _eventlog_dir: tempfile::TempDir,
        pool: HandlerPool,
    }

    fn setup() -> TestHarness {
        let metastore_dir = tempfile::TempDir::new().unwrap();
        let eventlog_dir = tempfile::TempDir::new().unwrap();
        let segments_dir = eventlog_dir.path().join("segments");
        std::fs::create_dir_all(&segments_dir).unwrap();

        let metastore = Metastore::open(
            metastore_dir.path(),
            MetastoreConfig {
                cache_size_bytes: 64 * 1024 * 1024,
            },
        )
        .unwrap();

        let event_log = EventLog::open(
            EventLogConfig {
                segments_dir,
                ..EventLogConfig::default()
            },
            RealIO::new(),
        )
        .unwrap();

        let bridge = Arc::new(EventLogBridge::new(Arc::new(event_log)));

        let pool = HandlerPool::spawn::<RealIO>(metastore, bridge, None, Some(2));

        TestHarness {
            _metastore_dir: metastore_dir,
            _eventlog_dir: eventlog_dir,
            pool,
        }
    }

    fn test_cid_link(seed: u8) -> CidLink {
        let digest: [u8; 32] = std::array::from_fn(|i| seed.wrapping_add(i as u8));
        let mh = multihash::Multihash::<64>::wrap(0x12, &digest).unwrap();
        let c = cid::Cid::new_v1(0x71, mh);
        CidLink::from_cid(&c)
    }

    #[tokio::test]
    async fn create_and_get_roundtrip() {
        let h = setup();
        let user_id = Uuid::new_v4();
        let did = Did::from("did:plc:handler_test".to_string());
        let handle = Handle::from("handler.test.invalid".to_string());
        let cid = test_cid_link(1);

        let (tx, rx) = oneshot::channel();
        h.pool
            .send(MetastoreRequest::Repo(RepoRequest::CreateRepoFull {
                user_id,
                did,
                handle,
                repo_root_cid: cid.clone(),
                repo_rev: "rev1".to_string(),
                tx,
            }))
            .unwrap();
        rx.await.unwrap().unwrap();

        let (tx, rx) = oneshot::channel();
        h.pool
            .send(MetastoreRequest::Repo(RepoRequest::GetRepo { user_id, tx }))
            .unwrap();
        let repo = rx.await.unwrap().unwrap().unwrap();
        assert_eq!(repo.repo_root_cid, cid);
        assert_eq!(repo.repo_rev.as_deref(), Some("rev1"));
    }

    #[test]
    fn routing_determinism() {
        let user_id = Uuid::from_u128(0x12345678);
        let bits = user_id.as_u128() as u64;
        let thread_count = 4usize;
        let expected = (bits as usize) % thread_count;
        (0..100).for_each(|_| {
            assert_eq!((bits as usize) % thread_count, expected);
        });
    }

    #[test]
    fn global_round_robin_distributes() {
        let counter = AtomicUsize::new(0);
        let thread_count = 4usize;
        let indices: Vec<usize> = (0..8)
            .map(|_| counter.fetch_add(1, Ordering::Relaxed) % thread_count)
            .collect();
        assert_eq!(indices, vec![0, 1, 2, 3, 0, 1, 2, 3]);
    }

    #[tokio::test]
    async fn shutdown_completes_inflight() {
        let mut h = setup();
        let user_id = Uuid::new_v4();
        let did = Did::from("did:plc:shutdown_test".to_string());
        let handle = Handle::from("shutdown.test.invalid".to_string());
        let cid = test_cid_link(2);

        let (tx, rx) = oneshot::channel();
        h.pool
            .send(MetastoreRequest::Repo(RepoRequest::CreateRepoFull {
                user_id,
                did,
                handle,
                repo_root_cid: cid,
                repo_rev: "rev1".to_string(),
                tx,
            }))
            .unwrap();
        rx.await.unwrap().unwrap();

        h.pool.shutdown().await;
    }
}
