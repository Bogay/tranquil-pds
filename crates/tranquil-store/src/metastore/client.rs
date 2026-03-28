use std::marker::PhantomData;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokio::sync::oneshot;
use tranquil_db_traits::{
    AccountSearchResult, AccountStatus, AdminAccountInfo, ApplyCommitError, ApplyCommitInput,
    ApplyCommitResult, Backlink, BrokenGenesisCommit, CommitEventData, CommsChannel, CommsType,
    CompletePasskeySetupInput, CreateAccountError, CreateDelegatedAccountInput,
    CreatePasskeyAccountInput, CreatePasswordAccountInput, CreatePasswordAccountResult,
    CreateSsoAccountInput, DbError, DeletionRequest, DidWebOverrides, EventBlocksCids, ImportBlock,
    ImportRecord, ImportRepoError, InviteCodeError, InviteCodeInfo, InviteCodeRow,
    InviteCodeSortOrder, InviteCodeUse, MigrationReactivationError, MigrationReactivationInput,
    NotificationHistoryRow, NotificationPrefs, OAuthTokenWithUser, PasswordResetResult,
    QueuedComms, ReactivatedAccountInfo, RecoverPasskeyAccountInput, RecoverPasskeyAccountResult,
    RepoAccountInfo, RepoInfo, RepoListItem, RepoWithoutRev, ReservedSigningKey,
    ScheduledDeletionAccount, ScopePreference, SequenceNumber, SequencedEvent, StoredBackupCode,
    StoredPasskey, TokenFamilyId, TotpRecord, TotpRecordState, User2faStatus, UserAuthInfo,
    UserCommsPrefs, UserConfirmSignup, UserDidWebInfo, UserEmailInfo, UserForDeletion,
    UserForDidDoc, UserForDidDocBuild, UserForPasskeyRecovery, UserForPasskeySetup,
    UserForRecovery, UserForVerification, UserIdAndHandle, UserIdAndPasswordHash,
    UserIdHandleEmail, UserInfoForAuth, UserKeyInfo, UserKeyWithId, UserLegacyLoginPref,
    UserLoginCheck, UserLoginFull, UserLoginInfo, UserNeedingRecordBlobsBackfill, UserPasswordInfo,
    UserResendVerification, UserResetCodeInfo, UserRow, UserSessionInfo, UserStatus,
    UserVerificationInfo, UserWithKey, UserWithoutBlocks, ValidatedInviteCode,
    WebauthnChallengeType,
};
use tranquil_oauth::{AuthorizedClientData, DeviceData, RequestData, TokenData};
use tranquil_types::{
    AtUri, AuthorizationCode, CidLink, ClientId, DPoPProofId, DeviceId, Did, Handle, Nsid,
    RefreshToken, RequestId, Rkey, TokenId,
};
use uuid::Uuid;

use super::handler::{
    BacklinkRequest, BlobRequest, CommitRequest, DelegationRequest, EventRequest, HandlerPool,
    InfraRequest, MetastoreRequest, OAuthRequest, RecordRequest, RepoRequest, SessionRequest,
    SsoRequest, UserBlockRequest, UserRequest,
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

async fn recv_invite(
    rx: oneshot::Receiver<Result<(), InviteCodeError>>,
) -> Result<(), InviteCodeError> {
    rx.await.map_err(|_| {
        InviteCodeError::DatabaseError(DbError::Connection(
            "metastore handler thread closed".to_string(),
        ))
    })?
}

async fn recv_create_account<T>(
    rx: oneshot::Receiver<Result<T, CreateAccountError>>,
) -> Result<T, CreateAccountError> {
    rx.await
        .map_err(|_| CreateAccountError::Database("metastore handler thread closed".to_string()))?
}

async fn recv_migration_reactivation(
    rx: oneshot::Receiver<Result<ReactivatedAccountInfo, MigrationReactivationError>>,
) -> Result<ReactivatedAccountInfo, MigrationReactivationError> {
    rx.await.map_err(|_| {
        MigrationReactivationError::Database("metastore handler thread closed".to_string())
    })?
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
                limit: usize::try_from(limit).unwrap_or(0),
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

#[async_trait]
impl<S: StorageIO + 'static> tranquil_db_traits::DelegationRepository for MetastoreClient<S> {
    async fn is_delegated_account(&self, did: &Did) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Delegation(
            DelegationRequest::IsDelegatedAccount {
                did: did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn create_delegation(
        &self,
        delegated_did: &Did,
        controller_did: &Did,
        granted_scopes: &tranquil_db_traits::DbScope,
        granted_by: &Did,
    ) -> Result<Uuid, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Delegation(
            DelegationRequest::CreateDelegation {
                delegated_did: delegated_did.clone(),
                controller_did: controller_did.clone(),
                granted_scopes: granted_scopes.clone(),
                granted_by: granted_by.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn revoke_delegation(
        &self,
        delegated_did: &Did,
        controller_did: &Did,
        revoked_by: &Did,
    ) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Delegation(
            DelegationRequest::RevokeDelegation {
                delegated_did: delegated_did.clone(),
                controller_did: controller_did.clone(),
                revoked_by: revoked_by.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn update_delegation_scopes(
        &self,
        delegated_did: &Did,
        controller_did: &Did,
        new_scopes: &tranquil_db_traits::DbScope,
    ) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Delegation(
            DelegationRequest::UpdateDelegationScopes {
                delegated_did: delegated_did.clone(),
                controller_did: controller_did.clone(),
                new_scopes: new_scopes.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_delegation(
        &self,
        delegated_did: &Did,
        controller_did: &Did,
    ) -> Result<Option<tranquil_db_traits::DelegationGrant>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Delegation(
            DelegationRequest::GetDelegation {
                delegated_did: delegated_did.clone(),
                controller_did: controller_did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_delegations_for_account(
        &self,
        delegated_did: &Did,
    ) -> Result<Vec<tranquil_db_traits::ControllerInfo>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Delegation(
            DelegationRequest::GetDelegationsForAccount {
                delegated_did: delegated_did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_accounts_controlled_by(
        &self,
        controller_did: &Did,
    ) -> Result<Vec<tranquil_db_traits::DelegatedAccountInfo>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Delegation(
            DelegationRequest::GetAccountsControlledBy {
                controller_did: controller_did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn count_active_controllers(&self, delegated_did: &Did) -> Result<i64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Delegation(
            DelegationRequest::CountActiveControllers {
                delegated_did: delegated_did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn controls_any_accounts(&self, did: &Did) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Delegation(
            DelegationRequest::ControlsAnyAccounts {
                did: did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn log_delegation_action(
        &self,
        delegated_did: &Did,
        actor_did: &Did,
        controller_did: Option<&Did>,
        action_type: tranquil_db_traits::DelegationActionType,
        action_details: Option<serde_json::Value>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Uuid, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Delegation(
            DelegationRequest::LogDelegationAction {
                delegated_did: delegated_did.clone(),
                actor_did: actor_did.clone(),
                controller_did: controller_did.cloned(),
                action_type,
                action_details,
                ip_address: ip_address.map(str::to_owned),
                user_agent: user_agent.map(str::to_owned),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_audit_log_for_account(
        &self,
        delegated_did: &Did,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<tranquil_db_traits::AuditLogEntry>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Delegation(
            DelegationRequest::GetAuditLogForAccount {
                delegated_did: delegated_did.clone(),
                limit,
                offset,
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn count_audit_log_entries(&self, delegated_did: &Did) -> Result<i64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Delegation(
            DelegationRequest::CountAuditLogEntries {
                delegated_did: delegated_did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }
}

#[async_trait]
impl<S: StorageIO + 'static> tranquil_db_traits::SsoRepository for MetastoreClient<S> {
    async fn create_external_identity(
        &self,
        did: &Did,
        provider: tranquil_db_traits::SsoProviderType,
        provider_user_id: &str,
        provider_username: Option<&str>,
        provider_email: Option<&str>,
    ) -> Result<Uuid, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Sso(SsoRequest::CreateExternalIdentity {
                did: did.clone(),
                provider,
                provider_user_id: provider_user_id.to_owned(),
                provider_username: provider_username.map(str::to_owned),
                provider_email: provider_email.map(str::to_owned),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_external_identity_by_provider(
        &self,
        provider: tranquil_db_traits::SsoProviderType,
        provider_user_id: &str,
    ) -> Result<Option<tranquil_db_traits::ExternalIdentity>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Sso(
            SsoRequest::GetExternalIdentityByProvider {
                provider,
                provider_user_id: provider_user_id.to_owned(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_external_identities_by_did(
        &self,
        did: &Did,
    ) -> Result<Vec<tranquil_db_traits::ExternalIdentity>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Sso(
            SsoRequest::GetExternalIdentitiesByDid {
                did: did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn update_external_identity_login(
        &self,
        id: Uuid,
        provider_username: Option<&str>,
        provider_email: Option<&str>,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Sso(
            SsoRequest::UpdateExternalIdentityLogin {
                id,
                provider_username: provider_username.map(str::to_owned),
                provider_email: provider_email.map(str::to_owned),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn delete_external_identity(&self, id: Uuid, did: &Did) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Sso(SsoRequest::DeleteExternalIdentity {
                id,
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn create_sso_auth_state(
        &self,
        state: &str,
        request_uri: &str,
        provider: tranquil_db_traits::SsoProviderType,
        action: tranquil_db_traits::SsoAction,
        nonce: Option<&str>,
        code_verifier: Option<&str>,
        did: Option<&Did>,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Sso(SsoRequest::CreateSsoAuthState {
                state: state.to_owned(),
                request_uri: request_uri.to_owned(),
                provider,
                action,
                nonce: nonce.map(str::to_owned),
                code_verifier: code_verifier.map(str::to_owned),
                did: did.cloned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn consume_sso_auth_state(
        &self,
        state: &str,
    ) -> Result<Option<tranquil_db_traits::SsoAuthState>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Sso(SsoRequest::ConsumeSsoAuthState {
                state: state.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn cleanup_expired_sso_auth_states(&self) -> Result<u64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Sso(
            SsoRequest::CleanupExpiredSsoAuthStates { tx },
        ))?;
        recv(rx).await
    }

    async fn create_pending_registration(
        &self,
        token: &str,
        request_uri: &str,
        provider: tranquil_db_traits::SsoProviderType,
        provider_user_id: &str,
        provider_username: Option<&str>,
        provider_email: Option<&str>,
        provider_email_verified: bool,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Sso(
            SsoRequest::CreatePendingRegistration {
                token: token.to_owned(),
                request_uri: request_uri.to_owned(),
                provider,
                provider_user_id: provider_user_id.to_owned(),
                provider_username: provider_username.map(str::to_owned),
                provider_email: provider_email.map(str::to_owned),
                provider_email_verified,
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_pending_registration(
        &self,
        token: &str,
    ) -> Result<Option<tranquil_db_traits::SsoPendingRegistration>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Sso(SsoRequest::GetPendingRegistration {
                token: token.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn consume_pending_registration(
        &self,
        token: &str,
    ) -> Result<Option<tranquil_db_traits::SsoPendingRegistration>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Sso(
            SsoRequest::ConsumePendingRegistration {
                token: token.to_owned(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn cleanup_expired_pending_registrations(&self) -> Result<u64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Sso(
            SsoRequest::CleanupExpiredPendingRegistrations { tx },
        ))?;
        recv(rx).await
    }
}

#[async_trait]
impl<S: StorageIO + 'static> tranquil_db_traits::SessionRepository for MetastoreClient<S> {
    async fn create_session(
        &self,
        data: &tranquil_db_traits::SessionTokenCreate,
    ) -> Result<tranquil_db_traits::SessionId, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Session(SessionRequest::CreateSession {
                data: data.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_session_by_access_jti(
        &self,
        access_jti: &str,
    ) -> Result<Option<tranquil_db_traits::SessionToken>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Session(
            SessionRequest::GetSessionByAccessJti {
                access_jti: access_jti.to_owned(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_session_for_refresh(
        &self,
        refresh_jti: &str,
    ) -> Result<Option<tranquil_db_traits::SessionForRefresh>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Session(
            SessionRequest::GetSessionForRefresh {
                refresh_jti: refresh_jti.to_owned(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn update_session_tokens(
        &self,
        session_id: tranquil_db_traits::SessionId,
        new_access_jti: &str,
        new_refresh_jti: &str,
        new_access_expires_at: DateTime<Utc>,
        new_refresh_expires_at: DateTime<Utc>,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Session(
            SessionRequest::UpdateSessionTokens {
                session_id,
                new_access_jti: new_access_jti.to_owned(),
                new_refresh_jti: new_refresh_jti.to_owned(),
                new_access_expires_at,
                new_refresh_expires_at,
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn delete_session_by_access_jti(&self, access_jti: &str) -> Result<u64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Session(
            SessionRequest::DeleteSessionByAccessJti {
                access_jti: access_jti.to_owned(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn delete_session_by_id(
        &self,
        session_id: tranquil_db_traits::SessionId,
    ) -> Result<u64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Session(
            SessionRequest::DeleteSessionById { session_id, tx },
        ))?;
        recv(rx).await
    }

    async fn delete_sessions_by_did(&self, did: &Did) -> Result<u64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Session(
            SessionRequest::DeleteSessionsByDid {
                did: did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn delete_sessions_by_did_except_jti(
        &self,
        did: &Did,
        except_jti: &str,
    ) -> Result<u64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Session(
            SessionRequest::DeleteSessionsByDidExceptJti {
                did: did.clone(),
                except_jti: except_jti.to_owned(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn list_sessions_by_did(
        &self,
        did: &Did,
    ) -> Result<Vec<tranquil_db_traits::SessionListItem>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Session(
            SessionRequest::ListSessionsByDid {
                did: did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_session_access_jti_by_id(
        &self,
        session_id: tranquil_db_traits::SessionId,
        did: &Did,
    ) -> Result<Option<String>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Session(
            SessionRequest::GetSessionAccessJtiById {
                session_id,
                did: did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn delete_sessions_by_app_password(
        &self,
        did: &Did,
        app_password_name: &str,
    ) -> Result<u64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Session(
            SessionRequest::DeleteSessionsByAppPassword {
                did: did.clone(),
                app_password_name: app_password_name.to_owned(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_session_jtis_by_app_password(
        &self,
        did: &Did,
        app_password_name: &str,
    ) -> Result<Vec<String>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Session(
            SessionRequest::GetSessionJtisByAppPassword {
                did: did.clone(),
                app_password_name: app_password_name.to_owned(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn check_refresh_token_used(
        &self,
        refresh_jti: &str,
    ) -> Result<Option<tranquil_db_traits::SessionId>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Session(
            SessionRequest::CheckRefreshTokenUsed {
                refresh_jti: refresh_jti.to_owned(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn mark_refresh_token_used(
        &self,
        refresh_jti: &str,
        session_id: tranquil_db_traits::SessionId,
    ) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Session(
            SessionRequest::MarkRefreshTokenUsed {
                refresh_jti: refresh_jti.to_owned(),
                session_id,
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn list_app_passwords(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<tranquil_db_traits::AppPasswordRecord>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Session(
            SessionRequest::ListAppPasswords { user_id, tx },
        ))?;
        recv(rx).await
    }

    async fn get_app_passwords_for_login(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<tranquil_db_traits::AppPasswordRecord>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Session(
            SessionRequest::GetAppPasswordsForLogin { user_id, tx },
        ))?;
        recv(rx).await
    }

    async fn get_app_password_by_name(
        &self,
        user_id: Uuid,
        name: &str,
    ) -> Result<Option<tranquil_db_traits::AppPasswordRecord>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Session(
            SessionRequest::GetAppPasswordByName {
                user_id,
                name: name.to_owned(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn create_app_password(
        &self,
        data: &tranquil_db_traits::AppPasswordCreate,
    ) -> Result<Uuid, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Session(
            SessionRequest::CreateAppPassword {
                data: data.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn delete_app_password(&self, user_id: Uuid, name: &str) -> Result<u64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Session(
            SessionRequest::DeleteAppPassword {
                user_id,
                name: name.to_owned(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn delete_app_passwords_by_controller(
        &self,
        did: &Did,
        controller_did: &Did,
    ) -> Result<u64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Session(
            SessionRequest::DeleteAppPasswordsByController {
                did: did.clone(),
                controller_did: controller_did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_last_reauth_at(&self, did: &Did) -> Result<Option<DateTime<Utc>>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Session(SessionRequest::GetLastReauthAt {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn update_last_reauth(&self, did: &Did) -> Result<DateTime<Utc>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Session(
            SessionRequest::UpdateLastReauth {
                did: did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_session_mfa_status(
        &self,
        did: &Did,
    ) -> Result<Option<tranquil_db_traits::SessionMfaStatus>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Session(
            SessionRequest::GetSessionMfaStatus {
                did: did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn update_mfa_verified(&self, did: &Did) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Session(
            SessionRequest::UpdateMfaVerified {
                did: did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_app_password_hashes_by_did(&self, did: &Did) -> Result<Vec<String>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Session(
            SessionRequest::GetAppPasswordHashesByDid {
                did: did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn refresh_session_atomic(
        &self,
        data: &tranquil_db_traits::SessionRefreshData,
    ) -> Result<tranquil_db_traits::RefreshSessionResult, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Session(
            SessionRequest::RefreshSessionAtomic {
                data: data.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }
}

#[async_trait]
impl<S: StorageIO + 'static> tranquil_db_traits::InfraRepository for MetastoreClient<S> {
    async fn enqueue_comms(
        &self,
        user_id: Option<Uuid>,
        channel: CommsChannel,
        comms_type: CommsType,
        recipient: &str,
        subject: Option<&str>,
        body: &str,
        metadata: Option<serde_json::Value>,
    ) -> Result<Uuid, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Infra(InfraRequest::EnqueueComms {
                user_id,
                channel,
                comms_type,
                recipient: recipient.to_owned(),
                subject: subject.map(str::to_owned),
                body: body.to_owned(),
                metadata,
                tx,
            }))?;
        recv(rx).await
    }

    async fn fetch_pending_comms(
        &self,
        now: DateTime<Utc>,
        batch_size: i64,
    ) -> Result<Vec<QueuedComms>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Infra(InfraRequest::FetchPendingComms {
                now,
                batch_size,
                tx,
            }))?;
        recv(rx).await
    }

    async fn mark_comms_sent(&self, id: Uuid) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Infra(InfraRequest::MarkCommsSent {
                id,
                tx,
            }))?;
        recv(rx).await
    }

    async fn mark_comms_failed(&self, id: Uuid, error: &str) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Infra(InfraRequest::MarkCommsFailed {
                id,
                error: error.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn create_invite_code(
        &self,
        code: &str,
        use_count: i32,
        for_account: Option<&Did>,
    ) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Infra(InfraRequest::CreateInviteCode {
                code: code.to_owned(),
                use_count,
                for_account: for_account.cloned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn create_invite_codes_batch(
        &self,
        codes: &[String],
        use_count: i32,
        created_by_user: Uuid,
        for_account: Option<&Did>,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Infra(
            InfraRequest::CreateInviteCodesBatch {
                codes: codes.to_vec(),
                use_count,
                created_by_user,
                for_account: for_account.cloned(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_invite_code_available_uses(&self, code: &str) -> Result<Option<i32>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Infra(
            InfraRequest::GetInviteCodeAvailableUses {
                code: code.to_owned(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn validate_invite_code<'a>(
        &self,
        code: &'a str,
    ) -> Result<ValidatedInviteCode<'a>, InviteCodeError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Infra(InfraRequest::ValidateInviteCode {
                code: code.to_owned(),
                tx,
            }))
            .map_err(|e| InviteCodeError::DatabaseError(DbError::Connection(e.to_string())))?;
        recv_invite(rx).await?;
        Ok(ValidatedInviteCode::new_validated(code))
    }

    async fn decrement_invite_code_uses(
        &self,
        code: &ValidatedInviteCode<'_>,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Infra(
            InfraRequest::DecrementInviteCodeUses {
                code: code.code().to_owned(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn record_invite_code_use(
        &self,
        code: &ValidatedInviteCode<'_>,
        used_by_user: Uuid,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Infra(InfraRequest::RecordInviteCodeUse {
                code: code.code().to_owned(),
                used_by_user,
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_invite_codes_for_account(
        &self,
        for_account: &Did,
    ) -> Result<Vec<InviteCodeInfo>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Infra(
            InfraRequest::GetInviteCodesForAccount {
                for_account: for_account.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_invite_code_uses(&self, code: &str) -> Result<Vec<InviteCodeUse>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Infra(InfraRequest::GetInviteCodeUses {
                code: code.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn disable_invite_codes_by_code(&self, codes: &[String]) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Infra(
            InfraRequest::DisableInviteCodesByCode {
                codes: codes.to_vec(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn disable_invite_codes_by_account(&self, accounts: &[Did]) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Infra(
            InfraRequest::DisableInviteCodesByAccount {
                accounts: accounts.to_vec(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn list_invite_codes(
        &self,
        cursor: Option<&str>,
        limit: i64,
        sort: InviteCodeSortOrder,
    ) -> Result<Vec<InviteCodeRow>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Infra(InfraRequest::ListInviteCodes {
                cursor: cursor.map(str::to_owned),
                limit,
                sort,
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_user_dids_by_ids(&self, user_ids: &[Uuid]) -> Result<Vec<(Uuid, Did)>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Infra(InfraRequest::GetUserDidsByIds {
                user_ids: user_ids.to_vec(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_invite_code_uses_batch(
        &self,
        codes: &[String],
    ) -> Result<Vec<InviteCodeUse>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Infra(
            InfraRequest::GetInviteCodeUsesBatch {
                codes: codes.to_vec(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_invites_created_by_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<InviteCodeInfo>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Infra(
            InfraRequest::GetInvitesCreatedByUser { user_id, tx },
        ))?;
        recv(rx).await
    }

    async fn get_invite_code_info(&self, code: &str) -> Result<Option<InviteCodeInfo>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Infra(InfraRequest::GetInviteCodeInfo {
                code: code.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_invite_codes_by_users(
        &self,
        user_ids: &[Uuid],
    ) -> Result<Vec<(Uuid, InviteCodeInfo)>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Infra(
            InfraRequest::GetInviteCodesByUsers {
                user_ids: user_ids.to_vec(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_invite_code_used_by_user(&self, user_id: Uuid) -> Result<Option<String>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Infra(
            InfraRequest::GetInviteCodeUsedByUser { user_id, tx },
        ))?;
        recv(rx).await
    }

    async fn delete_invite_code_uses_by_user(&self, user_id: Uuid) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Infra(
            InfraRequest::DeleteInviteCodeUsesByUser { user_id, tx },
        ))?;
        recv(rx).await
    }

    async fn delete_invite_codes_by_user(&self, user_id: Uuid) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Infra(
            InfraRequest::DeleteInviteCodesByUser { user_id, tx },
        ))?;
        recv(rx).await
    }

    async fn reserve_signing_key(
        &self,
        did: Option<&Did>,
        public_key_did_key: &str,
        private_key_bytes: &[u8],
        expires_at: DateTime<Utc>,
    ) -> Result<Uuid, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Infra(InfraRequest::ReserveSigningKey {
                did: did.cloned(),
                public_key_did_key: public_key_did_key.to_owned(),
                private_key_bytes: private_key_bytes.to_vec(),
                expires_at,
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_reserved_signing_key(
        &self,
        public_key_did_key: &str,
    ) -> Result<Option<ReservedSigningKey>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Infra(
            InfraRequest::GetReservedSigningKey {
                public_key_did_key: public_key_did_key.to_owned(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn mark_signing_key_used(&self, key_id: Uuid) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Infra(InfraRequest::MarkSigningKeyUsed {
                key_id,
                tx,
            }))?;
        recv(rx).await
    }

    async fn create_deletion_request(
        &self,
        token: &str,
        did: &Did,
        expires_at: DateTime<Utc>,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Infra(
            InfraRequest::CreateDeletionRequest {
                token: token.to_owned(),
                did: did.clone(),
                expires_at,
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_deletion_request(&self, token: &str) -> Result<Option<DeletionRequest>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Infra(InfraRequest::GetDeletionRequest {
                token: token.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn delete_deletion_request(&self, token: &str) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Infra(
            InfraRequest::DeleteDeletionRequest {
                token: token.to_owned(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn delete_deletion_requests_by_did(&self, did: &Did) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Infra(
            InfraRequest::DeleteDeletionRequestsByDid {
                did: did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn upsert_account_preference(
        &self,
        user_id: Uuid,
        name: &str,
        value_json: serde_json::Value,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Infra(
            InfraRequest::UpsertAccountPreference {
                user_id,
                name: name.to_owned(),
                value_json,
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn insert_account_preference_if_not_exists(
        &self,
        user_id: Uuid,
        name: &str,
        value_json: serde_json::Value,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Infra(
            InfraRequest::InsertAccountPreferenceIfNotExists {
                user_id,
                name: name.to_owned(),
                value_json,
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_server_config(&self, key: &str) -> Result<Option<String>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Infra(InfraRequest::GetServerConfig {
                key: key.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn health_check(&self) -> Result<bool, DbError> {
        Ok(true)
    }

    async fn insert_report(
        &self,
        id: i64,
        reason_type: &str,
        reason: Option<&str>,
        subject_json: serde_json::Value,
        reported_by_did: &Did,
        created_at: DateTime<Utc>,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Infra(InfraRequest::InsertReport {
                id,
                reason_type: reason_type.to_owned(),
                reason: reason.map(str::to_owned),
                subject_json,
                reported_by_did: reported_by_did.clone(),
                created_at,
                tx,
            }))?;
        recv(rx).await
    }

    async fn delete_plc_tokens_for_user(&self, user_id: Uuid) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Infra(
            InfraRequest::DeletePlcTokensForUser { user_id, tx },
        ))?;
        recv(rx).await
    }

    async fn insert_plc_token(
        &self,
        user_id: Uuid,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Infra(InfraRequest::InsertPlcToken {
                user_id,
                token: token.to_owned(),
                expires_at,
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_plc_token_expiry(
        &self,
        user_id: Uuid,
        token: &str,
    ) -> Result<Option<DateTime<Utc>>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Infra(InfraRequest::GetPlcTokenExpiry {
                user_id,
                token: token.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn delete_plc_token(&self, user_id: Uuid, token: &str) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Infra(InfraRequest::DeletePlcToken {
                user_id,
                token: token.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_account_preferences(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<(String, serde_json::Value)>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Infra(
            InfraRequest::GetAccountPreferences { user_id, tx },
        ))?;
        recv(rx).await
    }

    async fn replace_namespace_preferences(
        &self,
        user_id: Uuid,
        namespace: &str,
        preferences: Vec<(String, serde_json::Value)>,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Infra(
            InfraRequest::ReplaceNamespacePreferences {
                user_id,
                namespace: namespace.to_owned(),
                preferences,
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_notification_history(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<NotificationHistoryRow>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Infra(
            InfraRequest::GetNotificationHistory { user_id, limit, tx },
        ))?;
        recv(rx).await
    }

    async fn get_server_configs(&self, keys: &[&str]) -> Result<Vec<(String, String)>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Infra(InfraRequest::GetServerConfigs {
                keys: keys.iter().map(|s| (*s).to_owned()).collect(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn upsert_server_config(&self, key: &str, value: &str) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Infra(InfraRequest::UpsertServerConfig {
                key: key.to_owned(),
                value: value.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn delete_server_config(&self, key: &str) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Infra(InfraRequest::DeleteServerConfig {
                key: key.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_blob_storage_key_by_cid(&self, cid: &CidLink) -> Result<Option<String>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Infra(
            InfraRequest::GetBlobStorageKeyByCid {
                cid: cid.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn delete_blob_by_cid(&self, cid: &CidLink) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::Infra(InfraRequest::DeleteBlobByCid {
                cid: cid.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_admin_account_info_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<AdminAccountInfo>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Infra(
            InfraRequest::GetAdminAccountInfoByDid {
                did: did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_admin_account_infos_by_dids(
        &self,
        dids: &[Did],
    ) -> Result<Vec<AdminAccountInfo>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Infra(
            InfraRequest::GetAdminAccountInfosByDids {
                dids: dids.to_vec(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_invite_code_uses_by_users(
        &self,
        user_ids: &[Uuid],
    ) -> Result<Vec<(Uuid, String)>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::Infra(
            InfraRequest::GetInviteCodeUsesByUsers {
                user_ids: user_ids.to_vec(),
                tx,
            },
        ))?;
        recv(rx).await
    }
}

#[async_trait]
impl<S: StorageIO + 'static> tranquil_db_traits::OAuthRepository for MetastoreClient<S> {
    async fn create_token(&self, data: &TokenData) -> Result<TokenFamilyId, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::CreateToken {
                data: data.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_token_by_id(&self, token_id: &TokenId) -> Result<Option<TokenData>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::GetTokenById {
                token_id: token_id.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_token_by_refresh_token(
        &self,
        refresh_token: &RefreshToken,
    ) -> Result<Option<(TokenFamilyId, TokenData)>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::OAuth(
            OAuthRequest::GetTokenByRefreshToken {
                refresh_token: refresh_token.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_token_by_previous_refresh_token(
        &self,
        refresh_token: &RefreshToken,
    ) -> Result<Option<(TokenFamilyId, TokenData)>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::OAuth(
            OAuthRequest::GetTokenByPreviousRefreshToken {
                refresh_token: refresh_token.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn rotate_token(
        &self,
        old_db_id: TokenFamilyId,
        new_refresh_token: &RefreshToken,
        new_expires_at: DateTime<Utc>,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::RotateToken {
                old_db_id,
                new_refresh_token: new_refresh_token.clone(),
                new_expires_at,
                tx,
            }))?;
        recv(rx).await
    }

    async fn check_refresh_token_used(
        &self,
        refresh_token: &RefreshToken,
    ) -> Result<Option<TokenFamilyId>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::OAuth(
            OAuthRequest::CheckRefreshTokenUsed {
                refresh_token: refresh_token.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn delete_token(&self, token_id: &TokenId) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::DeleteToken {
                token_id: token_id.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn delete_token_family(&self, db_id: TokenFamilyId) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::DeleteTokenFamily {
                db_id,
                tx,
            }))?;
        recv(rx).await
    }

    async fn list_tokens_for_user(&self, did: &Did) -> Result<Vec<TokenData>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::ListTokensForUser {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn count_tokens_for_user(&self, did: &Did) -> Result<i64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::CountTokensForUser {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn delete_oldest_tokens_for_user(
        &self,
        did: &Did,
        keep_count: i64,
    ) -> Result<u64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::OAuth(
            OAuthRequest::DeleteOldestTokensForUser {
                did: did.clone(),
                keep_count,
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn revoke_tokens_for_client(
        &self,
        did: &Did,
        client_id: &ClientId,
    ) -> Result<u64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::OAuth(
            OAuthRequest::RevokeTokensForClient {
                did: did.clone(),
                client_id: client_id.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn revoke_tokens_for_controller(
        &self,
        delegated_did: &Did,
        controller_did: &Did,
    ) -> Result<u64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::OAuth(
            OAuthRequest::RevokeTokensForController {
                delegated_did: delegated_did.clone(),
                controller_did: controller_did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn create_authorization_request(
        &self,
        request_id: &RequestId,
        data: &RequestData,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::OAuth(
            OAuthRequest::CreateAuthorizationRequest {
                request_id: request_id.clone(),
                data: data.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_authorization_request(
        &self,
        request_id: &RequestId,
    ) -> Result<Option<RequestData>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::OAuth(
            OAuthRequest::GetAuthorizationRequest {
                request_id: request_id.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn set_authorization_did(
        &self,
        request_id: &RequestId,
        did: &Did,
        device_id: Option<&DeviceId>,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::SetAuthorizationDid {
                request_id: request_id.clone(),
                did: did.clone(),
                device_id: device_id.cloned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn update_authorization_request(
        &self,
        request_id: &RequestId,
        did: &Did,
        device_id: Option<&DeviceId>,
        code: &AuthorizationCode,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::OAuth(
            OAuthRequest::UpdateAuthorizationRequest {
                request_id: request_id.clone(),
                did: did.clone(),
                device_id: device_id.cloned(),
                code: code.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn consume_authorization_request_by_code(
        &self,
        code: &AuthorizationCode,
    ) -> Result<Option<RequestData>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::OAuth(
            OAuthRequest::ConsumeAuthorizationRequestByCode {
                code: code.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn delete_authorization_request(&self, request_id: &RequestId) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::OAuth(
            OAuthRequest::DeleteAuthorizationRequest {
                request_id: request_id.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn delete_expired_authorization_requests(&self) -> Result<u64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::OAuth(
            OAuthRequest::DeleteExpiredAuthorizationRequests { tx },
        ))?;
        recv(rx).await
    }

    async fn extend_authorization_request_expiry(
        &self,
        request_id: &RequestId,
        new_expires_at: DateTime<Utc>,
    ) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::OAuth(
            OAuthRequest::ExtendAuthorizationRequestExpiry {
                request_id: request_id.clone(),
                new_expires_at,
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn mark_request_authenticated(
        &self,
        request_id: &RequestId,
        did: &Did,
        device_id: Option<&DeviceId>,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::OAuth(
            OAuthRequest::MarkRequestAuthenticated {
                request_id: request_id.clone(),
                did: did.clone(),
                device_id: device_id.cloned(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn update_request_scope(
        &self,
        request_id: &RequestId,
        scope: &str,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::UpdateRequestScope {
                request_id: request_id.clone(),
                scope: scope.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn set_controller_did(
        &self,
        request_id: &RequestId,
        controller_did: &Did,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::SetControllerDid {
                request_id: request_id.clone(),
                controller_did: controller_did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn set_request_did(&self, request_id: &RequestId, did: &Did) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::SetRequestDid {
                request_id: request_id.clone(),
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn create_device(&self, device_id: &DeviceId, data: &DeviceData) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::CreateDevice {
                device_id: device_id.clone(),
                data: data.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_device(&self, device_id: &DeviceId) -> Result<Option<DeviceData>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::GetDevice {
                device_id: device_id.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn update_device_last_seen(&self, device_id: &DeviceId) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::OAuth(
            OAuthRequest::UpdateDeviceLastSeen {
                device_id: device_id.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn delete_device(&self, device_id: &DeviceId) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::DeleteDevice {
                device_id: device_id.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn upsert_account_device(&self, did: &Did, device_id: &DeviceId) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::UpsertAccountDevice {
                did: did.clone(),
                device_id: device_id.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_device_accounts(
        &self,
        device_id: &DeviceId,
    ) -> Result<Vec<tranquil_db_traits::DeviceAccountRow>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::GetDeviceAccounts {
                device_id: device_id.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn verify_account_on_device(
        &self,
        device_id: &DeviceId,
        did: &Did,
    ) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::OAuth(
            OAuthRequest::VerifyAccountOnDevice {
                device_id: device_id.clone(),
                did: did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn check_and_record_dpop_jti(&self, jti: &DPoPProofId) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::OAuth(
            OAuthRequest::CheckAndRecordDpopJti {
                jti: jti.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn cleanup_expired_dpop_jtis(&self, max_age_secs: i64) -> Result<u64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::OAuth(
            OAuthRequest::CleanupExpiredDpopJtis { max_age_secs, tx },
        ))?;
        recv(rx).await
    }

    async fn create_2fa_challenge(
        &self,
        did: &Did,
        request_uri: &RequestId,
    ) -> Result<tranquil_db_traits::TwoFactorChallenge, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::Create2faChallenge {
                did: did.clone(),
                request_uri: request_uri.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_2fa_challenge(
        &self,
        request_uri: &RequestId,
    ) -> Result<Option<tranquil_db_traits::TwoFactorChallenge>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::Get2faChallenge {
                request_uri: request_uri.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn increment_2fa_attempts(&self, id: Uuid) -> Result<i32, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::OAuth(
            OAuthRequest::Increment2faAttempts { id, tx },
        ))?;
        recv(rx).await
    }

    async fn delete_2fa_challenge(&self, id: Uuid) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::Delete2faChallenge {
                id,
                tx,
            }))?;
        recv(rx).await
    }

    async fn delete_2fa_challenge_by_request_uri(
        &self,
        request_uri: &RequestId,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::OAuth(
            OAuthRequest::Delete2faChallengeByRequestUri {
                request_uri: request_uri.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn cleanup_expired_2fa_challenges(&self) -> Result<u64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::OAuth(
            OAuthRequest::CleanupExpired2faChallenges { tx },
        ))?;
        recv(rx).await
    }

    async fn check_user_2fa_enabled(&self, did: &Did) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::CheckUser2faEnabled {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_scope_preferences(
        &self,
        did: &Did,
        client_id: &ClientId,
    ) -> Result<Vec<ScopePreference>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::GetScopePreferences {
                did: did.clone(),
                client_id: client_id.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn upsert_scope_preferences(
        &self,
        did: &Did,
        client_id: &ClientId,
        prefs: &[ScopePreference],
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::OAuth(
            OAuthRequest::UpsertScopePreferences {
                did: did.clone(),
                client_id: client_id.clone(),
                prefs: prefs.to_vec(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn delete_scope_preferences(
        &self,
        did: &Did,
        client_id: &ClientId,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::OAuth(
            OAuthRequest::DeleteScopePreferences {
                did: did.clone(),
                client_id: client_id.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn upsert_authorized_client(
        &self,
        did: &Did,
        client_id: &ClientId,
        data: &AuthorizedClientData,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::OAuth(
            OAuthRequest::UpsertAuthorizedClient {
                did: did.clone(),
                client_id: client_id.clone(),
                data: data.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_authorized_client(
        &self,
        did: &Did,
        client_id: &ClientId,
    ) -> Result<Option<AuthorizedClientData>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::GetAuthorizedClient {
                did: did.clone(),
                client_id: client_id.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn list_trusted_devices(
        &self,
        did: &Did,
    ) -> Result<Vec<tranquil_db_traits::TrustedDeviceRow>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::ListTrustedDevices {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_device_trust_info(
        &self,
        device_id: &DeviceId,
        did: &Did,
    ) -> Result<Option<tranquil_db_traits::DeviceTrustInfo>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::GetDeviceTrustInfo {
                device_id: device_id.clone(),
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn device_belongs_to_user(
        &self,
        device_id: &DeviceId,
        did: &Did,
    ) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::DeviceBelongsToUser {
                device_id: device_id.clone(),
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn revoke_device_trust(&self, device_id: &DeviceId, did: &Did) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::RevokeDeviceTrust {
                device_id: device_id.clone(),
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn update_device_friendly_name(
        &self,
        device_id: &DeviceId,
        did: &Did,
        friendly_name: Option<&str>,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::OAuth(
            OAuthRequest::UpdateDeviceFriendlyName {
                device_id: device_id.clone(),
                did: did.clone(),
                friendly_name: friendly_name.map(str::to_owned),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn trust_device(
        &self,
        device_id: &DeviceId,
        did: &Did,
        trusted_at: DateTime<Utc>,
        trusted_until: DateTime<Utc>,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::TrustDevice {
                device_id: device_id.clone(),
                did: did.clone(),
                trusted_at,
                trusted_until,
                tx,
            }))?;
        recv(rx).await
    }

    async fn extend_device_trust(
        &self,
        device_id: &DeviceId,
        did: &Did,
        trusted_until: DateTime<Utc>,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::ExtendDeviceTrust {
                device_id: device_id.clone(),
                did: did.clone(),
                trusted_until,
                tx,
            }))?;
        recv(rx).await
    }

    async fn list_sessions_by_did(
        &self,
        did: &Did,
    ) -> Result<Vec<tranquil_db_traits::OAuthSessionListItem>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::ListSessionsByDid {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn delete_session_by_id(
        &self,
        session_id: TokenFamilyId,
        did: &Did,
    ) -> Result<u64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::DeleteSessionById {
                session_id,
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn delete_sessions_by_did(&self, did: &Did) -> Result<u64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::OAuth(OAuthRequest::DeleteSessionsByDid {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn delete_sessions_by_did_except(
        &self,
        did: &Did,
        except_token_id: &TokenId,
    ) -> Result<u64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::OAuth(
            OAuthRequest::DeleteSessionsByDidExcept {
                did: did.clone(),
                except_token_id: except_token_id.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }
}

#[async_trait]
impl<S: StorageIO + 'static> tranquil_db_traits::UserRepository for MetastoreClient<S> {
    async fn get_by_did(&self, did: &Did) -> Result<Option<UserRow>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetByDid {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_by_handle(&self, handle: &Handle) -> Result<Option<UserRow>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetByHandle {
                handle: handle.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_with_key_by_did(&self, did: &Did) -> Result<Option<UserWithKey>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetWithKeyByDid {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_status_by_did(&self, did: &Did) -> Result<Option<UserStatus>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetStatusByDid {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn count_users(&self) -> Result<i64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::CountUsers { tx }))?;
        recv(rx).await
    }

    async fn get_session_access_expiry(
        &self,
        did: &Did,
        access_jti: &str,
    ) -> Result<Option<DateTime<Utc>>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::GetSessionAccessExpiry {
                did: did.clone(),
                access_jti: access_jti.to_owned(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_oauth_token_with_user(
        &self,
        token_id: &str,
    ) -> Result<Option<OAuthTokenWithUser>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetOAuthTokenWithUser {
                token_id: token_id.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_user_info_by_did(&self, did: &Did) -> Result<Option<UserInfoForAuth>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetUserInfoByDid {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_any_admin_user_id(&self) -> Result<Option<Uuid>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetAnyAdminUserId {
                tx,
            }))?;
        recv(rx).await
    }

    async fn set_invites_disabled(&self, did: &Did, disabled: bool) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::SetInvitesDisabled {
                did: did.clone(),
                disabled,
                tx,
            }))?;
        recv(rx).await
    }

    async fn search_accounts(
        &self,
        cursor_did: Option<&Did>,
        email_filter: Option<&str>,
        handle_filter: Option<&str>,
        limit: i64,
    ) -> Result<Vec<AccountSearchResult>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::SearchAccounts {
                cursor_did: cursor_did.cloned(),
                email_filter: email_filter.map(str::to_owned),
                handle_filter: handle_filter.map(str::to_owned),
                limit,
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_auth_info_by_did(&self, did: &Did) -> Result<Option<UserAuthInfo>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetAuthInfoByDid {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_by_email(&self, email: &str) -> Result<Option<UserForVerification>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetByEmail {
                email: email.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_login_check_by_handle_or_email(
        &self,
        identifier: &str,
    ) -> Result<Option<UserLoginCheck>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::GetLoginCheckByHandleOrEmail {
                identifier: identifier.to_owned(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_login_info_by_handle_or_email(
        &self,
        identifier: &str,
    ) -> Result<Option<UserLoginInfo>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::GetLoginInfoByHandleOrEmail {
                identifier: identifier.to_owned(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_2fa_status_by_did(&self, did: &Did) -> Result<Option<User2faStatus>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::Get2faStatusByDid {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_comms_prefs(&self, user_id: Uuid) -> Result<Option<UserCommsPrefs>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetCommsPrefs {
                user_id,
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_id_by_did(&self, did: &Did) -> Result<Option<Uuid>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetIdByDid {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_user_key_by_id(&self, user_id: Uuid) -> Result<Option<UserKeyInfo>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetUserKeyById {
                user_id,
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_id_and_handle_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserIdAndHandle>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetIdAndHandleByDid {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_did_web_info_by_handle(
        &self,
        handle: &Handle,
    ) -> Result<Option<UserDidWebInfo>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetDidWebInfoByHandle {
                handle: handle.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_did_web_overrides(
        &self,
        user_id: Uuid,
    ) -> Result<Option<DidWebOverrides>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetDidWebOverrides {
                user_id,
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_handle_by_did(&self, did: &Did) -> Result<Option<Handle>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetHandleByDid {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn is_account_active_by_did(&self, did: &Did) -> Result<Option<bool>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::IsAccountActiveByDid {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_user_for_deletion(&self, did: &Did) -> Result<Option<UserForDeletion>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetUserForDeletion {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn check_handle_exists(
        &self,
        handle: &Handle,
        exclude_user_id: Uuid,
    ) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::CheckHandleExists {
                handle: handle.clone(),
                exclude_user_id,
                tx,
            }))?;
        recv(rx).await
    }

    async fn update_handle(&self, user_id: Uuid, handle: &Handle) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::UpdateHandle {
                user_id,
                handle: handle.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_user_with_key_by_did(&self, did: &Did) -> Result<Option<UserKeyWithId>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetUserWithKeyByDid {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn is_account_migrated(&self, did: &Did) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::IsAccountMigrated {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn has_verified_comms_channel(&self, did: &Did) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::HasVerifiedCommsChannel {
                did: did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_id_by_handle(&self, handle: &Handle) -> Result<Option<Uuid>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetIdByHandle {
                handle: handle.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_email_info_by_did(&self, did: &Did) -> Result<Option<UserEmailInfo>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetEmailInfoByDid {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn check_email_exists(
        &self,
        email: &str,
        exclude_user_id: Uuid,
    ) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::CheckEmailExists {
                email: email.to_owned(),
                exclude_user_id,
                tx,
            }))?;
        recv(rx).await
    }

    async fn update_email(&self, user_id: Uuid, email: &str) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::UpdateEmail {
                user_id,
                email: email.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn set_email_verified(&self, user_id: Uuid, verified: bool) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::SetEmailVerified {
                user_id,
                verified,
                tx,
            }))?;
        recv(rx).await
    }

    async fn check_email_verified_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<bool>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::CheckEmailVerifiedByIdentifier {
                identifier: identifier.to_owned(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn check_channel_verified_by_did(
        &self,
        did: &Did,
        channel: CommsChannel,
    ) -> Result<Option<bool>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::CheckChannelVerifiedByDid {
                did: did.clone(),
                channel,
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn admin_update_email(&self, did: &Did, email: &str) -> Result<u64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::AdminUpdateEmail {
                did: did.clone(),
                email: email.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn admin_update_handle(&self, did: &Did, handle: &Handle) -> Result<u64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::AdminUpdateHandle {
                did: did.clone(),
                handle: handle.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn admin_update_password(&self, did: &Did, password_hash: &str) -> Result<u64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::AdminUpdatePassword {
                did: did.clone(),
                password_hash: password_hash.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_notification_prefs(
        &self,
        did: &Did,
    ) -> Result<Option<NotificationPrefs>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetNotificationPrefs {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_id_handle_email_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserIdHandleEmail>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetIdHandleEmailByDid {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn update_preferred_comms_channel(
        &self,
        did: &Did,
        channel: CommsChannel,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::UpdatePreferredCommsChannel {
                did: did.clone(),
                channel,
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn clear_discord(&self, user_id: Uuid) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::ClearDiscord {
                user_id,
                tx,
            }))?;
        recv(rx).await
    }

    async fn clear_telegram(&self, user_id: Uuid) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::ClearTelegram {
                user_id,
                tx,
            }))?;
        recv(rx).await
    }

    async fn clear_signal(&self, user_id: Uuid) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::ClearSignal {
                user_id,
                tx,
            }))?;
        recv(rx).await
    }

    async fn set_unverified_signal(
        &self,
        user_id: Uuid,
        signal_username: &str,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::SetUnverifiedSignal {
                user_id,
                signal_username: signal_username.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn set_unverified_telegram(
        &self,
        user_id: Uuid,
        telegram_username: &str,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::SetUnverifiedTelegram {
                user_id,
                telegram_username: telegram_username.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn store_telegram_chat_id(
        &self,
        telegram_username: &str,
        chat_id: i64,
        handle: Option<&str>,
    ) -> Result<Option<Uuid>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::StoreTelegramChatId {
                telegram_username: telegram_username.to_owned(),
                chat_id,
                handle: handle.map(str::to_owned),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_telegram_chat_id(&self, user_id: Uuid) -> Result<Option<i64>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetTelegramChatId {
                user_id,
                tx,
            }))?;
        recv(rx).await
    }

    async fn set_unverified_discord(
        &self,
        user_id: Uuid,
        discord_username: &str,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::SetUnverifiedDiscord {
                user_id,
                discord_username: discord_username.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn store_discord_user_id(
        &self,
        discord_username: &str,
        discord_id: &str,
        handle: Option<&str>,
    ) -> Result<Option<Uuid>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::StoreDiscordUserId {
                discord_username: discord_username.to_owned(),
                discord_id: discord_id.to_owned(),
                handle: handle.map(str::to_owned),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_verification_info(
        &self,
        did: &Did,
    ) -> Result<Option<UserVerificationInfo>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetVerificationInfo {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn verify_email_channel(&self, user_id: Uuid, email: &str) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::VerifyEmailChannel {
                user_id,
                email: email.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn verify_discord_channel(&self, user_id: Uuid, discord_id: &str) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::VerifyDiscordChannel {
                user_id,
                discord_id: discord_id.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn verify_telegram_channel(
        &self,
        user_id: Uuid,
        telegram_username: &str,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::VerifyTelegramChannel {
                user_id,
                telegram_username: telegram_username.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn verify_signal_channel(
        &self,
        user_id: Uuid,
        signal_username: &str,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::VerifySignalChannel {
                user_id,
                signal_username: signal_username.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn set_email_verified_flag(&self, user_id: Uuid) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::SetEmailVerifiedFlag {
                user_id,
                tx,
            }))?;
        recv(rx).await
    }

    async fn set_discord_verified_flag(&self, user_id: Uuid) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::SetDiscordVerifiedFlag { user_id, tx },
        ))?;
        recv(rx).await
    }

    async fn set_telegram_verified_flag(&self, user_id: Uuid) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::SetTelegramVerifiedFlag { user_id, tx },
        ))?;
        recv(rx).await
    }

    async fn set_signal_verified_flag(&self, user_id: Uuid) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::SetSignalVerifiedFlag {
                user_id,
                tx,
            }))?;
        recv(rx).await
    }

    async fn has_totp_enabled(&self, did: &Did) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::HasTotpEnabled {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn has_passkeys(&self, did: &Did) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::HasPasskeys {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_password_hash_by_did(&self, did: &Did) -> Result<Option<String>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetPasswordHashByDid {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_passkeys_for_user(&self, did: &Did) -> Result<Vec<StoredPasskey>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetPasskeysForUser {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<StoredPasskey>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::GetPasskeyByCredentialId {
                credential_id: credential_id.to_vec(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn save_passkey(
        &self,
        did: &Did,
        credential_id: &[u8],
        public_key: &[u8],
        friendly_name: Option<&str>,
    ) -> Result<Uuid, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::SavePasskey {
                did: did.clone(),
                credential_id: credential_id.to_vec(),
                public_key: public_key.to_vec(),
                friendly_name: friendly_name.map(str::to_owned),
                tx,
            }))?;
        recv(rx).await
    }

    async fn update_passkey_counter(
        &self,
        credential_id: &[u8],
        new_counter: i32,
    ) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::UpdatePasskeyCounter {
                credential_id: credential_id.to_vec(),
                new_counter,
                tx,
            }))?;
        recv(rx).await
    }

    async fn delete_passkey(&self, id: Uuid, did: &Did) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::DeletePasskey {
                id,
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn update_passkey_name(&self, id: Uuid, did: &Did, name: &str) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::UpdatePasskeyName {
                id,
                did: did.clone(),
                name: name.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn save_webauthn_challenge(
        &self,
        did: &Did,
        challenge_type: WebauthnChallengeType,
        state_json: &str,
    ) -> Result<Uuid, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::SaveWebauthnChallenge {
                did: did.clone(),
                challenge_type,
                state_json: state_json.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn load_webauthn_challenge(
        &self,
        did: &Did,
        challenge_type: WebauthnChallengeType,
    ) -> Result<Option<String>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::LoadWebauthnChallenge {
                did: did.clone(),
                challenge_type,
                tx,
            }))?;
        recv(rx).await
    }

    async fn delete_webauthn_challenge(
        &self,
        did: &Did,
        challenge_type: WebauthnChallengeType,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::DeleteWebauthnChallenge {
                did: did.clone(),
                challenge_type,
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_totp_record(&self, did: &Did) -> Result<Option<TotpRecord>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetTotpRecord {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_totp_record_state(&self, did: &Did) -> Result<Option<TotpRecordState>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetTotpRecordState {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn upsert_totp_secret(
        &self,
        did: &Did,
        secret_encrypted: &[u8],
        encryption_version: i32,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::UpsertTotpSecret {
                did: did.clone(),
                secret_encrypted: secret_encrypted.to_vec(),
                encryption_version,
                tx,
            }))?;
        recv(rx).await
    }

    async fn set_totp_verified(&self, did: &Did) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::SetTotpVerified {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn update_totp_last_used(&self, did: &Did) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::UpdateTotpLastUsed {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn delete_totp(&self, did: &Did) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::DeleteTotp {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_unused_backup_codes(&self, did: &Did) -> Result<Vec<StoredBackupCode>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetUnusedBackupCodes {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn mark_backup_code_used(&self, code_id: Uuid) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::MarkBackupCodeUsed {
                code_id,
                tx,
            }))?;
        recv(rx).await
    }

    async fn count_unused_backup_codes(&self, did: &Did) -> Result<i64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::CountUnusedBackupCodes {
                did: did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn delete_backup_codes(&self, did: &Did) -> Result<u64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::DeleteBackupCodes {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn insert_backup_codes(&self, did: &Did, code_hashes: &[String]) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::InsertBackupCodes {
                did: did.clone(),
                code_hashes: code_hashes.to_vec(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn enable_totp_with_backup_codes(
        &self,
        did: &Did,
        code_hashes: &[String],
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::EnableTotpWithBackupCodes {
                did: did.clone(),
                code_hashes: code_hashes.to_vec(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn delete_totp_and_backup_codes(&self, did: &Did) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::DeleteTotpAndBackupCodes {
                did: did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn replace_backup_codes(&self, did: &Did, code_hashes: &[String]) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::ReplaceBackupCodes {
                did: did.clone(),
                code_hashes: code_hashes.to_vec(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_session_info_by_did(&self, did: &Did) -> Result<Option<UserSessionInfo>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetSessionInfoByDid {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_legacy_login_pref(
        &self,
        did: &Did,
    ) -> Result<Option<UserLegacyLoginPref>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetLegacyLoginPref {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn update_legacy_login(&self, did: &Did, allow: bool) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::UpdateLegacyLogin {
                did: did.clone(),
                allow,
                tx,
            }))?;
        recv(rx).await
    }

    async fn update_locale(&self, did: &Did, locale: &str) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::UpdateLocale {
                did: did.clone(),
                locale: locale.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_login_full_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<UserLoginFull>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::GetLoginFullByIdentifier {
                identifier: identifier.to_owned(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_confirm_signup_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserConfirmSignup>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetConfirmSignupByDid {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_resend_verification_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserResendVerification>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::GetResendVerificationByDid {
                did: did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn set_channel_verified(&self, did: &Did, channel: CommsChannel) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::SetChannelVerified {
                did: did.clone(),
                channel,
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_id_by_email_or_handle(
        &self,
        email: &str,
        handle: &str,
    ) -> Result<Option<Uuid>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetIdByEmailOrHandle {
                email: email.to_owned(),
                handle: handle.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn count_accounts_by_email(&self, email: &str) -> Result<i64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::CountAccountsByEmail {
                email: email.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_handles_by_email(&self, email: &str) -> Result<Vec<Handle>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetHandlesByEmail {
                email: email.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn set_password_reset_code(
        &self,
        user_id: Uuid,
        code: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::SetPasswordResetCode {
                user_id,
                code: code.to_owned(),
                expires_at,
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_user_by_reset_code(
        &self,
        code: &str,
    ) -> Result<Option<UserResetCodeInfo>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetUserByResetCode {
                code: code.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn clear_password_reset_code(&self, user_id: Uuid) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::ClearPasswordResetCode { user_id, tx },
        ))?;
        recv(rx).await
    }

    async fn get_id_and_password_hash_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserIdAndPasswordHash>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::GetIdAndPasswordHashByDid {
                did: did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn update_password_hash(
        &self,
        user_id: Uuid,
        password_hash: &str,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::UpdatePasswordHash {
                user_id,
                password_hash: password_hash.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn reset_password_with_sessions(
        &self,
        user_id: Uuid,
        password_hash: &str,
    ) -> Result<PasswordResetResult, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::ResetPasswordWithSessions {
                user_id,
                password_hash: password_hash.to_owned(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn activate_account(&self, did: &Did) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::ActivateAccount {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn deactivate_account(
        &self,
        did: &Did,
        delete_after: Option<DateTime<Utc>>,
    ) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::DeactivateAccount {
                did: did.clone(),
                delete_after,
                tx,
            }))?;
        recv(rx).await
    }

    async fn has_password_by_did(&self, did: &Did) -> Result<Option<bool>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::HasPasswordByDid {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_password_info_by_did(
        &self,
        did: &Did,
    ) -> Result<Option<UserPasswordInfo>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetPasswordInfoByDid {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn remove_user_password(&self, user_id: Uuid) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::RemoveUserPassword {
                user_id,
                tx,
            }))?;
        recv(rx).await
    }

    async fn set_new_user_password(
        &self,
        user_id: Uuid,
        password_hash: &str,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::SetNewUserPassword {
                user_id,
                password_hash: password_hash.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_user_key_by_did(&self, did: &Did) -> Result<Option<UserKeyInfo>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetUserKeyByDid {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn delete_account_complete(&self, user_id: Uuid, did: &Did) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::DeleteAccountComplete {
                user_id,
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn set_user_takedown(
        &self,
        did: &Did,
        takedown_ref: Option<&str>,
    ) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::SetUserTakedown {
                did: did.clone(),
                takedown_ref: takedown_ref.map(str::to_owned),
                tx,
            }))?;
        recv(rx).await
    }

    async fn admin_delete_account_complete(&self, user_id: Uuid, did: &Did) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::AdminDeleteAccountComplete {
                user_id,
                did: did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_user_for_did_doc(&self, did: &Did) -> Result<Option<UserForDidDoc>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetUserForDidDoc {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_user_for_did_doc_build(
        &self,
        did: &Did,
    ) -> Result<Option<UserForDidDocBuild>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetUserForDidDocBuild {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn upsert_did_web_overrides(
        &self,
        user_id: Uuid,
        verification_methods: Option<serde_json::Value>,
        also_known_as: Option<Vec<String>>,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::UpsertDidWebOverrides {
                user_id,
                verification_methods,
                also_known_as,
                tx,
            }))?;
        recv(rx).await
    }

    async fn update_migrated_to_pds(&self, did: &Did, endpoint: &str) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::UpdateMigratedToPds {
                did: did.clone(),
                endpoint: endpoint.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_user_for_passkey_setup(
        &self,
        did: &Did,
    ) -> Result<Option<UserForPasskeySetup>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::GetUserForPasskeySetup {
                did: did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn get_user_for_passkey_recovery(
        &self,
        identifier: &str,
        normalized_handle: &str,
    ) -> Result<Option<UserForPasskeyRecovery>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::GetUserForPasskeyRecovery {
                identifier: identifier.to_owned(),
                normalized_handle: normalized_handle.to_owned(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn set_recovery_token(
        &self,
        did: &Did,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::SetRecoveryToken {
                did: did.clone(),
                token_hash: token_hash.to_owned(),
                expires_at,
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_user_for_recovery(&self, did: &Did) -> Result<Option<UserForRecovery>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::GetUserForRecovery {
                did: did.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn get_accounts_scheduled_for_deletion(
        &self,
        limit: i64,
    ) -> Result<Vec<ScheduledDeletionAccount>, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::GetAccountsScheduledForDeletion { limit, tx },
        ))?;
        recv(rx).await
    }

    async fn delete_account_with_firehose(&self, user_id: Uuid, did: &Did) -> Result<i64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::DeleteAccountWithFirehose {
                user_id,
                did: did.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn create_password_account(
        &self,
        input: &CreatePasswordAccountInput,
    ) -> Result<CreatePasswordAccountResult, CreateAccountError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::CreatePasswordAccount {
                input: input.clone(),
                tx,
            }))
            .map_err(|e| CreateAccountError::Database(e.to_string()))?;
        recv_create_account(rx).await
    }

    async fn create_delegated_account(
        &self,
        input: &CreateDelegatedAccountInput,
    ) -> Result<Uuid, CreateAccountError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(
                UserRequest::CreateDelegatedAccount {
                    input: input.clone(),
                    tx,
                },
            ))
            .map_err(|e| CreateAccountError::Database(e.to_string()))?;
        recv_create_account(rx).await
    }

    async fn create_passkey_account(
        &self,
        input: &CreatePasskeyAccountInput,
    ) -> Result<CreatePasswordAccountResult, CreateAccountError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::CreatePasskeyAccount {
                input: input.clone(),
                tx,
            }))
            .map_err(|e| CreateAccountError::Database(e.to_string()))?;
        recv_create_account(rx).await
    }

    async fn create_sso_account(
        &self,
        input: &CreateSsoAccountInput,
    ) -> Result<CreatePasswordAccountResult, CreateAccountError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::CreateSsoAccount {
                input: input.clone(),
                tx,
            }))
            .map_err(|e| CreateAccountError::Database(e.to_string()))?;
        recv_create_account(rx).await
    }

    async fn reactivate_migration_account(
        &self,
        input: &MigrationReactivationInput,
    ) -> Result<ReactivatedAccountInfo, MigrationReactivationError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(
                UserRequest::ReactivateMigrationAccount {
                    input: input.clone(),
                    tx,
                },
            ))
            .map_err(|e| MigrationReactivationError::Database(e.to_string()))?;
        recv_migration_reactivation(rx).await
    }

    async fn check_handle_available_for_new_account(
        &self,
        handle: &Handle,
    ) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::CheckHandleAvailableForNewAccount {
                handle: handle.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn reserve_handle(&self, handle: &Handle, reserved_by: &str) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::ReserveHandle {
                handle: handle.clone(),
                reserved_by: reserved_by.to_owned(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn release_handle_reservation(&self, handle: &Handle) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::ReleaseHandleReservation {
                handle: handle.clone(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn cleanup_expired_handle_reservations(&self) -> Result<u64, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::CleanupExpiredHandleReservations { tx },
        ))?;
        recv(rx).await
    }

    async fn check_and_consume_invite_code(&self, code: &str) -> Result<bool, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool.send(MetastoreRequest::User(
            UserRequest::CheckAndConsumeInviteCode {
                code: code.to_owned(),
                tx,
            },
        ))?;
        recv(rx).await
    }

    async fn complete_passkey_setup(
        &self,
        input: &CompletePasskeySetupInput,
    ) -> Result<(), DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::CompletePasskeySetup {
                input: input.clone(),
                tx,
            }))?;
        recv(rx).await
    }

    async fn recover_passkey_account(
        &self,
        input: &RecoverPasskeyAccountInput,
    ) -> Result<RecoverPasskeyAccountResult, DbError> {
        let (tx, rx) = oneshot::channel();
        self.pool
            .send(MetastoreRequest::User(UserRequest::RecoverPasskeyAccount {
                input: input.clone(),
                tx,
            }))?;
        recv(rx).await
    }
}
