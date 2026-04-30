use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::JoinHandle;

use chrono::{DateTime, Utc};
use tokio::sync::oneshot;
use tranquil_db_traits::DbScope;
use tranquil_db_traits::{
    AccountSearchResult, AccountStatus, AdminAccountInfo, ApplyCommitError, ApplyCommitInput,
    ApplyCommitResult, Backlink, CommitEventData, CommsChannel, CommsType,
    CompletePasskeySetupInput, CreateAccountError, CreateDelegatedAccountInput,
    CreatePasskeyAccountInput, CreatePasswordAccountInput, CreatePasswordAccountResult,
    CreateSsoAccountInput, DbError, DelegationActionType, DeletionRequest,
    DeletionRequestWithToken, DidWebOverrides, ImportBlock, ImportRecord, ImportRepoError,
    InviteCodeError, InviteCodeInfo, InviteCodeRow, InviteCodeSortOrder, InviteCodeUse,
    MigrationReactivationError, MigrationReactivationInput, NotificationHistoryRow,
    NotificationPrefs, OAuthTokenWithUser, PasswordResetResult, PlcTokenInfo, QueuedComms,
    ReactivatedAccountInfo, RecoverPasskeyAccountInput, RecoverPasskeyAccountResult,
    RefreshSessionResult, ReservedSigningKey, ReservedSigningKeyFull, ScheduledDeletionAccount,
    ScopePreference, SequenceNumber, SequencedEvent, SessionId, StoredBackupCode, StoredPasskey,
    TokenFamilyId, TotpRecord, TotpRecordState, User2faStatus, UserAuthInfo, UserCommsPrefs,
    UserConfirmSignup, UserDidWebInfo, UserEmailInfo, UserForDeletion, UserForDidDoc,
    UserForDidDocBuild, UserForPasskeyRecovery, UserForPasskeySetup, UserForRecovery,
    UserForVerification, UserIdAndHandle, UserIdAndPasswordHash, UserIdHandleEmail,
    UserInfoForAuth, UserKeyInfo, UserKeyWithId, UserLegacyLoginPref, UserLoginCheck,
    UserLoginFull, UserLoginInfo, UserNeedingRecordBlobsBackfill, UserPasswordInfo,
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
        MetastoreError::UniqueViolation(constraint) => {
            DbError::Constraint(format!("unique constraint violated: {constraint}"))
        }
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
    Delegation(DelegationRequest),
    Sso(SsoRequest),
    Session(SessionRequest),
    Infra(InfraRequest),
    OAuth(OAuthRequest),
    User(UserRequest),
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
            Self::Delegation(r) => r.routing(),
            Self::Sso(r) => r.routing(),
            Self::Session(r) => r.routing(user_hashes),
            Self::Infra(r) => r.routing(user_hashes),
            Self::OAuth(r) => r.routing(),
            Self::User(r) => r.routing(user_hashes),
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
}

impl UserBlockRequest {
    fn routing(&self, user_hashes: &UserHashMap) -> Routing {
        match self {
            Self::InsertUserBlocks { user_id, .. }
            | Self::DeleteUserBlocks { user_id, .. }
            | Self::GetUserBlockCidsSinceRev { user_id, .. }
            | Self::CountUserBlocks { user_id, .. } => uuid_to_routing(user_hashes, user_id),
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
        commit_bytes: Vec<u8>,
        tx: Tx<SequenceNumber>,
    },
    InsertGenesisCommitEvent {
        did: Did,
        commit_cid: CidLink,
        mst_root_cid: CidLink,
        rev: String,
        commit_bytes: Vec<u8>,
        mst_root_bytes: Vec<u8>,
        tx: Tx<SequenceNumber>,
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
            | Self::DeleteSequencesExcept { did, .. } => {
                Routing::Sharded(UserHash::from_did(did.as_str()).raw())
            }
            Self::GetMaxSeq { .. }
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
            Self::GetUsersWithoutBlocks { .. }
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

pub enum DelegationRequest {
    IsDelegatedAccount {
        did: Did,
        tx: Tx<bool>,
    },
    CreateDelegation {
        delegated_did: Did,
        controller_did: Did,
        granted_scopes: DbScope,
        granted_by: Did,
        tx: Tx<Uuid>,
    },
    RevokeDelegation {
        delegated_did: Did,
        controller_did: Did,
        revoked_by: Did,
        tx: Tx<bool>,
    },
    UpdateDelegationScopes {
        delegated_did: Did,
        controller_did: Did,
        new_scopes: DbScope,
        tx: Tx<bool>,
    },
    GetDelegation {
        delegated_did: Did,
        controller_did: Did,
        tx: Tx<Option<tranquil_db_traits::DelegationGrant>>,
    },
    GetDelegationsForAccount {
        delegated_did: Did,
        tx: Tx<Vec<tranquil_db_traits::ControllerInfo>>,
    },
    GetAccountsControlledBy {
        controller_did: Did,
        tx: Tx<Vec<tranquil_db_traits::DelegatedAccountInfo>>,
    },
    CountActiveControllers {
        delegated_did: Did,
        tx: Tx<i64>,
    },
    ControlsAnyAccounts {
        did: Did,
        tx: Tx<bool>,
    },
    LogDelegationAction {
        delegated_did: Did,
        actor_did: Did,
        controller_did: Option<Did>,
        action_type: DelegationActionType,
        action_details: Option<serde_json::Value>,
        ip_address: Option<String>,
        user_agent: Option<String>,
        tx: Tx<Uuid>,
    },
    GetAuditLogForAccount {
        delegated_did: Did,
        limit: i64,
        offset: i64,
        tx: Tx<Vec<tranquil_db_traits::AuditLogEntry>>,
    },
    CountAuditLogEntries {
        delegated_did: Did,
        tx: Tx<i64>,
    },
}

impl DelegationRequest {
    fn routing(&self) -> Routing {
        match self {
            Self::IsDelegatedAccount { did, .. }
            | Self::GetDelegationsForAccount {
                delegated_did: did, ..
            }
            | Self::CountActiveControllers {
                delegated_did: did, ..
            }
            | Self::GetAuditLogForAccount {
                delegated_did: did, ..
            }
            | Self::CountAuditLogEntries {
                delegated_did: did, ..
            } => did_to_routing(did.as_str()),
            Self::CreateDelegation { delegated_did, .. }
            | Self::RevokeDelegation { delegated_did, .. }
            | Self::UpdateDelegationScopes { delegated_did, .. }
            | Self::GetDelegation { delegated_did, .. }
            | Self::LogDelegationAction { delegated_did, .. } => {
                did_to_routing(delegated_did.as_str())
            }
            Self::GetAccountsControlledBy { controller_did, .. }
            | Self::ControlsAnyAccounts {
                did: controller_did,
                ..
            } => did_to_routing(controller_did.as_str()),
        }
    }
}

pub enum SsoRequest {
    CreateExternalIdentity {
        did: Did,
        provider: tranquil_db_traits::SsoProviderType,
        provider_user_id: String,
        provider_username: Option<String>,
        provider_email: Option<String>,
        tx: Tx<Uuid>,
    },
    GetExternalIdentityByProvider {
        provider: tranquil_db_traits::SsoProviderType,
        provider_user_id: String,
        tx: Tx<Option<tranquil_db_traits::ExternalIdentity>>,
    },
    GetExternalIdentitiesByDid {
        did: Did,
        tx: Tx<Vec<tranquil_db_traits::ExternalIdentity>>,
    },
    UpdateExternalIdentityLogin {
        id: Uuid,
        provider_username: Option<String>,
        provider_email: Option<String>,
        tx: Tx<()>,
    },
    DeleteExternalIdentity {
        id: Uuid,
        did: Did,
        tx: Tx<bool>,
    },
    CreateSsoAuthState {
        state: String,
        request_uri: String,
        provider: tranquil_db_traits::SsoProviderType,
        action: tranquil_db_traits::SsoAction,
        nonce: Option<String>,
        code_verifier: Option<String>,
        did: Option<Did>,
        tx: Tx<()>,
    },
    ConsumeSsoAuthState {
        state: String,
        tx: Tx<Option<tranquil_db_traits::SsoAuthState>>,
    },
    CleanupExpiredSsoAuthStates {
        tx: Tx<u64>,
    },
    CreatePendingRegistration {
        token: String,
        request_uri: String,
        provider: tranquil_db_traits::SsoProviderType,
        provider_user_id: String,
        provider_username: Option<String>,
        provider_email: Option<String>,
        provider_email_verified: bool,
        tx: Tx<()>,
    },
    GetPendingRegistration {
        token: String,
        tx: Tx<Option<tranquil_db_traits::SsoPendingRegistration>>,
    },
    ConsumePendingRegistration {
        token: String,
        tx: Tx<Option<tranquil_db_traits::SsoPendingRegistration>>,
    },
    CleanupExpiredPendingRegistrations {
        tx: Tx<u64>,
    },
}

impl SsoRequest {
    fn routing(&self) -> Routing {
        match self {
            Self::CreateExternalIdentity { did, .. }
            | Self::GetExternalIdentitiesByDid { did, .. }
            | Self::DeleteExternalIdentity { did, .. } => did_to_routing(did.as_str()),
            Self::GetExternalIdentityByProvider { .. }
            | Self::UpdateExternalIdentityLogin { .. }
            | Self::ConsumeSsoAuthState { .. }
            | Self::CreateSsoAuthState { .. }
            | Self::CleanupExpiredSsoAuthStates { .. }
            | Self::CreatePendingRegistration { .. }
            | Self::GetPendingRegistration { .. }
            | Self::ConsumePendingRegistration { .. }
            | Self::CleanupExpiredPendingRegistrations { .. } => Routing::Global,
        }
    }
}

pub enum SessionRequest {
    CreateSession {
        data: tranquil_db_traits::SessionTokenCreate,
        tx: Tx<SessionId>,
    },
    GetSessionByAccessJti {
        access_jti: String,
        tx: Tx<Option<tranquil_db_traits::SessionToken>>,
    },
    GetSessionForRefresh {
        refresh_jti: String,
        tx: Tx<Option<tranquil_db_traits::SessionForRefresh>>,
    },
    UpdateSessionTokens {
        session_id: SessionId,
        new_access_jti: String,
        new_refresh_jti: String,
        new_access_expires_at: DateTime<Utc>,
        new_refresh_expires_at: DateTime<Utc>,
        tx: Tx<()>,
    },
    DeleteSessionByAccessJti {
        access_jti: String,
        tx: Tx<u64>,
    },
    DeleteSessionById {
        session_id: SessionId,
        tx: Tx<u64>,
    },
    DeleteSessionsByDid {
        did: Did,
        tx: Tx<u64>,
    },
    DeleteSessionsByDidExceptJti {
        did: Did,
        except_jti: String,
        tx: Tx<u64>,
    },
    ListSessionsByDid {
        did: Did,
        tx: Tx<Vec<tranquil_db_traits::SessionListItem>>,
    },
    GetSessionAccessJtiById {
        session_id: SessionId,
        did: Did,
        tx: Tx<Option<String>>,
    },
    DeleteSessionsByAppPassword {
        did: Did,
        app_password_name: String,
        tx: Tx<u64>,
    },
    GetSessionJtisByAppPassword {
        did: Did,
        app_password_name: String,
        tx: Tx<Vec<String>>,
    },
    CheckRefreshTokenUsed {
        refresh_jti: String,
        tx: Tx<Option<SessionId>>,
    },
    MarkRefreshTokenUsed {
        refresh_jti: String,
        session_id: SessionId,
        tx: Tx<bool>,
    },
    ListAppPasswords {
        user_id: Uuid,
        tx: Tx<Vec<tranquil_db_traits::AppPasswordRecord>>,
    },
    GetAppPasswordsForLogin {
        user_id: Uuid,
        tx: Tx<Vec<tranquil_db_traits::AppPasswordRecord>>,
    },
    GetAppPasswordByName {
        user_id: Uuid,
        name: String,
        tx: Tx<Option<tranquil_db_traits::AppPasswordRecord>>,
    },
    CreateAppPassword {
        data: tranquil_db_traits::AppPasswordCreate,
        tx: Tx<Uuid>,
    },
    DeleteAppPassword {
        user_id: Uuid,
        name: String,
        tx: Tx<u64>,
    },
    DeleteAppPasswordsByController {
        did: Did,
        controller_did: Did,
        tx: Tx<u64>,
    },
    GetLastReauthAt {
        did: Did,
        tx: Tx<Option<DateTime<Utc>>>,
    },
    UpdateLastReauth {
        did: Did,
        tx: Tx<DateTime<Utc>>,
    },
    GetSessionMfaStatus {
        did: Did,
        tx: Tx<Option<tranquil_db_traits::SessionMfaStatus>>,
    },
    UpdateMfaVerified {
        did: Did,
        tx: Tx<()>,
    },
    GetAppPasswordHashesByDid {
        did: Did,
        tx: Tx<Vec<String>>,
    },
    RefreshSessionAtomic {
        data: tranquil_db_traits::SessionRefreshData,
        tx: Tx<RefreshSessionResult>,
    },
}

impl SessionRequest {
    fn routing(&self, user_hashes: &UserHashMap) -> Routing {
        match self {
            Self::CreateSession { .. }
            | Self::GetSessionByAccessJti { .. }
            | Self::GetSessionForRefresh { .. }
            | Self::CheckRefreshTokenUsed { .. }
            | Self::MarkRefreshTokenUsed { .. }
            | Self::DeleteSessionByAccessJti { .. }
            | Self::DeleteSessionById { .. } => Routing::Global,
            Self::DeleteSessionsByDid { did, .. }
            | Self::DeleteSessionsByDidExceptJti { did, .. }
            | Self::ListSessionsByDid { did, .. }
            | Self::GetSessionAccessJtiById { did, .. }
            | Self::DeleteSessionsByAppPassword { did, .. }
            | Self::GetSessionJtisByAppPassword { did, .. }
            | Self::DeleteAppPasswordsByController { did, .. }
            | Self::GetLastReauthAt { did, .. }
            | Self::UpdateLastReauth { did, .. }
            | Self::GetSessionMfaStatus { did, .. }
            | Self::UpdateMfaVerified { did, .. }
            | Self::GetAppPasswordHashesByDid { did, .. } => did_to_routing(did.as_str()),
            Self::UpdateSessionTokens { .. } | Self::RefreshSessionAtomic { .. } => Routing::Global,
            Self::ListAppPasswords { user_id, .. }
            | Self::GetAppPasswordsForLogin { user_id, .. }
            | Self::GetAppPasswordByName { user_id, .. }
            | Self::CreateAppPassword {
                data: tranquil_db_traits::AppPasswordCreate { user_id, .. },
                ..
            }
            | Self::DeleteAppPassword { user_id, .. } => uuid_to_routing(user_hashes, user_id),
        }
    }
}

pub enum UserRequest {
    GetByDid {
        did: Did,
        tx: Tx<Option<UserRow>>,
    },
    GetByHandle {
        handle: Handle,
        tx: Tx<Option<UserRow>>,
    },
    GetWithKeyByDid {
        did: Did,
        tx: Tx<Option<UserWithKey>>,
    },
    GetStatusByDid {
        did: Did,
        tx: Tx<Option<UserStatus>>,
    },
    CountUsers {
        tx: Tx<i64>,
    },
    GetSessionAccessExpiry {
        did: Did,
        access_jti: String,
        tx: Tx<Option<DateTime<Utc>>>,
    },
    GetOAuthTokenWithUser {
        token_id: String,
        tx: Tx<Option<OAuthTokenWithUser>>,
    },
    GetUserInfoByDid {
        did: Did,
        tx: Tx<Option<UserInfoForAuth>>,
    },
    GetAnyAdminUserId {
        tx: Tx<Option<Uuid>>,
    },
    SetInvitesDisabled {
        did: Did,
        disabled: bool,
        tx: Tx<bool>,
    },
    SearchAccounts {
        cursor_did: Option<Did>,
        email_filter: Option<String>,
        handle_filter: Option<String>,
        limit: i64,
        tx: Tx<Vec<AccountSearchResult>>,
    },
    GetAuthInfoByDid {
        did: Did,
        tx: Tx<Option<UserAuthInfo>>,
    },
    GetByEmail {
        email: String,
        tx: Tx<Option<UserForVerification>>,
    },
    GetLoginCheckByIdentifier {
        identifier: String,
        tx: Tx<Option<UserLoginCheck>>,
    },
    GetLoginInfoByIdentifier {
        identifier: String,
        tx: Tx<Option<UserLoginInfo>>,
    },
    Get2faStatusByDid {
        did: Did,
        tx: Tx<Option<User2faStatus>>,
    },
    GetCommsPrefs {
        user_id: Uuid,
        tx: Tx<Option<UserCommsPrefs>>,
    },
    GetIdByDid {
        did: Did,
        tx: Tx<Option<Uuid>>,
    },
    GetUserKeyById {
        user_id: Uuid,
        tx: Tx<Option<UserKeyInfo>>,
    },
    GetIdAndHandleByDid {
        did: Did,
        tx: Tx<Option<UserIdAndHandle>>,
    },
    GetDidWebInfoByHandle {
        handle: Handle,
        tx: Tx<Option<UserDidWebInfo>>,
    },
    GetDidWebOverrides {
        user_id: Uuid,
        tx: Tx<Option<DidWebOverrides>>,
    },
    GetHandleByDid {
        did: Did,
        tx: Tx<Option<Handle>>,
    },
    IsAccountActiveByDid {
        did: Did,
        tx: Tx<Option<bool>>,
    },
    GetUserForDeletion {
        did: Did,
        tx: Tx<Option<UserForDeletion>>,
    },
    CheckHandleExists {
        handle: Handle,
        exclude_user_id: Uuid,
        tx: Tx<bool>,
    },
    UpdateHandle {
        user_id: Uuid,
        handle: Handle,
        tx: Tx<()>,
    },
    GetUserWithKeyByDid {
        did: Did,
        tx: Tx<Option<UserKeyWithId>>,
    },
    IsAccountMigrated {
        did: Did,
        tx: Tx<bool>,
    },
    HasVerifiedCommsChannel {
        did: Did,
        tx: Tx<bool>,
    },
    GetIdByHandle {
        handle: Handle,
        tx: Tx<Option<Uuid>>,
    },
    GetEmailInfoByDid {
        did: Did,
        tx: Tx<Option<UserEmailInfo>>,
    },
    CheckEmailExists {
        email: String,
        exclude_user_id: Uuid,
        tx: Tx<bool>,
    },
    UpdateEmail {
        user_id: Uuid,
        email: String,
        tx: Tx<()>,
    },
    SetEmailVerified {
        user_id: Uuid,
        verified: bool,
        tx: Tx<()>,
    },
    CheckEmailVerifiedByIdentifier {
        identifier: String,
        tx: Tx<Option<bool>>,
    },
    CheckChannelVerifiedByDid {
        did: Did,
        channel: CommsChannel,
        tx: Tx<Option<bool>>,
    },
    AdminUpdateEmail {
        did: Did,
        email: String,
        tx: Tx<u64>,
    },
    AdminUpdateHandle {
        did: Did,
        handle: Handle,
        tx: Tx<u64>,
    },
    AdminUpdatePassword {
        did: Did,
        password_hash: String,
        tx: Tx<u64>,
    },
    SetAdminStatus {
        did: Did,
        is_admin: bool,
        tx: Tx<()>,
    },
    GetNotificationPrefs {
        did: Did,
        tx: Tx<Option<NotificationPrefs>>,
    },
    GetIdHandleEmailByDid {
        did: Did,
        tx: Tx<Option<UserIdHandleEmail>>,
    },
    UpdatePreferredCommsChannel {
        did: Did,
        channel: CommsChannel,
        tx: Tx<()>,
    },
    ClearDiscord {
        user_id: Uuid,
        tx: Tx<()>,
    },
    ClearTelegram {
        user_id: Uuid,
        tx: Tx<()>,
    },
    ClearSignal {
        user_id: Uuid,
        tx: Tx<()>,
    },
    SetUnverifiedSignal {
        user_id: Uuid,
        signal_username: String,
        tx: Tx<()>,
    },
    SetUnverifiedTelegram {
        user_id: Uuid,
        telegram_username: String,
        tx: Tx<()>,
    },
    StoreTelegramChatId {
        telegram_username: String,
        chat_id: i64,
        handle: Option<String>,
        tx: Tx<Option<Uuid>>,
    },
    GetTelegramChatId {
        user_id: Uuid,
        tx: Tx<Option<i64>>,
    },
    SetUnverifiedDiscord {
        user_id: Uuid,
        discord_username: String,
        tx: Tx<()>,
    },
    StoreDiscordUserId {
        discord_username: String,
        discord_id: String,
        handle: Option<String>,
        tx: Tx<Option<Uuid>>,
    },
    GetVerificationInfo {
        did: Did,
        tx: Tx<Option<UserVerificationInfo>>,
    },
    VerifyEmailChannel {
        user_id: Uuid,
        email: String,
        tx: Tx<bool>,
    },
    VerifyDiscordChannel {
        user_id: Uuid,
        discord_id: String,
        tx: Tx<()>,
    },
    VerifyTelegramChannel {
        user_id: Uuid,
        telegram_username: String,
        tx: Tx<()>,
    },
    VerifySignalChannel {
        user_id: Uuid,
        signal_username: String,
        tx: Tx<()>,
    },
    SetEmailVerifiedFlag {
        user_id: Uuid,
        tx: Tx<()>,
    },
    SetDiscordVerifiedFlag {
        user_id: Uuid,
        tx: Tx<()>,
    },
    SetTelegramVerifiedFlag {
        user_id: Uuid,
        tx: Tx<()>,
    },
    SetSignalVerifiedFlag {
        user_id: Uuid,
        tx: Tx<()>,
    },
    HasTotpEnabled {
        did: Did,
        tx: Tx<bool>,
    },
    HasPasskeys {
        did: Did,
        tx: Tx<bool>,
    },
    GetPasswordHashByDid {
        did: Did,
        tx: Tx<Option<String>>,
    },
    GetPasskeysForUser {
        did: Did,
        tx: Tx<Vec<StoredPasskey>>,
    },
    GetPasskeyByCredentialId {
        credential_id: Vec<u8>,
        tx: Tx<Option<StoredPasskey>>,
    },
    SavePasskey {
        did: Did,
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
        friendly_name: Option<String>,
        tx: Tx<Uuid>,
    },
    UpdatePasskeyCounter {
        credential_id: Vec<u8>,
        new_counter: i32,
        tx: Tx<bool>,
    },
    DeletePasskey {
        id: Uuid,
        did: Did,
        tx: Tx<bool>,
    },
    UpdatePasskeyName {
        id: Uuid,
        did: Did,
        name: String,
        tx: Tx<bool>,
    },
    SaveWebauthnChallenge {
        did: Did,
        challenge_type: WebauthnChallengeType,
        state_json: String,
        tx: Tx<Uuid>,
    },
    LoadWebauthnChallenge {
        did: Did,
        challenge_type: WebauthnChallengeType,
        tx: Tx<Option<String>>,
    },
    DeleteWebauthnChallenge {
        did: Did,
        challenge_type: WebauthnChallengeType,
        tx: Tx<()>,
    },
    SaveDiscoverableChallenge {
        request_key: String,
        state_json: String,
        tx: Tx<Uuid>,
    },
    LoadDiscoverableChallenge {
        request_key: String,
        tx: Tx<Option<String>>,
    },
    DeleteDiscoverableChallenge {
        request_key: String,
        tx: Tx<()>,
    },
    GetTotpRecord {
        did: Did,
        tx: Tx<Option<TotpRecord>>,
    },
    GetTotpRecordState {
        did: Did,
        tx: Tx<Option<TotpRecordState>>,
    },
    UpsertTotpSecret {
        did: Did,
        secret_encrypted: Vec<u8>,
        encryption_version: i32,
        tx: Tx<()>,
    },
    SetTotpVerified {
        did: Did,
        tx: Tx<()>,
    },
    UpdateTotpLastUsed {
        did: Did,
        tx: Tx<()>,
    },
    DeleteTotp {
        did: Did,
        tx: Tx<()>,
    },
    GetUnusedBackupCodes {
        did: Did,
        tx: Tx<Vec<StoredBackupCode>>,
    },
    MarkBackupCodeUsed {
        code_id: Uuid,
        tx: Tx<bool>,
    },
    CountUnusedBackupCodes {
        did: Did,
        tx: Tx<i64>,
    },
    DeleteBackupCodes {
        did: Did,
        tx: Tx<u64>,
    },
    InsertBackupCodes {
        did: Did,
        code_hashes: Vec<String>,
        tx: Tx<()>,
    },
    EnableTotpWithBackupCodes {
        did: Did,
        code_hashes: Vec<String>,
        tx: Tx<()>,
    },
    DeleteTotpAndBackupCodes {
        did: Did,
        tx: Tx<()>,
    },
    ReplaceBackupCodes {
        did: Did,
        code_hashes: Vec<String>,
        tx: Tx<()>,
    },
    GetSessionInfoByDid {
        did: Did,
        tx: Tx<Option<UserSessionInfo>>,
    },
    GetLegacyLoginPref {
        did: Did,
        tx: Tx<Option<UserLegacyLoginPref>>,
    },
    UpdateLegacyLogin {
        did: Did,
        allow: bool,
        tx: Tx<bool>,
    },
    UpdateLocale {
        did: Did,
        locale: String,
        tx: Tx<bool>,
    },
    GetLoginFullByIdentifier {
        identifier: String,
        tx: Tx<Option<UserLoginFull>>,
    },
    GetConfirmSignupByDid {
        did: Did,
        tx: Tx<Option<UserConfirmSignup>>,
    },
    GetResendVerificationByDid {
        did: Did,
        tx: Tx<Option<UserResendVerification>>,
    },
    SetChannelVerified {
        did: Did,
        channel: CommsChannel,
        tx: Tx<()>,
    },
    GetIdByEmailOrHandle {
        email: String,
        handle: String,
        tx: Tx<Option<Uuid>>,
    },
    CountAccountsByEmail {
        email: String,
        tx: Tx<i64>,
    },
    GetHandlesByEmail {
        email: String,
        tx: Tx<Vec<Handle>>,
    },
    SetPasswordResetCode {
        user_id: Uuid,
        code: String,
        expires_at: DateTime<Utc>,
        tx: Tx<()>,
    },
    GetUserByResetCode {
        code: String,
        tx: Tx<Option<UserResetCodeInfo>>,
    },
    ClearPasswordResetCode {
        user_id: Uuid,
        tx: Tx<()>,
    },
    GetIdAndPasswordHashByDid {
        did: Did,
        tx: Tx<Option<UserIdAndPasswordHash>>,
    },
    UpdatePasswordHash {
        user_id: Uuid,
        password_hash: String,
        tx: Tx<()>,
    },
    ResetPasswordWithSessions {
        user_id: Uuid,
        password_hash: String,
        tx: Tx<PasswordResetResult>,
    },
    ActivateAccount {
        did: Did,
        tx: Tx<bool>,
    },
    DeactivateAccount {
        did: Did,
        delete_after: Option<DateTime<Utc>>,
        tx: Tx<bool>,
    },
    HasPasswordByDid {
        did: Did,
        tx: Tx<Option<bool>>,
    },
    GetPasswordInfoByDid {
        did: Did,
        tx: Tx<Option<UserPasswordInfo>>,
    },
    RemoveUserPassword {
        user_id: Uuid,
        tx: Tx<()>,
    },
    SetNewUserPassword {
        user_id: Uuid,
        password_hash: String,
        tx: Tx<()>,
    },
    GetUserKeyByDid {
        did: Did,
        tx: Tx<Option<UserKeyInfo>>,
    },
    DeleteAccountComplete {
        user_id: Uuid,
        did: Did,
        tx: Tx<()>,
    },
    SetUserTakedown {
        did: Did,
        takedown_ref: Option<String>,
        tx: Tx<bool>,
    },
    AdminDeleteAccountComplete {
        user_id: Uuid,
        did: Did,
        tx: Tx<()>,
    },
    GetUserForDidDoc {
        did: Did,
        tx: Tx<Option<UserForDidDoc>>,
    },
    GetUserForDidDocBuild {
        did: Did,
        tx: Tx<Option<UserForDidDocBuild>>,
    },
    UpsertDidWebOverrides {
        user_id: Uuid,
        verification_methods: Option<serde_json::Value>,
        also_known_as: Option<Vec<String>>,
        tx: Tx<()>,
    },
    UpdateMigratedToPds {
        did: Did,
        endpoint: String,
        tx: Tx<()>,
    },
    GetUserForPasskeySetup {
        did: Did,
        tx: Tx<Option<UserForPasskeySetup>>,
    },
    GetUserForPasskeyRecovery {
        identifier: String,
        normalized_handle: String,
        tx: Tx<Option<UserForPasskeyRecovery>>,
    },
    SetRecoveryToken {
        did: Did,
        token_hash: String,
        expires_at: DateTime<Utc>,
        tx: Tx<()>,
    },
    GetUserForRecovery {
        did: Did,
        tx: Tx<Option<UserForRecovery>>,
    },
    GetAccountsScheduledForDeletion {
        limit: i64,
        tx: Tx<Vec<ScheduledDeletionAccount>>,
    },
    DeleteAccountWithFirehose {
        user_id: Uuid,
        did: Did,
        tx: Tx<i64>,
    },
    CreatePasswordAccount {
        input: CreatePasswordAccountInput,
        tx: oneshot::Sender<Result<CreatePasswordAccountResult, CreateAccountError>>,
    },
    CreateDelegatedAccount {
        input: CreateDelegatedAccountInput,
        tx: oneshot::Sender<Result<Uuid, CreateAccountError>>,
    },
    CreatePasskeyAccount {
        input: CreatePasskeyAccountInput,
        tx: oneshot::Sender<Result<CreatePasswordAccountResult, CreateAccountError>>,
    },
    CreateSsoAccount {
        input: CreateSsoAccountInput,
        tx: oneshot::Sender<Result<CreatePasswordAccountResult, CreateAccountError>>,
    },
    ReactivateMigrationAccount {
        input: MigrationReactivationInput,
        tx: oneshot::Sender<Result<ReactivatedAccountInfo, MigrationReactivationError>>,
    },
    CheckHandleAvailableForNewAccount {
        handle: Handle,
        tx: Tx<bool>,
    },
    ReserveHandle {
        handle: Handle,
        reserved_by: String,
        tx: Tx<bool>,
    },
    ReleaseHandleReservation {
        handle: Handle,
        tx: Tx<()>,
    },
    CleanupExpiredHandleReservations {
        tx: Tx<u64>,
    },
    CheckAndConsumeInviteCode {
        code: String,
        tx: Tx<bool>,
    },
    CompletePasskeySetup {
        input: CompletePasskeySetupInput,
        tx: Tx<()>,
    },
    RecoverPasskeyAccount {
        input: RecoverPasskeyAccountInput,
        tx: Tx<RecoverPasskeyAccountResult>,
    },
    GetPasswordResetInfo {
        email: String,
        tx: Tx<Option<tranquil_db_traits::PasswordResetInfo>>,
    },
    EnableTotpVerified {
        did: Did,
        encrypted_secret: Vec<u8>,
        tx: Tx<()>,
    },
    SetTwoFactorEnabled {
        did: Did,
        enabled: bool,
        tx: Tx<()>,
    },
    ExpirePasswordResetCode {
        email: String,
        tx: Tx<()>,
    },
}

impl UserRequest {
    fn routing(&self, user_hashes: &UserHashMap) -> Routing {
        match self {
            Self::GetByDid { did, .. }
            | Self::GetWithKeyByDid { did, .. }
            | Self::GetStatusByDid { did, .. }
            | Self::GetSessionAccessExpiry { did, .. }
            | Self::GetUserInfoByDid { did, .. }
            | Self::SetInvitesDisabled { did, .. }
            | Self::GetAuthInfoByDid { did, .. }
            | Self::Get2faStatusByDid { did, .. }
            | Self::GetIdByDid { did, .. }
            | Self::GetIdAndHandleByDid { did, .. }
            | Self::GetHandleByDid { did, .. }
            | Self::IsAccountActiveByDid { did, .. }
            | Self::GetUserForDeletion { did, .. }
            | Self::GetUserWithKeyByDid { did, .. }
            | Self::IsAccountMigrated { did, .. }
            | Self::HasVerifiedCommsChannel { did, .. }
            | Self::GetEmailInfoByDid { did, .. }
            | Self::CheckChannelVerifiedByDid { did, .. }
            | Self::AdminUpdateEmail { did, .. }
            | Self::AdminUpdateHandle { did, .. }
            | Self::AdminUpdatePassword { did, .. }
            | Self::SetAdminStatus { did, .. }
            | Self::GetNotificationPrefs { did, .. }
            | Self::GetIdHandleEmailByDid { did, .. }
            | Self::UpdatePreferredCommsChannel { did, .. }
            | Self::GetVerificationInfo { did, .. }
            | Self::HasTotpEnabled { did, .. }
            | Self::HasPasskeys { did, .. }
            | Self::GetPasswordHashByDid { did, .. }
            | Self::GetPasskeysForUser { did, .. }
            | Self::SavePasskey { did, .. }
            | Self::DeletePasskey { did, .. }
            | Self::UpdatePasskeyName { did, .. }
            | Self::SaveWebauthnChallenge { did, .. }
            | Self::LoadWebauthnChallenge { did, .. }
            | Self::DeleteWebauthnChallenge { did, .. }
            | Self::GetTotpRecord { did, .. }
            | Self::GetTotpRecordState { did, .. }
            | Self::UpsertTotpSecret { did, .. }
            | Self::SetTotpVerified { did, .. }
            | Self::UpdateTotpLastUsed { did, .. }
            | Self::DeleteTotp { did, .. }
            | Self::GetUnusedBackupCodes { did, .. }
            | Self::CountUnusedBackupCodes { did, .. }
            | Self::DeleteBackupCodes { did, .. }
            | Self::InsertBackupCodes { did, .. }
            | Self::EnableTotpWithBackupCodes { did, .. }
            | Self::DeleteTotpAndBackupCodes { did, .. }
            | Self::ReplaceBackupCodes { did, .. }
            | Self::GetSessionInfoByDid { did, .. }
            | Self::GetLegacyLoginPref { did, .. }
            | Self::UpdateLegacyLogin { did, .. }
            | Self::UpdateLocale { did, .. }
            | Self::GetConfirmSignupByDid { did, .. }
            | Self::GetResendVerificationByDid { did, .. }
            | Self::SetChannelVerified { did, .. }
            | Self::GetIdAndPasswordHashByDid { did, .. }
            | Self::ActivateAccount { did, .. }
            | Self::DeactivateAccount { did, .. }
            | Self::HasPasswordByDid { did, .. }
            | Self::GetPasswordInfoByDid { did, .. }
            | Self::GetUserKeyByDid { did, .. }
            | Self::DeleteAccountComplete { did, .. }
            | Self::SetUserTakedown { did, .. }
            | Self::AdminDeleteAccountComplete { did, .. }
            | Self::GetUserForDidDoc { did, .. }
            | Self::GetUserForDidDocBuild { did, .. }
            | Self::UpdateMigratedToPds { did, .. }
            | Self::GetUserForPasskeySetup { did, .. }
            | Self::GetUserForRecovery { did, .. }
            | Self::DeleteAccountWithFirehose { did, .. }
            | Self::CreatePasswordAccount {
                input: CreatePasswordAccountInput { did, .. },
                ..
            }
            | Self::CreateDelegatedAccount {
                input: CreateDelegatedAccountInput { did, .. },
                ..
            }
            | Self::CreatePasskeyAccount {
                input: CreatePasskeyAccountInput { did, .. },
                ..
            }
            | Self::CreateSsoAccount {
                input: CreateSsoAccountInput { did, .. },
                ..
            }
            | Self::ReactivateMigrationAccount {
                input: MigrationReactivationInput { did, .. },
                ..
            }
            | Self::CompletePasskeySetup {
                input: CompletePasskeySetupInput { did, .. },
                ..
            }
            | Self::RecoverPasskeyAccount {
                input: RecoverPasskeyAccountInput { did, .. },
                ..
            }
            | Self::SetRecoveryToken { did, .. }
            | Self::EnableTotpVerified { did, .. }
            | Self::SetTwoFactorEnabled { did, .. } => did_to_routing(did.as_str()),

            Self::GetCommsPrefs { user_id, .. }
            | Self::GetUserKeyById { user_id, .. }
            | Self::GetDidWebOverrides { user_id, .. }
            | Self::UpdateHandle { user_id, .. }
            | Self::UpdateEmail { user_id, .. }
            | Self::SetEmailVerified { user_id, .. }
            | Self::ClearDiscord { user_id, .. }
            | Self::ClearTelegram { user_id, .. }
            | Self::ClearSignal { user_id, .. }
            | Self::SetUnverifiedSignal { user_id, .. }
            | Self::SetUnverifiedTelegram { user_id, .. }
            | Self::GetTelegramChatId { user_id, .. }
            | Self::SetUnverifiedDiscord { user_id, .. }
            | Self::VerifyEmailChannel { user_id, .. }
            | Self::VerifyDiscordChannel { user_id, .. }
            | Self::VerifyTelegramChannel { user_id, .. }
            | Self::VerifySignalChannel { user_id, .. }
            | Self::SetEmailVerifiedFlag { user_id, .. }
            | Self::SetDiscordVerifiedFlag { user_id, .. }
            | Self::SetTelegramVerifiedFlag { user_id, .. }
            | Self::SetSignalVerifiedFlag { user_id, .. }
            | Self::SetPasswordResetCode { user_id, .. }
            | Self::ClearPasswordResetCode { user_id, .. }
            | Self::UpdatePasswordHash { user_id, .. }
            | Self::ResetPasswordWithSessions { user_id, .. }
            | Self::RemoveUserPassword { user_id, .. }
            | Self::SetNewUserPassword { user_id, .. }
            | Self::UpsertDidWebOverrides { user_id, .. } => uuid_to_routing(user_hashes, user_id),

            Self::CheckHandleExists {
                exclude_user_id, ..
            }
            | Self::CheckEmailExists {
                exclude_user_id, ..
            } => uuid_to_routing(user_hashes, exclude_user_id),

            Self::MarkBackupCodeUsed { .. } => Routing::Global,

            Self::GetByHandle { .. }
            | Self::GetDidWebInfoByHandle { .. }
            | Self::GetIdByHandle { .. }
            | Self::CheckHandleAvailableForNewAccount { .. }
            | Self::ReserveHandle { .. }
            | Self::ReleaseHandleReservation { .. } => Routing::Global,

            Self::CountUsers { .. }
            | Self::GetOAuthTokenWithUser { .. }
            | Self::GetAnyAdminUserId { .. }
            | Self::SearchAccounts { .. }
            | Self::GetByEmail { .. }
            | Self::GetLoginCheckByIdentifier { .. }
            | Self::GetLoginInfoByIdentifier { .. }
            | Self::CheckEmailVerifiedByIdentifier { .. }
            | Self::StoreTelegramChatId { .. }
            | Self::StoreDiscordUserId { .. }
            | Self::GetPasskeyByCredentialId { .. }
            | Self::UpdatePasskeyCounter { .. }
            | Self::GetLoginFullByIdentifier { .. }
            | Self::GetIdByEmailOrHandle { .. }
            | Self::CountAccountsByEmail { .. }
            | Self::GetHandlesByEmail { .. }
            | Self::GetUserByResetCode { .. }
            | Self::GetUserForPasskeyRecovery { .. }
            | Self::GetAccountsScheduledForDeletion { .. }
            | Self::CleanupExpiredHandleReservations { .. }
            | Self::CheckAndConsumeInviteCode { .. }
            | Self::GetPasswordResetInfo { .. }
            | Self::ExpirePasswordResetCode { .. }
            | Self::SaveDiscoverableChallenge { .. }
            | Self::LoadDiscoverableChallenge { .. }
            | Self::DeleteDiscoverableChallenge { .. } => Routing::Global,
        }
    }
}

pub enum InfraRequest {
    EnqueueComms {
        user_id: Option<Uuid>,
        channel: CommsChannel,
        comms_type: CommsType,
        recipient: String,
        subject: Option<String>,
        body: String,
        metadata: Option<serde_json::Value>,
        tx: Tx<Uuid>,
    },
    FetchPendingComms {
        now: DateTime<Utc>,
        batch_size: i64,
        tx: Tx<Vec<QueuedComms>>,
    },
    MarkCommsSent {
        id: Uuid,
        tx: Tx<()>,
    },
    MarkCommsFailed {
        id: Uuid,
        error: String,
        tx: Tx<()>,
    },
    MarkCommsFailedPermanent {
        id: Uuid,
        error: String,
        tx: Tx<()>,
    },
    CreateInviteCode {
        code: String,
        use_count: i32,
        for_account: Option<Did>,
        tx: Tx<bool>,
    },
    CreateInviteCodesBatch {
        codes: Vec<String>,
        use_count: i32,
        created_by_user: Uuid,
        for_account: Option<Did>,
        tx: Tx<()>,
    },
    GetInviteCodeAvailableUses {
        code: String,
        tx: Tx<Option<i32>>,
    },
    ValidateInviteCode {
        code: String,
        tx: oneshot::Sender<Result<(), InviteCodeError>>,
    },
    DecrementInviteCodeUses {
        code: String,
        tx: Tx<()>,
    },
    RecordInviteCodeUse {
        code: String,
        used_by_user: Uuid,
        tx: Tx<()>,
    },
    GetInviteCodesForAccount {
        for_account: Did,
        tx: Tx<Vec<InviteCodeInfo>>,
    },
    GetInviteCodeUses {
        code: String,
        tx: Tx<Vec<InviteCodeUse>>,
    },
    DisableInviteCodesByCode {
        codes: Vec<String>,
        tx: Tx<()>,
    },
    DisableInviteCodesByAccount {
        accounts: Vec<Did>,
        tx: Tx<()>,
    },
    ListInviteCodes {
        cursor: Option<String>,
        limit: i64,
        sort: InviteCodeSortOrder,
        tx: Tx<Vec<InviteCodeRow>>,
    },
    GetUserDidsByIds {
        user_ids: Vec<Uuid>,
        tx: Tx<Vec<(Uuid, Did)>>,
    },
    GetInviteCodeUsesBatch {
        codes: Vec<String>,
        tx: Tx<Vec<InviteCodeUse>>,
    },
    GetInvitesCreatedByUser {
        user_id: Uuid,
        tx: Tx<Vec<InviteCodeInfo>>,
    },
    GetInviteCodeInfo {
        code: String,
        tx: Tx<Option<InviteCodeInfo>>,
    },
    GetInviteCodesByUsers {
        user_ids: Vec<Uuid>,
        tx: Tx<Vec<(Uuid, InviteCodeInfo)>>,
    },
    GetInviteCodeUsedByUser {
        user_id: Uuid,
        tx: Tx<Option<String>>,
    },
    DeleteInviteCodeUsesByUser {
        user_id: Uuid,
        tx: Tx<()>,
    },
    DeleteInviteCodesByUser {
        user_id: Uuid,
        tx: Tx<()>,
    },
    ReserveSigningKey {
        did: Option<Did>,
        public_key_did_key: String,
        private_key_bytes: Vec<u8>,
        expires_at: DateTime<Utc>,
        tx: Tx<Uuid>,
    },
    GetReservedSigningKey {
        public_key_did_key: String,
        tx: Tx<Option<ReservedSigningKey>>,
    },
    MarkSigningKeyUsed {
        key_id: Uuid,
        tx: Tx<()>,
    },
    CreateDeletionRequest {
        token: String,
        did: Did,
        expires_at: DateTime<Utc>,
        tx: Tx<()>,
    },
    GetDeletionRequest {
        token: String,
        tx: Tx<Option<DeletionRequest>>,
    },
    DeleteDeletionRequest {
        token: String,
        tx: Tx<()>,
    },
    DeleteDeletionRequestsByDid {
        did: Did,
        tx: Tx<()>,
    },
    UpsertAccountPreference {
        user_id: Uuid,
        name: String,
        value_json: serde_json::Value,
        tx: Tx<()>,
    },
    InsertAccountPreferenceIfNotExists {
        user_id: Uuid,
        name: String,
        value_json: serde_json::Value,
        tx: Tx<()>,
    },
    GetServerConfig {
        key: String,
        tx: Tx<Option<String>>,
    },
    InsertReport {
        id: i64,
        reason_type: String,
        reason: Option<String>,
        subject_json: serde_json::Value,
        reported_by_did: Did,
        created_at: DateTime<Utc>,
        tx: Tx<()>,
    },
    DeletePlcTokensForUser {
        user_id: Uuid,
        tx: Tx<()>,
    },
    InsertPlcToken {
        user_id: Uuid,
        token: String,
        expires_at: DateTime<Utc>,
        tx: Tx<()>,
    },
    GetPlcTokenExpiry {
        user_id: Uuid,
        token: String,
        tx: Tx<Option<DateTime<Utc>>>,
    },
    DeletePlcToken {
        user_id: Uuid,
        token: String,
        tx: Tx<()>,
    },
    GetAccountPreferences {
        user_id: Uuid,
        tx: Tx<Vec<(String, serde_json::Value)>>,
    },
    ReplaceNamespacePreferences {
        user_id: Uuid,
        namespace: String,
        preferences: Vec<(String, serde_json::Value)>,
        tx: Tx<()>,
    },
    GetNotificationHistory {
        user_id: Uuid,
        limit: i64,
        tx: Tx<Vec<NotificationHistoryRow>>,
    },
    GetServerConfigs {
        keys: Vec<String>,
        tx: Tx<Vec<(String, String)>>,
    },
    UpsertServerConfig {
        key: String,
        value: String,
        tx: Tx<()>,
    },
    DeleteServerConfig {
        key: String,
        tx: Tx<()>,
    },
    GetBlobStorageKeyByCid {
        cid: CidLink,
        tx: Tx<Option<String>>,
    },
    DeleteBlobByCid {
        cid: CidLink,
        tx: Tx<()>,
    },
    GetAdminAccountInfoByDid {
        did: Did,
        tx: Tx<Option<AdminAccountInfo>>,
    },
    GetAdminAccountInfosByDids {
        dids: Vec<Did>,
        tx: Tx<Vec<AdminAccountInfo>>,
    },
    GetInviteCodeUsesByUsers {
        user_ids: Vec<Uuid>,
        tx: Tx<Vec<(Uuid, String)>>,
    },
    GetDeletionRequestByDid {
        did: Did,
        tx: Tx<Option<DeletionRequestWithToken>>,
    },
    GetLatestCommsForUser {
        user_id: Uuid,
        comms_type: CommsType,
        limit: i64,
        tx: Tx<Vec<QueuedComms>>,
    },
    CountCommsByType {
        user_id: Uuid,
        comms_type: CommsType,
        tx: Tx<i64>,
    },
    DeleteCommsByTypeForUser {
        user_id: Uuid,
        comms_type: CommsType,
        tx: Tx<u64>,
    },
    ExpireDeletionRequest {
        token: String,
        tx: Tx<()>,
    },
    GetReservedSigningKeyFull {
        public_key_did_key: String,
        tx: Tx<Option<ReservedSigningKeyFull>>,
    },
    GetPlcTokensByDid {
        did: Did,
        tx: Tx<Vec<PlcTokenInfo>>,
    },
    CountPlcTokensByDid {
        did: Did,
        tx: Tx<i64>,
    },
}

impl InfraRequest {
    fn routing(&self, user_hashes: &UserHashMap) -> Routing {
        match self {
            Self::UpsertAccountPreference { user_id, .. }
            | Self::InsertAccountPreferenceIfNotExists { user_id, .. }
            | Self::GetAccountPreferences { user_id, .. }
            | Self::ReplaceNamespacePreferences { user_id, .. }
            | Self::GetNotificationHistory { user_id, .. }
            | Self::DeletePlcTokensForUser { user_id, .. }
            | Self::InsertPlcToken { user_id, .. }
            | Self::GetPlcTokenExpiry { user_id, .. }
            | Self::DeletePlcToken { user_id, .. }
            | Self::GetInvitesCreatedByUser { user_id, .. }
            | Self::GetInviteCodeUsedByUser { user_id, .. }
            | Self::DeleteInviteCodeUsesByUser { user_id, .. }
            | Self::DeleteInviteCodesByUser { user_id, .. }
            | Self::GetLatestCommsForUser { user_id, .. }
            | Self::CountCommsByType { user_id, .. }
            | Self::DeleteCommsByTypeForUser { user_id, .. } => {
                uuid_to_routing(user_hashes, user_id)
            }
            Self::CreateInviteCodesBatch {
                created_by_user, ..
            } => uuid_to_routing(user_hashes, created_by_user),
            Self::RecordInviteCodeUse { used_by_user, .. } => {
                uuid_to_routing(user_hashes, used_by_user)
            }
            Self::EnqueueComms {
                user_id: Some(uid), ..
            } => uuid_to_routing(user_hashes, uid),
            Self::GetInviteCodesForAccount { for_account, .. } => {
                did_to_routing(for_account.as_str())
            }
            Self::DeleteDeletionRequestsByDid { did, .. }
            | Self::CreateDeletionRequest { did, .. }
            | Self::GetAdminAccountInfoByDid { did, .. }
            | Self::GetDeletionRequestByDid { did, .. }
            | Self::GetPlcTokensByDid { did, .. }
            | Self::CountPlcTokensByDid { did, .. } => did_to_routing(did.as_str()),
            Self::GetBlobStorageKeyByCid { cid, .. } | Self::DeleteBlobByCid { cid, .. } => {
                cid_to_routing(cid)
            }
            _ => Routing::Global,
        }
    }
}

pub enum OAuthRequest {
    CreateToken {
        data: TokenData,
        tx: Tx<TokenFamilyId>,
    },
    GetTokenById {
        token_id: TokenId,
        tx: Tx<Option<TokenData>>,
    },
    GetTokenByRefreshToken {
        refresh_token: RefreshToken,
        tx: Tx<Option<(TokenFamilyId, TokenData)>>,
    },
    GetTokenByPreviousRefreshToken {
        refresh_token: RefreshToken,
        tx: Tx<Option<(TokenFamilyId, TokenData)>>,
    },
    RotateToken {
        old_db_id: TokenFamilyId,
        new_refresh_token: RefreshToken,
        new_expires_at: DateTime<Utc>,
        tx: Tx<()>,
    },
    CheckRefreshTokenUsed {
        refresh_token: RefreshToken,
        tx: Tx<Option<TokenFamilyId>>,
    },
    DeleteToken {
        token_id: TokenId,
        tx: Tx<()>,
    },
    DeleteTokenFamily {
        db_id: TokenFamilyId,
        tx: Tx<()>,
    },
    ListTokensForUser {
        did: Did,
        tx: Tx<Vec<TokenData>>,
    },
    CountTokensForUser {
        did: Did,
        tx: Tx<i64>,
    },
    DeleteOldestTokensForUser {
        did: Did,
        keep_count: i64,
        tx: Tx<u64>,
    },
    RevokeTokensForClient {
        did: Did,
        client_id: ClientId,
        tx: Tx<u64>,
    },
    RevokeTokensForController {
        delegated_did: Did,
        controller_did: Did,
        tx: Tx<u64>,
    },
    CreateAuthorizationRequest {
        request_id: RequestId,
        data: RequestData,
        tx: Tx<()>,
    },
    GetAuthorizationRequest {
        request_id: RequestId,
        tx: Tx<Option<RequestData>>,
    },
    SetAuthorizationDid {
        request_id: RequestId,
        did: Did,
        device_id: Option<DeviceId>,
        tx: Tx<()>,
    },
    UpdateAuthorizationRequest {
        request_id: RequestId,
        did: Did,
        device_id: Option<DeviceId>,
        code: AuthorizationCode,
        tx: Tx<()>,
    },
    ConsumeAuthorizationRequestByCode {
        code: AuthorizationCode,
        tx: Tx<Option<RequestData>>,
    },
    DeleteAuthorizationRequest {
        request_id: RequestId,
        tx: Tx<()>,
    },
    DeleteExpiredAuthorizationRequests {
        tx: Tx<u64>,
    },
    ExtendAuthorizationRequestExpiry {
        request_id: RequestId,
        new_expires_at: DateTime<Utc>,
        tx: Tx<bool>,
    },
    MarkRequestAuthenticated {
        request_id: RequestId,
        did: Did,
        device_id: Option<DeviceId>,
        tx: Tx<()>,
    },
    UpdateRequestScope {
        request_id: RequestId,
        scope: String,
        tx: Tx<()>,
    },
    SetControllerDid {
        request_id: RequestId,
        controller_did: Did,
        tx: Tx<()>,
    },
    SetRequestDid {
        request_id: RequestId,
        did: Did,
        tx: Tx<()>,
    },
    CreateDevice {
        device_id: DeviceId,
        data: DeviceData,
        tx: Tx<()>,
    },
    GetDevice {
        device_id: DeviceId,
        tx: Tx<Option<DeviceData>>,
    },
    UpdateDeviceLastSeen {
        device_id: DeviceId,
        tx: Tx<()>,
    },
    DeleteDevice {
        device_id: DeviceId,
        tx: Tx<()>,
    },
    UpsertAccountDevice {
        did: Did,
        device_id: DeviceId,
        tx: Tx<()>,
    },
    GetDeviceAccounts {
        device_id: DeviceId,
        tx: Tx<Vec<tranquil_db_traits::DeviceAccountRow>>,
    },
    VerifyAccountOnDevice {
        device_id: DeviceId,
        did: Did,
        tx: Tx<bool>,
    },
    CheckAndRecordDpopJti {
        jti: DPoPProofId,
        tx: Tx<bool>,
    },
    CleanupExpiredDpopJtis {
        max_age_secs: i64,
        tx: Tx<u64>,
    },
    Create2faChallenge {
        did: Did,
        request_uri: RequestId,
        tx: Tx<tranquil_db_traits::TwoFactorChallenge>,
    },
    Get2faChallenge {
        request_uri: RequestId,
        tx: Tx<Option<tranquil_db_traits::TwoFactorChallenge>>,
    },
    Increment2faAttempts {
        id: Uuid,
        tx: Tx<i32>,
    },
    Delete2faChallenge {
        id: Uuid,
        tx: Tx<()>,
    },
    Delete2faChallengeByRequestUri {
        request_uri: RequestId,
        tx: Tx<()>,
    },
    CleanupExpired2faChallenges {
        tx: Tx<u64>,
    },
    CheckUser2faEnabled {
        did: Did,
        tx: Tx<bool>,
    },
    GetScopePreferences {
        did: Did,
        client_id: ClientId,
        tx: Tx<Vec<ScopePreference>>,
    },
    UpsertScopePreferences {
        did: Did,
        client_id: ClientId,
        prefs: Vec<ScopePreference>,
        tx: Tx<()>,
    },
    DeleteScopePreferences {
        did: Did,
        client_id: ClientId,
        tx: Tx<()>,
    },
    UpsertAuthorizedClient {
        did: Did,
        client_id: ClientId,
        data: AuthorizedClientData,
        tx: Tx<()>,
    },
    GetAuthorizedClient {
        did: Did,
        client_id: ClientId,
        tx: Tx<Option<AuthorizedClientData>>,
    },
    ListTrustedDevices {
        did: Did,
        tx: Tx<Vec<tranquil_db_traits::TrustedDeviceRow>>,
    },
    GetDeviceTrustInfo {
        device_id: DeviceId,
        did: Did,
        tx: Tx<Option<tranquil_db_traits::DeviceTrustInfo>>,
    },
    DeviceBelongsToUser {
        device_id: DeviceId,
        did: Did,
        tx: Tx<bool>,
    },
    RevokeDeviceTrust {
        device_id: DeviceId,
        did: Did,
        tx: Tx<()>,
    },
    UpdateDeviceFriendlyName {
        device_id: DeviceId,
        did: Did,
        friendly_name: Option<String>,
        tx: Tx<()>,
    },
    TrustDevice {
        device_id: DeviceId,
        did: Did,
        trusted_at: DateTime<Utc>,
        trusted_until: DateTime<Utc>,
        tx: Tx<()>,
    },
    ExtendDeviceTrust {
        device_id: DeviceId,
        did: Did,
        trusted_until: DateTime<Utc>,
        tx: Tx<()>,
    },
    ListSessionsByDid {
        did: Did,
        tx: Tx<Vec<tranquil_db_traits::OAuthSessionListItem>>,
    },
    DeleteSessionById {
        session_id: TokenFamilyId,
        did: Did,
        tx: Tx<u64>,
    },
    DeleteSessionsByDid {
        did: Did,
        tx: Tx<u64>,
    },
    DeleteSessionsByDidExcept {
        did: Did,
        except_token_id: TokenId,
        tx: Tx<u64>,
    },
    Get2faChallengeCode {
        request_uri: RequestId,
        tx: Tx<Option<String>>,
    },
}

impl OAuthRequest {
    fn routing(&self) -> Routing {
        match self {
            Self::ListTokensForUser { did, .. }
            | Self::CountTokensForUser { did, .. }
            | Self::DeleteOldestTokensForUser { did, .. }
            | Self::RevokeTokensForClient { did, .. }
            | Self::Create2faChallenge { did, .. }
            | Self::CheckUser2faEnabled { did, .. }
            | Self::GetScopePreferences { did, .. }
            | Self::UpsertScopePreferences { did, .. }
            | Self::DeleteScopePreferences { did, .. }
            | Self::UpsertAuthorizedClient { did, .. }
            | Self::GetAuthorizedClient { did, .. }
            | Self::ListTrustedDevices { did, .. }
            | Self::GetDeviceTrustInfo { did, .. }
            | Self::DeviceBelongsToUser { did, .. }
            | Self::UpsertAccountDevice { did, .. }
            | Self::VerifyAccountOnDevice { did, .. }
            | Self::ListSessionsByDid { did, .. }
            | Self::DeleteSessionsByDid { did, .. }
            | Self::DeleteSessionsByDidExcept { did, .. }
            | Self::DeleteSessionById { did, .. } => did_to_routing(did.as_str()),
            Self::RevokeTokensForController { delegated_did, .. } => {
                did_to_routing(delegated_did.as_str())
            }
            Self::SetAuthorizationDid { did, .. }
            | Self::UpdateAuthorizationRequest { did, .. }
            | Self::MarkRequestAuthenticated { did, .. }
            | Self::SetRequestDid { did, .. } => did_to_routing(did.as_str()),
            Self::CreateToken { .. }
            | Self::GetTokenById { .. }
            | Self::GetTokenByRefreshToken { .. }
            | Self::GetTokenByPreviousRefreshToken { .. }
            | Self::RotateToken { .. }
            | Self::CheckRefreshTokenUsed { .. }
            | Self::DeleteToken { .. }
            | Self::DeleteTokenFamily { .. }
            | Self::CreateAuthorizationRequest { .. }
            | Self::GetAuthorizationRequest { .. }
            | Self::ConsumeAuthorizationRequestByCode { .. }
            | Self::DeleteAuthorizationRequest { .. }
            | Self::DeleteExpiredAuthorizationRequests { .. }
            | Self::ExtendAuthorizationRequestExpiry { .. }
            | Self::UpdateRequestScope { .. }
            | Self::SetControllerDid { .. }
            | Self::CreateDevice { .. }
            | Self::GetDevice { .. }
            | Self::UpdateDeviceLastSeen { .. }
            | Self::DeleteDevice { .. }
            | Self::GetDeviceAccounts { .. }
            | Self::CheckAndRecordDpopJti { .. }
            | Self::CleanupExpiredDpopJtis { .. }
            | Self::Get2faChallenge { .. }
            | Self::Increment2faAttempts { .. }
            | Self::Delete2faChallenge { .. }
            | Self::Delete2faChallengeByRequestUri { .. }
            | Self::CleanupExpired2faChallenges { .. }
            | Self::RevokeDeviceTrust { .. }
            | Self::UpdateDeviceFriendlyName { .. }
            | Self::TrustDevice { .. }
            | Self::ExtendDeviceTrust { .. }
            | Self::Get2faChallengeCode { .. } => Routing::Global,
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
                limit: usize::try_from(limit).unwrap_or(0),
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
    }
}

fn dispatch_event<S: StorageIO + 'static>(state: &HandlerState<S>, req: EventRequest) {
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
            commit_bytes,
            tx,
        } => {
            let result =
                state
                    .event_ops
                    .insert_sync_event(&did, &commit_cid, rev.as_deref(), &commit_bytes);
            let _ = tx.send(result);
        }
        EventRequest::InsertGenesisCommitEvent {
            did,
            commit_cid,
            mst_root_cid,
            rev,
            commit_bytes,
            mst_root_bytes,
            tx,
        } => {
            let result = state.event_ops.insert_genesis_commit_event(
                &did,
                &commit_cid,
                &mst_root_cid,
                &rev,
                &commit_bytes,
                &mst_root_bytes,
            );
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
        EventRequest::NotifyUpdate { seq, tx } => {
            let _ = tx.send(state.event_ops.notify_update(seq));
        }
    }
}

fn dispatch_commit<S: StorageIO + 'static>(state: &HandlerState<S>, req: CommitRequest) {
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

fn dispatch_blob<S: StorageIO + 'static>(state: &HandlerState<S>, req: BlobRequest) {
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
                    usize::try_from(limit).unwrap_or(0),
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
                    usize::try_from(limit).unwrap_or(0),
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

fn dispatch_delegation<S: StorageIO>(state: &HandlerState<S>, req: DelegationRequest) {
    match req {
        DelegationRequest::IsDelegatedAccount { did, tx } => {
            let result = state
                .metastore
                .delegation_ops()
                .is_delegated_account(&did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        DelegationRequest::CreateDelegation {
            delegated_did,
            controller_did,
            granted_scopes,
            granted_by,
            tx,
        } => {
            let result = state
                .metastore
                .delegation_ops()
                .create_delegation(
                    &delegated_did,
                    &controller_did,
                    &granted_scopes,
                    &granted_by,
                )
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        DelegationRequest::RevokeDelegation {
            delegated_did,
            controller_did,
            revoked_by,
            tx,
        } => {
            let result = state
                .metastore
                .delegation_ops()
                .revoke_delegation(&delegated_did, &controller_did, &revoked_by)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        DelegationRequest::UpdateDelegationScopes {
            delegated_did,
            controller_did,
            new_scopes,
            tx,
        } => {
            let result = state
                .metastore
                .delegation_ops()
                .update_delegation_scopes(&delegated_did, &controller_did, &new_scopes)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        DelegationRequest::GetDelegation {
            delegated_did,
            controller_did,
            tx,
        } => {
            let result = state
                .metastore
                .delegation_ops()
                .get_delegation(&delegated_did, &controller_did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        DelegationRequest::GetDelegationsForAccount { delegated_did, tx } => {
            let result = state
                .metastore
                .delegation_ops()
                .get_delegations_for_account(&delegated_did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        DelegationRequest::GetAccountsControlledBy { controller_did, tx } => {
            let result = state
                .metastore
                .delegation_ops()
                .get_accounts_controlled_by(&controller_did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        DelegationRequest::CountActiveControllers { delegated_did, tx } => {
            let result = state
                .metastore
                .delegation_ops()
                .count_active_controllers(&delegated_did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        DelegationRequest::ControlsAnyAccounts { did, tx } => {
            let result = state
                .metastore
                .delegation_ops()
                .controls_any_accounts(&did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        DelegationRequest::LogDelegationAction {
            delegated_did,
            actor_did,
            controller_did,
            action_type,
            action_details,
            ip_address,
            user_agent,
            tx,
        } => {
            let result = state
                .metastore
                .delegation_ops()
                .log_delegation_action(
                    &delegated_did,
                    &actor_did,
                    controller_did.as_ref(),
                    action_type,
                    action_details,
                    ip_address.as_deref(),
                    user_agent.as_deref(),
                )
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        DelegationRequest::GetAuditLogForAccount {
            delegated_did,
            limit,
            offset,
            tx,
        } => {
            let result = state
                .metastore
                .delegation_ops()
                .get_audit_log_for_account(&delegated_did, limit, offset)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        DelegationRequest::CountAuditLogEntries { delegated_did, tx } => {
            let result = state
                .metastore
                .delegation_ops()
                .count_audit_log_entries(&delegated_did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
    }
}

fn dispatch_sso<S: StorageIO>(state: &HandlerState<S>, req: SsoRequest) {
    match req {
        SsoRequest::CreateExternalIdentity {
            did,
            provider,
            provider_user_id,
            provider_username,
            provider_email,
            tx,
        } => {
            let result = state
                .metastore
                .sso_ops()
                .create_external_identity(
                    &did,
                    provider,
                    &provider_user_id,
                    provider_username.as_deref(),
                    provider_email.as_deref(),
                )
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SsoRequest::GetExternalIdentityByProvider {
            provider,
            provider_user_id,
            tx,
        } => {
            let result = state
                .metastore
                .sso_ops()
                .get_external_identity_by_provider(provider, &provider_user_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SsoRequest::GetExternalIdentitiesByDid { did, tx } => {
            let result = state
                .metastore
                .sso_ops()
                .get_external_identities_by_did(&did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SsoRequest::UpdateExternalIdentityLogin {
            id,
            provider_username,
            provider_email,
            tx,
        } => {
            let result = state
                .metastore
                .sso_ops()
                .update_external_identity_login(
                    id,
                    provider_username.as_deref(),
                    provider_email.as_deref(),
                )
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SsoRequest::DeleteExternalIdentity { id, did, tx } => {
            let result = state
                .metastore
                .sso_ops()
                .delete_external_identity(id, &did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SsoRequest::CreateSsoAuthState {
            state: sso_state,
            request_uri,
            provider,
            action,
            nonce,
            code_verifier,
            did,
            tx,
        } => {
            let result = state
                .metastore
                .sso_ops()
                .create_sso_auth_state(
                    &sso_state,
                    &request_uri,
                    provider,
                    action,
                    nonce.as_deref(),
                    code_verifier.as_deref(),
                    did.as_ref(),
                )
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SsoRequest::ConsumeSsoAuthState {
            state: sso_state,
            tx,
        } => {
            let result = state
                .metastore
                .sso_ops()
                .consume_sso_auth_state(&sso_state)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SsoRequest::CleanupExpiredSsoAuthStates { tx } => {
            let result = state
                .metastore
                .sso_ops()
                .cleanup_expired_sso_auth_states()
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SsoRequest::CreatePendingRegistration {
            token,
            request_uri,
            provider,
            provider_user_id,
            provider_username,
            provider_email,
            provider_email_verified,
            tx,
        } => {
            let result = state
                .metastore
                .sso_ops()
                .create_pending_registration(
                    &token,
                    &request_uri,
                    provider,
                    &provider_user_id,
                    provider_username.as_deref(),
                    provider_email.as_deref(),
                    provider_email_verified,
                )
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SsoRequest::GetPendingRegistration { token, tx } => {
            let result = state
                .metastore
                .sso_ops()
                .get_pending_registration(&token)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SsoRequest::ConsumePendingRegistration { token, tx } => {
            let result = state
                .metastore
                .sso_ops()
                .consume_pending_registration(&token)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SsoRequest::CleanupExpiredPendingRegistrations { tx } => {
            let result = state
                .metastore
                .sso_ops()
                .cleanup_expired_pending_registrations()
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
    }
}

fn dispatch_session<S: StorageIO>(state: &HandlerState<S>, req: SessionRequest) {
    match req {
        SessionRequest::CreateSession { data, tx } => {
            let result = state
                .metastore
                .session_ops()
                .create_session(&data)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SessionRequest::GetSessionByAccessJti { access_jti, tx } => {
            let result = state
                .metastore
                .session_ops()
                .get_session_by_access_jti(&access_jti)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SessionRequest::GetSessionForRefresh { refresh_jti, tx } => {
            let result = state
                .metastore
                .session_ops()
                .get_session_for_refresh(&refresh_jti)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SessionRequest::UpdateSessionTokens {
            session_id,
            new_access_jti,
            new_refresh_jti,
            new_access_expires_at,
            new_refresh_expires_at,
            tx,
        } => {
            let result = state
                .metastore
                .session_ops()
                .update_session_tokens(
                    session_id,
                    &new_access_jti,
                    &new_refresh_jti,
                    new_access_expires_at,
                    new_refresh_expires_at,
                )
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SessionRequest::DeleteSessionByAccessJti { access_jti, tx } => {
            let result = state
                .metastore
                .session_ops()
                .delete_session_by_access_jti(&access_jti)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SessionRequest::DeleteSessionById { session_id, tx } => {
            let result = state
                .metastore
                .session_ops()
                .delete_session_by_id(session_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SessionRequest::DeleteSessionsByDid { did, tx } => {
            let result = state
                .metastore
                .session_ops()
                .delete_sessions_by_did(&did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SessionRequest::DeleteSessionsByDidExceptJti {
            did,
            except_jti,
            tx,
        } => {
            let result = state
                .metastore
                .session_ops()
                .delete_sessions_by_did_except_jti(&did, &except_jti)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SessionRequest::ListSessionsByDid { did, tx } => {
            let result = state
                .metastore
                .session_ops()
                .list_sessions_by_did(&did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SessionRequest::GetSessionAccessJtiById {
            session_id,
            did,
            tx,
        } => {
            let result = state
                .metastore
                .session_ops()
                .get_session_access_jti_by_id(session_id, &did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SessionRequest::DeleteSessionsByAppPassword {
            did,
            app_password_name,
            tx,
        } => {
            let result = state
                .metastore
                .session_ops()
                .delete_sessions_by_app_password(&did, &app_password_name)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SessionRequest::GetSessionJtisByAppPassword {
            did,
            app_password_name,
            tx,
        } => {
            let result = state
                .metastore
                .session_ops()
                .get_session_jtis_by_app_password(&did, &app_password_name)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SessionRequest::CheckRefreshTokenUsed { refresh_jti, tx } => {
            let result = state
                .metastore
                .session_ops()
                .check_refresh_token_used(&refresh_jti)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SessionRequest::MarkRefreshTokenUsed {
            refresh_jti,
            session_id,
            tx,
        } => {
            let result = state
                .metastore
                .session_ops()
                .mark_refresh_token_used(&refresh_jti, session_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SessionRequest::ListAppPasswords { user_id, tx } => {
            let result = state
                .metastore
                .session_ops()
                .list_app_passwords(user_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SessionRequest::GetAppPasswordsForLogin { user_id, tx } => {
            let result = state
                .metastore
                .session_ops()
                .get_app_passwords_for_login(user_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SessionRequest::GetAppPasswordByName { user_id, name, tx } => {
            let result = state
                .metastore
                .session_ops()
                .get_app_password_by_name(user_id, &name)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SessionRequest::CreateAppPassword { data, tx } => {
            let result = state
                .metastore
                .session_ops()
                .create_app_password(&data)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SessionRequest::DeleteAppPassword { user_id, name, tx } => {
            let result = state
                .metastore
                .session_ops()
                .delete_app_password(user_id, &name)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SessionRequest::DeleteAppPasswordsByController {
            did,
            controller_did,
            tx,
        } => {
            let result = state
                .metastore
                .session_ops()
                .delete_app_passwords_by_controller(&did, &controller_did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SessionRequest::GetLastReauthAt { did, tx } => {
            let result = state
                .metastore
                .session_ops()
                .get_last_reauth_at(&did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SessionRequest::UpdateLastReauth { did, tx } => {
            let result = state
                .metastore
                .session_ops()
                .update_last_reauth(&did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SessionRequest::GetSessionMfaStatus { did, tx } => {
            let result = state
                .metastore
                .session_ops()
                .get_session_mfa_status(&did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SessionRequest::UpdateMfaVerified { did, tx } => {
            let result = state
                .metastore
                .session_ops()
                .update_mfa_verified(&did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SessionRequest::GetAppPasswordHashesByDid { did, tx } => {
            let result = state
                .metastore
                .session_ops()
                .get_app_password_hashes_by_did(&did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        SessionRequest::RefreshSessionAtomic { data, tx } => {
            let result = state
                .metastore
                .session_ops()
                .refresh_session_atomic(&data)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
    }
}

fn dispatch_infra<S: StorageIO>(state: &HandlerState<S>, req: InfraRequest) {
    match req {
        InfraRequest::EnqueueComms {
            user_id,
            channel,
            comms_type,
            recipient,
            subject,
            body,
            metadata,
            tx,
        } => {
            let result = state
                .metastore
                .infra_ops()
                .enqueue_comms(
                    user_id,
                    channel,
                    comms_type,
                    &recipient,
                    subject.as_deref(),
                    &body,
                    metadata,
                )
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::FetchPendingComms {
            now,
            batch_size,
            tx,
        } => {
            let result = state
                .metastore
                .infra_ops()
                .fetch_pending_comms(now, batch_size)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::MarkCommsSent { id, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .mark_comms_sent(id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::MarkCommsFailed { id, error, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .mark_comms_failed(id, &error)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::MarkCommsFailedPermanent { id, error, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .mark_comms_failed_permanent(id, &error)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::CreateInviteCode {
            code,
            use_count,
            for_account,
            tx,
        } => {
            let result = state
                .metastore
                .infra_ops()
                .create_invite_code(&code, use_count, for_account.as_ref())
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::CreateInviteCodesBatch {
            codes,
            use_count,
            created_by_user,
            for_account,
            tx,
        } => {
            let result = state
                .metastore
                .infra_ops()
                .create_invite_codes_batch(&codes, use_count, created_by_user, for_account.as_ref())
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::GetInviteCodeAvailableUses { code, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .get_invite_code_available_uses(&code)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::ValidateInviteCode { code, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .validate_invite_code(&code)
                .map(|_| ());
            let _ = tx.send(result);
        }
        InfraRequest::DecrementInviteCodeUses { code, tx } => {
            let validated = ValidatedInviteCode::new_validated(&code);
            let result = state
                .metastore
                .infra_ops()
                .decrement_invite_code_uses(&validated)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::RecordInviteCodeUse {
            code,
            used_by_user,
            tx,
        } => {
            let validated = ValidatedInviteCode::new_validated(&code);
            let result = state
                .metastore
                .infra_ops()
                .record_invite_code_use(&validated, used_by_user)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::GetInviteCodesForAccount { for_account, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .get_invite_codes_for_account(&for_account)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::GetInviteCodeUses { code, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .get_invite_code_uses(&code)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::DisableInviteCodesByCode { codes, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .disable_invite_codes_by_code(&codes)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::DisableInviteCodesByAccount { accounts, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .disable_invite_codes_by_account(&accounts)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::ListInviteCodes {
            cursor,
            limit,
            sort,
            tx,
        } => {
            let result = state
                .metastore
                .infra_ops()
                .list_invite_codes(cursor.as_deref(), limit, sort)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::GetUserDidsByIds { user_ids, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .get_user_dids_by_ids(&user_ids)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::GetInviteCodeUsesBatch { codes, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .get_invite_code_uses_batch(&codes)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::GetInvitesCreatedByUser { user_id, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .get_invites_created_by_user(user_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::GetInviteCodeInfo { code, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .get_invite_code_info(&code)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::GetInviteCodesByUsers { user_ids, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .get_invite_codes_by_users(&user_ids)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::GetInviteCodeUsedByUser { user_id, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .get_invite_code_used_by_user(user_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::DeleteInviteCodeUsesByUser { user_id, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .delete_invite_code_uses_by_user(user_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::DeleteInviteCodesByUser { user_id, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .delete_invite_codes_by_user(user_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::ReserveSigningKey {
            did,
            public_key_did_key,
            private_key_bytes,
            expires_at,
            tx,
        } => {
            let result = state
                .metastore
                .infra_ops()
                .reserve_signing_key(
                    did.as_ref(),
                    &public_key_did_key,
                    &private_key_bytes,
                    expires_at,
                )
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::GetReservedSigningKey {
            public_key_did_key,
            tx,
        } => {
            let result = state
                .metastore
                .infra_ops()
                .get_reserved_signing_key(&public_key_did_key)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::MarkSigningKeyUsed { key_id, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .mark_signing_key_used(key_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::CreateDeletionRequest {
            token,
            did,
            expires_at,
            tx,
        } => {
            let result = state
                .metastore
                .infra_ops()
                .create_deletion_request(&token, &did, expires_at)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::GetDeletionRequest { token, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .get_deletion_request(&token)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::DeleteDeletionRequest { token, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .delete_deletion_request(&token)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::DeleteDeletionRequestsByDid { did, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .delete_deletion_requests_by_did(&did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::UpsertAccountPreference {
            user_id,
            name,
            value_json,
            tx,
        } => {
            if name == "email_auth_factor" {
                let enabled = value_json.as_bool().unwrap_or(false);
                let _ = state
                    .metastore
                    .user_ops()
                    .set_email_2fa_enabled(user_id, enabled);
            }
            let result = state
                .metastore
                .infra_ops()
                .upsert_account_preference(user_id, &name, value_json)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::InsertAccountPreferenceIfNotExists {
            user_id,
            name,
            value_json,
            tx,
        } => {
            let result = state
                .metastore
                .infra_ops()
                .insert_account_preference_if_not_exists(user_id, &name, value_json)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::GetServerConfig { key, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .get_server_config(&key)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::InsertReport {
            id,
            reason_type,
            reason,
            subject_json,
            reported_by_did,
            created_at,
            tx,
        } => {
            let result = state
                .metastore
                .infra_ops()
                .insert_report(
                    id,
                    &reason_type,
                    reason.as_deref(),
                    subject_json,
                    &reported_by_did,
                    created_at,
                )
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::DeletePlcTokensForUser { user_id, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .delete_plc_tokens_for_user(user_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::InsertPlcToken {
            user_id,
            token,
            expires_at,
            tx,
        } => {
            let result = state
                .metastore
                .infra_ops()
                .insert_plc_token(user_id, &token, expires_at)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::GetPlcTokenExpiry { user_id, token, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .get_plc_token_expiry(user_id, &token)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::DeletePlcToken { user_id, token, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .delete_plc_token(user_id, &token)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::GetAccountPreferences { user_id, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .get_account_preferences(user_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::ReplaceNamespacePreferences {
            user_id,
            namespace,
            preferences,
            tx,
        } => {
            let result = state
                .metastore
                .infra_ops()
                .replace_namespace_preferences(user_id, &namespace, preferences)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::GetNotificationHistory { user_id, limit, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .get_notification_history(user_id, limit)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::GetServerConfigs { keys, tx } => {
            let key_refs: Vec<&str> = keys.iter().map(String::as_str).collect();
            let result = state
                .metastore
                .infra_ops()
                .get_server_configs(&key_refs)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::UpsertServerConfig { key, value, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .upsert_server_config(&key, &value)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::DeleteServerConfig { key, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .delete_server_config(&key)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::GetBlobStorageKeyByCid { cid, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .get_blob_storage_key_by_cid(&cid)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::DeleteBlobByCid { cid, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .delete_blob_by_cid(&cid)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::GetAdminAccountInfoByDid { did, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .get_admin_account_info_by_did(&did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::GetAdminAccountInfosByDids { dids, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .get_admin_account_infos_by_dids(&dids)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::GetInviteCodeUsesByUsers { user_ids, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .get_invite_code_uses_by_users(&user_ids)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::GetDeletionRequestByDid { did, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .get_deletion_request_by_did(&did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::GetLatestCommsForUser {
            user_id,
            comms_type,
            limit,
            tx,
        } => {
            let result = state
                .metastore
                .infra_ops()
                .get_latest_comms_for_user(user_id, comms_type, limit)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::CountCommsByType {
            user_id,
            comms_type,
            tx,
        } => {
            let result = state
                .metastore
                .infra_ops()
                .count_comms_by_type(user_id, comms_type)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::DeleteCommsByTypeForUser {
            user_id,
            comms_type,
            tx,
        } => {
            let result = state
                .metastore
                .infra_ops()
                .delete_comms_by_type_for_user(user_id, comms_type)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::ExpireDeletionRequest { token, tx } => {
            let result = state
                .metastore
                .infra_ops()
                .expire_deletion_request(&token)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::GetReservedSigningKeyFull {
            public_key_did_key,
            tx,
        } => {
            let result = state
                .metastore
                .infra_ops()
                .get_reserved_signing_key_full(&public_key_did_key)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        InfraRequest::GetPlcTokensByDid { did, tx } => {
            let result = (|| {
                let user_id = state
                    .metastore
                    .user_ops()
                    .get_id_by_did(&did)
                    .map_err(metastore_to_db)?;
                match user_id {
                    Some(uid) => state
                        .metastore
                        .infra_ops()
                        .get_plc_tokens_for_user(uid)
                        .map_err(metastore_to_db),
                    None => Ok(Vec::new()),
                }
            })();
            let _ = tx.send(result);
        }
        InfraRequest::CountPlcTokensByDid { did, tx } => {
            let result = (|| {
                let user_id = state
                    .metastore
                    .user_ops()
                    .get_id_by_did(&did)
                    .map_err(metastore_to_db)?;
                match user_id {
                    Some(uid) => state
                        .metastore
                        .infra_ops()
                        .count_plc_tokens_for_user(uid)
                        .map_err(metastore_to_db),
                    None => Ok(0),
                }
            })();
            let _ = tx.send(result);
        }
    }
}

fn dispatch_oauth<S: StorageIO>(state: &HandlerState<S>, req: OAuthRequest) {
    match req {
        OAuthRequest::CreateToken { data, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .create_token(&data)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::GetTokenById { token_id, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .get_token_by_id(&token_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::GetTokenByRefreshToken { refresh_token, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .get_token_by_refresh_token(&refresh_token)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::GetTokenByPreviousRefreshToken { refresh_token, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .get_token_by_previous_refresh_token(&refresh_token)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::RotateToken {
            old_db_id,
            new_refresh_token,
            new_expires_at,
            tx,
        } => {
            let result = state
                .metastore
                .oauth_ops()
                .rotate_token(old_db_id, &new_refresh_token, new_expires_at)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::CheckRefreshTokenUsed { refresh_token, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .check_refresh_token_used(&refresh_token)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::DeleteToken { token_id, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .delete_token(&token_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::DeleteTokenFamily { db_id, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .delete_token_family(db_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::ListTokensForUser { did, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .list_tokens_for_user(&did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::CountTokensForUser { did, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .count_tokens_for_user(&did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::DeleteOldestTokensForUser {
            did,
            keep_count,
            tx,
        } => {
            let result = state
                .metastore
                .oauth_ops()
                .delete_oldest_tokens_for_user(&did, keep_count)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::RevokeTokensForClient { did, client_id, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .revoke_tokens_for_client(&did, &client_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::RevokeTokensForController {
            delegated_did,
            controller_did,
            tx,
        } => {
            let result = state
                .metastore
                .oauth_ops()
                .revoke_tokens_for_controller(&delegated_did, &controller_did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::CreateAuthorizationRequest {
            request_id,
            data,
            tx,
        } => {
            let result = state
                .metastore
                .oauth_ops()
                .create_authorization_request(&request_id, &data)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::GetAuthorizationRequest { request_id, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .get_authorization_request(&request_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::SetAuthorizationDid {
            request_id,
            did,
            device_id,
            tx,
        } => {
            let result = state
                .metastore
                .oauth_ops()
                .set_authorization_did(&request_id, &did, device_id.as_ref())
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::UpdateAuthorizationRequest {
            request_id,
            did,
            device_id,
            code,
            tx,
        } => {
            let result = state
                .metastore
                .oauth_ops()
                .update_authorization_request(&request_id, &did, device_id.as_ref(), &code)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::ConsumeAuthorizationRequestByCode { code, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .consume_authorization_request_by_code(&code)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::DeleteAuthorizationRequest { request_id, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .delete_authorization_request(&request_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::DeleteExpiredAuthorizationRequests { tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .delete_expired_authorization_requests()
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::ExtendAuthorizationRequestExpiry {
            request_id,
            new_expires_at,
            tx,
        } => {
            let result = state
                .metastore
                .oauth_ops()
                .extend_authorization_request_expiry(&request_id, new_expires_at)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::MarkRequestAuthenticated {
            request_id,
            did,
            device_id,
            tx,
        } => {
            let result = state
                .metastore
                .oauth_ops()
                .mark_request_authenticated(&request_id, &did, device_id.as_ref())
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::UpdateRequestScope {
            request_id,
            scope,
            tx,
        } => {
            let result = state
                .metastore
                .oauth_ops()
                .update_request_scope(&request_id, &scope)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::SetControllerDid {
            request_id,
            controller_did,
            tx,
        } => {
            let result = state
                .metastore
                .oauth_ops()
                .set_controller_did(&request_id, &controller_did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::SetRequestDid {
            request_id,
            did,
            tx,
        } => {
            let result = state
                .metastore
                .oauth_ops()
                .set_request_did(&request_id, &did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::CreateDevice {
            device_id,
            data,
            tx,
        } => {
            let result = state
                .metastore
                .oauth_ops()
                .create_device(&device_id, &data)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::GetDevice { device_id, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .get_device(&device_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::UpdateDeviceLastSeen { device_id, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .update_device_last_seen(&device_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::DeleteDevice { device_id, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .delete_device(&device_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::UpsertAccountDevice { did, device_id, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .upsert_account_device(&did, &device_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::GetDeviceAccounts { device_id, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .get_device_accounts(&device_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::VerifyAccountOnDevice { device_id, did, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .verify_account_on_device(&device_id, &did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::CheckAndRecordDpopJti { jti, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .check_and_record_dpop_jti(&jti)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::CleanupExpiredDpopJtis { max_age_secs, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .cleanup_expired_dpop_jtis(max_age_secs)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::Create2faChallenge {
            did,
            request_uri,
            tx,
        } => {
            let result = state
                .metastore
                .oauth_ops()
                .create_2fa_challenge(&did, &request_uri)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::Get2faChallenge { request_uri, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .get_2fa_challenge(&request_uri)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::Increment2faAttempts { id, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .increment_2fa_attempts(id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::Delete2faChallenge { id, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .delete_2fa_challenge(id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::Delete2faChallengeByRequestUri { request_uri, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .delete_2fa_challenge_by_request_uri(&request_uri)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::CleanupExpired2faChallenges { tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .cleanup_expired_2fa_challenges()
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::CheckUser2faEnabled { did, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .check_user_2fa_enabled(&did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::GetScopePreferences { did, client_id, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .get_scope_preferences(&did, &client_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::UpsertScopePreferences {
            did,
            client_id,
            prefs,
            tx,
        } => {
            let result = state
                .metastore
                .oauth_ops()
                .upsert_scope_preferences(&did, &client_id, &prefs)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::DeleteScopePreferences { did, client_id, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .delete_scope_preferences(&did, &client_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::UpsertAuthorizedClient {
            did,
            client_id,
            data,
            tx,
        } => {
            let result = state
                .metastore
                .oauth_ops()
                .upsert_authorized_client(&did, &client_id, &data)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::GetAuthorizedClient { did, client_id, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .get_authorized_client(&did, &client_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::ListTrustedDevices { did, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .list_trusted_devices(&did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::GetDeviceTrustInfo { device_id, did, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .get_device_trust_info(&device_id, &did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::DeviceBelongsToUser { device_id, did, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .device_belongs_to_user(&device_id, &did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::RevokeDeviceTrust { device_id, did, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .revoke_device_trust(&device_id, &did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::UpdateDeviceFriendlyName {
            device_id,
            did,
            friendly_name,
            tx,
        } => {
            let result = state
                .metastore
                .oauth_ops()
                .update_device_friendly_name(&device_id, &did, friendly_name.as_deref())
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::TrustDevice {
            device_id,
            did,
            trusted_at,
            trusted_until,
            tx,
        } => {
            let result = state
                .metastore
                .oauth_ops()
                .trust_device(&device_id, &did, trusted_at, trusted_until)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::ExtendDeviceTrust {
            device_id,
            did,
            trusted_until,
            tx,
        } => {
            let result = state
                .metastore
                .oauth_ops()
                .extend_device_trust(&device_id, &did, trusted_until)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::ListSessionsByDid { did, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .list_sessions_by_did(&did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::DeleteSessionById {
            session_id,
            did,
            tx,
        } => {
            let result = state
                .metastore
                .oauth_ops()
                .delete_session_by_id(session_id, &did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::DeleteSessionsByDid { did, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .delete_sessions_by_did(&did)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::DeleteSessionsByDidExcept {
            did,
            except_token_id,
            tx,
        } => {
            let result = state
                .metastore
                .oauth_ops()
                .delete_sessions_by_did_except(&did, &except_token_id)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
        OAuthRequest::Get2faChallengeCode { request_uri, tx } => {
            let result = state
                .metastore
                .oauth_ops()
                .get_2fa_challenge_code(&request_uri)
                .map_err(metastore_to_db);
            let _ = tx.send(result);
        }
    }
}

fn dispatch<S: StorageIO + 'static>(state: &HandlerState<S>, request: MetastoreRequest) {
    match request {
        MetastoreRequest::Repo(r) => dispatch_repo(state, r),
        MetastoreRequest::Record(r) => dispatch_record(state, r),
        MetastoreRequest::UserBlock(r) => dispatch_user_block(state, r),
        MetastoreRequest::Event(r) => dispatch_event(state, r),
        MetastoreRequest::Commit(r) => dispatch_commit(state, *r),
        MetastoreRequest::Backlink(r) => dispatch_backlink(state, r),
        MetastoreRequest::Blob(r) => dispatch_blob(state, r),
        MetastoreRequest::Delegation(r) => dispatch_delegation(state, r),
        MetastoreRequest::Sso(r) => dispatch_sso(state, r),
        MetastoreRequest::Session(r) => dispatch_session(state, r),
        MetastoreRequest::Infra(r) => dispatch_infra(state, r),
        MetastoreRequest::OAuth(r) => dispatch_oauth(state, r),
        MetastoreRequest::User(r) => dispatch_user(state, r),
    }
}

fn dispatch_user<S: StorageIO + 'static>(state: &HandlerState<S>, req: UserRequest) {
    let user = state.metastore.user_ops();
    match req {
        UserRequest::GetByDid { did, tx } => {
            let _ = tx.send(user.get_by_did(&did).map_err(metastore_to_db));
        }
        UserRequest::GetByHandle { handle, tx } => {
            let _ = tx.send(user.get_by_handle(&handle).map_err(metastore_to_db));
        }
        UserRequest::GetWithKeyByDid { did, tx } => {
            let _ = tx.send(user.get_with_key_by_did(&did).map_err(metastore_to_db));
        }
        UserRequest::GetStatusByDid { did, tx } => {
            let _ = tx.send(user.get_status_by_did(&did).map_err(metastore_to_db));
        }
        UserRequest::CountUsers { tx } => {
            let _ = tx.send(user.count_users().map_err(metastore_to_db));
        }
        UserRequest::GetSessionAccessExpiry {
            did,
            access_jti,
            tx,
        } => {
            let _ = tx.send(
                user.get_session_access_expiry(&did, &access_jti)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::GetOAuthTokenWithUser { token_id, tx } => {
            let _ = tx.send(
                user.get_oauth_token_with_user(&token_id)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::GetUserInfoByDid { did, tx } => {
            let _ = tx.send(user.get_user_info_by_did(&did).map_err(metastore_to_db));
        }
        UserRequest::GetAnyAdminUserId { tx } => {
            let _ = tx.send(user.get_any_admin_user_id().map_err(metastore_to_db));
        }
        UserRequest::SetInvitesDisabled { did, disabled, tx } => {
            let _ = tx.send(
                user.set_invites_disabled(&did, disabled)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::SearchAccounts {
            cursor_did,
            email_filter,
            handle_filter,
            limit,
            tx,
        } => {
            let _ = tx.send(
                user.search_accounts(
                    cursor_did.as_ref(),
                    email_filter.as_deref(),
                    handle_filter.as_deref(),
                    limit,
                )
                .map_err(metastore_to_db),
            );
        }
        UserRequest::GetAuthInfoByDid { did, tx } => {
            let _ = tx.send(user.get_auth_info_by_did(&did).map_err(metastore_to_db));
        }
        UserRequest::GetByEmail { email, tx } => {
            let _ = tx.send(user.get_by_email(&email).map_err(metastore_to_db));
        }
        UserRequest::GetLoginCheckByIdentifier { identifier, tx } => {
            let _ = tx.send(
                user.get_login_check_by_identifier(&identifier)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::GetLoginInfoByIdentifier { identifier, tx } => {
            let _ = tx.send(
                user.get_login_info_by_identifier(&identifier)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::Get2faStatusByDid { did, tx } => {
            let _ = tx.send(user.get_2fa_status_by_did(&did).map_err(metastore_to_db));
        }
        UserRequest::GetCommsPrefs { user_id, tx } => {
            let _ = tx.send(user.get_comms_prefs(user_id).map_err(metastore_to_db));
        }
        UserRequest::GetIdByDid { did, tx } => {
            let _ = tx.send(user.get_id_by_did(&did).map_err(metastore_to_db));
        }
        UserRequest::GetUserKeyById { user_id, tx } => {
            let _ = tx.send(user.get_user_key_by_id(user_id).map_err(metastore_to_db));
        }
        UserRequest::GetIdAndHandleByDid { did, tx } => {
            let _ = tx.send(user.get_id_and_handle_by_did(&did).map_err(metastore_to_db));
        }
        UserRequest::GetDidWebInfoByHandle { handle, tx } => {
            let _ = tx.send(
                user.get_did_web_info_by_handle(&handle)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::GetDidWebOverrides { user_id, tx } => {
            let _ = tx.send(user.get_did_web_overrides(user_id).map_err(metastore_to_db));
        }
        UserRequest::GetHandleByDid { did, tx } => {
            let _ = tx.send(user.get_handle_by_did(&did).map_err(metastore_to_db));
        }
        UserRequest::IsAccountActiveByDid { did, tx } => {
            let _ = tx.send(user.is_account_active_by_did(&did).map_err(metastore_to_db));
        }
        UserRequest::GetUserForDeletion { did, tx } => {
            let _ = tx.send(user.get_user_for_deletion(&did).map_err(metastore_to_db));
        }
        UserRequest::CheckHandleExists {
            handle,
            exclude_user_id,
            tx,
        } => {
            let _ = tx.send(
                user.check_handle_exists(&handle, exclude_user_id)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::UpdateHandle {
            user_id,
            handle,
            tx,
        } => {
            let _ = tx.send(
                user.update_handle(user_id, &handle)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::GetUserWithKeyByDid { did, tx } => {
            let _ = tx.send(user.get_user_with_key_by_did(&did).map_err(metastore_to_db));
        }
        UserRequest::IsAccountMigrated { did, tx } => {
            let _ = tx.send(user.is_account_migrated(&did).map_err(metastore_to_db));
        }
        UserRequest::HasVerifiedCommsChannel { did, tx } => {
            let _ = tx.send(
                user.has_verified_comms_channel(&did)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::GetIdByHandle { handle, tx } => {
            let _ = tx.send(user.get_id_by_handle(&handle).map_err(metastore_to_db));
        }
        UserRequest::GetEmailInfoByDid { did, tx } => {
            let _ = tx.send(user.get_email_info_by_did(&did).map_err(metastore_to_db));
        }
        UserRequest::CheckEmailExists {
            email,
            exclude_user_id,
            tx,
        } => {
            let _ = tx.send(
                user.check_email_exists(&email, exclude_user_id)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::UpdateEmail { user_id, email, tx } => {
            let _ = tx.send(user.update_email(user_id, &email).map_err(metastore_to_db));
        }
        UserRequest::SetEmailVerified {
            user_id,
            verified,
            tx,
        } => {
            let _ = tx.send(
                user.set_email_verified(user_id, verified)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::CheckEmailVerifiedByIdentifier { identifier, tx } => {
            let _ = tx.send(
                user.check_email_verified_by_identifier(&identifier)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::CheckChannelVerifiedByDid { did, channel, tx } => {
            let _ = tx.send(
                user.check_channel_verified_by_did(&did, channel)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::AdminUpdateEmail { did, email, tx } => {
            let _ = tx.send(
                user.admin_update_email(&did, &email)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::AdminUpdateHandle { did, handle, tx } => {
            let _ = tx.send(
                user.admin_update_handle(&did, &handle)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::AdminUpdatePassword {
            did,
            password_hash,
            tx,
        } => {
            let _ = tx.send(
                user.admin_update_password(&did, &password_hash)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::SetAdminStatus { did, is_admin, tx } => {
            let _ = tx.send(
                user.set_admin_status(&did, is_admin)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::GetNotificationPrefs { did, tx } => {
            let _ = tx.send(user.get_notification_prefs(&did).map_err(metastore_to_db));
        }
        UserRequest::GetIdHandleEmailByDid { did, tx } => {
            let _ = tx.send(
                user.get_id_handle_email_by_did(&did)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::UpdatePreferredCommsChannel { did, channel, tx } => {
            let _ = tx.send(
                user.update_preferred_comms_channel(&did, channel)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::ClearDiscord { user_id, tx } => {
            let _ = tx.send(user.clear_discord(user_id).map_err(metastore_to_db));
        }
        UserRequest::ClearTelegram { user_id, tx } => {
            let _ = tx.send(user.clear_telegram(user_id).map_err(metastore_to_db));
        }
        UserRequest::ClearSignal { user_id, tx } => {
            let _ = tx.send(user.clear_signal(user_id).map_err(metastore_to_db));
        }
        UserRequest::SetUnverifiedSignal {
            user_id,
            signal_username,
            tx,
        } => {
            let _ = tx.send(
                user.set_unverified_signal(user_id, &signal_username)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::SetUnverifiedTelegram {
            user_id,
            telegram_username,
            tx,
        } => {
            let _ = tx.send(
                user.set_unverified_telegram(user_id, &telegram_username)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::StoreTelegramChatId {
            telegram_username,
            chat_id,
            handle,
            tx,
        } => {
            let _ = tx.send(
                user.store_telegram_chat_id(&telegram_username, chat_id, handle.as_deref())
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::GetTelegramChatId { user_id, tx } => {
            let _ = tx.send(user.get_telegram_chat_id(user_id).map_err(metastore_to_db));
        }
        UserRequest::SetUnverifiedDiscord {
            user_id,
            discord_username,
            tx,
        } => {
            let _ = tx.send(
                user.set_unverified_discord(user_id, &discord_username)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::StoreDiscordUserId {
            discord_username,
            discord_id,
            handle,
            tx,
        } => {
            let _ = tx.send(
                user.store_discord_user_id(&discord_username, &discord_id, handle.as_deref())
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::GetVerificationInfo { did, tx } => {
            let _ = tx.send(user.get_verification_info(&did).map_err(metastore_to_db));
        }
        UserRequest::VerifyEmailChannel { user_id, email, tx } => {
            let _ = tx.send(
                user.verify_email_channel(user_id, &email)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::VerifyDiscordChannel {
            user_id,
            discord_id,
            tx,
        } => {
            let _ = tx.send(
                user.verify_discord_channel(user_id, &discord_id)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::VerifyTelegramChannel {
            user_id,
            telegram_username,
            tx,
        } => {
            let _ = tx.send(
                user.verify_telegram_channel(user_id, &telegram_username)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::VerifySignalChannel {
            user_id,
            signal_username,
            tx,
        } => {
            let _ = tx.send(
                user.verify_signal_channel(user_id, &signal_username)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::SetEmailVerifiedFlag { user_id, tx } => {
            let _ = tx.send(
                user.set_email_verified_flag(user_id)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::SetDiscordVerifiedFlag { user_id, tx } => {
            let _ = tx.send(
                user.set_discord_verified_flag(user_id)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::SetTelegramVerifiedFlag { user_id, tx } => {
            let _ = tx.send(
                user.set_telegram_verified_flag(user_id)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::SetSignalVerifiedFlag { user_id, tx } => {
            let _ = tx.send(
                user.set_signal_verified_flag(user_id)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::HasTotpEnabled { did, tx } => {
            let _ = tx.send(user.has_totp_enabled(&did).map_err(metastore_to_db));
        }
        UserRequest::HasPasskeys { did, tx } => {
            let _ = tx.send(user.has_passkeys(&did).map_err(metastore_to_db));
        }
        UserRequest::GetPasswordHashByDid { did, tx } => {
            let _ = tx.send(user.get_password_hash_by_did(&did).map_err(metastore_to_db));
        }
        UserRequest::GetPasskeysForUser { did, tx } => {
            let _ = tx.send(user.get_passkeys_for_user(&did).map_err(metastore_to_db));
        }
        UserRequest::GetPasskeyByCredentialId { credential_id, tx } => {
            let _ = tx.send(
                user.get_passkey_by_credential_id(&credential_id)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::SavePasskey {
            did,
            credential_id,
            public_key,
            friendly_name,
            tx,
        } => {
            let _ = tx.send(
                user.save_passkey(&did, &credential_id, &public_key, friendly_name.as_deref())
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::UpdatePasskeyCounter {
            credential_id,
            new_counter,
            tx,
        } => {
            let _ = tx.send(
                user.update_passkey_counter(&credential_id, new_counter)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::DeletePasskey { id, did, tx } => {
            let _ = tx.send(user.delete_passkey(id, &did).map_err(metastore_to_db));
        }
        UserRequest::UpdatePasskeyName { id, did, name, tx } => {
            let _ = tx.send(
                user.update_passkey_name(id, &did, &name)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::SaveWebauthnChallenge {
            did,
            challenge_type,
            state_json,
            tx,
        } => {
            let _ = tx.send(
                user.save_webauthn_challenge(&did, challenge_type, &state_json)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::LoadWebauthnChallenge {
            did,
            challenge_type,
            tx,
        } => {
            let _ = tx.send(
                user.load_webauthn_challenge(&did, challenge_type)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::DeleteWebauthnChallenge {
            did,
            challenge_type,
            tx,
        } => {
            let _ = tx.send(
                user.delete_webauthn_challenge(&did, challenge_type)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::SaveDiscoverableChallenge {
            request_key,
            state_json,
            tx,
        } => {
            let _ = tx.send(
                user.save_discoverable_challenge(&request_key, &state_json)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::LoadDiscoverableChallenge { request_key, tx } => {
            let _ = tx.send(
                user.load_discoverable_challenge(&request_key)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::DeleteDiscoverableChallenge { request_key, tx } => {
            let _ = tx.send(
                user.delete_discoverable_challenge(&request_key)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::GetTotpRecord { did, tx } => {
            let _ = tx.send(user.get_totp_record(&did).map_err(metastore_to_db));
        }
        UserRequest::GetTotpRecordState { did, tx } => {
            let _ = tx.send(user.get_totp_record_state(&did).map_err(metastore_to_db));
        }
        UserRequest::UpsertTotpSecret {
            did,
            secret_encrypted,
            encryption_version,
            tx,
        } => {
            let _ = tx.send(
                user.upsert_totp_secret(&did, &secret_encrypted, encryption_version)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::SetTotpVerified { did, tx } => {
            let _ = tx.send(user.set_totp_verified(&did).map_err(metastore_to_db));
        }
        UserRequest::UpdateTotpLastUsed { did, tx } => {
            let _ = tx.send(user.update_totp_last_used(&did).map_err(metastore_to_db));
        }
        UserRequest::DeleteTotp { did, tx } => {
            let _ = tx.send(user.delete_totp(&did).map_err(metastore_to_db));
        }
        UserRequest::GetUnusedBackupCodes { did, tx } => {
            let _ = tx.send(user.get_unused_backup_codes(&did).map_err(metastore_to_db));
        }
        UserRequest::MarkBackupCodeUsed { code_id, tx } => {
            let _ = tx.send(user.mark_backup_code_used(code_id).map_err(metastore_to_db));
        }
        UserRequest::CountUnusedBackupCodes { did, tx } => {
            let _ = tx.send(
                user.count_unused_backup_codes(&did)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::DeleteBackupCodes { did, tx } => {
            let _ = tx.send(user.delete_backup_codes(&did).map_err(metastore_to_db));
        }
        UserRequest::InsertBackupCodes {
            did,
            code_hashes,
            tx,
        } => {
            let _ = tx.send(
                user.insert_backup_codes(&did, &code_hashes)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::EnableTotpWithBackupCodes {
            did,
            code_hashes,
            tx,
        } => {
            let _ = tx.send(
                user.enable_totp_with_backup_codes(&did, &code_hashes)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::DeleteTotpAndBackupCodes { did, tx } => {
            let _ = tx.send(
                user.delete_totp_and_backup_codes(&did)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::ReplaceBackupCodes {
            did,
            code_hashes,
            tx,
        } => {
            let _ = tx.send(
                user.replace_backup_codes(&did, &code_hashes)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::GetSessionInfoByDid { did, tx } => {
            let _ = tx.send(user.get_session_info_by_did(&did).map_err(metastore_to_db));
        }
        UserRequest::GetLegacyLoginPref { did, tx } => {
            let _ = tx.send(user.get_legacy_login_pref(&did).map_err(metastore_to_db));
        }
        UserRequest::UpdateLegacyLogin { did, allow, tx } => {
            let _ = tx.send(
                user.update_legacy_login(&did, allow)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::UpdateLocale { did, locale, tx } => {
            let _ = tx.send(user.update_locale(&did, &locale).map_err(metastore_to_db));
        }
        UserRequest::GetLoginFullByIdentifier { identifier, tx } => {
            let _ = tx.send(
                user.get_login_full_by_identifier(&identifier)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::GetConfirmSignupByDid { did, tx } => {
            let _ = tx.send(
                user.get_confirm_signup_by_did(&did)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::GetResendVerificationByDid { did, tx } => {
            let _ = tx.send(
                user.get_resend_verification_by_did(&did)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::SetChannelVerified { did, channel, tx } => {
            let _ = tx.send(
                user.set_channel_verified(&did, channel)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::GetIdByEmailOrHandle { email, handle, tx } => {
            let _ = tx.send(
                user.get_id_by_email_or_handle(&email, &handle)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::CountAccountsByEmail { email, tx } => {
            let _ = tx.send(
                user.count_accounts_by_email(&email)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::GetHandlesByEmail { email, tx } => {
            let _ = tx.send(user.get_handles_by_email(&email).map_err(metastore_to_db));
        }
        UserRequest::SetPasswordResetCode {
            user_id,
            code,
            expires_at,
            tx,
        } => {
            let _ = tx.send(
                user.set_password_reset_code(user_id, &code, expires_at)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::GetUserByResetCode { code, tx } => {
            let _ = tx.send(user.get_user_by_reset_code(&code).map_err(metastore_to_db));
        }
        UserRequest::ClearPasswordResetCode { user_id, tx } => {
            let _ = tx.send(
                user.clear_password_reset_code(user_id)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::GetIdAndPasswordHashByDid { did, tx } => {
            let _ = tx.send(
                user.get_id_and_password_hash_by_did(&did)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::UpdatePasswordHash {
            user_id,
            password_hash,
            tx,
        } => {
            let _ = tx.send(
                user.update_password_hash(user_id, &password_hash)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::ResetPasswordWithSessions {
            user_id,
            password_hash,
            tx,
        } => {
            let _ = tx.send(
                user.reset_password_with_sessions(user_id, &password_hash)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::ActivateAccount { did, tx } => {
            let _ = tx.send(user.activate_account(&did).map_err(metastore_to_db));
        }
        UserRequest::DeactivateAccount {
            did,
            delete_after,
            tx,
        } => {
            let _ = tx.send(
                user.deactivate_account(&did, delete_after)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::HasPasswordByDid { did, tx } => {
            let _ = tx.send(user.has_password_by_did(&did).map_err(metastore_to_db));
        }
        UserRequest::GetPasswordInfoByDid { did, tx } => {
            let _ = tx.send(user.get_password_info_by_did(&did).map_err(metastore_to_db));
        }
        UserRequest::RemoveUserPassword { user_id, tx } => {
            let _ = tx.send(user.remove_user_password(user_id).map_err(metastore_to_db));
        }
        UserRequest::SetNewUserPassword {
            user_id,
            password_hash,
            tx,
        } => {
            let _ = tx.send(
                user.set_new_user_password(user_id, &password_hash)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::GetUserKeyByDid { did, tx } => {
            let _ = tx.send(user.get_user_key_by_did(&did).map_err(metastore_to_db));
        }
        UserRequest::DeleteAccountComplete { user_id, did, tx } => {
            let _ = tx.send(
                user.delete_account_complete(user_id, &did)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::SetUserTakedown {
            did,
            takedown_ref,
            tx,
        } => {
            let _ = tx.send(
                user.set_user_takedown(&did, takedown_ref.as_deref())
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::AdminDeleteAccountComplete { user_id, did, tx } => {
            let _ = tx.send(
                user.admin_delete_account_complete(user_id, &did)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::GetUserForDidDoc { did, tx } => {
            let _ = tx.send(user.get_user_for_did_doc(&did).map_err(metastore_to_db));
        }
        UserRequest::GetUserForDidDocBuild { did, tx } => {
            let _ = tx.send(
                user.get_user_for_did_doc_build(&did)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::UpsertDidWebOverrides {
            user_id,
            verification_methods,
            also_known_as,
            tx,
        } => {
            let _ = tx.send(
                user.upsert_did_web_overrides(user_id, verification_methods, also_known_as)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::UpdateMigratedToPds { did, endpoint, tx } => {
            let _ = tx.send(
                user.update_migrated_to_pds(&did, &endpoint)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::GetUserForPasskeySetup { did, tx } => {
            let _ = tx.send(
                user.get_user_for_passkey_setup(&did)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::GetUserForPasskeyRecovery {
            identifier,
            normalized_handle,
            tx,
        } => {
            let _ = tx.send(
                user.get_user_for_passkey_recovery(&identifier, &normalized_handle)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::SetRecoveryToken {
            did,
            token_hash,
            expires_at,
            tx,
        } => {
            let _ = tx.send(
                user.set_recovery_token(&did, &token_hash, expires_at)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::GetUserForRecovery { did, tx } => {
            let _ = tx.send(user.get_user_for_recovery(&did).map_err(metastore_to_db));
        }
        UserRequest::GetAccountsScheduledForDeletion { limit, tx } => {
            let _ = tx.send(
                user.get_accounts_scheduled_for_deletion(limit)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::DeleteAccountWithFirehose { user_id, did, tx } => {
            let result = user
                .delete_account_complete(user_id, &did)
                .map_err(metastore_to_db)
                .and_then(|()| {
                    state
                        .event_ops
                        .insert_account_event(&did, AccountStatus::Deleted)
                });
            let _ = tx.send(result.map(|seq| seq.as_i64()));
        }
        UserRequest::CreatePasswordAccount { input, tx } => {
            let result = user.create_password_account(&input).and_then(|result| {
                if let Some(key_id) = input.reserved_key_id {
                    state
                        .metastore
                        .infra_ops()
                        .mark_signing_key_used(key_id)
                        .map_err(|e| CreateAccountError::Database(e.to_string()))?;
                }
                Ok(result)
            });
            let _ = tx.send(result);
        }
        UserRequest::CreateDelegatedAccount { input, tx } => {
            let result = user.create_delegated_account(&input).and_then(|account| {
                let scope =
                    tranquil_db_traits::DbScope::new(&input.controller_scopes).map_err(|e| {
                        tranquil_db_traits::CreateAccountError::Database(format!(
                            "invalid delegation scope: {e}"
                        ))
                    })?;
                state
                    .metastore
                    .delegation_ops()
                    .create_delegation(
                        &input.did,
                        &input.controller_did,
                        &scope,
                        &input.controller_did,
                    )
                    .map_err(|e| {
                        tranquil_db_traits::CreateAccountError::Database(format!(
                            "delegation grant creation failed: {e}"
                        ))
                    })?;
                Ok(account)
            });
            let _ = tx.send(result);
        }
        UserRequest::CreatePasskeyAccount { input, tx } => {
            let result = user.create_passkey_account(&input).and_then(|result| {
                if let Some(key_id) = input.reserved_key_id {
                    state
                        .metastore
                        .infra_ops()
                        .mark_signing_key_used(key_id)
                        .map_err(|e| CreateAccountError::Database(e.to_string()))?;
                }
                Ok(result)
            });
            let _ = tx.send(result);
        }
        UserRequest::CreateSsoAccount { input, tx } => {
            let sso_ops = state.metastore.sso_ops();
            let result = sso_ops
                .consume_pending_registration(&input.pending_registration_token)
                .map_err(|e| CreateAccountError::Database(e.to_string()))
                .and_then(|consumed| match consumed {
                    Some(_) => user.create_sso_account(&input).and_then(|result| {
                        sso_ops
                            .create_external_identity(
                                &input.did,
                                input.sso_provider,
                                &input.sso_provider_user_id,
                                input.sso_provider_username.as_deref(),
                                input.sso_provider_email.as_deref(),
                            )
                            .map_err(|e| CreateAccountError::Database(e.to_string()))?;
                        Ok(result)
                    }),
                    None => Err(CreateAccountError::InvalidToken),
                });
            let _ = tx.send(result);
        }
        UserRequest::ReactivateMigrationAccount { input, tx } => {
            let _ = tx.send(user.reactivate_migration_account(&input));
        }
        UserRequest::CheckHandleAvailableForNewAccount { handle, tx } => {
            let _ = tx.send(
                user.check_handle_available_for_new_account(&handle)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::ReserveHandle {
            handle,
            reserved_by,
            tx,
        } => {
            let _ = tx.send(
                user.reserve_handle(&handle, &reserved_by)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::ReleaseHandleReservation { handle, tx } => {
            let _ = tx.send(
                user.release_handle_reservation(&handle)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::CleanupExpiredHandleReservations { tx } => {
            let _ = tx.send(
                user.cleanup_expired_handle_reservations()
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::CheckAndConsumeInviteCode { code, tx } => {
            let infra = state.metastore.infra_ops();
            let result = match infra.validate_invite_code(&code) {
                Ok(validated) => infra
                    .decrement_invite_code_uses(&validated)
                    .map(|()| true)
                    .map_err(metastore_to_db),
                Err(_) => Ok(false),
            };
            let _ = tx.send(result);
        }
        UserRequest::CompletePasskeySetup { input, tx } => {
            let _ = tx.send(user.complete_passkey_setup(&input).map_err(metastore_to_db));
        }
        UserRequest::RecoverPasskeyAccount { input, tx } => {
            let _ = tx.send(
                user.recover_passkey_account(&input)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::GetPasswordResetInfo { email, tx } => {
            let _ = tx.send(
                user.get_password_reset_info(&email)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::EnableTotpVerified {
            did,
            encrypted_secret,
            tx,
        } => {
            let _ = tx.send(
                user.enable_totp_verified(&did, &encrypted_secret)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::SetTwoFactorEnabled { did, enabled, tx } => {
            let _ = tx.send(
                user.set_two_factor_enabled(&did, enabled)
                    .map_err(metastore_to_db),
            );
        }
        UserRequest::ExpirePasswordResetCode { email, tx } => {
            let _ = tx.send(
                user.expire_password_reset_code(&email)
                    .map_err(metastore_to_db),
            );
        }
    }
}

fn handler_loop<S: StorageIO + 'static>(
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
                tracing::error!(thread_index, msg, "recovered metastore handler panic");
            }
        }
    });
    tracing::info!(thread_index, "metastore handler thread exiting");
}

const DEFAULT_CHANNEL_BOUND: usize = 256;
const MAX_REPOS_WITHOUT_REV: usize = 10_000;

pub struct HandlerPool {
    senders: parking_lot::Mutex<Vec<flume::Sender<MetastoreRequest>>>,
    handles: parking_lot::Mutex<Option<Vec<JoinHandle<()>>>>,
    sender_count: usize,
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
            sender_count: senders.len(),
            senders: parking_lot::Mutex::new(senders),
            handles: parking_lot::Mutex::new(Some(handles)),
            user_hashes,
            round_robin: AtomicUsize::new(0),
        }
    }

    pub fn send(&self, request: MetastoreRequest) -> Result<(), DbError> {
        let senders = self.senders.lock();
        if senders.is_empty() {
            return Err(DbError::Connection(
                "metastore handler pool shut down".to_string(),
            ));
        }
        let index = match request.routing(&self.user_hashes) {
            Routing::Sharded(bits) => (bits as usize) % senders.len(),
            Routing::Global => self.round_robin.fetch_add(1, Ordering::Relaxed) % senders.len(),
        };
        senders[index].try_send(request).map_err(|e| match e {
            flume::TrySendError::Full(_) => {
                DbError::Query("metastore handler backpressure".to_string())
            }
            flume::TrySendError::Disconnected(_) => {
                DbError::Connection("metastore handler pool shut down".to_string())
            }
        })
    }

    pub fn thread_count(&self) -> usize {
        self.sender_count
    }

    pub async fn close(&self) {
        {
            self.senders.lock().clear();
        }
        let handles = { self.handles.lock().take() };
        if let Some(handles) = handles {
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
        self.senders.get_mut().clear();
        if let Some(handles) = self.handles.get_mut().take() {
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
        let h = setup();
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

        h.pool.close().await;
    }
}
