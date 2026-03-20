use crate::api::error::ApiError;
use crate::state::AppState;
use crate::sync::firehose::SequencedEvent;
use crate::sync::frame::{
    AccountFrame, CommitFrame, ErrorFrameBody, ErrorFrameHeader, ErrorFrameName, FrameHeader,
    FrameType, IdentityFrame, InfoFrame, InfoFrameName, SyncFrame,
};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use cid::Cid;
use iroh_car::{CarHeader, CarWriter};
use jacquard_repo::commit::Commit;
use jacquard_repo::storage::BlockStore;
use std::collections::{BTreeMap, HashMap};
use std::io::Cursor;
use std::str::FromStr;
use tokio::io::AsyncWriteExt;
use tranquil_db_traits::{AccountStatus, RepoEventType, RepoRepository};
use tranquil_types::Did;

#[derive(Debug)]
pub enum SyncFrameError {
    CarWrite(iroh_car::Error),
    CarFinalize(iroh_car::Error),
    IoFlush(std::io::Error),
    CborSerialize(String),
    MissingCommitCid,
    CommitBlockNotFound,
    RevExtraction,
    InvalidEvent(String),
    BlockStore(tranquil_db_traits::DbError),
    CidParse(cid::Error),
}

impl std::fmt::Display for SyncFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CarWrite(e) => write!(f, "CAR block write failed: {}", e),
            Self::CarFinalize(e) => write!(f, "CAR finalize failed: {}", e),
            Self::IoFlush(e) => write!(f, "CAR buffer flush failed: {}", e),
            Self::CborSerialize(e) => write!(f, "CBOR serialization failed: {}", e),
            Self::MissingCommitCid => write!(f, "missing commit_cid"),
            Self::CommitBlockNotFound => write!(f, "commit block not found"),
            Self::RevExtraction => write!(f, "could not extract rev from commit"),
            Self::InvalidEvent(msg) => write!(f, "invalid event: {}", msg),
            Self::BlockStore(e) => write!(f, "block store error: {}", e),
            Self::CidParse(e) => write!(f, "CID parse failed: {}", e),
        }
    }
}

impl std::error::Error for SyncFrameError {}

impl From<serde_ipld_dagcbor::EncodeError<std::collections::TryReserveError>> for SyncFrameError {
    fn from(e: serde_ipld_dagcbor::EncodeError<std::collections::TryReserveError>) -> Self {
        Self::CborSerialize(e.to_string())
    }
}

impl From<serde_ipld_dagcbor::EncodeError<std::io::Error>> for SyncFrameError {
    fn from(e: serde_ipld_dagcbor::EncodeError<std::io::Error>) -> Self {
        Self::CborSerialize(e.to_string())
    }
}

impl From<cid::Error> for SyncFrameError {
    fn from(e: cid::Error) -> Self {
        Self::CidParse(e)
    }
}

impl From<tranquil_db_traits::DbError> for SyncFrameError {
    fn from(e: tranquil_db_traits::DbError) -> Self {
        Self::BlockStore(e)
    }
}

impl From<jacquard_repo::error::RepoError> for SyncFrameError {
    fn from(e: jacquard_repo::error::RepoError) -> Self {
        Self::BlockStore(tranquil_db_traits::DbError::from_query_error(e.to_string()))
    }
}

pub struct RepoAccount {
    pub did: Did,
    pub user_id: uuid::Uuid,
    pub status: AccountStatus,
    pub repo_root_cid: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoAccessLevel {
    Public,
    Privileged,
}

pub enum RepoAvailabilityError {
    NotFound(Did),
    Takendown(Did),
    Deactivated(Did),
    Internal(String),
}

impl IntoResponse for RepoAvailabilityError {
    fn into_response(self) -> Response {
        match self {
            RepoAvailabilityError::NotFound(did) => {
                ApiError::RepoNotFound(Some(format!("Could not find repo for DID: {}", did)))
                    .into_response()
            }
            RepoAvailabilityError::Takendown(_) => ApiError::RepoTakendown.into_response(),
            RepoAvailabilityError::Deactivated(_) => ApiError::RepoDeactivated.into_response(),
            RepoAvailabilityError::Internal(msg) => {
                ApiError::InternalError(Some(msg)).into_response()
            }
        }
    }
}

pub async fn get_account_with_status(
    repo_repo: &dyn RepoRepository,
    did: &Did,
) -> Result<Option<RepoAccount>, tranquil_db_traits::DbError> {
    let row = repo_repo.get_account_with_repo(did).await?;

    Ok(row.map(|r| {
        let status = if r.takedown_ref.is_some() {
            AccountStatus::Takendown
        } else if r.deactivated_at.is_some() {
            AccountStatus::Deactivated
        } else {
            AccountStatus::Active
        };

        RepoAccount {
            did: r.did,
            user_id: r.user_id,
            status,
            repo_root_cid: r.repo_root_cid.map(|c| c.to_string()),
        }
    }))
}

pub async fn assert_repo_availability(
    repo_repo: &dyn RepoRepository,
    did: &Did,
    access_level: RepoAccessLevel,
) -> Result<RepoAccount, RepoAvailabilityError> {
    let account = get_account_with_status(repo_repo, did)
        .await
        .map_err(|e| RepoAvailabilityError::Internal(e.to_string()))?;

    let account = match account {
        Some(a) => a,
        None => return Err(RepoAvailabilityError::NotFound(did.clone())),
    };

    if access_level == RepoAccessLevel::Privileged {
        return Ok(account);
    }

    match account.status {
        AccountStatus::Takendown => return Err(RepoAvailabilityError::Takendown(did.clone())),
        AccountStatus::Deactivated => {
            return Err(RepoAvailabilityError::Deactivated(did.clone()));
        }
        _ => {}
    }

    Ok(account)
}

fn extract_rev_from_commit_bytes(commit_bytes: &[u8]) -> Option<String> {
    Commit::from_cbor(commit_bytes)
        .ok()
        .map(|c| c.rev().to_string())
}

async fn write_car_blocks(
    commit_cid: Cid,
    commit_bytes: Option<Bytes>,
    other_blocks: BTreeMap<Cid, Bytes>,
) -> Result<Vec<u8>, SyncFrameError> {
    let mut buffer = Cursor::new(Vec::new());
    let header = CarHeader::new_v1(vec![commit_cid]);
    let mut writer = CarWriter::new(header, &mut buffer);
    for (cid, data) in other_blocks.iter().filter(|(c, _)| **c != commit_cid) {
        writer
            .write(*cid, data.as_ref())
            .await
            .map_err(SyncFrameError::CarWrite)?;
    }
    if let Some(data) = commit_bytes {
        writer
            .write(commit_cid, data.as_ref())
            .await
            .map_err(SyncFrameError::CarWrite)?;
    }
    writer.finish().await.map_err(SyncFrameError::CarFinalize)?;
    buffer.flush().await.map_err(SyncFrameError::IoFlush)?;
    Ok(buffer.into_inner())
}

fn format_atproto_time(dt: chrono::DateTime<chrono::Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

fn serialize_cbor_pair<H: serde::Serialize, P: serde::Serialize>(
    header: &H,
    payload: &P,
    capacity: usize,
) -> Result<Vec<u8>, SyncFrameError> {
    let mut bytes = Vec::with_capacity(capacity);
    serde_ipld_dagcbor::to_writer(&mut bytes, header)?;
    serde_ipld_dagcbor::to_writer(&mut bytes, payload)?;
    Ok(bytes)
}

fn serialize_event_frame<P: serde::Serialize>(
    frame_type: FrameType,
    payload: &P,
    capacity: usize,
) -> Result<Vec<u8>, SyncFrameError> {
    serialize_cbor_pair(&FrameHeader { op: 1, t: frame_type }, payload, capacity)
}

fn format_identity_event(event: &SequencedEvent) -> Result<Vec<u8>, SyncFrameError> {
    serialize_event_frame(
        FrameType::Identity,
        &IdentityFrame {
            did: event.did.clone(),
            handle: event.handle.as_ref().map(|h| h.to_string()),
            seq: event.seq.as_i64(),
            time: format_atproto_time(event.created_at),
        },
        256,
    )
}

fn format_account_event(event: &SequencedEvent) -> Result<Vec<u8>, SyncFrameError> {
    let frame = AccountFrame {
        did: event.did.clone(),
        active: event.active.unwrap_or(true),
        status: event.status.filter(|s| !s.is_active()),
        seq: event.seq.as_i64(),
        time: format_atproto_time(event.created_at),
    };
    let bytes = serialize_event_frame(FrameType::Account, &frame, 256)?;
    let hex_str: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    tracing::info!(
        did = %frame.did,
        active = frame.active,
        status = ?frame.status,
        cbor_len = bytes.len(),
        cbor_hex = %hex_str,
        "Sending account event to firehose"
    );
    Ok(bytes)
}

async fn format_sync_event(
    state: &AppState,
    event: &SequencedEvent,
) -> Result<Vec<u8>, SyncFrameError> {
    let commit_cid_str = event
        .commit_cid
        .as_ref()
        .ok_or(SyncFrameError::MissingCommitCid)?;
    let commit_cid = Cid::from_str(commit_cid_str)?;
    let commit_bytes = state
        .block_store
        .get(&commit_cid)
        .await?
        .ok_or(SyncFrameError::CommitBlockNotFound)?;
    let rev = if let Some(ref stored_rev) = event.rev {
        stored_rev.clone()
    } else {
        extract_rev_from_commit_bytes(&commit_bytes).ok_or(SyncFrameError::RevExtraction)?
    };
    let car_bytes = write_car_blocks(commit_cid, Some(commit_bytes), BTreeMap::new()).await?;
    serialize_event_frame(
        FrameType::Sync,
        &SyncFrame {
            did: event.did.clone(),
            rev,
            blocks: car_bytes,
            seq: event.seq.as_i64(),
            time: format_atproto_time(event.created_at),
        },
        512,
    )
}

struct CommitEventContext {
    frame: CommitFrame,
    commit_cid: Cid,
    prev_cid: Option<Cid>,
    block_cids: Vec<Cid>,
}

fn prepare_commit_event(event: SequencedEvent) -> Result<CommitEventContext, SyncFrameError> {
    let block_cids_str = event.blocks_cids.clone().unwrap_or_default();
    let prev_cid_link = event.prev_cid.clone();
    let prev_data_cid_link = event.prev_data_cid.clone();
    let mut frame: CommitFrame =
        event
            .try_into()
            .map_err(|e: crate::sync::frame::CommitFrameError| {
                SyncFrameError::InvalidEvent(e.to_string())
            })?;
    if let Some(ref pdc) = prev_data_cid_link
        && let Ok(cid) = Cid::from_str(pdc.as_str())
    {
        frame.prev_data = Some(cid);
    }
    let commit_cid = frame.commit;
    let prev_cid = prev_cid_link
        .as_ref()
        .and_then(|c| Cid::from_str(c.as_str()).ok());
    let mut block_cids: Vec<Cid> = block_cids_str
        .iter()
        .filter_map(|s| Cid::from_str(s).ok())
        .filter(|c| Some(*c) != prev_cid)
        .collect();
    if !block_cids.contains(&commit_cid) {
        block_cids.push(commit_cid);
    }
    Ok(CommitEventContext {
        frame,
        commit_cid,
        prev_cid,
        block_cids,
    })
}

fn partition_blocks(
    block_cids: impl IntoIterator<Item = (Cid, Bytes)>,
    commit_cid: Cid,
) -> (Option<Bytes>, BTreeMap<Cid, Bytes>) {
    let (commit_data, other_blocks): (Vec<_>, Vec<_>) = block_cids
        .into_iter()
        .partition(|(cid, _)| *cid == commit_cid);
    let commit_bytes = commit_data.into_iter().next().map(|(_, data)| data);
    let other = other_blocks.into_iter().collect();
    (commit_bytes, other)
}

async fn finalize_commit_frame(
    mut frame: CommitFrame,
    commit_cid: Cid,
    commit_bytes: Option<Bytes>,
    other_blocks: BTreeMap<Cid, Bytes>,
) -> Result<Vec<u8>, SyncFrameError> {
    if let Some(ref cb) = commit_bytes
        && let Some(rev) = extract_rev_from_commit_bytes(cb)
    {
        frame.rev = rev;
    }
    frame.blocks = write_car_blocks(commit_cid, commit_bytes, other_blocks).await?;
    let capacity = frame.blocks.len() + 512;
    serialize_event_frame(FrameType::Commit, &frame, capacity)
}

pub async fn format_event_for_sending(
    state: &AppState,
    event: SequencedEvent,
) -> Result<Vec<u8>, SyncFrameError> {
    match event.event_type {
        RepoEventType::Identity => return format_identity_event(&event),
        RepoEventType::Account => return format_account_event(&event),
        RepoEventType::Sync => return format_sync_event(state, &event).await,
        RepoEventType::Commit => {}
    }
    let ctx = prepare_commit_event(event)?;
    let mut frame = ctx.frame;
    if let Some(ref pc) = ctx.prev_cid
        && let Ok(Some(prev_bytes)) = state.block_store.get(pc).await
        && let Some(rev) = extract_rev_from_commit_bytes(&prev_bytes)
    {
        frame.since = Some(rev);
    }
    if ctx.block_cids.is_empty() {
        frame.blocks = Vec::new();
        let capacity = frame.blocks.len() + 512;
        return serialize_event_frame(FrameType::Commit, &frame, capacity);
    }
    let fetched = state.block_store.get_many(&ctx.block_cids).await?;
    let resolved = ctx
        .block_cids
        .iter()
        .zip(fetched.iter())
        .filter_map(|(cid, data_opt)| data_opt.as_ref().map(|data| (*cid, data.clone())));
    let (commit_bytes, other_blocks) = partition_blocks(resolved, ctx.commit_cid);
    finalize_commit_frame(frame, ctx.commit_cid, commit_bytes, other_blocks).await
}

pub async fn prefetch_blocks_for_events(
    state: &AppState,
    events: &[SequencedEvent],
) -> Result<HashMap<Cid, Bytes>, SyncFrameError> {
    let mut all_cids: Vec<Cid> = events
        .iter()
        .flat_map(|event| {
            let commit_cid = event
                .commit_cid
                .as_ref()
                .and_then(|s| Cid::from_str(s).ok());
            let prev_cid = event.prev_cid.as_ref().and_then(|s| Cid::from_str(s).ok());
            let block_cids = event
                .blocks_cids
                .as_ref()
                .map(|cids| cids.iter().filter_map(|s| Cid::from_str(s).ok()).collect())
                .unwrap_or_else(Vec::new);
            commit_cid.into_iter().chain(prev_cid).chain(block_cids)
        })
        .collect();
    all_cids.sort();
    all_cids.dedup();
    if all_cids.is_empty() {
        return Ok(HashMap::new());
    }
    let fetched = state.block_store.get_many(&all_cids).await?;
    let blocks_map: HashMap<Cid, Bytes> = all_cids
        .into_iter()
        .zip(fetched)
        .filter_map(|(cid, data_opt)| data_opt.map(|data| (cid, data)))
        .collect();
    Ok(blocks_map)
}

fn format_sync_event_with_prefetched(
    event: &SequencedEvent,
    prefetched: &HashMap<Cid, Bytes>,
) -> Result<Vec<u8>, SyncFrameError> {
    let commit_cid_str = event
        .commit_cid
        .as_ref()
        .ok_or(SyncFrameError::MissingCommitCid)?;
    let commit_cid = Cid::from_str(commit_cid_str)?;
    let commit_bytes = prefetched
        .get(&commit_cid)
        .ok_or(SyncFrameError::CommitBlockNotFound)?;
    let rev = if let Some(ref stored_rev) = event.rev {
        stored_rev.clone()
    } else {
        extract_rev_from_commit_bytes(commit_bytes).ok_or(SyncFrameError::RevExtraction)?
    };
    let car_bytes = futures::executor::block_on(write_car_blocks(
        commit_cid,
        Some(commit_bytes.clone()),
        BTreeMap::new(),
    ))?;
    serialize_event_frame(
        FrameType::Sync,
        &SyncFrame {
            did: event.did.clone(),
            rev,
            blocks: car_bytes,
            seq: event.seq.as_i64(),
            time: format_atproto_time(event.created_at),
        },
        512,
    )
}

pub async fn format_event_with_prefetched_blocks(
    event: SequencedEvent,
    prefetched: &HashMap<Cid, Bytes>,
) -> Result<Vec<u8>, SyncFrameError> {
    match event.event_type {
        RepoEventType::Identity => return format_identity_event(&event),
        RepoEventType::Account => return format_account_event(&event),
        RepoEventType::Sync => return format_sync_event_with_prefetched(&event, prefetched),
        RepoEventType::Commit => {}
    }
    let ctx = prepare_commit_event(event)?;
    let mut frame = ctx.frame;
    if let Some(ref pc) = ctx.prev_cid
        && let Some(prev_bytes) = prefetched.get(pc)
        && let Some(rev) = extract_rev_from_commit_bytes(prev_bytes)
    {
        frame.since = Some(rev);
    }
    if ctx.block_cids.is_empty() {
        frame.blocks = Vec::new();
        let capacity = frame.blocks.len() + 512;
        return serialize_event_frame(FrameType::Commit, &frame, capacity);
    }
    let resolved = ctx
        .block_cids
        .into_iter()
        .filter_map(|cid| prefetched.get(&cid).map(|data| (cid, data.clone())));
    let (commit_bytes, other_blocks) = partition_blocks(resolved, ctx.commit_cid);
    finalize_commit_frame(frame, ctx.commit_cid, commit_bytes, other_blocks).await
}

pub fn format_info_frame(
    name: InfoFrameName,
    message: Option<&str>,
) -> Result<Vec<u8>, SyncFrameError> {
    serialize_event_frame(
        FrameType::Info,
        &InfoFrame {
            name,
            message: message.map(String::from),
        },
        128,
    )
}

pub fn format_error_frame(
    error: ErrorFrameName,
    message: Option<&str>,
) -> Result<Vec<u8>, SyncFrameError> {
    serialize_cbor_pair(
        &ErrorFrameHeader { op: -1 },
        &ErrorFrameBody {
            error,
            message: message.map(String::from),
        },
        128,
    )
}
