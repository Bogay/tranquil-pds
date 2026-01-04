use crate::api::error::ApiError;
use crate::state::AppState;
use crate::sync::firehose::SequencedEvent;
use crate::sync::frame::{
    AccountFrame, CommitFrame, ErrorFrameBody, ErrorFrameHeader, FrameHeader, IdentityFrame,
    InfoFrame, SyncFrame,
};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use cid::Cid;
use iroh_car::{CarHeader, CarWriter};
use jacquard_repo::commit::Commit;
use jacquard_repo::storage::BlockStore;
use serde::Serialize;
use sqlx::PgPool;
use std::collections::{BTreeMap, HashMap};
use std::io::Cursor;
use std::str::FromStr;
use tokio::io::AsyncWriteExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    Active,
    Takendown,
    Suspended,
    Deactivated,
    Deleted,
}

impl AccountStatus {
    pub fn as_str(&self) -> Option<&'static str> {
        match self {
            Self::Active => None,
            Self::Takendown => Some("takendown"),
            Self::Suspended => Some("suspended"),
            Self::Deactivated => Some("deactivated"),
            Self::Deleted => Some("deleted"),
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn is_takendown(&self) -> bool {
        matches!(self, Self::Takendown)
    }

    pub fn is_suspended(&self) -> bool {
        matches!(self, Self::Suspended)
    }

    pub fn is_deactivated(&self) -> bool {
        matches!(self, Self::Deactivated)
    }

    pub fn is_deleted(&self) -> bool {
        matches!(self, Self::Deleted)
    }

    pub fn allows_read(&self) -> bool {
        matches!(self, Self::Active | Self::Deactivated)
    }

    pub fn allows_write(&self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn from_db_fields(takedown_ref: Option<&str>, deactivated_at: Option<chrono::DateTime<chrono::Utc>>) -> Self {
        if takedown_ref.is_some() {
            Self::Takendown
        } else if deactivated_at.is_some() {
            Self::Deactivated
        } else {
            Self::Active
        }
    }
}

impl From<crate::types::AccountState> for AccountStatus {
    fn from(state: crate::types::AccountState) -> Self {
        match state {
            crate::types::AccountState::Active => AccountStatus::Active,
            crate::types::AccountState::Deactivated { .. } => AccountStatus::Deactivated,
            crate::types::AccountState::TakenDown { .. } => AccountStatus::Takendown,
            crate::types::AccountState::Migrated { .. } => AccountStatus::Deactivated,
        }
    }
}

impl From<&crate::types::AccountState> for AccountStatus {
    fn from(state: &crate::types::AccountState) -> Self {
        match state {
            crate::types::AccountState::Active => AccountStatus::Active,
            crate::types::AccountState::Deactivated { .. } => AccountStatus::Deactivated,
            crate::types::AccountState::TakenDown { .. } => AccountStatus::Takendown,
            crate::types::AccountState::Migrated { .. } => AccountStatus::Deactivated,
        }
    }
}

pub struct RepoAccount {
    pub did: String,
    pub user_id: uuid::Uuid,
    pub status: AccountStatus,
    pub repo_root_cid: Option<String>,
}

pub enum RepoAvailabilityError {
    NotFound(String),
    Takendown(String),
    Deactivated(String),
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
    db: &PgPool,
    did: &str,
) -> Result<Option<RepoAccount>, sqlx::Error> {
    let row = sqlx::query!(
        r#"
        SELECT u.id, u.did, u.deactivated_at, u.takedown_ref, r.repo_root_cid
        FROM users u
        LEFT JOIN repos r ON r.user_id = u.id
        WHERE u.did = $1
        "#,
        did
    )
    .fetch_optional(db)
    .await?;

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
            user_id: r.id,
            status,
            repo_root_cid: Some(r.repo_root_cid),
        }
    }))
}

pub async fn assert_repo_availability(
    db: &PgPool,
    did: &str,
    is_admin_or_self: bool,
) -> Result<RepoAccount, RepoAvailabilityError> {
    let account = get_account_with_status(db, did)
        .await
        .map_err(|e| RepoAvailabilityError::Internal(e.to_string()))?;

    let account = match account {
        Some(a) => a,
        None => return Err(RepoAvailabilityError::NotFound(did.to_string())),
    };

    if is_admin_or_self {
        return Ok(account);
    }

    match account.status {
        AccountStatus::Takendown => return Err(RepoAvailabilityError::Takendown(did.to_string())),
        AccountStatus::Deactivated => {
            return Err(RepoAvailabilityError::Deactivated(did.to_string()));
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
) -> Result<Vec<u8>, anyhow::Error> {
    let mut buffer = Cursor::new(Vec::new());
    let header = CarHeader::new_v1(vec![commit_cid]);
    let mut writer = CarWriter::new(header, &mut buffer);
    for (cid, data) in other_blocks {
        if cid != commit_cid {
            writer
                .write(cid, data.as_ref())
                .await
                .map_err(|e| anyhow::anyhow!("writing block {}: {}", cid, e))?;
        }
    }
    if let Some(data) = commit_bytes {
        writer
            .write(commit_cid, data.as_ref())
            .await
            .map_err(|e| anyhow::anyhow!("writing commit block: {}", e))?;
    }
    writer
        .finish()
        .await
        .map_err(|e| anyhow::anyhow!("finalizing CAR: {}", e))?;
    buffer
        .flush()
        .await
        .map_err(|e| anyhow::anyhow!("flushing CAR buffer: {}", e))?;
    Ok(buffer.into_inner())
}

fn format_atproto_time(dt: chrono::DateTime<chrono::Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

fn format_identity_event(event: &SequencedEvent) -> Result<Vec<u8>, anyhow::Error> {
    let frame = IdentityFrame {
        did: event.did.clone(),
        handle: event.handle.clone(),
        seq: event.seq,
        time: format_atproto_time(event.created_at),
    };
    let header = FrameHeader {
        op: 1,
        t: "#identity".to_string(),
    };
    let mut bytes = Vec::with_capacity(256);
    serde_ipld_dagcbor::to_writer(&mut bytes, &header)?;
    serde_ipld_dagcbor::to_writer(&mut bytes, &frame)?;
    Ok(bytes)
}

fn format_account_event(event: &SequencedEvent) -> Result<Vec<u8>, anyhow::Error> {
    let frame = AccountFrame {
        did: event.did.clone(),
        active: event.active.unwrap_or(true),
        status: event.status.clone(),
        seq: event.seq,
        time: format_atproto_time(event.created_at),
    };
    let header = FrameHeader {
        op: 1,
        t: "#account".to_string(),
    };
    let mut bytes = Vec::with_capacity(256);
    serde_ipld_dagcbor::to_writer(&mut bytes, &header)?;
    serde_ipld_dagcbor::to_writer(&mut bytes, &frame)?;
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
) -> Result<Vec<u8>, anyhow::Error> {
    let commit_cid_str = event
        .commit_cid
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Sync event missing commit_cid"))?;
    let commit_cid = Cid::from_str(commit_cid_str)?;
    let commit_bytes = state
        .block_store
        .get(&commit_cid)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Commit block not found"))?;
    let rev = if let Some(ref stored_rev) = event.rev {
        stored_rev.clone()
    } else {
        extract_rev_from_commit_bytes(&commit_bytes)
            .ok_or_else(|| anyhow::anyhow!("Could not extract rev from commit"))?
    };
    let car_bytes = write_car_blocks(commit_cid, Some(commit_bytes), BTreeMap::new()).await?;
    let frame = SyncFrame {
        did: event.did.clone(),
        rev,
        blocks: car_bytes,
        seq: event.seq,
        time: format_atproto_time(event.created_at),
    };
    let header = FrameHeader {
        op: 1,
        t: "#sync".to_string(),
    };
    let mut bytes = Vec::with_capacity(512);
    serde_ipld_dagcbor::to_writer(&mut bytes, &header)?;
    serde_ipld_dagcbor::to_writer(&mut bytes, &frame)?;
    Ok(bytes)
}

pub async fn format_event_for_sending(
    state: &AppState,
    event: SequencedEvent,
) -> Result<Vec<u8>, anyhow::Error> {
    match event.event_type.as_str() {
        "identity" => return format_identity_event(&event),
        "account" => return format_account_event(&event),
        "sync" => return format_sync_event(state, &event).await,
        _ => {}
    }
    let block_cids_str = event.blocks_cids.clone().unwrap_or_default();
    let prev_cid_str = event.prev_cid.clone();
    let prev_data_cid_str = event.prev_data_cid.clone();
    let mut frame: CommitFrame = event
        .try_into()
        .map_err(|e| anyhow::anyhow!("Invalid event: {}", e))?;
    if let Some(ref pdc) = prev_data_cid_str
        && let Ok(cid) = Cid::from_str(pdc)
    {
        frame.prev_data = Some(cid);
    }
    let commit_cid = frame.commit;
    let prev_cid = prev_cid_str.as_ref().and_then(|s| Cid::from_str(s).ok());
    let mut all_cids: Vec<Cid> = block_cids_str
        .iter()
        .filter_map(|s| Cid::from_str(s).ok())
        .filter(|c| Some(*c) != prev_cid)
        .collect();
    if !all_cids.contains(&commit_cid) {
        all_cids.push(commit_cid);
    }
    if let Some(ref pc) = prev_cid
        && let Ok(Some(prev_bytes)) = state.block_store.get(pc).await
        && let Some(rev) = extract_rev_from_commit_bytes(&prev_bytes)
    {
        frame.since = Some(rev);
    }
    let car_bytes = if !all_cids.is_empty() {
        let fetched = state.block_store.get_many(&all_cids).await?;
        let mut blocks = std::collections::BTreeMap::new();
        let mut commit_bytes: Option<Bytes> = None;
        for (cid, data_opt) in all_cids.iter().zip(fetched.iter()) {
            if let Some(data) = data_opt {
                if *cid == commit_cid {
                    commit_bytes = Some(data.clone());
                    if let Some(rev) = extract_rev_from_commit_bytes(data) {
                        frame.rev = rev;
                    }
                } else {
                    blocks.insert(*cid, data.clone());
                }
            }
        }
        write_car_blocks(commit_cid, commit_bytes, blocks).await?
    } else {
        Vec::new()
    };
    frame.blocks = car_bytes;
    let header = FrameHeader {
        op: 1,
        t: "#commit".to_string(),
    };
    let mut bytes = Vec::with_capacity(frame.blocks.len() + 512);
    serde_ipld_dagcbor::to_writer(&mut bytes, &header)?;
    serde_ipld_dagcbor::to_writer(&mut bytes, &frame)?;
    Ok(bytes)
}

pub async fn prefetch_blocks_for_events(
    state: &AppState,
    events: &[SequencedEvent],
) -> Result<HashMap<Cid, Bytes>, anyhow::Error> {
    let mut all_cids: Vec<Cid> = Vec::new();
    for event in events {
        if let Some(ref commit_cid_str) = event.commit_cid
            && let Ok(cid) = Cid::from_str(commit_cid_str)
        {
            all_cids.push(cid);
        }
        if let Some(ref prev_cid_str) = event.prev_cid
            && let Ok(cid) = Cid::from_str(prev_cid_str)
        {
            all_cids.push(cid);
        }
        if let Some(ref block_cids_str) = event.blocks_cids {
            for s in block_cids_str {
                if let Ok(cid) = Cid::from_str(s) {
                    all_cids.push(cid);
                }
            }
        }
    }
    all_cids.sort();
    all_cids.dedup();
    if all_cids.is_empty() {
        return Ok(HashMap::new());
    }
    let fetched = state.block_store.get_many(&all_cids).await?;
    let mut blocks_map = HashMap::with_capacity(all_cids.len());
    for (cid, data_opt) in all_cids.into_iter().zip(fetched.into_iter()) {
        if let Some(data) = data_opt {
            blocks_map.insert(cid, data);
        }
    }
    Ok(blocks_map)
}

fn format_sync_event_with_prefetched(
    event: &SequencedEvent,
    prefetched: &HashMap<Cid, Bytes>,
) -> Result<Vec<u8>, anyhow::Error> {
    let commit_cid_str = event
        .commit_cid
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Sync event missing commit_cid"))?;
    let commit_cid = Cid::from_str(commit_cid_str)?;
    let commit_bytes = prefetched
        .get(&commit_cid)
        .ok_or_else(|| anyhow::anyhow!("Commit block not found in prefetched"))?;
    let rev = if let Some(ref stored_rev) = event.rev {
        stored_rev.clone()
    } else {
        extract_rev_from_commit_bytes(commit_bytes)
            .ok_or_else(|| anyhow::anyhow!("Could not extract rev from commit"))?
    };
    let car_bytes = futures::executor::block_on(write_car_blocks(
        commit_cid,
        Some(commit_bytes.clone()),
        BTreeMap::new(),
    ))?;
    let frame = SyncFrame {
        did: event.did.clone(),
        rev,
        blocks: car_bytes,
        seq: event.seq,
        time: format_atproto_time(event.created_at),
    };
    let header = FrameHeader {
        op: 1,
        t: "#sync".to_string(),
    };
    let mut bytes = Vec::new();
    serde_ipld_dagcbor::to_writer(&mut bytes, &header)?;
    serde_ipld_dagcbor::to_writer(&mut bytes, &frame)?;
    Ok(bytes)
}

pub async fn format_event_with_prefetched_blocks(
    event: SequencedEvent,
    prefetched: &HashMap<Cid, Bytes>,
) -> Result<Vec<u8>, anyhow::Error> {
    match event.event_type.as_str() {
        "identity" => return format_identity_event(&event),
        "account" => return format_account_event(&event),
        "sync" => return format_sync_event_with_prefetched(&event, prefetched),
        _ => {}
    }
    let block_cids_str = event.blocks_cids.clone().unwrap_or_default();
    let prev_cid_str = event.prev_cid.clone();
    let prev_data_cid_str = event.prev_data_cid.clone();
    let mut frame: CommitFrame = event
        .try_into()
        .map_err(|e| anyhow::anyhow!("Invalid event: {}", e))?;
    if let Some(ref pdc) = prev_data_cid_str
        && let Ok(cid) = Cid::from_str(pdc)
    {
        frame.prev_data = Some(cid);
    }
    let commit_cid = frame.commit;
    let prev_cid = prev_cid_str.as_ref().and_then(|s| Cid::from_str(s).ok());
    let mut all_cids: Vec<Cid> = block_cids_str
        .iter()
        .filter_map(|s| Cid::from_str(s).ok())
        .filter(|c| Some(*c) != prev_cid)
        .collect();
    if !all_cids.contains(&commit_cid) {
        all_cids.push(commit_cid);
    }
    if let Some(commit_bytes) = prefetched.get(&commit_cid)
        && let Some(rev) = extract_rev_from_commit_bytes(commit_bytes)
    {
        frame.rev = rev;
    }
    if let Some(ref pc) = prev_cid
        && let Some(prev_bytes) = prefetched.get(pc)
        && let Some(rev) = extract_rev_from_commit_bytes(prev_bytes)
    {
        frame.since = Some(rev);
    }
    let car_bytes = if !all_cids.is_empty() {
        let mut blocks = BTreeMap::new();
        let mut commit_bytes_for_car: Option<Bytes> = None;
        for cid in all_cids {
            if let Some(data) = prefetched.get(&cid) {
                if cid == commit_cid {
                    commit_bytes_for_car = Some(data.clone());
                } else {
                    blocks.insert(cid, data.clone());
                }
            }
        }
        write_car_blocks(commit_cid, commit_bytes_for_car, blocks).await?
    } else {
        Vec::new()
    };
    frame.blocks = car_bytes;
    let header = FrameHeader {
        op: 1,
        t: "#commit".to_string(),
    };
    let mut bytes = Vec::with_capacity(frame.blocks.len() + 512);
    serde_ipld_dagcbor::to_writer(&mut bytes, &header)?;
    serde_ipld_dagcbor::to_writer(&mut bytes, &frame)?;
    Ok(bytes)
}

pub fn format_info_frame(name: &str, message: Option<&str>) -> Result<Vec<u8>, anyhow::Error> {
    let header = FrameHeader {
        op: 1,
        t: "#info".to_string(),
    };
    let frame = InfoFrame {
        name: name.to_string(),
        message: message.map(String::from),
    };
    let mut bytes = Vec::with_capacity(128);
    serde_ipld_dagcbor::to_writer(&mut bytes, &header)?;
    serde_ipld_dagcbor::to_writer(&mut bytes, &frame)?;
    Ok(bytes)
}

pub fn format_error_frame(error: &str, message: Option<&str>) -> Result<Vec<u8>, anyhow::Error> {
    let header = ErrorFrameHeader { op: -1 };
    let frame = ErrorFrameBody {
        error: error.to_string(),
        message: message.map(String::from),
    };
    let mut bytes = Vec::with_capacity(128);
    serde_ipld_dagcbor::to_writer(&mut bytes, &header)?;
    serde_ipld_dagcbor::to_writer(&mut bytes, &frame)?;
    Ok(bytes)
}
