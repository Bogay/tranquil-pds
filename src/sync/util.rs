use crate::state::AppState;
use crate::sync::firehose::SequencedEvent;
use crate::sync::frame::{AccountFrame, CommitFrame, FrameHeader, IdentityFrame, SyncFrame};
use bytes::Bytes;
use cid::Cid;
use iroh_car::{CarHeader, CarWriter};
use jacquard_repo::commit::Commit;
use jacquard_repo::storage::BlockStore;
use std::collections::{BTreeMap, HashMap};
use std::io::Cursor;
use std::str::FromStr;
use tokio::io::AsyncWriteExt;

fn extract_rev_from_commit_bytes(commit_bytes: &[u8]) -> Option<String> {
    Commit::from_cbor(commit_bytes).ok().map(|c| c.rev().to_string())
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
            writer.write(cid, data.as_ref()).await
                .map_err(|e| anyhow::anyhow!("writing block {}: {}", cid, e))?;
        }
    }
    if let Some(data) = commit_bytes {
        writer.write(commit_cid, data.as_ref()).await
            .map_err(|e| anyhow::anyhow!("writing commit block: {}", e))?;
    }
    writer.finish().await
        .map_err(|e| anyhow::anyhow!("finalizing CAR: {}", e))?;
    buffer.flush().await
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
    let mut bytes = Vec::new();
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
    let mut bytes = Vec::new();
    serde_ipld_dagcbor::to_writer(&mut bytes, &header)?;
    serde_ipld_dagcbor::to_writer(&mut bytes, &frame)?;
    Ok(bytes)
}

async fn format_sync_event(
    state: &AppState,
    event: &SequencedEvent,
) -> Result<Vec<u8>, anyhow::Error> {
    let commit_cid_str = event.commit_cid.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Sync event missing commit_cid"))?;
    let commit_cid = Cid::from_str(commit_cid_str)?;
    let commit_bytes = state.block_store.get(&commit_cid).await?
        .ok_or_else(|| anyhow::anyhow!("Commit block not found"))?;
    let rev = extract_rev_from_commit_bytes(&commit_bytes)
        .ok_or_else(|| anyhow::anyhow!("Could not extract rev from commit"))?;
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
    let mut bytes = Vec::new();
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
    let mut frame: CommitFrame = event.try_into()
        .map_err(|e| anyhow::anyhow!("Invalid event: {}", e))?;
    if let Some(ref pdc) = prev_data_cid_str {
        if let Ok(cid) = Cid::from_str(pdc) {
            frame.prev_data = Some(cid);
        }
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
    if let Some(ref pc) = prev_cid {
        if let Ok(Some(prev_bytes)) = state.block_store.get(pc).await {
            if let Some(rev) = extract_rev_from_commit_bytes(&prev_bytes) {
                frame.since = Some(rev);
            }
        }
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
    let mut bytes = Vec::new();
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
        if let Some(ref commit_cid_str) = event.commit_cid {
            if let Ok(cid) = Cid::from_str(commit_cid_str) {
                all_cids.push(cid);
            }
        }
        if let Some(ref prev_cid_str) = event.prev_cid {
            if let Ok(cid) = Cid::from_str(prev_cid_str) {
                all_cids.push(cid);
            }
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
    let mut blocks_map = HashMap::new();
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
    let commit_cid_str = event.commit_cid.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Sync event missing commit_cid"))?;
    let commit_cid = Cid::from_str(commit_cid_str)?;
    let commit_bytes = prefetched.get(&commit_cid)
        .ok_or_else(|| anyhow::anyhow!("Commit block not found in prefetched"))?;
    let rev = extract_rev_from_commit_bytes(commit_bytes)
        .ok_or_else(|| anyhow::anyhow!("Could not extract rev from commit"))?;
    let car_bytes = futures::executor::block_on(
        write_car_blocks(commit_cid, Some(commit_bytes.clone()), BTreeMap::new())
    )?;
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
    let mut frame: CommitFrame = event.try_into()
        .map_err(|e| anyhow::anyhow!("Invalid event: {}", e))?;
    if let Some(ref pdc) = prev_data_cid_str {
        if let Ok(cid) = Cid::from_str(pdc) {
            frame.prev_data = Some(cid);
        }
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
    if let Some(commit_bytes) = prefetched.get(&commit_cid) {
        if let Some(rev) = extract_rev_from_commit_bytes(commit_bytes) {
            frame.rev = rev;
        }
    }
    if let Some(ref pc) = prev_cid {
        if let Some(prev_bytes) = prefetched.get(pc) {
            if let Some(rev) = extract_rev_from_commit_bytes(prev_bytes) {
                frame.since = Some(rev);
            }
        }
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
    let mut bytes = Vec::new();
    serde_ipld_dagcbor::to_writer(&mut bytes, &header)?;
    serde_ipld_dagcbor::to_writer(&mut bytes, &frame)?;
    Ok(bytes)
}
