use crate::state::AppState;
use crate::sync::firehose::SequencedEvent;
use crate::sync::frame::{CommitFrame, Frame, FrameData};
use bytes::Bytes;
use cid::Cid;
use jacquard_repo::car::write_car_bytes;
use jacquard_repo::storage::BlockStore;
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;

pub async fn format_event_for_sending(
    state: &AppState,
    event: SequencedEvent,
) -> Result<Vec<u8>, anyhow::Error> {
    let block_cids_str = event.blocks_cids.clone().unwrap_or_default();
    let mut frame: CommitFrame = event.try_into()
        .map_err(|e| anyhow::anyhow!("Invalid event: {}", e))?;

    let car_bytes = if !block_cids_str.is_empty() {
        let cids: Vec<Cid> = block_cids_str
            .iter()
            .filter_map(|s| Cid::from_str(s).ok())
            .collect();

        let fetched = state.block_store.get_many(&cids).await?;

        let mut blocks = std::collections::BTreeMap::new();
        for (cid, data_opt) in cids.into_iter().zip(fetched.into_iter()) {
            if let Some(data) = data_opt {
                blocks.insert(cid, data);
            }
        }

        let root = Cid::from_str(&frame.commit)?;
        write_car_bytes(root, blocks).await?
    } else {
        Vec::new()
    };
    frame.blocks = car_bytes;

    let frame = Frame {
        op: 1,
        data: FrameData::Commit(Box::new(frame)),
    };

    let mut bytes = Vec::new();
    serde_ipld_dagcbor::to_writer(&mut bytes, &frame)?;
    Ok(bytes)
}

pub async fn prefetch_blocks_for_events(
    state: &AppState,
    events: &[SequencedEvent],
) -> Result<HashMap<Cid, Bytes>, anyhow::Error> {
    let mut all_cids: Vec<Cid> = Vec::new();

    for event in events {
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

pub async fn format_event_with_prefetched_blocks(
    event: SequencedEvent,
    prefetched: &HashMap<Cid, Bytes>,
) -> Result<Vec<u8>, anyhow::Error> {
    let block_cids_str = event.blocks_cids.clone().unwrap_or_default();
    let mut frame: CommitFrame = event.try_into()
        .map_err(|e| anyhow::anyhow!("Invalid event: {}", e))?;

    let car_bytes = if !block_cids_str.is_empty() {
        let cids: Vec<Cid> = block_cids_str
            .iter()
            .filter_map(|s| Cid::from_str(s).ok())
            .collect();

        let mut blocks = BTreeMap::new();
        for cid in cids {
            if let Some(data) = prefetched.get(&cid) {
                blocks.insert(cid, data.clone());
            }
        }

        let root = Cid::from_str(&frame.commit)?;
        write_car_bytes(root, blocks).await?
    } else {
        Vec::new()
    };
    frame.blocks = car_bytes;

    let frame = Frame {
        op: 1,
        data: FrameData::Commit(Box::new(frame)),
    };

    let mut bytes = Vec::new();
    serde_ipld_dagcbor::to_writer(&mut bytes, &frame)?;
    Ok(bytes)
}
