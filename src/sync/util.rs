use crate::state::AppState;
use crate::sync::firehose::SequencedEvent;
use crate::sync::frame::{CommitFrame, Frame, FrameData};
use cid::Cid;
use jacquard_repo::car::write_car_bytes;
use jacquard_repo::storage::BlockStore;
use std::str::FromStr;

pub async fn format_event_for_sending(
    state: &AppState,
    event: SequencedEvent,
) -> Result<Vec<u8>, anyhow::Error> {
    let block_cids_str = event.blocks_cids.clone().unwrap_or_default();
    let mut frame: CommitFrame = event.try_into()
        .map_err(|e| anyhow::anyhow!("Invalid event: {}", e))?;

    let car_bytes = if !block_cids_str.is_empty() {
        let mut blocks = std::collections::BTreeMap::new();

        for cid_str in block_cids_str {
            let cid = Cid::from_str(&cid_str)?;
            let data = state
                .block_store
                .get(&cid)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Block not found: {}", cid))?;
            blocks.insert(cid, data);
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
