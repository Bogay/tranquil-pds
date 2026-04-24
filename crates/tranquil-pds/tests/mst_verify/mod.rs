use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use cid::Cid;
use jacquard_repo::storage::MemoryBlockStore;
use tranquil_db_traits::{EventBlockInline, EventBlocks, SequencedEvent};

pub fn extract_event_blocks(event: &SequencedEvent) -> Result<&[EventBlockInline], String> {
    match event.blocks.as_ref() {
        Some(EventBlocks::Inline(v)) => Ok(v.as_slice()),
        Some(EventBlocks::LegacyCids(_)) => Err("legacy cids, not inline".into()),
        None => Err("event missing blocks".into()),
    }
}

pub fn inline_to_store(inline: &[EventBlockInline]) -> Arc<MemoryBlockStore> {
    let map: BTreeMap<Cid, Bytes> = inline
        .iter()
        .map(|b| {
            let cid = Cid::read_bytes(b.cid_bytes.as_slice()).expect("valid cid bytes");
            (cid, Bytes::from(b.data.clone()))
        })
        .collect();
    Arc::new(MemoryBlockStore::new_from_blocks(map))
}
