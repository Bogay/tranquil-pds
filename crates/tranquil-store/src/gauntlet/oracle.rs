use std::collections::{HashMap, HashSet};

use cid::Cid;

use super::op::{CollectionName, EventKind, RecordKey};
use crate::blockstore::CidBytes;
use crate::eventlog::{EventSequence, SegmentId};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("unexpected CID encoding: got {actual} bytes, expected 36 for sha256 CIDv1")]
pub struct CidFormatError {
    pub actual: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventExpectation {
    pub seq: EventSequence,
    pub timestamp_us: u64,
    pub kind: EventKind,
    pub did_hash: u32,
    pub segment: SegmentId,
}

#[derive(Debug, Default)]
pub struct Oracle {
    live: HashMap<(CollectionName, RecordKey), CidBytes>,
    current_root: Option<Cid>,
    mst_node_cids: Vec<CidBytes>,
    synced_events: Vec<EventExpectation>,
    unsynced_events: Vec<EventExpectation>,
    last_synced_seq: Option<EventSequence>,
    last_retention_cutoff_us: Option<u64>,
    last_retention_active_segment: Option<SegmentId>,
    lost_blocks: HashSet<CidBytes>,
}

impl Oracle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(
        &mut self,
        coll: CollectionName,
        rkey: RecordKey,
        record_cid: CidBytes,
    ) -> Option<CidBytes> {
        self.live.insert((coll, rkey), record_cid)
    }

    pub fn delete(&mut self, coll: &CollectionName, rkey: &RecordKey) -> Option<CidBytes> {
        self.live.remove(&(coll.clone(), rkey.clone()))
    }

    pub fn contains_record(&self, coll: &CollectionName, rkey: &RecordKey) -> bool {
        self.live.contains_key(&(coll.clone(), rkey.clone()))
    }

    pub fn expected_record_cid(&self, coll: &CollectionName, rkey: &RecordKey) -> Option<CidBytes> {
        self.live.get(&(coll.clone(), rkey.clone())).copied()
    }

    pub fn set_root(&mut self, root: Cid) {
        self.current_root = Some(root);
    }

    pub fn root(&self) -> Option<Cid> {
        self.current_root
    }

    pub fn set_mst_node_cids(&mut self, cids: Vec<CidBytes>) {
        self.mst_node_cids = cids;
    }

    pub fn clear_mst_state(&mut self) {
        self.current_root = None;
        self.mst_node_cids.clear();
    }

    pub fn live_records(&self) -> impl Iterator<Item = (&CollectionName, &RecordKey, &CidBytes)> {
        self.live.iter().map(|((c, r), v)| (c, r, v))
    }

    pub fn live_count(&self) -> usize {
        self.live.len()
    }

    pub fn live_cids_labeled(&self) -> Vec<(String, CidBytes)> {
        let nodes = self
            .mst_node_cids
            .iter()
            .map(|bytes| (format!("mst {}", hex_short(bytes)), *bytes));
        let records = self
            .live_records()
            .map(|(c, r, v)| (format!("record {}/{}", c.0, r.0), *v));
        nodes.chain(records).collect()
    }

    pub fn record_event_append(&mut self, event: EventExpectation) {
        self.unsynced_events.push(event);
    }

    pub fn mark_blocks_lost(&mut self, cids: impl IntoIterator<Item = CidBytes>) -> usize {
        let added: HashSet<CidBytes> = cids.into_iter().collect();
        let added_count = added.len();
        self.live
            .retain(|_, record_cid| !added.contains(record_cid));
        self.lost_blocks.extend(added);
        added_count
    }

    pub fn lost_blocks(&self) -> &HashSet<CidBytes> {
        &self.lost_blocks
    }

    pub fn is_block_lost(&self, cid: &CidBytes) -> bool {
        self.lost_blocks.contains(cid)
    }

    pub fn has_lost_blocks(&self) -> bool {
        !self.lost_blocks.is_empty()
    }

    pub fn record_event_sync(&mut self, synced_through: EventSequence) {
        let (promoted, remaining): (Vec<_>, Vec<_>) = self
            .unsynced_events
            .drain(..)
            .partition(|e| e.seq <= synced_through);
        self.synced_events.extend(promoted);
        self.unsynced_events = remaining;
        self.last_synced_seq = Some(synced_through);
    }

    pub fn record_crash(&mut self) {
        self.unsynced_events.clear();
    }

    pub fn forget_events_in_segments(&mut self, lost: &HashSet<SegmentId>) {
        if lost.is_empty() {
            return;
        }
        self.synced_events.retain(|e| !lost.contains(&e.segment));
        self.unsynced_events.retain(|e| !lost.contains(&e.segment));
    }

    pub fn record_retention(&mut self, cutoff_us: u64, active_segment: Option<SegmentId>) {
        self.synced_events.retain(|e| e.timestamp_us >= cutoff_us);
        self.last_retention_cutoff_us = Some(cutoff_us);
        self.last_retention_active_segment = active_segment;
    }

    pub fn synced_events(&self) -> &[EventExpectation] {
        &self.synced_events
    }

    pub fn unsynced_events(&self) -> &[EventExpectation] {
        &self.unsynced_events
    }

    pub fn last_synced_seq(&self) -> Option<EventSequence> {
        self.last_synced_seq
    }

    pub fn last_retention_cutoff_us(&self) -> Option<u64> {
        self.last_retention_cutoff_us
    }

    pub fn last_retention_active_segment(&self) -> Option<SegmentId> {
        self.last_retention_active_segment
    }
}

pub(super) fn try_cid_to_fixed(cid: &Cid) -> Result<CidBytes, CidFormatError> {
    let bytes = cid.to_bytes();
    let actual = bytes.len();
    bytes.try_into().map_err(|_| CidFormatError { actual })
}

pub(super) fn hex_short(cid: &CidBytes) -> String {
    cid[cid.len() - 6..]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
