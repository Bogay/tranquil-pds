use std::collections::HashMap;

use cid::Cid;

use super::op::{CollectionName, RecordKey};
use crate::blockstore::CidBytes;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("unexpected CID encoding: got {actual} bytes, expected 36 for sha256 CIDv1")]
pub struct CidFormatError {
    pub actual: usize,
}

#[derive(Debug, Default)]
pub struct Oracle {
    live: HashMap<(CollectionName, RecordKey), CidBytes>,
    current_root: Option<Cid>,
    mst_node_cids: Vec<CidBytes>,
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
