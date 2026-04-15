use std::collections::HashMap;

use cid::Cid;

use super::op::{CollectionName, RecordKey};
use crate::blockstore::CidBytes;

#[derive(Debug, Default)]
pub struct Oracle {
    live: HashMap<(CollectionName, RecordKey), CidBytes>,
    current_root: Option<Cid>,
    mst_node_cids: Vec<Cid>,
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

    pub fn set_node_cids(&mut self, cids: Vec<Cid>) {
        self.mst_node_cids = cids;
    }

    pub fn mst_node_cids(&self) -> &[Cid] {
        &self.mst_node_cids
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
            .map(|cid| (format!("mst {cid}"), cid_to_fixed(cid)));
        let records = self
            .live_records()
            .map(|(c, r, v)| (format!("record {}/{}", c.0, r.0), *v));
        nodes.chain(records).collect()
    }
}

pub(super) fn cid_to_fixed(cid: &Cid) -> CidBytes {
    let bytes = cid.to_bytes();
    debug_assert_eq!(bytes.len(), 36, "expected 36 byte CIDv1+sha256");
    let mut arr = [0u8; 36];
    arr.copy_from_slice(&bytes[..36]);
    arr
}
