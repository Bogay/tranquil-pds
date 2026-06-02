use std::collections::HashSet;

use cid::Cid;
use jacquard_repo::mst::NodeData;

use super::oracle::{hex_short, try_cid_to_fixed};
use crate::StorageIO;
use crate::blockstore::{CidBytes, TranquilBlockStore};
use crate::clock::Clock;

pub enum LookupResult {
    Found(Cid),
    NotFound,
    LostPath,
}

pub fn walk_mst_node_cids_tolerant<S: StorageIO + Send + Sync + 'static, C: Clock>(
    store: &TranquilBlockStore<S, C>,
    root: Cid,
    lost: &HashSet<CidBytes>,
) -> Result<Vec<CidBytes>, String> {
    let mut visited: HashSet<CidBytes> = HashSet::new();
    let mut to_visit: Vec<Cid> = vec![root];
    let mut result: Vec<CidBytes> = Vec::new();

    while let Some(cid) = to_visit.pop() {
        let cid_bytes = try_cid_to_fixed(&cid).map_err(|e| format!("cid format: {e}"))?;
        if !visited.insert(cid_bytes) {
            continue;
        }
        if lost.contains(&cid_bytes) {
            continue;
        }
        let node = read_node(store, &cid_bytes)?;
        result.push(cid_bytes);
        if let Some(left) = node.left {
            to_visit.push(left);
        }
        node.entries
            .into_iter()
            .filter_map(|e| e.tree)
            .for_each(|t| to_visit.push(t));
    }

    Ok(result)
}

pub fn mst_get_tolerant<S: StorageIO + Send + Sync + 'static, C: Clock>(
    store: &TranquilBlockStore<S, C>,
    root: Cid,
    target: &str,
    lost: &HashSet<CidBytes>,
) -> Result<LookupResult, String> {
    let mut cursor = root;
    loop {
        let cursor_bytes = try_cid_to_fixed(&cursor).map_err(|e| format!("cid format: {e}"))?;
        if lost.contains(&cursor_bytes) {
            return Ok(LookupResult::LostPath);
        }
        let node = read_node(store, &cursor_bytes)?;
        let keys = full_keys(&node)?;
        let index = keys
            .iter()
            .position(|k| k.as_str() >= target)
            .unwrap_or(keys.len());
        if index < keys.len() && keys[index] == target {
            return Ok(LookupResult::Found(node.entries[index].value));
        }
        let subtree = match index {
            0 => node.left,
            n => node.entries[n - 1].tree,
        };
        match subtree {
            Some(child) => cursor = child,
            None => return Ok(LookupResult::NotFound),
        }
    }
}

pub fn walk_mst_entries_tolerant<S: StorageIO + Send + Sync + 'static, C: Clock>(
    store: &TranquilBlockStore<S, C>,
    root: Cid,
    lost: &HashSet<CidBytes>,
) -> Result<Option<Vec<(String, CidBytes)>>, String> {
    let mut to_visit: Vec<Cid> = vec![root];
    let mut visited: HashSet<CidBytes> = HashSet::new();
    let mut entries: Vec<(String, CidBytes)> = Vec::new();

    while let Some(cid) = to_visit.pop() {
        let cid_bytes = try_cid_to_fixed(&cid).map_err(|e| format!("cid format: {e}"))?;
        if !visited.insert(cid_bytes) {
            continue;
        }
        if lost.contains(&cid_bytes) {
            return Ok(None);
        }
        let node = match store.get_block_sync(&cid_bytes) {
            Ok(Some(bytes)) => match serde_ipld_dagcbor::from_slice::<NodeData>(&bytes) {
                Ok(n) => n,
                Err(_) => return Ok(None),
            },
            Ok(None) => return Ok(None),
            Err(_) => return Ok(None),
        };
        let keys = full_keys(&node)?;
        keys.iter().zip(node.entries.iter()).try_for_each(
            |(key, entry)| -> Result<(), String> {
                let value =
                    try_cid_to_fixed(&entry.value).map_err(|e| format!("cid format: {e}"))?;
                entries.push((key.clone(), value));
                Ok(())
            },
        )?;
        if let Some(left) = node.left {
            to_visit.push(left);
        }
        node.entries
            .iter()
            .filter_map(|e| e.tree)
            .for_each(|t| to_visit.push(t));
    }

    Ok(Some(entries))
}

fn read_node<S: StorageIO + Send + Sync + 'static, C: Clock>(
    store: &TranquilBlockStore<S, C>,
    cid_bytes: &CidBytes,
) -> Result<NodeData, String> {
    let bytes = match store.get_block_sync(cid_bytes) {
        Ok(Some(b)) => b,
        Ok(None) => return Err(format!("missing block: {}", hex_short(cid_bytes))),
        Err(e) => return Err(format!("read {}: {e}", hex_short(cid_bytes))),
    };
    serde_ipld_dagcbor::from_slice(&bytes)
        .map_err(|e| format!("deserialize node {}: {e}", hex_short(cid_bytes)))
}

fn full_keys(node: &NodeData) -> Result<Vec<String>, String> {
    node.entries
        .iter()
        .scan(String::new(), |last_key, entry| {
            let suffix = match std::str::from_utf8(&entry.key_suffix) {
                Ok(s) => s,
                Err(e) => return Some(Err(format!("invalid utf-8 in key suffix: {e}"))),
            };
            let prefix_len = entry.prefix_len as usize;
            if prefix_len > last_key.len() {
                return Some(Err(format!(
                    "prefix length {} exceeds last key length {}",
                    prefix_len,
                    last_key.len()
                )));
            }
            let full = format!("{}{}", &last_key[..prefix_len], suffix);
            *last_key = full.clone();
            Some(Ok(full))
        })
        .collect()
}
