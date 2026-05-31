use std::sync::Arc;

use cid::Cid;
use jacquard_repo::error::RepoError;
use jacquard_repo::mst::Mst;
use jacquard_repo::storage::MemoryBlockStore;

use crate::clock::Clock;
use crate::io::StorageIO;

use super::store::{TranquilBlockStore, cid_to_bytes};
use super::types::CidBytes;

const REPAIR_FILE_BYTE_BUDGET: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepairOutcome {
    pub nodes_total: usize,
    pub nodes_repaired: u64,
}

fn rebuild_err(context: &str, e: impl std::fmt::Display) -> RepoError {
    RepoError::storage(std::io::Error::other(format!("{context}: {e}")))
}

async fn rebuild_node_blocks(
    entries: Vec<(String, Cid)>,
    expected_root: Cid,
) -> Result<Vec<(CidBytes, Vec<u8>)>, RepoError> {
    let scratch = Arc::new(MemoryBlockStore::new());
    let mut mst = Mst::new(scratch);
    for (key, cid) in &entries {
        mst.add_mut(key.as_str(), *cid)
            .await
            .map_err(|e| rebuild_err("mst rebuild add", e))?;
    }

    let (root, blocks) = mst
        .collect_blocks()
        .await
        .map_err(|e| rebuild_err("mst collect_blocks", e))?;

    if root != expected_root {
        return Err(RepoError::storage(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "rebuilt MST root {root} does not match expected root {expected_root}, refusing to repair"
            ),
        )));
    }

    blocks
        .into_iter()
        .map(|(cid, bytes)| Ok((cid_to_bytes(&cid)?, bytes.to_vec())))
        .collect()
}

fn batch_by_bytes(blocks: Vec<(CidBytes, Vec<u8>)>) -> Vec<Vec<(CidBytes, Vec<u8>)>> {
    blocks
        .into_iter()
        .fold(
            (Vec::<Vec<(CidBytes, Vec<u8>)>>::new(), 0usize),
            |(mut batches, current_bytes), item| {
                let item_len = item.1.len();
                match batches.last_mut() {
                    Some(last) if current_bytes + item_len <= REPAIR_FILE_BYTE_BUDGET => {
                        last.push(item);
                        (batches, current_bytes + item_len)
                    }
                    _ => {
                        batches.push(vec![item]);
                        (batches, item_len)
                    }
                }
            },
        )
        .0
}

pub async fn rebuild_and_repair_mst<S, C>(
    store: &TranquilBlockStore<S, C>,
    entries: &[(String, Cid)],
    expected_root: Cid,
) -> Result<RepairOutcome, RepoError>
where
    S: StorageIO + Send + Sync + 'static,
    C: Clock,
{
    let store = store.clone();
    let entries = entries.to_vec();
    tokio::task::spawn_blocking(move || -> Result<RepairOutcome, RepoError> {
        let handle = tokio::runtime::Handle::current();
        let node_blocks = handle.block_on(rebuild_node_blocks(entries, expected_root))?;
        let nodes_total = node_blocks.len();

        let to_repair: Vec<(CidBytes, Vec<u8>)> = node_blocks
            .into_iter()
            .filter(|(cid, _)| !matches!(store.get_block_sync(cid), Ok(Some(_))))
            .collect();

        let nodes_repaired = batch_by_bytes(to_repair)
            .into_iter()
            .try_fold(0u64, |acc, batch| store.repair_blocks(batch).map(|n| acc + n))
            .map_err(|e| rebuild_err("repair_blocks", e))?;

        Ok(RepairOutcome {
            nodes_total,
            nodes_repaired,
        })
    })
    .await
    .map_err(RepoError::task_failed)?
}
