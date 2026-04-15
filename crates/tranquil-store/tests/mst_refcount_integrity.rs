mod common;

use std::sync::Arc;

use cid::Cid;
use common::{compact_by_liveness, tiny_blockstore_config};
use jacquard_repo::mst::Mst;
use jacquard_repo::storage::BlockStore;
use tranquil_store::blockstore::TranquilBlockStore;

fn cid_to_fixed(cid: &Cid) -> [u8; 36] {
    let bytes = cid.to_bytes();
    let mut arr = [0u8; 36];
    arr.copy_from_slice(&bytes[..36]);
    arr
}

fn make_record_bytes(seed: u32) -> Vec<u8> {
    serde_ipld_dagcbor::to_vec(&serde_json::json!({
        "$type": "app.bsky.feed.post",
        "text": format!("record {seed}"),
        "createdAt": "2026-01-01T00:00:00Z"
    }))
    .unwrap()
}

fn make_fake_commit_cid(counter: u32) -> Cid {
    let data = format!("commit-{counter}");
    let mh = multihash::Multihash::wrap(0x12, &{
        use sha2::Digest;
        sha2::Sha256::digest(data.as_bytes())
    })
    .unwrap();
    Cid::new_v1(0x71, mh)
}

async fn compute_obsolete_from_diff<S: BlockStore + Sync + Send + 'static>(
    old_mst: &Mst<S>,
    new_mst: &Mst<S>,
    old_commit_cid: Cid,
) -> Vec<Cid> {
    let diff = old_mst.diff(new_mst).await.unwrap();
    std::iter::once(old_commit_cid)
        .chain(diff.removed_mst_blocks.into_iter())
        .chain(diff.removed_cids.into_iter())
        .collect()
}

#[tokio::test]
async fn mst_shared_subtrees_survive_incremental_writes_compaction_restart() {
    let dir = tempfile::TempDir::new().unwrap();

    let mut commit_counter = 0u32;
    let final_node_cids: Vec<Cid>;

    {
        let store = Arc::new(TranquilBlockStore::open(tiny_blockstore_config(dir.path())).unwrap());

        let mut mst = Mst::new(store.clone());
        let mut root: Option<Cid> = None;
        let mut prev_commit = make_fake_commit_cid(commit_counter);
        commit_counter += 1;

        for i in 0..30u32 {
            let record_bytes = make_record_bytes(i);
            let record_cid = store.put(&record_bytes).await.unwrap();
            let key = format!("app.bsky.feed.post/{i:06}");
            mst = match root {
                None => mst.add(&key, record_cid).await.unwrap(),
                Some(r) => {
                    let loaded = Mst::load(store.clone(), r, None);
                    loaded.add(&key, record_cid).await.unwrap()
                }
            };
            let new_root = mst.persist().await.unwrap();

            if let Some(old_root) = root {
                let old_settled = Mst::load(store.clone(), old_root, None);
                let new_settled = Mst::load(store.clone(), new_root, None);

                let obsolete =
                    compute_obsolete_from_diff(&old_settled, &new_settled, prev_commit).await;
                let obsolete_fixed: Vec<[u8; 36]> = obsolete.iter().map(cid_to_fixed).collect();
                let s = store.clone();
                tokio::task::spawn_blocking(move || {
                    s.apply_commit_blocking(vec![], obsolete_fixed).unwrap();
                })
                .await
                .unwrap();
            }

            root = Some(new_root);
            prev_commit = make_fake_commit_cid(commit_counter);
            commit_counter += 1;

            if i % 5 == 0 {
                let s = store.clone();
                tokio::task::spawn_blocking(move || compact_by_liveness(&s))
                    .await
                    .unwrap();
            }
        }

        for i in 0..15u32 {
            let record_bytes = make_record_bytes(1000 + i);
            let record_cid = store.put(&record_bytes).await.unwrap();
            let key = format!("app.bsky.feed.like/{i:06}");
            let loaded = Mst::load(store.clone(), root.unwrap(), None);
            mst = loaded.add(&key, record_cid).await.unwrap();
            let new_root = mst.persist().await.unwrap();

            let old_settled = Mst::load(store.clone(), root.unwrap(), None);
            let new_settled = Mst::load(store.clone(), new_root, None);

            let obsolete =
                compute_obsolete_from_diff(&old_settled, &new_settled, prev_commit).await;
            let obsolete_fixed: Vec<[u8; 36]> = obsolete.iter().map(cid_to_fixed).collect();
            let s = store.clone();
            tokio::task::spawn_blocking(move || {
                s.apply_commit_blocking(vec![], obsolete_fixed).unwrap();
            })
            .await
            .unwrap();

            root = Some(new_root);
            prev_commit = make_fake_commit_cid(commit_counter);
            commit_counter += 1;

            if i % 3 == 0 {
                let s = store.clone();
                tokio::task::spawn_blocking(move || compact_by_liveness(&s))
                    .await
                    .unwrap();
            }
        }

        let final_settled = Mst::load(store.clone(), root.unwrap(), None);
        final_node_cids = final_settled.collect_node_cids().await.unwrap();

        final_node_cids.iter().for_each(|cid| {
            let fixed = cid_to_fixed(cid);
            let rc = store.block_index().get(&fixed).map(|e| e.refcount.raw());
            assert!(
                rc.is_some_and(|r| r > 0),
                "MST node {cid} has refcount {rc:?} before shutdown"
            );
        });

        let s = store.clone();
        tokio::task::spawn_blocking(move || {
            (0..100).for_each(|_| compact_by_liveness(&s));
        })
        .await
        .unwrap();

        final_node_cids.iter().for_each(|cid| {
            let fixed = cid_to_fixed(cid);
            let block = store.get_block_sync(&fixed).unwrap();
            assert!(
                block.is_some(),
                "MST node {cid} missing after compaction before shutdown"
            );
        });

        drop(store);
    }

    {
        let store = Arc::new(TranquilBlockStore::open(tiny_blockstore_config(dir.path())).unwrap());

        let missing: Vec<String> = final_node_cids
            .iter()
            .filter_map(|cid| {
                let fixed = cid_to_fixed(cid);
                match store.get_block_sync(&fixed) {
                    Ok(Some(_)) => None,
                    Ok(None) => {
                        let rc = store.block_index().get(&fixed).map(|e| e.refcount.raw());
                        Some(format!("{cid} missing, index refcount {rc:?}"))
                    }
                    Err(e) => Some(format!("{cid} error: {e}")),
                }
            })
            .collect();

        assert!(
            missing.is_empty(),
            "{} of {} MST nodes missing after reopen:\n{}",
            missing.len(),
            final_node_cids.len(),
            missing.join("\n"),
        );

        let refcount_issues: Vec<String> = final_node_cids
            .iter()
            .filter_map(|cid| {
                let fixed = cid_to_fixed(cid);
                let rc = store.block_index().get(&fixed).map(|e| e.refcount.raw());
                match rc {
                    Some(0) => Some(format!("{cid} refcount dropped to 0")),
                    None => Some(format!("{cid} not in index")),
                    _ => None,
                }
            })
            .collect();

        assert!(
            refcount_issues.is_empty(),
            "MST nodes with bad refcounts after reopen:\n{}",
            refcount_issues.join("\n"),
        );
    }
}
