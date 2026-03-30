mod common;

use std::collections::HashSet;

use rayon::prelude::*;
use tranquil_store::blockstore::{CidBytes, TranquilBlockStore};
use tranquil_store::{sim_seed_range, sim_single_seed};

use common::{
    advance_epoch, block_data, collect_all_dead, compact_all_sealed, default_blockstore_config,
    small_blockstore_config, test_cid, with_runtime,
};

#[test]
fn sim_reachability_detects_known_leaks() {
    with_runtime(|| {
        let seed_range = match sim_single_seed() {
            Some(s) => s..s + 1,
            None => 0..sim_seed_range().end.min(1000),
        };

        seed_range.into_par_iter().for_each(|seed| {
            let dir = tempfile::TempDir::new().unwrap();
            let store = TranquilBlockStore::open(default_blockstore_config(dir.path())).unwrap();

            let reachable_count = ((seed % 30) as u32) + 10;
            let leaked_count = ((seed % 10) as u32) + 3;

            let reachable_cids: Vec<CidBytes> = (0..reachable_count).map(test_cid).collect();
            let leaked_cids: Vec<CidBytes> = (reachable_count..reachable_count + leaked_count)
                .map(test_cid)
                .collect();

            let all_blocks: Vec<(CidBytes, Vec<u8>)> = reachable_cids
                .iter()
                .chain(leaked_cids.iter())
                .map(|&cid| {
                    (
                        cid,
                        block_data(u32::from_le_bytes(cid[4..8].try_into().unwrap())),
                    )
                })
                .collect();
            store.put_blocks_blocking(all_blocks).unwrap();

            let reachable_set: HashSet<CidBytes> = reachable_cids.iter().copied().collect();
            let (leaked, live_scanned) = store
                .find_leaked_refcounts(|cid| reachable_set.contains(cid))
                .unwrap();

            assert_eq!(
                live_scanned,
                (reachable_count + leaked_count) as u64,
                "seed={seed} must scan all live blocks"
            );

            let leaked_found: HashSet<CidBytes> = leaked.iter().map(|(cid, _)| *cid).collect();
            leaked_cids.iter().for_each(|cid| {
                assert!(
                    leaked_found.contains(cid),
                    "seed={seed} leaked block must be detected by reachability walk"
                );
            });
            reachable_cids.iter().for_each(|cid| {
                assert!(
                    !leaked_found.contains(cid),
                    "seed={seed} reachable block must NOT be flagged as leaked"
                );
            });
        });
    });
}

#[test]
fn sim_reachability_repair_makes_leaked_blocks_gc_eligible() {
    with_runtime(|| {
        let seed_range = match sim_single_seed() {
            Some(s) => s..s + 1,
            None => 0..sim_seed_range().end.min(500),
        };

        seed_range.into_par_iter().for_each(|seed| {
            let dir = tempfile::TempDir::new().unwrap();
            let store = TranquilBlockStore::open(default_blockstore_config(dir.path())).unwrap();

            let reachable_count = ((seed % 20) as u32) + 5;
            let leaked_count = ((seed % 8) as u32) + 2;

            let reachable_cids: Vec<CidBytes> = (0..reachable_count).map(test_cid).collect();
            let leaked_cids: Vec<CidBytes> = (reachable_count..reachable_count + leaked_count)
                .map(test_cid)
                .collect();

            let all_blocks: Vec<(CidBytes, Vec<u8>)> = reachable_cids
                .iter()
                .chain(leaked_cids.iter())
                .map(|&cid| {
                    (
                        cid,
                        block_data(u32::from_le_bytes(cid[4..8].try_into().unwrap())),
                    )
                })
                .collect();
            store.put_blocks_blocking(all_blocks).unwrap();

            let reachable_set: HashSet<CidBytes> = reachable_cids.iter().copied().collect();
            let (leaked, _) = store
                .find_leaked_refcounts(|cid| reachable_set.contains(cid))
                .unwrap();

            assert_eq!(
                leaked.len(),
                leaked_count as usize,
                "seed={seed} must detect all leaked blocks"
            );

            let repaired = store.repair_leaked_refcounts(&leaked).unwrap();
            assert_eq!(
                repaired, leaked_count as u64,
                "seed={seed} must repair all leaked blocks"
            );

            advance_epoch(&store);
            std::thread::sleep(std::time::Duration::from_millis(5));

            let dead = collect_all_dead(&store);
            leaked_cids.iter().for_each(|cid| {
                assert!(
                    dead.contains(cid),
                    "seed={seed} repaired leaked block must now be GC-eligible"
                );
            });
            reachable_cids.iter().for_each(|cid| {
                assert!(
                    !dead.contains(cid),
                    "seed={seed} reachable block must NOT be GC-eligible"
                );
            });
        });
    });
}

#[test]
fn sim_crash_retry_scenario_produces_leaked_refcounts() {
    with_runtime(|| {
        let seed_range = match sim_single_seed() {
            Some(s) => s..s + 1,
            None => 0..sim_seed_range().end.min(500),
        };

        seed_range.into_par_iter().for_each(|seed| {
            let dir = tempfile::TempDir::new().unwrap();
            let store = TranquilBlockStore::open(default_blockstore_config(dir.path())).unwrap();

            let shared_count = ((seed % 15) as u32) + 5;
            let shared_cids: Vec<CidBytes> = (0..shared_count).map(test_cid).collect();

            let shared_blocks: Vec<(CidBytes, Vec<u8>)> = shared_cids
                .iter()
                .map(|&cid| {
                    (
                        cid,
                        block_data(u32::from_le_bytes(cid[4..8].try_into().unwrap())),
                    )
                })
                .collect();
            store.put_blocks_blocking(shared_blocks.clone()).unwrap();

            let retry_count = ((seed % 3) as usize) + 1;
            (0..retry_count).for_each(|_| {
                store.put_blocks_blocking(shared_blocks.clone()).unwrap();
            });

            let reachable_set: HashSet<CidBytes> = shared_cids.iter().copied().collect();
            let (leaked, live_scanned) = store
                .find_leaked_refcounts(|cid| reachable_set.contains(cid))
                .unwrap();

            assert_eq!(
                live_scanned, shared_count as u64,
                "seed={seed} all blocks are reachable, so live_scanned should equal total"
            );
            assert!(
                leaked.is_empty(),
                "seed={seed} all blocks are reachable, none should be leaked"
            );

            let extra_count = ((seed % 5) as u32) + 2;
            let extra_cids: Vec<CidBytes> = (shared_count..shared_count + extra_count)
                .map(test_cid)
                .collect();
            let extra_blocks: Vec<(CidBytes, Vec<u8>)> = extra_cids
                .iter()
                .map(|&cid| {
                    (
                        cid,
                        block_data(u32::from_le_bytes(cid[4..8].try_into().unwrap())),
                    )
                })
                .collect();
            store.put_blocks_blocking(extra_blocks).unwrap();

            let (leaked_after, _) = store
                .find_leaked_refcounts(|cid| reachable_set.contains(cid))
                .unwrap();

            let leaked_cid_set: HashSet<CidBytes> =
                leaked_after.iter().map(|(cid, _)| *cid).collect();
            extra_cids.iter().for_each(|cid| {
                assert!(
                    leaked_cid_set.contains(cid),
                    "seed={seed} extra block not in reachable set must be detected as leaked"
                );
            });

            let repaired = store.repair_leaked_refcounts(&leaked_after).unwrap();
            assert_eq!(
                repaired, extra_count as u64,
                "seed={seed} must repair exactly the extra blocks"
            );
        });
    });
}

#[test]
fn sim_reachability_after_compaction() {
    with_runtime(|| {
        let seed_range = match sim_single_seed() {
            Some(s) => s..s + 1,
            None => 0..sim_seed_range().end.min(200),
        };

        seed_range.into_par_iter().for_each(|seed| {
            let dir = tempfile::TempDir::new().unwrap();
            let store = TranquilBlockStore::open(small_blockstore_config(dir.path())).unwrap();

            let total = ((seed % 40) as u32) + 20;
            let blocks: Vec<(CidBytes, Vec<u8>)> =
                (0..total).map(|i| (test_cid(i), block_data(i))).collect();
            blocks.chunks(10).for_each(|chunk| {
                store.put_blocks_blocking(chunk.to_vec()).unwrap();
            });

            let kill_mask: HashSet<u32> = (0..total)
                .filter(|i| i.wrapping_mul(2654435761).wrapping_add(seed as u32) % 3 == 0)
                .collect();
            let kill_cids: Vec<CidBytes> = kill_mask.iter().map(|&i| test_cid(i)).collect();
            store.apply_commit_blocking(vec![], kill_cids).unwrap();
            advance_epoch(&store);
            std::thread::sleep(std::time::Duration::from_millis(5));

            compact_all_sealed(&store);

            let reachable: HashSet<CidBytes> = (0..total)
                .filter(|i| !kill_mask.contains(i))
                .map(test_cid)
                .collect();

            let (leaked, _) = store
                .find_leaked_refcounts(|cid| reachable.contains(cid))
                .unwrap();

            assert!(
                leaked.is_empty(),
                "seed={seed} no leaked refcounts expected after proper delete+compact cycle, found {}",
                leaked.len()
            );

            reachable.iter().for_each(|cid| {
                let data = store.get_block_sync(cid).unwrap();
                assert!(
                    data.is_some(),
                    "seed={seed} reachable block must be readable after compaction"
                );
            });
        });
    });
}

#[test]
fn sim_reachability_with_dedup_refcounts() {
    with_runtime(|| {
        let seed_range = match sim_single_seed() {
            Some(s) => s..s + 1,
            None => 0..sim_seed_range().end.min(200),
        };

        seed_range.into_par_iter().for_each(|seed| {
            let dir = tempfile::TempDir::new().unwrap();
            let store = TranquilBlockStore::open(default_blockstore_config(dir.path())).unwrap();

            let block_count = ((seed % 20) as u32) + 5;
            let cids: Vec<CidBytes> = (0..block_count).map(test_cid).collect();

            let dup_count = ((seed % 4) as usize) + 2;
            (0..dup_count).for_each(|_| {
                let blocks: Vec<(CidBytes, Vec<u8>)> = cids
                    .iter()
                    .map(|&cid| {
                        (
                            cid,
                            block_data(u32::from_le_bytes(cid[4..8].try_into().unwrap())),
                        )
                    })
                    .collect();
                store.put_blocks_blocking(blocks).unwrap();
            });

            let partially_deleted: Vec<u32> = (0..block_count).filter(|i| i % 2 == 0).collect();
            partially_deleted.iter().for_each(|&i| {
                (0..dup_count - 1).for_each(|_| {
                    store
                        .apply_commit_blocking(vec![], vec![test_cid(i)])
                        .unwrap();
                });
            });

            let reachable: HashSet<CidBytes> = cids.iter().copied().collect();
            let (leaked, _) = store
                .find_leaked_refcounts(|cid| reachable.contains(cid))
                .unwrap();

            assert!(
                leaked.is_empty(),
                "seed={seed} all blocks are still reachable (refcount>0), none should be leaked"
            );

            cids.iter().for_each(|cid| {
                let data = store.get_block_sync(cid).unwrap();
                assert!(
                    data.is_some(),
                    "seed={seed} block with remaining refcount must be readable"
                );
            });
        });
    });
}
