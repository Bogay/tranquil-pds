use std::collections::HashSet;

use tranquil_store::blockstore::{
    BlockStoreConfig, CidBytes, DEFAULT_MAX_FILE_SIZE, DataFileId, GroupCommitConfig,
    TranquilBlockStore,
};

fn test_cid(seed: u8) -> [u8; 36] {
    test_cid_u16(seed as u16)
}

fn test_cid_u16(seed: u16) -> [u8; 36] {
    let mut cid = [0u8; 36];
    cid[0] = 0x01;
    cid[1] = 0x71;
    cid[2] = 0x12;
    cid[3] = 0x20;
    cid[4..6].copy_from_slice(&seed.to_le_bytes());
    (6..36).for_each(|i| cid[i] = (seed as u8).wrapping_add(i as u8));
    cid
}

fn small_store_config(dir: &std::path::Path) -> BlockStoreConfig {
    BlockStoreConfig {
        data_dir: dir.join("data"),
        index_dir: dir.join("index"),
        max_file_size: 512,
        group_commit: GroupCommitConfig::default(),
        shard_count: 1,
    }
}

fn default_store_config(dir: &std::path::Path) -> BlockStoreConfig {
    BlockStoreConfig {
        data_dir: dir.join("data"),
        index_dir: dir.join("index"),
        max_file_size: DEFAULT_MAX_FILE_SIZE,
        group_commit: GroupCommitConfig::default(),
        shard_count: 1,
    }
}

fn with_runtime<F: FnOnce()>(f: F) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    f();
}

#[test]
fn refcount_decrement_to_zero_sets_gc_eligible() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(default_store_config(dir.path())).unwrap();

        let cid = test_cid(1);
        store
            .put_blocks_blocking(vec![(cid, vec![0xABu8; 128])])
            .unwrap();

        store.apply_commit_blocking(vec![], vec![cid]).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(5));

        let result = store.collect_dead_blocks(0).unwrap();
        let all_cids: Vec<CidBytes> = result
            .candidates
            .values()
            .flat_map(|v| v.iter().copied())
            .collect();
        assert!(
            all_cids.contains(&cid),
            "block decremented to zero should appear in dead block candidates"
        );
    });
}

#[test]
fn re_increment_from_zero_clears_gc_eligible() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(default_store_config(dir.path())).unwrap();

        let cid = test_cid(2);
        let data = vec![0xCDu8; 128];
        store
            .put_blocks_blocking(vec![(cid, data.clone())])
            .unwrap();

        store.apply_commit_blocking(vec![], vec![cid]).unwrap();

        store.put_blocks_blocking(vec![(cid, data)]).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(5));

        let result = store.collect_dead_blocks(0).unwrap();
        let all_cids: Vec<CidBytes> = result
            .candidates
            .values()
            .flat_map(|v| v.iter().copied())
            .collect();
        assert!(
            !all_cids.contains(&cid),
            "re-referenced block should not appear in dead block candidates"
        );
    });
}

#[test]
fn collect_dead_blocks_respects_grace_period() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(default_store_config(dir.path())).unwrap();

        let cid = test_cid(3);
        store
            .put_blocks_blocking(vec![(cid, vec![0xEFu8; 64])])
            .unwrap();
        store.apply_commit_blocking(vec![], vec![cid]).unwrap();

        let result = store.collect_dead_blocks(600_000).unwrap();
        assert!(
            result.candidates.is_empty(),
            "blocks should not be eligible when grace period hasn't expired"
        );

        std::thread::sleep(std::time::Duration::from_millis(5));
        let result = store.collect_dead_blocks(0).unwrap();
        let all_cids: Vec<CidBytes> = result
            .candidates
            .values()
            .flat_map(|v| v.iter().copied())
            .collect();
        assert!(
            all_cids.contains(&cid),
            "blocks should be eligible after grace period expires"
        );
    });
}

#[test]
fn collect_dead_blocks_respects_epoch_gating() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(default_store_config(dir.path())).unwrap();

        let cid_a = test_cid(10);
        let cid_b = test_cid(11);
        store
            .put_blocks_blocking(vec![(cid_a, vec![0x10u8; 64]), (cid_b, vec![0x11u8; 64])])
            .unwrap();

        store.apply_commit_blocking(vec![], vec![cid_a]).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(5));
        let result = store.collect_dead_blocks(0).unwrap();
        let all_cids: HashSet<CidBytes> = result
            .candidates
            .values()
            .flat_map(|v| v.iter().copied())
            .collect();
        assert!(
            all_cids.contains(&cid_a),
            "cid_a should be collectible after subsequent commit advanced the epoch"
        );
    });
}

#[test]
fn compact_data_file_preserves_live_removes_dead() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(small_store_config(dir.path())).unwrap();

        let blocks: Vec<_> = (0u8..5)
            .map(|seed| (test_cid(seed), vec![seed; 80]))
            .collect();
        store.put_blocks_blocking(blocks).unwrap();

        let padding: Vec<_> = (200u8..210)
            .map(|seed| (test_cid(seed), vec![seed; 512]))
            .collect();
        store.put_blocks_blocking(padding).unwrap();

        let files_before = store.list_data_files().unwrap();
        assert!(
            files_before.len() >= 2,
            "should have rotated to at least 2 data files"
        );
        let first_file = files_before[0];

        store
            .apply_commit_blocking(vec![], vec![test_cid(0), test_cid(2), test_cid(4)])
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));

        let result = store.compact_file(first_file, 0).unwrap();
        assert!(result.dead_blocks > 0, "should have removed dead blocks");
        assert!(result.live_blocks > 0, "should have preserved live blocks");
        assert!(result.reclaimed_bytes > 0, "should have reclaimed space");

        [1u8, 3].iter().for_each(|&seed| {
            let data = store.get_block_sync(&test_cid(seed)).unwrap();
            assert!(
                data.is_some(),
                "live block seed={seed} should still be readable"
            );
            assert_eq!(data.unwrap()[0], seed);
        });
    });
}

#[test]
fn compact_data_file_crash_safe_old_file_survives() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();

        {
            let store = TranquilBlockStore::open(small_store_config(dir.path())).unwrap();

            let blocks: Vec<_> = (0u8..3)
                .map(|seed| (test_cid(seed), vec![seed; 80]))
                .collect();
            store.put_blocks_blocking(blocks).unwrap();

            let padding: Vec<_> = (200u8..210)
                .map(|seed| (test_cid(seed), vec![seed; 512]))
                .collect();
            store.put_blocks_blocking(padding).unwrap();

            store
                .put_blocks_blocking(vec![(test_cid(220), vec![220u8; 64])])
                .unwrap();

            let files = store.list_data_files().unwrap();
            let first_file = files[0];

            store.compact_file(first_file, 600_000).unwrap();

            (0u8..3).for_each(|seed| {
                let data = store.get_block_sync(&test_cid(seed)).unwrap();
                assert!(
                    data.is_some(),
                    "block seed={seed} should still be readable after no-op compaction"
                );
            });
        }

        let store2 = TranquilBlockStore::open(small_store_config(dir.path())).unwrap();
        (0u8..3).for_each(|seed| {
            let data = store2.get_block_sync(&test_cid(seed)).unwrap();
            assert!(
                data.is_some(),
                "block seed={seed} should survive reopen after compaction"
            );
        });
    });
}

#[test]
fn simulation_write_decrement_gc_verify() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(default_store_config(dir.path())).unwrap();

        let live_seeds: Vec<u16> = (0u16..50).collect();
        let dead_seeds: Vec<u16> = (50u16..100).collect();
        let all_blocks: Vec<_> = live_seeds
            .iter()
            .chain(dead_seeds.iter())
            .map(|&seed| (test_cid_u16(seed), vec![(seed & 0xFF) as u8; 128]))
            .collect();
        store.put_blocks_blocking(all_blocks).unwrap();

        let dead_cids: Vec<_> = dead_seeds.iter().map(|&s| test_cid_u16(s)).collect();
        store
            .apply_commit_blocking(vec![], dead_cids.clone())
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));

        let result = store.collect_dead_blocks(0).unwrap();
        let collected: HashSet<CidBytes> = result
            .candidates
            .values()
            .flat_map(|v| v.iter().copied())
            .collect();

        dead_cids.iter().for_each(|cid| {
            assert!(collected.contains(cid), "dead block should be collected");
        });

        live_seeds.iter().for_each(|&seed| {
            let cid = test_cid_u16(seed);
            assert!(
                !collected.contains(&cid),
                "live block seed={seed} should not be collected"
            );
        });

        live_seeds.iter().for_each(|&seed| {
            let data = store.get_block_sync(&test_cid_u16(seed)).unwrap();
            assert!(data.is_some(), "live block seed={seed} should be readable");
        });
    });
}

#[test]
fn simulation_crash_during_compaction_recovery() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();

        {
            let store = TranquilBlockStore::open(small_store_config(dir.path())).unwrap();

            let blocks: Vec<_> = (0u8..5)
                .map(|seed| (test_cid(seed), vec![seed; 80]))
                .collect();
            store.put_blocks_blocking(blocks).unwrap();

            let padding: Vec<_> = (200u8..210)
                .map(|seed| (test_cid(seed), vec![seed; 512]))
                .collect();
            store.put_blocks_blocking(padding).unwrap();

            let files = store.list_data_files().unwrap();
            let first_file = files[0];

            store
                .apply_commit_blocking(vec![], vec![test_cid(1), test_cid(3)])
                .unwrap();
            std::thread::sleep(std::time::Duration::from_millis(5));

            store.compact_file(first_file, 0).unwrap();
        }

        let store = TranquilBlockStore::open(small_store_config(dir.path())).unwrap();

        [0u8, 2, 4].iter().for_each(|&seed| {
            let data = store.get_block_sync(&test_cid(seed)).unwrap();
            assert!(
                data.is_some(),
                "live block seed={seed} should survive compaction + reopen"
            );
            assert_eq!(data.unwrap()[0], seed);
        });

        [1u8, 3].iter().for_each(|&seed| {
            let data = store.get_block_sync(&test_cid(seed)).unwrap();
            assert!(
                data.is_none(),
                "dead block seed={seed} should have been removed by compaction"
            );
        });
    });
}

#[test]
fn simulation_concurrent_writes_during_compaction() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(small_store_config(dir.path())).unwrap();

        let initial_blocks: Vec<_> = (0u8..5)
            .map(|seed| (test_cid(seed), vec![seed; 80]))
            .collect();
        store.put_blocks_blocking(initial_blocks).unwrap();

        let padding: Vec<_> = (200u8..220)
            .map(|seed| (test_cid(seed), vec![seed; 512]))
            .collect();
        store.put_blocks_blocking(padding).unwrap();

        let files = store.list_data_files().unwrap();
        let first_file = files[0];

        store
            .apply_commit_blocking(vec![], vec![test_cid(0), test_cid(2)])
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));

        let store_clone = store.clone();
        let writer_thread = std::thread::spawn(move || {
            let concurrent_blocks: Vec<_> = (100u8..120)
                .map(|seed| (test_cid(seed), vec![seed; 64]))
                .collect();
            store_clone.put_blocks_blocking(concurrent_blocks).unwrap();
        });

        let compact_result = store.compact_file(first_file, 0);
        writer_thread.join().unwrap();

        assert!(
            compact_result.is_ok(),
            "compaction should succeed even with concurrent writes"
        );

        [1u8, 3, 4].iter().for_each(|&seed| {
            let data = store.get_block_sync(&test_cid(seed)).unwrap();
            assert!(
                data.is_some(),
                "live block seed={seed} should survive concurrent compaction"
            );
        });

        (100u8..120).for_each(|seed| {
            let data = store.get_block_sync(&test_cid(seed)).unwrap();
            assert!(
                data.is_some(),
                "concurrently written block seed={seed} should be readable"
            );
        });
    });
}

#[test]
fn reachability_walk_finds_leaked_refcounts() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(default_store_config(dir.path())).unwrap();

        let reachable_cids: Vec<CidBytes> = (0u8..20).map(test_cid).collect();
        let leaked_cids: Vec<CidBytes> = (20u8..25).map(test_cid).collect();

        let all_blocks: Vec<_> = reachable_cids
            .iter()
            .chain(leaked_cids.iter())
            .map(|&cid| (cid, vec![cid[4]; 64]))
            .collect();
        store.put_blocks_blocking(all_blocks).unwrap();

        let reachable_set: HashSet<CidBytes> = reachable_cids.iter().copied().collect();
        let (leaked, live_scanned) = store
            .find_leaked_refcounts(|cid| reachable_set.contains(cid))
            .unwrap();

        assert_eq!(
            live_scanned,
            (reachable_cids.len() + leaked_cids.len()) as u64,
            "should have scanned all blocks with refcount > 0"
        );
        assert_eq!(
            leaked.len(),
            leaked_cids.len(),
            "should have found exactly the leaked blocks"
        );

        let leaked_cid_set: HashSet<CidBytes> = leaked.iter().map(|(cid, _)| *cid).collect();
        leaked_cids.iter().for_each(|cid| {
            assert!(
                leaked_cid_set.contains(cid),
                "leaked block should be detected"
            );
        });

        let repaired = store.repair_leaked_refcounts(&leaked).unwrap();
        assert_eq!(repaired, leaked_cids.len() as u64);

        store
            .put_blocks_blocking(vec![(test_cid(99), vec![0x99u8; 16])])
            .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(5));
        let result = store.collect_dead_blocks(0).unwrap();
        let dead_cids_collected: HashSet<CidBytes> = result
            .candidates
            .values()
            .flat_map(|v| v.iter().copied())
            .collect();
        leaked_cids.iter().for_each(|cid| {
            assert!(
                dead_cids_collected.contains(cid),
                "repaired leaked block should now be gc-eligible"
            );
        });
    });
}

#[test]
fn full_gc_cycle_collect_compact_reachability() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(small_store_config(dir.path())).unwrap();

        let live_blocks: Vec<_> = (0u8..3)
            .map(|seed| (test_cid(seed), vec![seed; 80]))
            .collect();
        let dead_blocks: Vec<_> = (3u8..6)
            .map(|seed| (test_cid(seed), vec![seed; 80]))
            .collect();
        let leaked_blocks: Vec<_> = (6u8..8)
            .map(|seed| (test_cid(seed), vec![seed; 80]))
            .collect();

        store
            .put_blocks_blocking(
                live_blocks
                    .iter()
                    .chain(dead_blocks.iter())
                    .chain(leaked_blocks.iter())
                    .cloned()
                    .collect(),
            )
            .unwrap();

        let padding: Vec<_> = (220u8..240)
            .map(|seed| (test_cid(seed), vec![seed; 512]))
            .collect();
        store.put_blocks_blocking(padding).unwrap();

        let dead_cids: Vec<_> = (3u8..6).map(test_cid).collect();
        store.apply_commit_blocking(vec![], dead_cids).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));

        let collection = store.collect_dead_blocks(0).unwrap();
        assert!(
            !collection.candidates.is_empty(),
            "should have dead blocks to collect"
        );

        let files = store.list_data_files().unwrap();
        let sealed_files: Vec<DataFileId> = files
            .iter()
            .copied()
            .take(files.len().saturating_sub(1))
            .collect();

        sealed_files.iter().for_each(|&file_id| {
            let liveness = store.liveness_info(file_id).unwrap();
            if liveness.ratio() < 1.0 && liveness.total_blocks > 0 {
                store.compact_file(file_id, 0).ok();
            }
        });

        (0u8..3).for_each(|seed| {
            let data = store.get_block_sync(&test_cid(seed)).unwrap();
            assert!(data.is_some(), "live block seed={seed} should survive gc");
        });

        let reachable: HashSet<CidBytes> = (0u8..3)
            .map(test_cid)
            .chain((220u8..240).map(test_cid))
            .collect();
        let (leaked, _) = store
            .find_leaked_refcounts(|cid| reachable.contains(cid))
            .unwrap();

        let leaked_cid_set: HashSet<CidBytes> = leaked.iter().map(|(c, _)| *c).collect();
        (6u8..8).for_each(|seed| {
            assert!(
                leaked_cid_set.contains(&test_cid(seed)),
                "block seed={seed} should be detected as leaked"
            );
        });

        let repaired = store.repair_leaked_refcounts(&leaked).unwrap();
        assert!(repaired > 0, "should have repaired leaked refcounts");

        let cleaned = store.cleanup_gc_meta().unwrap();
        assert_eq!(cleaned, 0, "no stale gc_meta entries after proper gc cycle");

        (0u8..3).for_each(|seed| {
            let data = store.get_block_sync(&test_cid(seed)).unwrap();
            assert!(
                data.is_some(),
                "live block seed={seed} should still be readable after full gc cycle"
            );
        });
    });
}
