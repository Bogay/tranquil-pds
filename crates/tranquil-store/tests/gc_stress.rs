use std::collections::{HashMap, HashSet};

use proptest::prelude::*;
use tranquil_store::blockstore::{
    BlockStoreConfig, CidBytes, DEFAULT_MAX_FILE_SIZE, DataFileId, GroupCommitConfig,
    TranquilBlockStore,
};

fn test_cid_u32(seed: u32) -> [u8; 36] {
    let mut cid = [0u8; 36];
    cid[0] = 0x01;
    cid[1] = 0x71;
    cid[2] = 0x12;
    cid[3] = 0x20;
    cid[4..8].copy_from_slice(&seed.to_le_bytes());
    (8..36).for_each(|i| cid[i] = (seed as u8).wrapping_add(i as u8));
    cid
}

fn block_data(seed: u32) -> Vec<u8> {
    let tag = seed.to_le_bytes();
    let mut data = vec![0u8; 80];
    data[..4].copy_from_slice(&tag);
    data
}

fn small_config(dir: &std::path::Path) -> BlockStoreConfig {
    BlockStoreConfig {
        data_dir: dir.join("data"),
        index_dir: dir.join("index"),
        max_file_size: 512,
        group_commit: GroupCommitConfig::default(),
        shard_count: 1,
    }
}

fn default_config(dir: &std::path::Path) -> BlockStoreConfig {
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

fn collect_all_dead(store: &TranquilBlockStore) -> HashSet<CidBytes> {
    let result = store.collect_dead_blocks(0).unwrap();
    result
        .candidates
        .values()
        .flat_map(|v| v.iter().copied())
        .collect()
}

fn compact_all_sealed(store: &TranquilBlockStore) {
    let files = store.list_data_files().unwrap();
    let sealed: Vec<DataFileId> = files
        .iter()
        .copied()
        .take(files.len().saturating_sub(1))
        .collect();

    sealed.iter().for_each(|&fid| {
        store.compact_file(fid, 0).ok();
    });
}

fn verify_live_readable(store: &TranquilBlockStore, oracle: &GcOracle) {
    oracle.live_seeds().iter().for_each(|&seed| {
        let cid = test_cid_u32(seed);
        let data = store
            .get_block_sync(&cid)
            .unwrap_or_else(|e| panic!("get_block_sync failed for seed={seed}: {e}"));
        assert!(
            data.is_some(),
            "live block seed={seed} (refcount={}) must be readable",
            oracle.refcount(seed)
        );
        let expected = block_data(seed);
        assert_eq!(
            &data.unwrap()[..4],
            &expected[..4],
            "data mismatch for live block seed={seed}"
        );
    });
}

fn verify_no_live_in_dead(store: &TranquilBlockStore, oracle: &GcOracle) {
    let dead = collect_all_dead(store);
    oracle.live_seeds().iter().for_each(|&seed| {
        let cid = test_cid_u32(seed);
        assert!(
            !dead.contains(&cid),
            "live block seed={seed} (refcount={}) must not appear in dead candidates",
            oracle.refcount(seed)
        );
    });
}

struct GcOracle {
    refcounts: HashMap<u32, u32>,
}

impl GcOracle {
    fn new() -> Self {
        Self {
            refcounts: HashMap::new(),
        }
    }

    fn put(&mut self, seed: u32) {
        *self.refcounts.entry(seed).or_insert(0) += 1;
    }

    fn delete(&mut self, seed: u32) -> bool {
        match self.refcounts.get_mut(&seed) {
            Some(rc) if *rc > 0 => {
                *rc -= 1;
                true
            }
            _ => false,
        }
    }

    fn refcount(&self, seed: u32) -> u32 {
        self.refcounts.get(&seed).copied().unwrap_or(0)
    }

    fn live_seeds(&self) -> Vec<u32> {
        self.refcounts
            .iter()
            .filter(|&(_, rc)| *rc > 0)
            .map(|(&seed, _)| seed)
            .collect()
    }

    fn dead_seeds(&self) -> Vec<u32> {
        self.refcounts
            .iter()
            .filter(|&(_, rc)| *rc == 0)
            .map(|(&seed, _)| seed)
            .collect()
    }
}

fn advance_epoch(store: &TranquilBlockStore) {
    store.apply_commit_blocking(vec![], vec![]).unwrap();
}

#[test]
fn oracle_deterministic_1000_blocks_multi_round() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(default_config(dir.path())).unwrap();
        let mut oracle = GcOracle::new();

        let all_blocks: Vec<_> = (0u32..1000)
            .map(|seed| {
                oracle.put(seed);
                (test_cid_u32(seed), block_data(seed))
            })
            .collect();
        all_blocks.chunks(50).for_each(|chunk| {
            store.put_blocks_blocking(chunk.to_vec()).unwrap();
        });

        verify_live_readable(&store, &oracle);

        let kill_round_1: Vec<_> = (0u32..1000)
            .step_by(2)
            .filter(|&seed| oracle.delete(seed))
            .map(test_cid_u32)
            .collect();
        kill_round_1.chunks(100).for_each(|chunk| {
            store.apply_commit_blocking(vec![], chunk.to_vec()).unwrap();
        });

        advance_epoch(&store);
        std::thread::sleep(std::time::Duration::from_millis(10));

        verify_no_live_in_dead(&store, &oracle);
        verify_live_readable(&store, &oracle);

        let resurrect: Vec<u32> = (0u32..200).step_by(4).collect();
        resurrect.iter().for_each(|&seed| {
            oracle.put(seed);
            store
                .put_blocks_blocking(vec![(test_cid_u32(seed), block_data(seed))])
                .unwrap();
        });

        let kill_round_2: Vec<_> = (1u32..1000)
            .step_by(4)
            .filter(|&seed| oracle.delete(seed))
            .map(test_cid_u32)
            .collect();
        kill_round_2.chunks(100).for_each(|chunk| {
            store.apply_commit_blocking(vec![], chunk.to_vec()).unwrap();
        });

        advance_epoch(&store);
        std::thread::sleep(std::time::Duration::from_millis(10));

        verify_no_live_in_dead(&store, &oracle);
        verify_live_readable(&store, &oracle);

        let live_count = oracle.live_seeds().len();
        let dead_count = oracle.dead_seeds().len();
        assert!(
            live_count > 0 && dead_count > 0,
            "test should exercise both live ({live_count}) and dead ({dead_count}) blocks"
        );
    });
}

#[test]
fn oracle_deterministic_1000_blocks_reopen_survives() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let mut oracle = GcOracle::new();

        {
            let store = TranquilBlockStore::open(default_config(dir.path())).unwrap();

            let all_blocks: Vec<_> = (0u32..1000)
                .map(|seed| {
                    oracle.put(seed);
                    (test_cid_u32(seed), block_data(seed))
                })
                .collect();
            all_blocks.chunks(50).for_each(|chunk| {
                store.put_blocks_blocking(chunk.to_vec()).unwrap();
            });

            let kill: Vec<_> = (0u32..500)
                .filter(|&seed| oracle.delete(seed))
                .map(test_cid_u32)
                .collect();
            kill.chunks(100).for_each(|chunk| {
                store.apply_commit_blocking(vec![], chunk.to_vec()).unwrap();
            });

            advance_epoch(&store);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let store = TranquilBlockStore::open(default_config(dir.path())).unwrap();
        verify_live_readable(&store, &oracle);
    });
}

#[derive(Debug, Clone)]
enum Op {
    Put(u32),
    Delete(u32),
    CompactAll,
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0u32..300).prop_map(Op::Put),
        2 => (0u32..300).prop_map(Op::Delete),
        1 => Just(Op::CompactAll),
    ]
}

fn run_oracle_scenario(ops: Vec<Op>) {
    let dir = tempfile::TempDir::new().unwrap();
    let store = TranquilBlockStore::open(small_config(dir.path())).unwrap();
    let mut oracle = GcOracle::new();

    ops.iter().for_each(|op| match op {
        Op::Put(seed) => {
            oracle.put(*seed);
            store
                .put_blocks_blocking(vec![(test_cid_u32(*seed), block_data(*seed))])
                .unwrap();
        }
        Op::Delete(seed) => {
            if oracle.delete(*seed) {
                store
                    .apply_commit_blocking(vec![], vec![test_cid_u32(*seed)])
                    .unwrap();
            }
        }
        Op::CompactAll => {
            advance_epoch(&store);
            std::thread::sleep(std::time::Duration::from_millis(5));
            compact_all_sealed(&store);
        }
    });

    advance_epoch(&store);
    std::thread::sleep(std::time::Duration::from_millis(5));

    verify_live_readable(&store, &oracle);
    verify_no_live_in_dead(&store, &oracle);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn proptest_oracle_random_operations(ops in prop::collection::vec(op_strategy(), 80..200)) {
        with_runtime(|| {
            run_oracle_scenario(ops);
        });
    }
}

#[test]
fn content_addressable_dedup_multi_repo() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(default_config(dir.path())).unwrap();

        let shared_seeds: Vec<u32> = (0u32..50).collect();
        let repo_count: u32 = 5;
        let mut oracle = GcOracle::new();

        (0..repo_count).for_each(|_repo| {
            let blocks: Vec<_> = shared_seeds
                .iter()
                .map(|&seed| {
                    oracle.put(seed);
                    (test_cid_u32(seed), block_data(seed))
                })
                .collect();
            store.put_blocks_blocking(blocks).unwrap();
        });

        shared_seeds.iter().for_each(|&seed| {
            assert_eq!(oracle.refcount(seed), repo_count);
        });

        (0..repo_count.saturating_sub(1)).for_each(|_repo| {
            let deletes: Vec<_> = shared_seeds
                .iter()
                .filter(|&&seed| oracle.delete(seed))
                .map(|&seed| test_cid_u32(seed))
                .collect();
            store.apply_commit_blocking(vec![], deletes).unwrap();

            advance_epoch(&store);
            std::thread::sleep(std::time::Duration::from_millis(5));

            verify_live_readable(&store, &oracle);
            verify_no_live_in_dead(&store, &oracle);
        });

        shared_seeds.iter().for_each(|&seed| {
            assert_eq!(
                oracle.refcount(seed),
                1,
                "after deleting {repo_count}-1 repos, refcount should be 1"
            );
        });

        verify_live_readable(&store, &oracle);

        let final_deletes: Vec<_> = shared_seeds
            .iter()
            .filter(|&&seed| oracle.delete(seed))
            .map(|&seed| test_cid_u32(seed))
            .collect();
        store.apply_commit_blocking(vec![], final_deletes).unwrap();

        advance_epoch(&store);
        std::thread::sleep(std::time::Duration::from_millis(5));

        let dead = collect_all_dead(&store);
        shared_seeds.iter().for_each(|&seed| {
            assert!(
                dead.contains(&test_cid_u32(seed)),
                "fully dereferenced block seed={seed} must be dead"
            );
        });
    });
}

#[test]
fn rapid_resurrection_cycling() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(default_config(dir.path())).unwrap();

        let cid = test_cid_u32(42);
        let data = block_data(42);
        let cycles = 50u32;

        store
            .put_blocks_blocking(vec![(cid, data.clone())])
            .unwrap();

        (0..cycles).for_each(|_| {
            store.apply_commit_blocking(vec![], vec![cid]).unwrap();

            store
                .put_blocks_blocking(vec![(cid, data.clone())])
                .unwrap();
        });

        advance_epoch(&store);
        std::thread::sleep(std::time::Duration::from_millis(5));

        let dead = collect_all_dead(&store);
        assert!(
            !dead.contains(&cid),
            "block that was resurrected must not be in dead candidates"
        );

        let read = store.get_block_sync(&cid).unwrap();
        assert!(read.is_some(), "resurrected block must be readable");
        assert_eq!(&read.unwrap()[..4], &data[..4]);
    });
}

#[test]
fn epoch_boundary_strict_gating() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(default_config(dir.path())).unwrap();

        let cid_a = test_cid_u32(1);
        let cid_b = test_cid_u32(2);
        store
            .put_blocks_blocking(vec![(cid_a, block_data(1)), (cid_b, block_data(2))])
            .unwrap();

        store.apply_commit_blocking(vec![], vec![cid_a]).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(5));

        let dead_same_epoch = store.collect_dead_blocks(0).unwrap();
        let dead_cids: HashSet<CidBytes> = dead_same_epoch
            .candidates
            .values()
            .flat_map(|v| v.iter().copied())
            .collect();

        assert!(
            !dead_cids.contains(&cid_b),
            "cid_b was never deleted, must not be in dead candidates"
        );

        advance_epoch(&store);
        std::thread::sleep(std::time::Duration::from_millis(5));

        let dead_next = collect_all_dead(&store);
        assert!(
            dead_next.contains(&cid_a),
            "cid_a must be collectible after epoch advances past its deletion epoch"
        );
        assert!(
            !dead_next.contains(&cid_b),
            "cid_b was never deleted, still must not be dead"
        );
    });
}

#[test]
fn multi_round_compaction_relay() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(small_config(dir.path())).unwrap();

        let survivors: Vec<u32> = vec![10, 11, 12];
        let victims_r1: Vec<u32> = vec![20, 21];
        let all_r1: Vec<_> = survivors
            .iter()
            .chain(victims_r1.iter())
            .map(|&s| (test_cid_u32(s), block_data(s)))
            .collect();
        store.put_blocks_blocking(all_r1).unwrap();

        let padding_r1: Vec<_> = (5000u32..5040)
            .map(|s| (test_cid_u32(s), vec![0xAAu8; 512]))
            .collect();
        store.put_blocks_blocking(padding_r1).unwrap();

        let del_r1: Vec<_> = victims_r1.iter().map(|&s| test_cid_u32(s)).collect();
        store.apply_commit_blocking(vec![], del_r1).unwrap();
        advance_epoch(&store);
        std::thread::sleep(std::time::Duration::from_millis(5));

        let files_before = store.list_data_files().unwrap();
        let sealed_r1: Vec<DataFileId> = files_before
            .iter()
            .copied()
            .take(files_before.len().saturating_sub(1))
            .collect();
        sealed_r1.iter().for_each(|&fid| {
            let info = store.liveness_info(fid).unwrap();
            if info.ratio() < 1.0 && info.total_blocks > 0 {
                store.compact_file(fid, 0).ok();
            }
        });

        survivors.iter().for_each(|&seed| {
            let data = store.get_block_sync(&test_cid_u32(seed)).unwrap();
            assert!(
                data.is_some(),
                "survivor seed={seed} must be readable after round 1 compaction"
            );
        });

        let padding_r2: Vec<_> = (6000u32..6040)
            .map(|s| (test_cid_u32(s), vec![0xBBu8; 512]))
            .collect();
        store.put_blocks_blocking(padding_r2).unwrap();

        let victims_r2: Vec<u32> = vec![12];
        let del_r2: Vec<_> = victims_r2.iter().map(|&s| test_cid_u32(s)).collect();
        store.apply_commit_blocking(vec![], del_r2).unwrap();
        advance_epoch(&store);
        std::thread::sleep(std::time::Duration::from_millis(5));

        let files_r2 = store.list_data_files().unwrap();
        let sealed_r2: Vec<DataFileId> = files_r2
            .iter()
            .copied()
            .take(files_r2.len().saturating_sub(1))
            .collect();
        sealed_r2.iter().for_each(|&fid| {
            let info = store.liveness_info(fid).unwrap();
            if info.ratio() < 1.0 && info.total_blocks > 0 {
                store.compact_file(fid, 0).ok();
            }
        });

        [10u32, 11].iter().for_each(|&seed| {
            let data = store.get_block_sync(&test_cid_u32(seed)).unwrap();
            assert!(
                data.is_some(),
                "double-relocated survivor seed={seed} must be readable after round 2"
            );
            assert_eq!(&data.unwrap()[..4], &seed.to_le_bytes());
        });

        let data_12 = store.get_block_sync(&test_cid_u32(12)).unwrap();
        assert!(
            data_12.is_none(),
            "block 12 was deleted and compacted, should not be readable"
        );
    });
}

#[test]
fn all_dead_file_compaction() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(small_config(dir.path())).unwrap();

        let blocks: Vec<_> = (0u32..5)
            .map(|s| (test_cid_u32(s), block_data(s)))
            .collect();
        store.put_blocks_blocking(blocks).unwrap();

        let padding: Vec<_> = (9000u32..9020)
            .map(|s| (test_cid_u32(s), vec![0xFFu8; 512]))
            .collect();
        store.put_blocks_blocking(padding).unwrap();

        let files = store.list_data_files().unwrap();
        let first_file = files[0];

        let info_before = store.liveness_info(first_file).unwrap();
        assert!(info_before.total_blocks > 0);

        let kill_all: Vec<_> = (0u32..5).map(test_cid_u32).collect();
        store.apply_commit_blocking(vec![], kill_all).unwrap();
        advance_epoch(&store);
        std::thread::sleep(std::time::Duration::from_millis(5));

        let result = store.compact_file(first_file, 0).unwrap();
        assert_eq!(result.live_blocks, 0);
        assert!(result.dead_blocks > 0);

        (0u32..5).for_each(|seed| {
            let data = store.get_block_sync(&test_cid_u32(seed)).unwrap();
            assert!(
                data.is_none(),
                "fully dead block seed={seed} should not be readable after compaction"
            );
        });
    });
}

#[test]
fn multi_reference_partial_decrement() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(default_config(dir.path())).unwrap();

        let cid = test_cid_u32(77);
        let data = block_data(77);

        (0..5).for_each(|_| {
            store
                .put_blocks_blocking(vec![(cid, data.clone())])
                .unwrap();
        });

        (0..4).for_each(|_| {
            store.apply_commit_blocking(vec![], vec![cid]).unwrap();
        });

        advance_epoch(&store);
        std::thread::sleep(std::time::Duration::from_millis(5));

        let dead = collect_all_dead(&store);
        assert!(
            !dead.contains(&cid),
            "block with refcount=1 must not be in dead candidates"
        );

        let read = store.get_block_sync(&cid).unwrap();
        assert!(read.is_some(), "block with refcount=1 must be readable");

        store.apply_commit_blocking(vec![], vec![cid]).unwrap();
        advance_epoch(&store);
        std::thread::sleep(std::time::Duration::from_millis(5));

        let dead = collect_all_dead(&store);
        assert!(
            dead.contains(&cid),
            "block decremented to zero must be in dead candidates"
        );
    });
}

#[test]
fn compaction_preserves_blocks_across_reopen() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let mut oracle = GcOracle::new();

        {
            let store = TranquilBlockStore::open(small_config(dir.path())).unwrap();

            let blocks: Vec<_> = (0u32..200)
                .map(|seed| {
                    oracle.put(seed);
                    (test_cid_u32(seed), block_data(seed))
                })
                .collect();
            blocks.chunks(20).for_each(|chunk| {
                store.put_blocks_blocking(chunk.to_vec()).unwrap();
            });

            let kill: Vec<_> = (0u32..200)
                .step_by(3)
                .filter(|&seed| oracle.delete(seed))
                .map(test_cid_u32)
                .collect();
            store.apply_commit_blocking(vec![], kill).unwrap();

            advance_epoch(&store);
            std::thread::sleep(std::time::Duration::from_millis(10));
            compact_all_sealed(&store);

            verify_live_readable(&store, &oracle);
        }

        {
            let store = TranquilBlockStore::open(small_config(dir.path())).unwrap();
            verify_live_readable(&store, &oracle);

            let kill_2: Vec<_> = (1u32..200)
                .step_by(5)
                .filter(|&seed| oracle.delete(seed))
                .map(test_cid_u32)
                .collect();
            store.apply_commit_blocking(vec![], kill_2).unwrap();

            advance_epoch(&store);
            std::thread::sleep(std::time::Duration::from_millis(10));
            compact_all_sealed(&store);
        }

        {
            let store = TranquilBlockStore::open(small_config(dir.path())).unwrap();
            verify_live_readable(&store, &oracle);
        }
    });
}

#[test]
fn resurrection_clears_gc_meta_atomically() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(default_config(dir.path())).unwrap();

        let seeds: Vec<u32> = (0u32..20).collect();
        let blocks: Vec<_> = seeds
            .iter()
            .map(|&s| (test_cid_u32(s), block_data(s)))
            .collect();
        store.put_blocks_blocking(blocks).unwrap();

        let delete_cids: Vec<_> = seeds.iter().map(|&s| test_cid_u32(s)).collect();
        store.apply_commit_blocking(vec![], delete_cids).unwrap();

        let resurrect: Vec<_> = (0u32..10)
            .map(|s| (test_cid_u32(s), block_data(s)))
            .collect();
        store.put_blocks_blocking(resurrect).unwrap();

        let cleaned = store.cleanup_gc_meta().unwrap();
        assert_eq!(
            cleaned, 0,
            "batch_put already clears gc_meta on resurrection, nothing stale"
        );

        advance_epoch(&store);
        std::thread::sleep(std::time::Duration::from_millis(5));

        let dead = collect_all_dead(&store);
        (0u32..10).for_each(|seed| {
            assert!(
                !dead.contains(&test_cid_u32(seed)),
                "resurrected block seed={seed} must not be dead"
            );
        });
        (10u32..20).for_each(|seed| {
            assert!(
                dead.contains(&test_cid_u32(seed)),
                "non-resurrected block seed={seed} must be dead"
            );
        });
    });
}

#[test]
fn batch_put_and_delete_same_cid_single_commit() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(default_config(dir.path())).unwrap();

        let cid = test_cid_u32(99);
        let data = block_data(99);

        store
            .apply_commit_blocking(vec![(cid, data.clone())], vec![cid])
            .unwrap();

        advance_epoch(&store);
        std::thread::sleep(std::time::Duration::from_millis(5));

        let dead = collect_all_dead(&store);
        assert!(
            dead.contains(&cid),
            "block put then immediately deleted in same commit should be dead"
        );
    });
}

#[test]
fn concurrent_compactions_different_files() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(small_config(dir.path())).unwrap();

        let blocks: Vec<_> = (0u32..100)
            .map(|s| (test_cid_u32(s), block_data(s)))
            .collect();
        blocks.chunks(10).for_each(|chunk| {
            store.put_blocks_blocking(chunk.to_vec()).unwrap();
        });

        let kill: Vec<_> = (0u32..100).step_by(2).map(test_cid_u32).collect();
        store.apply_commit_blocking(vec![], kill).unwrap();
        advance_epoch(&store);
        std::thread::sleep(std::time::Duration::from_millis(10));

        let files = store.list_data_files().unwrap();
        let sealed: Vec<DataFileId> = files
            .iter()
            .copied()
            .take(files.len().saturating_sub(1))
            .collect();

        let store_a = store.clone();
        let store_b = store.clone();
        let sealed_a: Vec<_> = sealed.iter().step_by(2).copied().collect();
        let sealed_b: Vec<_> = sealed.iter().skip(1).step_by(2).copied().collect();

        let thread_a = std::thread::spawn(move || {
            sealed_a.iter().for_each(|&fid| {
                store_a.compact_file(fid, 0).ok();
            });
        });
        let thread_b = std::thread::spawn(move || {
            sealed_b.iter().for_each(|&fid| {
                store_b.compact_file(fid, 0).ok();
            });
        });

        thread_a.join().unwrap();
        thread_b.join().unwrap();

        (1u32..100).step_by(2).for_each(|seed| {
            let data = store.get_block_sync(&test_cid_u32(seed)).unwrap();
            assert!(
                data.is_some(),
                "odd-seeded block {seed} (live) must survive concurrent compaction"
            );
            assert_eq!(&data.unwrap()[..4], &seed.to_le_bytes());
        });
    });
}

#[test]
fn grace_period_prevents_collection_during_active_write() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(small_config(dir.path())).unwrap();

        let cid = test_cid_u32(1);
        let data = block_data(1);
        store.put_blocks_blocking(vec![(cid, data)]).unwrap();

        store.apply_commit_blocking(vec![], vec![cid]).unwrap();

        let padding: Vec<_> = (8000u32..8020)
            .map(|s| (test_cid_u32(s), vec![0xCCu8; 512]))
            .collect();
        store.put_blocks_blocking(padding).unwrap();

        advance_epoch(&store);

        let files = store.list_data_files().unwrap();
        let first_file = files[0];
        let result = store.compact_file(first_file, 600_000).unwrap();

        assert_eq!(
            result.dead_blocks, 0,
            "grace period should prevent any collection"
        );

        let read = store.get_block_sync(&cid).unwrap();
        assert!(
            read.is_some(),
            "block within grace period must survive compaction"
        );
    });
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    #[test]
    fn proptest_dedup_stress(
        ref_counts in prop::collection::vec(1u32..8, 20..60),
        kill_pattern in prop::collection::vec(prop::bool::ANY, 20..60),
    ) {
        with_runtime(|| {
            let len = ref_counts.len().min(kill_pattern.len());
            let dir = tempfile::TempDir::new().unwrap();
            let store = TranquilBlockStore::open(small_config(dir.path())).unwrap();
            let mut oracle = GcOracle::new();

            (0..len).for_each(|i| {
                let seed = i as u32;
                let count = ref_counts[i];
                (0..count).for_each(|_| {
                    oracle.put(seed);
                    store
                        .put_blocks_blocking(vec![(test_cid_u32(seed), block_data(seed))])
                        .unwrap();
                });
            });

            (0..len).for_each(|i| {
                let seed = i as u32;
                if kill_pattern[i] {
                    let rc = oracle.refcount(seed);
                    (0..rc).for_each(|_| {
                        if oracle.delete(seed) {
                            store
                                .apply_commit_blocking(vec![], vec![test_cid_u32(seed)])
                                .unwrap();
                        }
                    });
                }
            });

            advance_epoch(&store);
            std::thread::sleep(std::time::Duration::from_millis(10));

            compact_all_sealed(&store);
            verify_live_readable(&store, &oracle);
            verify_no_live_in_dead(&store, &oracle);
        });
    }
}
