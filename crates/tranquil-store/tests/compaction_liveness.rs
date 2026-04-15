mod common;

use std::collections::HashSet;

use tranquil_store::blockstore::{
    BlockStoreConfig, CidBytes, GroupCommitConfig, TranquilBlockStore,
};

fn tiny_store_config(dir: &std::path::Path) -> BlockStoreConfig {
    BlockStoreConfig {
        data_dir: dir.join("data"),
        index_dir: dir.join("index"),
        max_file_size: 4096,
        group_commit: GroupCommitConfig {
            checkpoint_interval_ms: 600_000,
            checkpoint_write_threshold: 1_000_000,
            ..GroupCommitConfig::default()
        },
        shard_count: 1,
    }
}

fn make_block(seed: u32, size: usize) -> (CidBytes, Vec<u8>) {
    (
        common::test_cid(seed),
        common::block_data(seed)
            .into_iter()
            .cycle()
            .take(size)
            .collect(),
    )
}

fn verify_live_blocks(store: &TranquilBlockStore, live: &HashSet<u32>, context: &str) {
    let missing: Vec<u32> = live
        .iter()
        .copied()
        .filter(|&seed| {
            store
                .get_block_sync(&common::test_cid(seed))
                .unwrap()
                .is_none()
        })
        .collect();

    assert!(
        missing.is_empty(),
        "{context}: {count} live blocks missing from store: {missing:?}",
        count = missing.len(),
    );
}

fn compact_sealed(store: &TranquilBlockStore) {
    let files = store.list_data_files().unwrap();
    files
        .iter()
        .copied()
        .take(files.len().saturating_sub(1))
        .for_each(|fid| {
            let _ = store.compact_file(fid, 0);
        });
}

fn delete_checkpoints(index_dir: &std::path::Path) {
    let _ = std::fs::remove_file(index_dir.join("checkpoint_a.tqc"));
    let _ = std::fs::remove_file(index_dir.join("checkpoint_b.tqc"));
}

#[test]
fn relocate_loses_refcount_on_hint_rebuild() {
    common::with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();

        let target = common::test_cid(1);
        let target_data = vec![0xABu8; 200];

        {
            let store = TranquilBlockStore::open(tiny_store_config(dir.path())).unwrap();

            store
                .put_blocks_blocking(vec![(target, target_data.clone())])
                .unwrap();
            store
                .put_blocks_blocking(vec![(target, target_data.clone())])
                .unwrap();

            let padding: Vec<_> = (100..130u32).map(|s| make_block(s, 300)).collect();
            store.put_blocks_blocking(padding).unwrap();

            std::thread::sleep(std::time::Duration::from_millis(10));
            compact_sealed(&store);

            store.apply_commit_blocking(vec![], vec![target]).unwrap();

            let data = store.get_block_sync(&target).unwrap();
            assert!(data.is_some(), "target should be live, refcount 2 - 1 = 1");
        }

        delete_checkpoints(&dir.path().join("index"));

        {
            let store = TranquilBlockStore::open(tiny_store_config(dir.path())).unwrap();

            let data = store.get_block_sync(&target).unwrap();
            assert!(
                data.is_some(),
                "BUG: target missing after hint-only rebuild. \
                 RELOCATE created entry with refcount 1 instead of 2, \
                 then DEC brought it to 0 instead of 1."
            );

            std::thread::sleep(std::time::Duration::from_millis(10));
            compact_sealed(&store);

            let data = store.get_block_sync(&target).unwrap();
            assert!(
                data.is_some(),
                "BUG: target removed by compaction after hint rebuild \
                 incorrectly set refcount to 0"
            );
        }
    });
}

#[test]
fn multi_restart_with_compaction_between_put_and_dec() {
    common::with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();

        let shared = common::test_cid(42);
        let shared_data = vec![0xCDu8; 200];

        {
            let store = TranquilBlockStore::open(tiny_store_config(dir.path())).unwrap();

            store
                .put_blocks_blocking(vec![(shared, shared_data.clone())])
                .unwrap();
            store
                .put_blocks_blocking(vec![(shared, shared_data.clone())])
                .unwrap();
            store
                .put_blocks_blocking(vec![(shared, shared_data.clone())])
                .unwrap();

            let filler: Vec<_> = (200..230u32).map(|s| make_block(s, 300)).collect();
            store.put_blocks_blocking(filler).unwrap();
        }

        delete_checkpoints(&dir.path().join("index"));

        {
            let store = TranquilBlockStore::open(tiny_store_config(dir.path())).unwrap();

            let data = store.get_block_sync(&shared).unwrap();
            assert!(
                data.is_some(),
                "round 1: shared block present after rebuild"
            );

            std::thread::sleep(std::time::Duration::from_millis(10));
            compact_sealed(&store);

            store.apply_commit_blocking(vec![], vec![shared]).unwrap();

            let data = store.get_block_sync(&shared).unwrap();
            assert!(
                data.is_some(),
                "round 1: shared block should survive, refcount 3 - 1 = 2"
            );
        }

        delete_checkpoints(&dir.path().join("index"));

        {
            let store = TranquilBlockStore::open(tiny_store_config(dir.path())).unwrap();

            let data = store.get_block_sync(&shared).unwrap();
            assert!(
                data.is_some(),
                "round 2: shared block should survive hint rebuild, refcount should be 2"
            );

            store.apply_commit_blocking(vec![], vec![shared]).unwrap();

            let data = store.get_block_sync(&shared).unwrap();
            assert!(
                data.is_some(),
                "round 2: shared block should survive DEC, refcount 2 - 1 = 1"
            );

            std::thread::sleep(std::time::Duration::from_millis(10));
            compact_sealed(&store);

            let data = store.get_block_sync(&shared).unwrap();
            assert!(
                data.is_some(),
                "BUG: shared block removed by compaction. \
                 Multiple restarts with RELOCATE collapsed refcount \
                 from 3 down to 1, two DECs made it 0."
            );
        }
    });
}

#[test]
fn stress_create_delete_restart_cycle_matches_bug_report() {
    common::with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let mut live: HashSet<u32> = HashSet::new();
        let mut rng = common::Rng::new(12345);
        let mut next_seed: u32 = 0;

        (0..4).for_each(|cycle| {
            {
                let store = TranquilBlockStore::open(tiny_store_config(dir.path())).unwrap();

                (0..20).for_each(|_| {
                    let seed_a = next_seed;
                    let seed_b = next_seed + 1;
                    next_seed += 2;

                    store
                        .put_blocks_blocking(vec![make_block(seed_a, 150), make_block(seed_b, 150)])
                        .unwrap();
                    live.insert(seed_a);
                    live.insert(seed_b);

                    if rng.next_u32().is_multiple_of(2) {
                        let victim: Option<u32> = live.iter().copied().next();
                        if let Some(v) = victim {
                            store
                                .apply_commit_blocking(vec![], vec![common::test_cid(v)])
                                .unwrap();
                            live.remove(&v);
                        }
                    }
                });

                std::thread::sleep(std::time::Duration::from_millis(10));
                compact_sealed(&store);

                verify_live_blocks(&store, &live, &format!("cycle {cycle} before kill"));
            }

            delete_checkpoints(&dir.path().join("index"));

            {
                let store = TranquilBlockStore::open(tiny_store_config(dir.path())).unwrap();
                verify_live_blocks(&store, &live, &format!("cycle {cycle} after hint rebuild"));
            }
        });
    });
}
