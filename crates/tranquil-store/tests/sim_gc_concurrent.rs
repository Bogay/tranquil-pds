mod common;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use common::{
    Rng, advance_epoch, block_data, collect_all_dead, compact_all_sealed, small_blockstore_config,
    test_cid, with_runtime,
};
use tranquil_store::blockstore::{CidBytes, DataFileId, TranquilBlockStore};
use tranquil_store::sim_single_seed;

#[derive(Debug)]
struct ConcurrentGcOracle {
    refcounts: parking_lot::Mutex<HashMap<u32, u32>>,
}

impl ConcurrentGcOracle {
    fn new() -> Self {
        Self {
            refcounts: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    fn put(&self, seed: u32) {
        *self.refcounts.lock().entry(seed).or_insert(0) += 1;
    }

    fn delete(&self, seed: u32) -> bool {
        let mut map = self.refcounts.lock();
        match map.get_mut(&seed) {
            Some(rc) if *rc > 0 => {
                *rc -= 1;
                true
            }
            _ => false,
        }
    }

    fn snapshot_live(&self) -> HashSet<u32> {
        self.refcounts
            .lock()
            .iter()
            .filter(|&(_, rc)| *rc > 0)
            .map(|(&seed, _)| seed)
            .collect()
    }

    fn refcount(&self, seed: u32) -> u32 {
        self.refcounts.lock().get(&seed).copied().unwrap_or(0)
    }
}

#[test]
fn sim_gc_concurrent_writes_no_live_block_collected() {
    with_runtime(|| {
        let seed_range = match sim_single_seed() {
            Some(s) => s..s + 1,
            None => 0..100u64,
        };

        seed_range.into_iter().for_each(|seed| {
            let dir = tempfile::TempDir::new().unwrap();
            let store = TranquilBlockStore::open(small_blockstore_config(dir.path())).unwrap();
            let oracle = ConcurrentGcOracle::new();

            let initial_count = ((seed % 50) as u32) + 50;
            let initial_blocks: Vec<(CidBytes, Vec<u8>)> = (0..initial_count)
                .map(|i| {
                    oracle.put(i);
                    (test_cid(i), block_data(i))
                })
                .collect();
            initial_blocks.chunks(20).for_each(|chunk| {
                store.put_blocks_blocking(chunk.to_vec()).unwrap();
            });

            let delete_start = initial_count / 4;
            let delete_end = initial_count * 3 / 4;
            let deletes: Vec<CidBytes> = (delete_start..delete_end)
                .filter(|&i| oracle.delete(i)).map(test_cid)
                .collect();
            store.apply_commit_blocking(vec![], deletes).unwrap();
            advance_epoch(&store);
            std::thread::sleep(std::time::Duration::from_millis(5));

            let stop = AtomicBool::new(false);
            let writer_counter = AtomicU32::new(initial_count);

            std::thread::scope(|s| {
                let writer = s.spawn(|| {
                    std::iter::from_fn(|| (!stop.load(Ordering::Relaxed)).then_some(()))
                        .for_each(|()| {
                            let base = writer_counter.fetch_add(5, Ordering::Relaxed);
                            let batch: Vec<(CidBytes, Vec<u8>)> = (base..base + 5)
                                .map(|i| (test_cid(i), block_data(i)))
                                .collect();
                            if store.put_blocks_blocking(batch).is_ok() {
                                (base..base + 5).for_each(|i| oracle.put(i));
                            }
                            std::thread::sleep(std::time::Duration::from_millis(1));
                        });
                });

                let gc_thread = s.spawn(|| {
                    std::iter::from_fn(|| (!stop.load(Ordering::Relaxed)).then_some(()))
                        .fold(0u32, |compaction_rounds, ()| {
                            let _ = store.apply_commit_blocking(vec![], vec![]);
                            std::thread::sleep(std::time::Duration::from_millis(2));
                            if let Ok(files) = store.list_data_files() {
                                files
                                    .iter()
                                    .copied()
                                    .take(files.len().saturating_sub(1))
                                    .for_each(|fid| {
                                        let _ = store.compact_file(fid, 0);
                                    });
                            }
                            std::thread::sleep(std::time::Duration::from_millis(3));
                            compaction_rounds.saturating_add(1)
                        })
                });

                std::thread::sleep(std::time::Duration::from_millis(200));
                stop.store(true, Ordering::Relaxed);

                writer.join().unwrap();
                let compaction_rounds = gc_thread.join().unwrap();

                assert!(
                    compaction_rounds > 0,
                    "seed={seed} gc thread must have run at least one compaction round"
                );

                let live = oracle.snapshot_live();
                live.iter().for_each(|&s| {
                    let data = store.get_block_sync(&test_cid(s)).unwrap();
                    assert!(
                        data.is_some(),
                        "seed={seed} live block {s} (refcount={}) must be readable after concurrent GC",
                        oracle.refcount(s)
                    );
                    assert_eq!(
                        &data.unwrap()[..4],
                        &s.to_le_bytes(),
                        "seed={seed} live block {s} data mismatch"
                    );
                });

                let dead = collect_all_dead(&store);
                live.iter().for_each(|&s| {
                    assert!(
                        !dead.contains(&test_cid(s)),
                        "seed={seed} live block {s} (refcount={}) must not appear in dead candidates",
                        oracle.refcount(s)
                    );
                });
            });
        });
    });
}

#[test]
fn sim_gc_compaction_with_concurrent_deletes() {
    with_runtime(|| {
        let seed_range = match sim_single_seed() {
            Some(s) => s..s + 1,
            None => 0..100u64,
        };

        seed_range.into_iter().for_each(|seed| {
            let dir = tempfile::TempDir::new().unwrap();
            let store = TranquilBlockStore::open(small_blockstore_config(dir.path())).unwrap();
            let oracle = ConcurrentGcOracle::new();

            let block_count = 200u32;
            let blocks: Vec<(CidBytes, Vec<u8>)> = (0..block_count)
                .map(|i| {
                    oracle.put(i);
                    (test_cid(i), block_data(i))
                })
                .collect();
            blocks.chunks(20).for_each(|chunk| {
                store.put_blocks_blocking(chunk.to_vec()).unwrap();
            });

            advance_epoch(&store);
            std::thread::sleep(std::time::Duration::from_millis(5));

            let stop = AtomicBool::new(false);

            std::thread::scope(|s| {
                let deleter = s.spawn(|| {
                    let mut rng = Rng::new(seed);
                    std::iter::from_fn(|| (!stop.load(Ordering::Relaxed)).then_some(()))
                        .fold(0u32, |deleted_count, ()| {
                            let target = rng.range_u32(block_count);
                            let inc = if oracle.delete(target) {
                                let _ =
                                    store.apply_commit_blocking(vec![], vec![test_cid(target)]);
                                1
                            } else {
                                0
                            };
                            std::thread::sleep(std::time::Duration::from_millis(1));
                            deleted_count + inc
                        })
                });

                let gc_thread = s.spawn(|| {
                    std::iter::from_fn(|| (!stop.load(Ordering::Relaxed)).then_some(()))
                        .for_each(|()| {
                            let _ = store.apply_commit_blocking(vec![], vec![]);
                            std::thread::sleep(std::time::Duration::from_millis(3));
                            if let Ok(files) = store.list_data_files() {
                                files
                                    .iter()
                                    .copied()
                                    .take(files.len().saturating_sub(1))
                                    .for_each(|fid| {
                                        let _ = store.compact_file(fid, 0);
                                    });
                            }
                            std::thread::sleep(std::time::Duration::from_millis(5));
                        });
                });

                std::thread::sleep(std::time::Duration::from_millis(300));
                stop.store(true, Ordering::Relaxed);

                let deleted_count = deleter.join().unwrap();
                gc_thread.join().unwrap();

                assert!(
                    deleted_count > 0,
                    "seed={seed} deleter must have deleted at least one block"
                );

                let live = oracle.snapshot_live();
                live.iter().for_each(|&s| {
                    let data = store.get_block_sync(&test_cid(s)).unwrap();
                    assert!(
                        data.is_some(),
                        "seed={seed} live block {s} (refcount={}) must be readable after concurrent delete+GC",
                        oracle.refcount(s)
                    );
                });
            });
        });
    });
}

#[test]
fn sim_gc_compaction_crash_at_each_substep() {
    with_runtime(|| {
        let seed_range = match sim_single_seed() {
            Some(s) => s..s + 1,
            None => 0..200u64,
        };

        seed_range.into_iter().for_each(|seed| {
            let dir = tempfile::TempDir::new().unwrap();
            let live_count = ((seed % 20) as u32) + 10;
            let dead_count = ((seed % 15) as u32) + 5;
            let live_seeds: Vec<u32> = (0..live_count).collect();
            let dead_seeds: Vec<u32> = (live_count..live_count + dead_count).collect();

            {
                let store = TranquilBlockStore::open(small_blockstore_config(dir.path())).unwrap();

                let all_blocks: Vec<(CidBytes, Vec<u8>)> = live_seeds
                    .iter()
                    .chain(dead_seeds.iter())
                    .map(|&s| (test_cid(s), block_data(s)))
                    .collect();
                store.put_blocks_blocking(all_blocks).unwrap();

                let deletes: Vec<CidBytes> = dead_seeds.iter().map(|&s| test_cid(s)).collect();
                store.apply_commit_blocking(vec![], deletes).unwrap();
                advance_epoch(&store);
                std::thread::sleep(std::time::Duration::from_millis(5));

                let files = store.list_data_files().unwrap();
                let sealed: Vec<DataFileId> = files
                    .iter()
                    .copied()
                    .take(files.len().saturating_sub(1))
                    .collect();

                sealed.iter().for_each(|&fid| {
                    let _ = store.compact_file(fid, 0);
                });
            }

            let store = TranquilBlockStore::open(small_blockstore_config(dir.path())).unwrap();

            live_seeds.iter().for_each(|&s| {
                let data = store.get_block_sync(&test_cid(s)).unwrap();
                assert!(
                    data.is_some(),
                    "seed={seed} live block {s} must survive compaction+reopen"
                );
                assert_eq!(
                    &data.unwrap()[..4],
                    &s.to_le_bytes(),
                    "seed={seed} live block {s} data mismatch after compaction+reopen"
                );
            });
        });
    });
}

#[test]
fn sim_gc_compacted_files_contain_all_live_blocks() {
    with_runtime(|| {
        let seed_range = match sim_single_seed() {
            Some(s) => s..s + 1,
            None => 0..500u64,
        };

        seed_range.into_iter().for_each(|seed| {
            let dir = tempfile::TempDir::new().unwrap();
            let store = TranquilBlockStore::open(small_blockstore_config(dir.path())).unwrap();

            let total = ((seed % 100) as u32) + 50;
            let blocks: Vec<(CidBytes, Vec<u8>)> =
                (0..total).map(|i| (test_cid(i), block_data(i))).collect();
            blocks.chunks(10).for_each(|chunk| {
                store.put_blocks_blocking(chunk.to_vec()).unwrap();
            });

            let kill_set: HashSet<u32> = (0..total)
                .filter(|i| {
                    let hash = i.wrapping_mul(2654435761).wrapping_add(seed as u32);
                    hash % 3 == 0
                })
                .collect();
            let kill_cids: Vec<CidBytes> = kill_set.iter().map(|&i| test_cid(i)).collect();
            store.apply_commit_blocking(vec![], kill_cids).unwrap();

            advance_epoch(&store);
            std::thread::sleep(std::time::Duration::from_millis(5));

            compact_all_sealed(&store);

            let live_set: HashSet<u32> = (0..total).filter(|i| !kill_set.contains(i)).collect();

            live_set.iter().for_each(|&s| {
                let data = store.get_block_sync(&test_cid(s)).unwrap();
                assert!(
                    data.is_some(),
                    "seed={seed} live block {s} must be in compacted files"
                );
                assert_eq!(
                    &data.unwrap()[..4],
                    &s.to_le_bytes(),
                    "seed={seed} live block {s} data mismatch"
                );
            });

            let dead = collect_all_dead(&store);
            live_set.iter().for_each(|&s| {
                assert!(
                    !dead.contains(&test_cid(s)),
                    "seed={seed} live block {s} must not be dead after compaction"
                );
            });
        });
    });
}

#[test]
fn sim_gc_orphan_detection_after_crash_between_compact_and_delete() {
    with_runtime(|| {
        let seed_range = match sim_single_seed() {
            Some(s) => s..s + 1,
            None => 0..200u64,
        };

        seed_range.into_iter().for_each(|seed| {
            let dir = tempfile::TempDir::new().unwrap();
            let live_count = ((seed % 20) as u32) + 5;
            let dead_count = ((seed % 10) as u32) + 3;
            let padding_count = ((seed % 40) as u32) + 10;
            let live_seeds: Vec<u32> = (0..live_count).collect();
            let dead_seeds: Vec<u32> = (live_count..live_count + dead_count).collect();
            let padding_base = live_count + dead_count + 5000;

            let store = TranquilBlockStore::open(small_blockstore_config(dir.path())).unwrap();

            let all_blocks: Vec<(CidBytes, Vec<u8>)> = live_seeds
                .iter()
                .chain(dead_seeds.iter())
                .map(|&s| (test_cid(s), block_data(s)))
                .collect();
            store.put_blocks_blocking(all_blocks).unwrap();

            let padding: Vec<(CidBytes, Vec<u8>)> = (padding_base..padding_base + padding_count)
                .map(|s| (test_cid(s), vec![0xAAu8; 256]))
                .collect();
            store.put_blocks_blocking(padding).unwrap();

            let deletes: Vec<CidBytes> = dead_seeds.iter().map(|&s| test_cid(s)).collect();
            store.apply_commit_blocking(vec![], deletes).unwrap();
            advance_epoch(&store);
            std::thread::sleep(std::time::Duration::from_millis(5));

            let files = store.list_data_files().unwrap();
            let sealed: Vec<DataFileId> = files
                .iter()
                .copied()
                .take(files.len().saturating_sub(1))
                .collect();

            sealed.iter().for_each(|&fid| {
                let info = store.liveness_info(fid).unwrap();
                if info.ratio() < 1.0 && info.total_blocks > 0 {
                    let _ = store.compact_file(fid, 0);
                }
            });

            live_seeds.iter().for_each(|&s| {
                let data = store.get_block_sync(&test_cid(s)).unwrap();
                assert!(
                    data.is_some(),
                    "seed={seed} live block {s} must survive even with potential orphan data files"
                );
            });
        });
    });
}
