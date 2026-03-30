mod common;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tranquil_store::backup::{BackupCoordinator, restore_from_backup, verify_backup};
use tranquil_store::blockstore::CidBytes;
use tranquil_store::sim_single_seed;

use common::{
    Rng, TestStores, block_data, compact_all_sealed, open_test_stores, test_cid, test_cid_link,
    test_did, test_handle, test_uuid,
};
use tranquil_db_traits::{RepoEventType, SequenceNumber, SequencedEvent};

const CACHE_SIZE: u64 = 32 * 1024 * 1024;

fn open_soak_stores(base: &std::path::Path) -> TestStores {
    open_test_stores(base, 4096, CACHE_SIZE)
}

#[derive(Debug)]
struct SoakOracle {
    live_blocks: HashMap<u32, u32>,
    repos: HashSet<u64>,
    event_count: u64,
}

impl SoakOracle {
    fn new() -> Self {
        Self {
            live_blocks: HashMap::new(),
            repos: HashSet::new(),
            event_count: 0,
        }
    }

    fn put_block(&mut self, seed: u32) {
        *self.live_blocks.entry(seed).or_insert(0) += 1;
    }

    fn delete_block(&mut self, seed: u32) -> bool {
        match self.live_blocks.get_mut(&seed) {
            Some(rc) if *rc > 0 => {
                *rc -= 1;
                true
            }
            _ => false,
        }
    }

    fn add_repo(&mut self, idx: u64) {
        self.repos.insert(idx);
    }

    fn add_event(&mut self) {
        self.event_count += 1;
    }

    fn live_block_seeds(&self) -> Vec<u32> {
        self.live_blocks
            .iter()
            .filter(|&(_, rc)| *rc > 0)
            .map(|(&s, _)| s)
            .collect()
    }
}

#[derive(Debug)]
enum SoakOp {
    PutBlocks { count: u32 },
    DeleteBlocks { count: u32 },
    ReadBlocks { count: u32 },
    CreateRepo,
    AppendEvent,
    CompactGc,
    Backup,
    CrashRecover,
}

fn generate_ops(rng: &mut Rng, total: usize) -> Vec<SoakOp> {
    (0..total)
        .map(|_| {
            let roll = rng.range_u32(100);
            match roll {
                0..30 => SoakOp::PutBlocks {
                    count: rng.range_u32(10) + 1,
                },
                30..45 => SoakOp::DeleteBlocks {
                    count: rng.range_u32(5) + 1,
                },
                45..65 => SoakOp::ReadBlocks {
                    count: rng.range_u32(10) + 1,
                },
                65..75 => SoakOp::CreateRepo,
                75..85 => SoakOp::AppendEvent,
                85..92 => SoakOp::CompactGc,
                92..97 => SoakOp::Backup,
                _ => SoakOp::CrashRecover,
            }
        })
        .collect()
}

fn verify_integrity(stores: &TestStores, oracle: &SoakOracle) {
    oracle.live_block_seeds().iter().for_each(|&seed| {
        let data = stores.blockstore.get_block_sync(&test_cid(seed)).unwrap();
        assert!(
            data.is_some(),
            "soak: live block seed={seed} must be readable"
        );
        assert_eq!(
            &data.unwrap()[..4],
            &seed.to_le_bytes(),
            "soak: live block seed={seed} data mismatch"
        );
    });

    oracle.repos.iter().for_each(|&idx| {
        let uid = test_uuid(idx);
        let meta = stores.metastore.repo_ops().get_repo_meta(uid).unwrap();
        assert!(meta.is_some(), "soak: persisted repo idx={idx} must exist");
    });
}

#[test]
fn sim_soak_continuous_operations_with_crash_recovery() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();

    let seed = sim_single_seed().unwrap_or(42);
    let mut rng = Rng::new(seed);

    let op_count = match std::env::var("TRANQUIL_SOAK_OPS") {
        Ok(v) => v.parse::<usize>().unwrap_or(10_000),
        Err(_) => 10_000,
    };

    let ops = generate_ops(&mut rng, op_count);

    let dir = tempfile::TempDir::new().unwrap();
    let mut stores = Some(open_soak_stores(dir.path()));
    let mut oracle = SoakOracle::new();
    let mut block_counter: u32 = 0;
    let mut repo_counter: u64 = 0;
    let mut crash_count: u32 = 0;
    let mut backup_count: u32 = 0;
    let mut last_persist_repos: HashSet<u64> = HashSet::new();

    ops.iter().enumerate().for_each(|(op_idx, op)| {
        if matches!(op, SoakOp::CrashRecover) {
            {
                let s = stores.as_ref().unwrap();
                s.metastore.persist().unwrap();
                s.eventlog.sync().unwrap();
            }
            last_persist_repos = oracle.repos.clone();

            stores.take();
            stores = Some(open_soak_stores(dir.path()));
            crash_count += 1;

            let fresh = stores.as_ref().unwrap();
            oracle.live_block_seeds().iter().for_each(|&bseed| {
                let data = fresh.blockstore.get_block_sync(&test_cid(bseed)).unwrap();
                assert!(
                    data.is_some(),
                    "soak: after crash #{crash_count} (op={op_idx}), live block seed={bseed} must survive"
                );
            });

            last_persist_repos.iter().for_each(|&idx| {
                let uid = test_uuid(idx);
                let meta = fresh.metastore.repo_ops().get_repo_meta(uid).unwrap();
                assert!(
                    meta.is_some(),
                    "soak: after crash #{crash_count} (op={op_idx}), persisted repo idx={idx} must survive"
                );
            });

            return;
        }

        let s = stores.as_ref().unwrap();
        match op {
            SoakOp::PutBlocks { count } => {
                let base = block_counter;
                let blocks: Vec<(CidBytes, Vec<u8>)> = (0..*count)
                    .map(|j| {
                        let bseed = base + j;
                        (test_cid(bseed), block_data(bseed))
                    })
                    .collect();
                if s.blockstore.put_blocks_blocking(blocks).is_ok() {
                    (base..base + count).for_each(|bseed| oracle.put_block(bseed));
                }
                block_counter = base + count;
            }
            SoakOp::DeleteBlocks { count } => {
                let candidates: Vec<u32> = oracle.live_block_seeds();
                let to_delete: Vec<u32> =
                    candidates.iter().take(*count as usize).copied().collect();
                let cids: Vec<CidBytes> = to_delete.iter().map(|&bseed| test_cid(bseed)).collect();
                if !cids.is_empty()
                    && s.blockstore.apply_commit_blocking(vec![], cids).is_ok()
                {
                    to_delete.iter().for_each(|&bseed| {
                        let _ = oracle.delete_block(bseed);
                    });
                }
            }
            SoakOp::ReadBlocks { count } => {
                let live = oracle.live_block_seeds();
                live.iter().take(*count as usize).for_each(|&bseed| {
                    let data = s.blockstore.get_block_sync(&test_cid(bseed)).unwrap();
                    assert!(
                        data.is_some(),
                        "soak op={op_idx}: live block seed={bseed} must be readable"
                    );
                });
            }
            SoakOp::CreateRepo => {
                let idx = repo_counter;
                repo_counter += 1;
                let uid = test_uuid(idx);
                let did = test_did(idx);
                let handle = test_handle(idx);
                let cid_link = test_cid_link((idx & 0xFF) as u8);
                s.metastore
                    .repo_ops()
                    .create_repo(
                        s.metastore.database(),
                        uid,
                        &did,
                        &handle,
                        &cid_link,
                        &format!("rev{idx}"),
                    )
                    .unwrap();
                oracle.add_repo(idx);
            }
            SoakOp::AppendEvent => {
                let event_idx = oracle.event_count;
                let did = test_did(event_idx);
                let event = SequencedEvent {
                    seq: SequenceNumber::from_raw(0),
                    did: did.clone(),
                    created_at: chrono::Utc::now(),
                    event_type: RepoEventType::Commit,
                    commit_cid: None,
                    prev_cid: None,
                    prev_data_cid: None,
                    ops: None,
                    blobs: None,
                    blocks: None,
                    handle: None,
                    active: None,
                    status: None,
                    rev: Some(format!("soak-rev-{event_idx}")),
                };
                s.eventlog
                    .append_event(&did, RepoEventType::Commit, &event)
                    .unwrap();
                oracle.add_event();
            }
            SoakOp::CompactGc => {
                let _ = s.blockstore.apply_commit_blocking(vec![], vec![]);
                std::thread::sleep(std::time::Duration::from_millis(2));
                compact_all_sealed(&s.blockstore);
            }
            SoakOp::Backup => {
                s.metastore.persist().unwrap();
                s.eventlog.sync().unwrap();

                let backup_path = dir.path().join("_backup");
                let restore_path = dir.path().join("_restore");
                let _ = std::fs::remove_dir_all(&backup_path);
                let _ = std::fs::remove_dir_all(&restore_path);
                std::fs::create_dir_all(&backup_path).unwrap();

                let coordinator =
                    BackupCoordinator::new(&s.blockstore, &s.eventlog, &s.metastore);
                match coordinator.create_backup(&backup_path) {
                    Ok(manifest) => {
                        let verify_result = verify_backup(&backup_path).unwrap();
                        assert!(
                            verify_result.is_healthy(),
                            "soak op={op_idx}: backup must be healthy after {backup_count} backups"
                        );

                        let _ = restore_from_backup(&backup_path, &restore_path);

                        let _ = std::fs::remove_dir_all(&backup_path);
                        let _ = std::fs::remove_dir_all(&restore_path);

                        backup_count += 1;
                        let _ = manifest;
                    }
                    Err(_) => {
                        let _ = std::fs::remove_dir_all(&backup_path);
                    }
                }
            }
            SoakOp::CrashRecover => unreachable!(),
        }
    });

    let s = stores.as_ref().unwrap();
    s.metastore.persist().unwrap();
    s.eventlog.sync().unwrap();

    verify_integrity(s, &oracle);

    let live = oracle.live_block_seeds();
    let total_blocks = block_counter;
    let total_repos = repo_counter;
    let total_events = oracle.event_count;

    assert!(total_blocks > 0, "soak test must have written blocks");
    assert!(
        !live.is_empty(),
        "soak test must have live blocks at the end"
    );

    eprintln!(
        "soak test complete: seed={seed} ops={op_count} blocks_written={total_blocks} \
         live_blocks={} repos={total_repos} events={total_events} crashes={crash_count} \
         backups={backup_count}",
        live.len()
    );
}

#[test]
fn sim_soak_concurrent_writers_with_gc_and_reads() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();

    let seed = sim_single_seed().unwrap_or(99);
    let duration_ms: u64 = match std::env::var("TRANQUIL_SOAK_DURATION_MS") {
        Ok(v) => v.parse().unwrap_or(5_000),
        Err(_) => 5_000,
    };

    let dir = tempfile::TempDir::new().unwrap();
    let stores = open_soak_stores(dir.path());
    let stop = AtomicBool::new(false);
    let block_counter = AtomicU64::new(0);
    let ops_counter = AtomicU64::new(0);

    let initial_blocks: Vec<(CidBytes, Vec<u8>)> =
        (0u32..100).map(|i| (test_cid(i), block_data(i))).collect();
    stores
        .blockstore
        .put_blocks_blocking(initial_blocks)
        .unwrap();
    block_counter.store(100, Ordering::SeqCst);

    std::thread::scope(|s| {
        let writer = s.spawn(|| {
            std::iter::from_fn(|| (!stop.load(Ordering::Relaxed)).then_some(())).for_each(|()| {
                let base = block_counter.fetch_add(5, Ordering::SeqCst) as u32;
                let batch: Vec<(CidBytes, Vec<u8>)> = (base..base + 5)
                    .map(|i| (test_cid(i), block_data(i)))
                    .collect();
                let _ = stores.blockstore.put_blocks_blocking(batch);
                ops_counter.fetch_add(5, Ordering::Relaxed);
                std::thread::sleep(std::time::Duration::from_micros(100));
            });
        });

        let deleter = s.spawn(|| {
            let mut rng_d = Rng::new(seed + 1);
            std::iter::from_fn(|| (!stop.load(Ordering::Relaxed)).then_some(())).for_each(|()| {
                let target = rng_d.range_u32(50);
                let _ = stores
                    .blockstore
                    .apply_commit_blocking(vec![], vec![test_cid(target)]);
                ops_counter.fetch_add(1, Ordering::Relaxed);
                std::thread::sleep(std::time::Duration::from_millis(2));
            });
        });

        let reader = s.spawn(|| {
            let mut rng_r = Rng::new(seed + 2);
            std::iter::from_fn(|| (!stop.load(Ordering::Relaxed)).then_some(())).fold(
                0u64,
                |read_failures, ()| {
                    let target = rng_r.range_u32(80);
                    let inc = match stores.blockstore.get_block_sync(&test_cid(target)) {
                        Ok(Some(data)) => {
                            assert_eq!(
                                &data[..4],
                                &target.to_le_bytes(),
                                "reader: block {target} data mismatch during concurrent ops"
                            );
                            0
                        }
                        Ok(None) | Err(_) => 1,
                    };
                    ops_counter.fetch_add(1, Ordering::Relaxed);
                    std::thread::sleep(std::time::Duration::from_micros(50));
                    read_failures + inc
                },
            )
        });

        let gc_thread = s.spawn(|| {
            std::iter::from_fn(|| (!stop.load(Ordering::Relaxed)).then_some(())).fold(
                0u32,
                |gc_rounds, ()| {
                    let _ = stores.blockstore.apply_commit_blocking(vec![], vec![]);
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    if let Ok(files) = stores.blockstore.list_data_files() {
                        files
                            .iter()
                            .copied()
                            .take(files.len().saturating_sub(1))
                            .for_each(|fid| {
                                let _ = stores.blockstore.compact_file(fid, 0);
                            });
                    }
                    ops_counter.fetch_add(1, Ordering::Relaxed);
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    gc_rounds.saturating_add(1)
                },
            )
        });

        std::thread::sleep(std::time::Duration::from_millis(duration_ms));
        stop.store(true, Ordering::Relaxed);

        writer.join().unwrap();
        deleter.join().unwrap();
        let _read_failures = reader.join().unwrap();
        let gc_rounds = gc_thread.join().unwrap();

        let total_ops = ops_counter.load(Ordering::SeqCst);
        let final_block_count = block_counter.load(Ordering::SeqCst);

        assert!(gc_rounds > 0, "soak: gc must have run at least once");
        assert!(
            total_ops > 100,
            "soak: must have executed significant operations"
        );

        (50u32..80).for_each(|i| {
            let data = stores.blockstore.get_block_sync(&test_cid(i)).unwrap();
            assert!(
                data.is_some(),
                "soak: block {i} (never deleted) must be present after concurrent ops"
            );
            assert_eq!(
                &data.unwrap()[..4],
                &i.to_le_bytes(),
                "soak: block {i} content integrity check"
            );
        });

        eprintln!(
            "concurrent soak complete: seed={seed} duration={duration_ms}ms total_ops={total_ops} \
             blocks_allocated={final_block_count} gc_rounds={gc_rounds}"
        );
    });
}
