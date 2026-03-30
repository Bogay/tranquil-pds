mod common;

use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, Ordering};

use rayon::prelude::*;
use tranquil_store::RealIO;
use tranquil_store::backup::{BackupCoordinator, restore_from_backup, verify_backup};
use tranquil_store::blockstore::{
    BlockStoreConfig, CidBytes, DEFAULT_MAX_FILE_SIZE, GroupCommitConfig, TranquilBlockStore,
};
use tranquil_store::eventlog::{EventLog, EventLogConfig, EventSequence};
use tranquil_store::metastore::{Metastore, MetastoreConfig};
use tranquil_store::{sim_seed_range, sim_single_seed};

use common::{
    TestStores, assert_store_consistent, block_data, open_test_stores, test_cid, test_cid_link,
    test_did, test_handle, test_uuid, with_runtime,
};
use tranquil_db_traits::{RepoEventType, SequenceNumber, SequencedEvent};
use tranquil_types::Did;
use uuid::Uuid;

const CACHE_SIZE: u64 = 16 * 1024 * 1024;

fn open_stores(dir: &std::path::Path) -> TestStores {
    open_test_stores(dir, DEFAULT_MAX_FILE_SIZE, CACHE_SIZE)
}

fn seed_repo(stores: &TestStores, idx: u64) -> Uuid {
    let uid = test_uuid(idx);
    let did = test_did(idx);
    let handle = test_handle(idx);
    let cid = test_cid_link((idx & 0xFF) as u8);

    stores
        .metastore
        .repo_ops()
        .create_repo(
            stores.metastore.database(),
            uid,
            &did,
            &handle,
            &cid,
            &format!("rev{idx}"),
        )
        .unwrap();
    uid
}

fn append_event(stores: &TestStores, idx: u64) {
    let did = test_did(idx);
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
        rev: Some(format!("rev{idx}")),
    };
    stores
        .eventlog
        .append_event(&did, RepoEventType::Commit, &event)
        .unwrap();
}

#[derive(Debug)]
enum CrashPoint {
    AfterBlockstorePut,
    AfterMetastoreWrite,
    AfterEventlogAppend,
    AfterEventlogSync,
    NoAbruptDrop,
}

impl CrashPoint {
    fn from_seed(seed: u64) -> Self {
        match seed % 5 {
            0 => CrashPoint::AfterBlockstorePut,
            1 => CrashPoint::AfterMetastoreWrite,
            2 => CrashPoint::AfterEventlogAppend,
            3 => CrashPoint::AfterEventlogSync,
            _ => CrashPoint::NoAbruptDrop,
        }
    }
}

fn run_cross_store_crash_scenario(seed: u64) {
    let dir = tempfile::TempDir::new().unwrap();
    let crash_point = CrashPoint::from_seed(seed);
    let block_count = ((seed % 20) as u32) + 5;
    let repo_count = (seed % 3) + 1;

    {
        let stores = open_stores(dir.path());

        let blocks: Vec<(CidBytes, Vec<u8>)> = (0..block_count)
            .map(|i| (test_cid(i), block_data(i)))
            .collect();
        stores.blockstore.put_blocks_blocking(blocks).unwrap();

        if matches!(crash_point, CrashPoint::AfterBlockstorePut) {
            return;
        }

        (0..repo_count).for_each(|i| {
            seed_repo(&stores, seed * 100 + i);
        });
        stores.metastore.persist().unwrap();

        if matches!(crash_point, CrashPoint::AfterMetastoreWrite) {
            return;
        }

        (0..repo_count).for_each(|i| {
            append_event(&stores, seed * 100 + i);
        });

        if matches!(crash_point, CrashPoint::AfterEventlogAppend) {
            return;
        }

        stores.eventlog.sync().unwrap();

        if matches!(crash_point, CrashPoint::AfterEventlogSync) {
            return;
        }
    }

    let stores = open_stores(dir.path());

    (0..block_count).for_each(|i| {
        let cid = test_cid(i);
        let data = stores.blockstore.get_block_sync(&cid).unwrap();
        assert!(
            data.is_some(),
            "seed={seed} block {i} must survive crash (blocks are durable after put_blocks_blocking)"
        );
        assert_eq!(
            &data.unwrap()[..4],
            &i.to_le_bytes(),
            "seed={seed} block {i} content mismatch"
        );
    });

    match crash_point {
        CrashPoint::AfterBlockstorePut => {
            assert_eq!(
                stores.eventlog.max_seq(),
                EventSequence::BEFORE_ALL,
                "seed={seed} no events should exist after crash before metastore write"
            );
        }
        CrashPoint::AfterMetastoreWrite
        | CrashPoint::AfterEventlogAppend
        | CrashPoint::AfterEventlogSync
        | CrashPoint::NoAbruptDrop => {
            (0..repo_count).for_each(|i| {
                let uid = test_uuid(seed * 100 + i);
                let meta = stores.metastore.repo_ops().get_repo_meta(uid).unwrap();
                assert!(
                    meta.is_some(),
                    "seed={seed} repo {i} must survive (metastore persist was called)"
                );
            });
        }
    }

    match crash_point {
        CrashPoint::AfterEventlogSync | CrashPoint::NoAbruptDrop => {
            let max_seq = stores.eventlog.max_seq();
            assert!(
                max_seq.raw() >= repo_count,
                "seed={seed} eventlog should have at least {repo_count} events after sync, got {}",
                max_seq.raw()
            );
        }
        CrashPoint::AfterEventlogAppend => {
            let max_seq = stores.eventlog.max_seq();
            assert!(
                max_seq.raw() <= repo_count,
                "seed={seed} eventlog should have at most {repo_count} events without sync, got {}",
                max_seq.raw()
            );
        }
        _ => {}
    }

    assert_store_consistent(&stores, &format!("seed={seed} crash={crash_point:?}"));
}

#[test]
fn sim_cross_store_crash_at_random_points() {
    with_runtime(|| {
        sim_seed_range().into_par_iter().for_each(|seed| {
            run_cross_store_crash_scenario(seed);
        });
    });
}

fn run_partial_commit_consistency(seed: u64) {
    let dir = tempfile::TempDir::new().unwrap();
    let phase_count = ((seed % 4) as usize) + 2;
    let blocks_per_phase = ((seed % 8) as u32) + 3;

    let mut committed_block_ranges: Vec<std::ops::Range<u32>> = Vec::new();
    let mut committed_repo_ids: Vec<(u64, Uuid)> = Vec::new();
    let mut total_blocks: u32 = 0;

    (0..phase_count).for_each(|phase| {
        let crash_this_phase = phase == phase_count - 1 && !seed.is_multiple_of(3);
        let block_start = total_blocks;
        let block_end = block_start + blocks_per_phase;

        {
            let stores = open_stores(dir.path());

            committed_repo_ids.iter().for_each(|&(idx, uid)| {
                let meta = stores.metastore.repo_ops().get_repo_meta(uid).unwrap();
                assert!(
                    meta.is_some(),
                    "seed={seed} phase={phase} previously committed repo idx={idx} missing"
                );
            });

            committed_block_ranges.iter().for_each(|range| {
                range.clone().for_each(|i| {
                    let data = stores.blockstore.get_block_sync(&test_cid(i)).unwrap();
                    assert!(
                        data.is_some(),
                        "seed={seed} phase={phase} previously committed block {i} missing"
                    );
                });
            });

            let blocks: Vec<(CidBytes, Vec<u8>)> = (block_start..block_end)
                .map(|i| (test_cid(i), block_data(i)))
                .collect();
            stores.blockstore.put_blocks_blocking(blocks).unwrap();

            if crash_this_phase {
                return;
            }

            let idx = seed * 1000 + phase as u64;
            let uid = seed_repo(&stores, idx);
            stores.metastore.persist().unwrap();

            append_event(&stores, idx);
            stores.eventlog.sync().unwrap();

            committed_block_ranges.push(block_start..block_end);
            committed_repo_ids.push((idx, uid));
        }

        total_blocks = block_end;
    });

    let stores = open_stores(dir.path());

    committed_block_ranges.iter().for_each(|range| {
        range.clone().for_each(|i| {
            let data = stores.blockstore.get_block_sync(&test_cid(i)).unwrap();
            assert!(
                data.is_some(),
                "seed={seed} final verify: committed block {i} missing"
            );
        });
    });

    committed_repo_ids.iter().for_each(|&(idx, uid)| {
        let meta = stores.metastore.repo_ops().get_repo_meta(uid).unwrap();
        assert!(
            meta.is_some(),
            "seed={seed} final verify: committed repo idx={idx} missing"
        );
    });

    let expected_event_count = committed_repo_ids.len() as u64;
    let actual = stores.eventlog.max_seq();
    assert!(
        actual.raw() >= expected_event_count,
        "seed={seed} expected at least {expected_event_count} events, got {}",
        actual.raw()
    );

    assert_store_consistent(&stores, &format!("seed={seed} partial_commit_final"));
}

#[test]
fn sim_partial_commit_multi_phase_consistency() {
    with_runtime(|| {
        sim_seed_range().into_par_iter().for_each(|seed| {
            run_partial_commit_consistency(seed);
        });
    });
}

fn run_group_commit_crash(seed: u64) {
    let dir = tempfile::TempDir::new().unwrap();
    let batch_sizes: Vec<u32> = (0..((seed % 5) + 2))
        .map(|i| ((seed.wrapping_mul(7).wrapping_add(i * 13)) % 30) as u32 + 1)
        .collect();

    let mut expected_blocks: Vec<u32> = Vec::new();
    let crash_batch = (seed % batch_sizes.len() as u64) as usize;

    {
        let stores = open_stores(dir.path());
        let mut next_cid: u32 = 0;

        let _ = batch_sizes
            .iter()
            .enumerate()
            .try_for_each(|(batch_idx, &size)| {
                let start = next_cid;
                next_cid = start + size;
                let blocks: Vec<(CidBytes, Vec<u8>)> = (start..start + size)
                    .map(|i| (test_cid(i), block_data(i)))
                    .collect();

                stores.blockstore.put_blocks_blocking(blocks).unwrap();

                if batch_idx == crash_batch {
                    return ControlFlow::Break(());
                }

                expected_blocks.extend(start..start + size);
                ControlFlow::Continue(())
            });
    }

    let stores = open_stores(dir.path());

    expected_blocks.iter().for_each(|&i| {
        let data = stores.blockstore.get_block_sync(&test_cid(i)).unwrap();
        assert!(
            data.is_some(),
            "seed={seed} block {i} (committed before crash batch) must survive"
        );
    });
}

#[test]
fn sim_group_commit_crash_partial_batch() {
    with_runtime(|| {
        sim_seed_range().into_par_iter().for_each(|seed| {
            run_group_commit_crash(seed);
        });
    });
}

fn run_every_record_references_existing_block(seed: u64) {
    let dir = tempfile::TempDir::new().unwrap();
    let block_count = ((seed % 50) as u32) + 10;
    let repo_count = (seed % 5) + 1;

    {
        let stores = open_stores(dir.path());

        let blocks: Vec<(CidBytes, Vec<u8>)> = (0..block_count)
            .map(|i| (test_cid(i), block_data(i)))
            .collect();
        stores.blockstore.put_blocks_blocking(blocks).unwrap();

        (0..repo_count).for_each(|i| {
            seed_repo(&stores, seed * 100 + i);
        });
        stores.metastore.persist().unwrap();

        (0..repo_count).for_each(|i| {
            append_event(&stores, seed * 100 + i);
        });
        stores.eventlog.sync().unwrap();
    }

    let stores = open_stores(dir.path());

    (0..repo_count).for_each(|i| {
        let uid = test_uuid(seed * 100 + i);
        let meta = stores.metastore.repo_ops().get_repo_meta(uid).unwrap();
        assert!(
            meta.is_some(),
            "seed={seed} repo {i} must exist after recovery"
        );
        let (_, repo_meta) = meta.unwrap();

        let root_cid_bytes: &[u8] = &repo_meta.repo_root_cid;
        assert!(
            root_cid_bytes.len() >= 4,
            "seed={seed} repo {i} root CID must be valid"
        );
    });

    let max_seq = stores.eventlog.max_seq();
    assert!(
        max_seq.raw() >= repo_count,
        "seed={seed} eventlog must have at least {repo_count} events"
    );

    assert_store_consistent(&stores, &format!("seed={seed} every_record_refs_block"));
}

#[test]
fn sim_every_record_references_existing_block() {
    with_runtime(|| {
        sim_seed_range().into_par_iter().for_each(|seed| {
            run_every_record_references_existing_block(seed);
        });
    });
}

#[test]
fn sim_backup_during_concurrent_block_and_event_writes() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();

    let seed_range = match sim_single_seed() {
        Some(s) => s..s + 1,
        None => 0..50u64,
    };

    seed_range.into_par_iter().for_each(|seed| {
        let dir = tempfile::TempDir::new().unwrap();
        let stores = open_stores(dir.path());
        let block_base = (seed * 200) as u32;

        let initial_blocks: Vec<(CidBytes, Vec<u8>)> = (block_base..block_base + 30)
            .map(|i| (test_cid(i), block_data(i)))
            .collect();
        stores
            .blockstore
            .put_blocks_blocking(initial_blocks)
            .unwrap();

        (0..3).for_each(|i| {
            seed_repo(&stores, seed * 100 + i);
        });
        stores.metastore.persist().unwrap();

        (0..5).for_each(|i| {
            append_event(&stores, seed * 100 + i);
        });
        stores.eventlog.sync().unwrap();

        let writer_flag = AtomicBool::new(true);
        let write_base = block_base + 500;

        std::thread::scope(|s| {
            let writer_handle = s.spawn(|| {
                std::iter::from_fn(|| writer_flag.load(Ordering::Relaxed).then_some(())).fold(
                    write_base,
                    |idx, ()| {
                        let batch: Vec<(CidBytes, Vec<u8>)> = (idx..idx.saturating_add(3))
                            .map(|i| (test_cid(i), block_data(i)))
                            .collect();
                        let _ = stores.blockstore.put_blocks_blocking(batch);
                        std::thread::sleep(std::time::Duration::from_millis(1));
                        idx.saturating_add(3)
                    },
                );
            });

            let event_handle = s.spawn(|| {
                let did = Did::from("did:plc:concurrent_writer".to_string());
                std::iter::from_fn(|| writer_flag.load(Ordering::Relaxed).then_some(())).fold(
                    100u32,
                    |i, ()| {
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
                            rev: Some(format!("concurrent-{i}")),
                        };
                        let _ = stores
                            .eventlog
                            .append_event(&did, RepoEventType::Commit, &event);
                        let _ = stores.eventlog.sync();
                        std::thread::sleep(std::time::Duration::from_millis(2));
                        i.saturating_add(1)
                    },
                );
            });

            std::thread::sleep(std::time::Duration::from_millis(30));

            let backup_dir = tempfile::TempDir::new().unwrap();
            let coordinator =
                BackupCoordinator::new(&stores.blockstore, &stores.eventlog, &stores.metastore);
            let manifest = coordinator.create_backup(backup_dir.path()).unwrap();

            writer_flag.store(false, Ordering::Relaxed);
            writer_handle.join().unwrap();
            event_handle.join().unwrap();

            let verify_result = verify_backup(backup_dir.path()).unwrap();
            assert!(
                verify_result.is_healthy(),
                "seed={seed} backup during concurrent writes must be healthy: \
                 corrupted_blocks={}, corrupted_events={}, file_failures={}",
                verify_result.corrupted_blocks,
                verify_result.corrupted_events,
                verify_result.file_failures.len()
            );

            let restore_dir = tempfile::TempDir::new().unwrap();
            let restore_result =
                restore_from_backup(backup_dir.path(), restore_dir.path()).unwrap();
            assert!(
                restore_result.blocks_files_restored > 0,
                "seed={seed} restore must have block files"
            );

            let restored_bs = TranquilBlockStore::open(BlockStoreConfig {
                data_dir: restore_dir.path().join("blocks"),
                index_dir: restore_dir.path().join("block_index"),
                max_file_size: DEFAULT_MAX_FILE_SIZE,
                group_commit: GroupCommitConfig::default(),
                shard_count: 1,
            })
            .unwrap();

            (block_base..block_base + 30).for_each(|i| {
                let data = restored_bs.get_block_sync(&test_cid(i)).unwrap();
                assert!(
                    data.is_some(),
                    "seed={seed} pre-existing block {i} must exist in restored backup"
                );
                assert_eq!(
                    &data.unwrap()[..4],
                    &i.to_le_bytes(),
                    "seed={seed} block {i} content mismatch in restored backup"
                );
            });

            let restored_el = EventLog::open(
                EventLogConfig {
                    segments_dir: restore_dir.path().join("events"),
                    ..EventLogConfig::default()
                },
                RealIO::new(),
            )
            .unwrap();
            assert_eq!(
                restored_el.max_seq().raw(),
                manifest.eventlog.max_seq.raw(),
                "seed={seed} restored eventlog max_seq must match manifest"
            );
            let _ = restored_el.shutdown();

            let restored_ms = Metastore::open(
                &restore_dir.path().join("metastore"),
                MetastoreConfig {
                    cache_size_bytes: CACHE_SIZE,
                },
            )
            .unwrap();
            (0..3u64).for_each(|i| {
                let uid = test_uuid(seed * 100 + i);
                let meta = restored_ms.repo_ops().get_repo_meta(uid).unwrap();
                assert!(
                    meta.is_some(),
                    "seed={seed} repo {i} must exist in restored metastore"
                );
            });
        });
    });
}
