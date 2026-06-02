mod common;

use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, Ordering};

use rayon::prelude::*;
use tranquil_store::backup::{BackupCoordinator, restore_from_backup, verify_backup};
use tranquil_store::blockstore::{
    BlockStoreConfig, CidBytes, DEFAULT_MAX_FILE_SIZE, GroupCommitConfig, TranquilBlockStore,
};
use tranquil_store::consistency::{ConsistencyCheckOptions, verify_store_consistency_with_options};
use tranquil_store::eventlog::{EventLog, EventLogBridge, EventLogConfig, EventSequence};
use tranquil_store::metastore::record_ops::RecordWrite;
use tranquil_store::metastore::{Metastore, MetastoreConfig};
use tranquil_store::{RealIO, SimClock, SimulatedIO, SystemClock, sim_seed_range, sim_single_seed};

use common::{
    TestStores, assert_store_consistent, block_data, open_test_stores, test_cid, test_cid_link,
    test_did, test_handle, test_uuid, with_runtime,
};
use tranquil_db_traits::{
    ImportBlock, ImportRecord, RepoEventType, SequenceNumber, SequencedEvent,
};
use tranquil_types::{CidLink, Did, Nsid, Rkey};
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

fn make_commit_event(did: &Did, idx: u64) -> SequencedEvent {
    SequencedEvent {
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
    }
}

fn append_event(stores: &TestStores, idx: u64) {
    let did = test_did(idx);
    let event = make_commit_event(&did, idx);
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

fn import_blockstore(dir: &std::path::Path) -> TranquilBlockStore<RealIO, SystemClock> {
    TranquilBlockStore::open(BlockStoreConfig {
        data_dir: dir.join("blockstore/data"),
        index_dir: dir.join("blockstore/index"),
        max_file_size: DEFAULT_MAX_FILE_SIZE,
        group_commit: GroupCommitConfig::default(),
        shard_count: 1,
    })
    .unwrap()
}

fn import_metastore(dir: &std::path::Path) -> Metastore {
    Metastore::open(
        &dir.join("metastore"),
        MetastoreConfig {
            cache_size_bytes: CACHE_SIZE,
        },
    )
    .unwrap()
}

fn import_eventlog(dir: &std::path::Path) -> std::sync::Arc<EventLog<RealIO>> {
    std::sync::Arc::new(
        EventLog::open(
            EventLogConfig {
                segments_dir: dir.join("eventlog/segments"),
                ..EventLogConfig::default()
            },
            RealIO::new(),
        )
        .unwrap(),
    )
}

fn create_import_dirs(dir: &std::path::Path) {
    [
        dir.join("blockstore/data"),
        dir.join("blockstore/index"),
        dir.join("eventlog/segments"),
        dir.join("metastore"),
    ]
    .iter()
    .for_each(|d| std::fs::create_dir_all(d).unwrap());
}

fn import_fixture(seed: u64) -> (Vec<ImportBlock>, Vec<ImportRecord>) {
    let block_count = ((seed % 12) + 4) as u32;
    let collection = Nsid::from("app.bsky.feed.post".to_string());
    let blocks: Vec<ImportBlock> = (0..block_count)
        .map(|i| ImportBlock {
            cid_bytes: test_cid(i).to_vec(),
            data: block_data(i),
        })
        .collect();
    let records: Vec<ImportRecord> = (0..block_count)
        .map(|i| {
            let cid = cid::Cid::try_from(&test_cid(i)[..]).unwrap();
            ImportRecord {
                collection: collection.clone(),
                rkey: Rkey::from(format!("3kimport{i:04}")),
                record_cid: CidLink::from_cid(&cid),
            }
        })
        .collect();
    (blocks, records)
}

fn assert_import_complete(
    dir: &std::path::Path,
    user_id: Uuid,
    blocks: &[ImportBlock],
    records: &[ImportRecord],
    ctx: &str,
) {
    let bs = import_blockstore(dir);
    blocks.iter().for_each(|b| {
        let cid: CidBytes = b.cid_bytes.as_slice().try_into().unwrap();
        assert!(
            bs.get_block_sync(&cid).unwrap().is_some(),
            "{ctx}: imported block must be durable"
        );
    });
    let ms = import_metastore(dir);
    records.iter().enumerate().for_each(|(i, r)| {
        let got = ms
            .record_ops()
            .get_record_cid(user_id, &r.collection, &r.rkey)
            .unwrap();
        assert_eq!(
            got.as_ref(),
            Some(&r.record_cid),
            "{ctx}: imported record {i} must reference its block after recovery"
        );
    });
    let el = import_eventlog(dir);
    let report = verify_store_consistency_with_options(
        &bs,
        &ms,
        &el,
        ConsistencyCheckOptions {
            check_block_references: true,
            ..ConsistencyCheckOptions::default()
        },
    );
    assert!(
        report.dangling_record_cids.is_empty(),
        "{ctx}: every imported record must reference a present block: {report}"
    );
}

fn run_import_crash_scenario(seed: u64) {
    let dir = tempfile::TempDir::new().unwrap();
    create_import_dirs(dir.path());
    let user_id = test_uuid(seed);
    let did = test_did(seed);
    let handle = test_handle(seed);
    let root_cid = test_cid_link((seed & 0xFF) as u8);
    let (blocks, records) = import_fixture(seed);

    {
        let ms = import_metastore(dir.path());
        ms.repo_ops()
            .create_repo(ms.database(), user_id, &did, &handle, &root_cid, "rev0")
            .unwrap();
        ms.persist().unwrap();
    }

    if seed.is_multiple_of(2) {
        {
            let bs = import_blockstore(dir.path());
            let pairs: Vec<(CidBytes, Vec<u8>)> = blocks
                .iter()
                .map(|b| (b.cid_bytes.as_slice().try_into().unwrap(), b.data.clone()))
                .collect();
            bs.put_blocks_blocking(pairs).unwrap();
        }

        {
            let bs = import_blockstore(dir.path());
            blocks.iter().for_each(|b| {
                let cid: CidBytes = b.cid_bytes.as_slice().try_into().unwrap();
                assert!(
                    bs.get_block_sync(&cid).unwrap().is_some(),
                    "seed={seed} blocks are durable after put, before metastore commit"
                );
            });
            let ms = import_metastore(dir.path());
            records.iter().for_each(|r| {
                assert!(
                    ms.record_ops()
                        .get_record_cid(user_id, &r.collection, &r.rkey)
                        .unwrap()
                        .is_none(),
                    "seed={seed} no import record may exist before the metastore commit lands"
                );
            });
            let bridge = EventLogBridge::new(import_eventlog(dir.path()));
            let commit_ops = ms
                .commit_ops(std::sync::Arc::new(bridge))
                .with_blockstore(bs);
            commit_ops
                .import_repo_data(user_id, &blocks, &records, Some(&root_cid))
                .unwrap();
            ms.persist().unwrap();
        }
    } else {
        let ms = import_metastore(dir.path());
        let bs = import_blockstore(dir.path());
        let bridge = EventLogBridge::new(import_eventlog(dir.path()));
        let commit_ops = ms
            .commit_ops(std::sync::Arc::new(bridge))
            .with_blockstore(bs);
        commit_ops
            .import_repo_data(user_id, &blocks, &records, Some(&root_cid))
            .unwrap();
        ms.persist().unwrap();
    }

    assert_import_complete(
        dir.path(),
        user_id,
        &blocks,
        &records,
        &format!("seed={seed} import recovery"),
    );
}

#[test]
fn sim_import_repo_data_crash_during_import_recovers() {
    with_runtime(|| {
        sim_seed_range().into_par_iter().for_each(|seed| {
            run_import_crash_scenario(seed);
        });
    });
}

struct SimStores {
    blockstore: TranquilBlockStore<std::sync::Arc<SimulatedIO>, SimClock>,
    eventlog: std::sync::Arc<EventLog<std::sync::Arc<SimulatedIO>>>,
    metastore: Metastore,
}

fn open_sim_stores(
    dir: &std::path::Path,
    sim: &std::sync::Arc<SimulatedIO>,
    clock: &SimClock,
) -> SimStores {
    let blockstore = {
        let factory = std::sync::Arc::clone(sim);
        TranquilBlockStore::<std::sync::Arc<SimulatedIO>, SimClock>::open_with_io(
            BlockStoreConfig {
                data_dir: dir.join("blockstore/data"),
                index_dir: dir.join("blockstore/index"),
                max_file_size: 16 * 1024,
                group_commit: GroupCommitConfig {
                    synchronous: true,
                    verify_persisted_blocks: true,
                    ..GroupCommitConfig::default()
                },
                shard_count: 1,
            },
            move || std::sync::Arc::clone(&factory),
            clock.clone(),
        )
        .unwrap()
    };
    let eventlog = std::sync::Arc::new(
        EventLog::open(
            EventLogConfig {
                segments_dir: dir.join("eventlog/segments"),
                ..EventLogConfig::default()
            },
            std::sync::Arc::clone(sim),
        )
        .unwrap(),
    );
    let metastore = import_metastore(dir);
    SimStores {
        blockstore,
        eventlog,
        metastore,
    }
}

fn sim_fault_for(seed: u64) -> tranquil_store::FaultConfig {
    match seed % 3 {
        0 => tranquil_store::FaultConfig::recoverable(),
        1 => tranquil_store::FaultConfig::torn_pages_only(),
        _ => tranquil_store::FaultConfig::fsyncgate_only(),
    }
}

fn block_cid_link(i: u32) -> CidLink {
    let cid = cid::Cid::try_from(&test_cid(i)[..]).expect("test_cid is a valid cid");
    CidLink::from_cid(&cid)
}

fn commit_block_records(stores: &SimStores, uid: Uuid, collection: &Nsid, block_ids: &[u32]) {
    let Some(user_hash) = stores.metastore.user_hashes().get(&uid) else {
        return;
    };
    let rkeys: Vec<Rkey> = block_ids
        .iter()
        .map(|i| Rkey::from(format!("3k{i:08}")))
        .collect();
    let links: Vec<CidLink> = block_ids.iter().map(|&i| block_cid_link(i)).collect();
    let writes: Vec<RecordWrite<'_>> = rkeys
        .iter()
        .zip(links.iter())
        .map(|(rkey, cid)| RecordWrite {
            collection,
            rkey,
            cid,
        })
        .collect();
    let mut batch = stores.metastore.database().batch();
    stores
        .metastore
        .record_ops()
        .upsert_records(&mut batch, user_hash, &writes)
        .unwrap();
    batch.commit().unwrap();
    stores.metastore.persist().unwrap();
}

fn run_cross_store_fault_scenario(seed: u64) {
    let dir = tempfile::TempDir::new().unwrap();
    create_import_dirs(dir.path());
    let fault = sim_fault_for(seed);
    let sim = std::sync::Arc::new(SimulatedIO::new(seed, fault));
    let clock = sim.clock();

    let repo_count = ((seed % 4) + 1) as u32;
    let blocks_per_round = ((seed % 6) + 3) as u32;
    let rounds = ((seed % 4) + 2) as u32;
    let collection = Nsid::from("app.bsky.feed.post".to_string());
    let root_base = (seed as u32).wrapping_mul(100_000);

    let mut acked_blocks: Vec<u32> = Vec::new();
    let mut committed_repos: Vec<(u64, Uuid)> = Vec::new();

    sim.set_pristine_mode(true);
    let stores = open_sim_stores(dir.path(), &sim, &clock);

    let repo_uids: Vec<Uuid> = (0..repo_count)
        .map(|i| test_uuid(seed * 100 + i as u64))
        .collect();

    let root_pairs: Vec<(CidBytes, Vec<u8>)> = (0..repo_count)
        .map(|i| (test_cid(root_base + i), block_data(root_base + i)))
        .collect();
    stores.blockstore.put_blocks_blocking(root_pairs).unwrap();
    acked_blocks.extend((0..repo_count).map(|i| root_base + i));

    (0..repo_count).for_each(|i| {
        let idx = seed * 100 + i as u64;
        let uid = repo_uids[i as usize];
        let did = test_did(idx);
        let handle = test_handle(idx);
        let root = block_cid_link(root_base + i);
        stores
            .metastore
            .repo_ops()
            .create_repo(
                stores.metastore.database(),
                uid,
                &did,
                &handle,
                &root,
                &format!("rev{idx}"),
            )
            .unwrap();
        committed_repos.push((idx, uid));
    });
    stores.metastore.persist().unwrap();

    sim.set_pristine_mode(false);
    let mut next_block: u32 = root_base.wrapping_add(1000);
    (0..rounds).for_each(|round| {
        let start = next_block;
        next_block = next_block.wrapping_add(blocks_per_round);
        let block_ids: Vec<u32> = (start..start + blocks_per_round).collect();
        let pairs: Vec<(CidBytes, Vec<u8>)> = block_ids
            .iter()
            .map(|&i| (test_cid(i), block_data(i)))
            .collect();
        if stores.blockstore.put_blocks_blocking(pairs).is_ok() {
            acked_blocks.extend(block_ids.iter().copied());
            let uid = repo_uids[(round % repo_count) as usize];
            commit_block_records(&stores, uid, &collection, &block_ids);
        }
    });

    sim.set_pristine_mode(true);
    sim.crash();
    drop(stores);

    let stores = open_sim_stores(dir.path(), &sim, &clock);

    acked_blocks.iter().for_each(|&i| {
        let got = stores.blockstore.get_block_sync(&test_cid(i)).unwrap();
        assert!(
            got.is_some(),
            "seed={seed} fault={fault:?}: acked block {i} must survive fault+crash"
        );
        assert_eq!(
            &got.unwrap()[..4],
            &i.to_le_bytes(),
            "seed={seed} fault={fault:?}: acked block {i} content mismatch after recovery"
        );
    });

    committed_repos.iter().for_each(|&(idx, uid)| {
        assert!(
            stores
                .metastore
                .repo_ops()
                .get_repo_meta(uid)
                .unwrap()
                .is_some(),
            "seed={seed} fault={fault:?}: persisted repo {idx} must survive"
        );
    });

    let report = verify_store_consistency_with_options(
        &stores.blockstore,
        &stores.metastore,
        &stores.eventlog,
        ConsistencyCheckOptions::default(),
    );
    assert!(
        report.is_consistent(),
        "seed={seed} fault={fault:?}: every surviving record and repo root must reference a present block after fault+crash: {report}"
    );
}

#[test]
fn sim_cross_store_coordinated_commit_under_faults() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        run_cross_store_fault_scenario(seed);
    });
}

fn open_fault_eventlog(
    dir: &std::path::Path,
    sim: &std::sync::Arc<SimulatedIO>,
) -> std::sync::Arc<EventLog<std::sync::Arc<SimulatedIO>>> {
    std::sync::Arc::new(
        EventLog::open(
            EventLogConfig {
                segments_dir: dir.join("eventlog/segments"),
                ..EventLogConfig::default()
            },
            std::sync::Arc::clone(sim),
        )
        .unwrap(),
    )
}

fn run_eventlog_commit_loop_under_faults(seed: u64) {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join("eventlog/segments")).unwrap();
    let fault = sim_fault_for(seed);
    let sim = std::sync::Arc::new(SimulatedIO::new(seed, fault));
    let did = test_did(seed);
    let event_count = (seed % 40) + 20;

    let mut acked_sync_seq: u64 = 0;
    {
        sim.set_pristine_mode(true);
        let eventlog = open_fault_eventlog(dir.path(), &sim);
        sim.set_pristine_mode(false);

        (0..event_count).for_each(|i| {
            if eventlog
                .append_event(&did, RepoEventType::Commit, &make_commit_event(&did, i))
                .is_ok()
                && let Ok(result) = eventlog.sync()
            {
                acked_sync_seq = acked_sync_seq.max(result.synced_through.raw());
            }
        });

        sim.crash();
        drop(eventlog);
    }

    sim.set_pristine_mode(true);
    let reopened = open_fault_eventlog(dir.path(), &sim);
    let recovered = reopened.max_seq().raw();
    assert!(
        recovered >= acked_sync_seq,
        "seed={seed} fault={fault:?}: events acknowledged synced through {acked_sync_seq} must survive crash, recovered max_seq={recovered}"
    );
    assert!(
        recovered <= event_count,
        "seed={seed} fault={fault:?}: recovery invented events beyond the {event_count} appended, recovered max_seq={recovered}"
    );
    let _ = reopened.shutdown();
}

#[test]
fn sim_eventlog_commit_loop_durability_under_faults() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        run_eventlog_commit_loop_under_faults(seed);
    });
}

fn open_sim_blockstore(
    dir: &std::path::Path,
    sim: &std::sync::Arc<SimulatedIO>,
    clock: &SimClock,
) -> TranquilBlockStore<std::sync::Arc<SimulatedIO>, SimClock> {
    let factory = std::sync::Arc::clone(sim);
    TranquilBlockStore::<std::sync::Arc<SimulatedIO>, SimClock>::open_with_io(
        BlockStoreConfig {
            data_dir: dir.join("blockstore/data"),
            index_dir: dir.join("blockstore/index"),
            max_file_size: 64 * 1024,
            group_commit: GroupCommitConfig {
                synchronous: true,
                verify_persisted_blocks: true,
                ..GroupCommitConfig::default()
            },
            shard_count: 1,
        },
        move || std::sync::Arc::clone(&factory),
        clock.clone(),
    )
    .unwrap()
}

fn run_midcommit_crash_atomicity(seed: u64) -> bool {
    let dir = tempfile::TempDir::new().unwrap();
    create_import_dirs(dir.path());
    let sim = std::sync::Arc::new(SimulatedIO::new(seed, tranquil_store::FaultConfig::none()));
    let clock = sim.clock();
    let base = (seed as u32).wrapping_mul(10_000);
    let baseline: Vec<u32> = (base..base + 5).collect();
    let victim: Vec<u32> = (base + 5..base + 5 + 12).collect();
    let after_writes = ((seed % 8) + 1) as i64;

    {
        let bs = open_sim_blockstore(dir.path(), &sim, &clock);
        bs.put_blocks_blocking(
            baseline
                .iter()
                .map(|&i| (test_cid(i), block_data(i)))
                .collect(),
        )
        .unwrap();
        sim.arm_write_crash(after_writes);
        let _ = bs.put_blocks_blocking(
            victim
                .iter()
                .map(|&i| (test_cid(i), block_data(i)))
                .collect(),
        );
        sim.crash();
        drop(bs);
    }

    let bs = open_sim_blockstore(dir.path(), &sim, &clock);
    baseline.iter().for_each(|&i| {
        assert!(
            bs.get_block_sync(&test_cid(i)).unwrap().is_some(),
            "seed={seed} baseline block {i} committed before the mid-commit crash must survive"
        );
    });
    let present = victim
        .iter()
        .filter(|&&i| bs.get_block_sync(&test_cid(i)).unwrap().is_some())
        .count();
    assert!(
        present == 0 || present == victim.len(),
        "seed={seed} multi-block commit must be atomic across a mid-commit crash: {present}/{} victim blocks present",
        victim.len()
    );
    present == 0
}

#[test]
fn sim_blockstore_atomic_commit_under_midcommit_crash() {
    let interrupted = std::sync::atomic::AtomicU32::new(0);
    let total = std::sync::atomic::AtomicU32::new(0);
    sim_seed_range().into_par_iter().for_each(|seed| {
        total.fetch_add(1, Ordering::Relaxed);
        if run_midcommit_crash_atomicity(seed) {
            interrupted.fetch_add(1, Ordering::Relaxed);
        }
    });
    let interrupted = interrupted.load(Ordering::Relaxed);
    let total = total.load(Ordering::Relaxed);
    assert!(
        interrupted * 2 >= total,
        "mid-commit crash must actually interrupt the commit in most seeds, otherwise this test has no teeth: interrupted {interrupted}/{total}"
    );
}
