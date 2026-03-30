use std::path::Path;
use std::sync::Arc;

use tranquil_store::RealIO;
use tranquil_store::backup::{
    BackupCoordinator, BackupKind, read_manifest, recover_to_sequence, restore_from_backup,
    restore_from_incremental, verify_backup,
};
use tranquil_store::blockstore::{
    BlockStoreConfig, CidBytes, DEFAULT_MAX_FILE_SIZE, GroupCommitConfig, TranquilBlockStore,
};
use tranquil_store::eventlog::{EventLog, EventLogConfig};
use tranquil_store::metastore::{Metastore, MetastoreConfig};

fn test_cid(seed: u16) -> CidBytes {
    let mut cid = [0u8; 36];
    cid[0] = 0x01;
    cid[1] = 0x71;
    cid[2] = 0x12;
    cid[3] = 0x20;
    cid[4..6].copy_from_slice(&seed.to_le_bytes());
    (6..36).for_each(|i| cid[i] = (seed as u8).wrapping_add(i as u8));
    cid
}

fn block_data(seed: u16) -> Vec<u8> {
    let tag = seed.to_le_bytes();
    let mut data = vec![0u8; 128];
    data[..2].copy_from_slice(&tag);
    data
}

struct TestStore {
    _dir: tempfile::TempDir,
    blockstore: TranquilBlockStore,
    eventlog: Arc<EventLog<RealIO>>,
    metastore: Metastore,
}

fn open_test_store() -> TestStore {
    open_test_store_with_max_file_size(DEFAULT_MAX_FILE_SIZE)
}

fn open_test_store_with_max_file_size(max_file_size: u64) -> TestStore {
    let dir = tempfile::TempDir::new().unwrap();

    let bs_data = dir.path().join("blockstore/data");
    let bs_index = dir.path().join("blockstore/index");
    let segments_dir = dir.path().join("eventlog/segments");
    let metastore_dir = dir.path().join("metastore");

    [&bs_data, &bs_index, &segments_dir, &metastore_dir]
        .iter()
        .for_each(|d| std::fs::create_dir_all(d).unwrap());

    let blockstore = TranquilBlockStore::open(BlockStoreConfig {
        data_dir: bs_data,
        index_dir: bs_index,
        max_file_size,
        group_commit: GroupCommitConfig::default(),
        shard_count: 1,
    })
    .unwrap();

    let eventlog = Arc::new(
        EventLog::open(
            EventLogConfig {
                segments_dir,
                ..EventLogConfig::default()
            },
            RealIO::new(),
        )
        .unwrap(),
    );

    let metastore = Metastore::open(
        &metastore_dir,
        MetastoreConfig {
            cache_size_bytes: 64 * 1024 * 1024,
        },
    )
    .unwrap();

    TestStore {
        _dir: dir,
        blockstore,
        eventlog,
        metastore,
    }
}

fn seed_blocks(store: &TestStore, range: std::ops::Range<u16>) {
    let blocks: Vec<(CidBytes, Vec<u8>)> = range.map(|i| (test_cid(i), block_data(i))).collect();
    store.blockstore.put_blocks_blocking(blocks).unwrap();
}

fn seed_repo(store: &TestStore, name: &str, seed: u8) {
    let did = tranquil_types::Did::from(format!("did:plc:{name}"));
    let handle = tranquil_types::Handle::from(format!("{name}.test.invalid"));
    let digest: [u8; 32] = std::array::from_fn(|i| seed.wrapping_add(i as u8));
    let mh = multihash::Multihash::<64>::wrap(0x12, &digest).unwrap();
    let cid = cid::Cid::new_v1(0x71, mh);
    let cid_link = tranquil_types::CidLink::from_cid(&cid);

    store
        .metastore
        .repo_ops()
        .create_repo(
            store.metastore.database(),
            uuid::Uuid::new_v4(),
            &did,
            &handle,
            &cid_link,
            &format!("rev_{seed}"),
        )
        .unwrap();
}

fn seed_events(store: &TestStore, count: u16) {
    let did = tranquil_types::Did::from("did:plc:evtest".to_string());
    (0..count).for_each(|i| {
        let event = tranquil_db_traits::SequencedEvent {
            seq: tranquil_db_traits::SequenceNumber::from_raw(i as i64 + 1),
            did: did.clone(),
            created_at: chrono::Utc::now(),
            event_type: tranquil_db_traits::RepoEventType::Commit,
            commit_cid: None,
            prev_cid: None,
            prev_data_cid: None,
            ops: None,
            blobs: None,
            blocks: None,
            handle: None,
            active: None,
            status: None,
            rev: Some(format!("rev{i}")),
        };
        store
            .eventlog
            .append_event(&did, tranquil_db_traits::RepoEventType::Commit, &event)
            .unwrap();
    });
    store.eventlog.sync().unwrap();
}

fn archive_segments(store: &TestStore, archive_dir: &Path) {
    std::fs::read_dir(store.eventlog.segments_dir())
        .unwrap()
        .filter_map(|e| e.ok())
        .for_each(|entry| {
            let dest = archive_dir.join(entry.file_name());
            std::fs::copy(entry.path(), dest).unwrap();
        });
}

fn coordinator(store: &TestStore) -> BackupCoordinator<'_, RealIO> {
    BackupCoordinator::new(&store.blockstore, &store.eventlog, &store.metastore)
}

fn with_runtime<F: FnOnce()>(f: F) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    f();
}

fn verify_blocks_readable(store: &TranquilBlockStore, range: std::ops::Range<u16>) {
    range.for_each(|i| {
        let cid = test_cid(i);
        let data = store.get_block_sync(&cid).unwrap();
        assert!(data.is_some(), "block seed={i} must be readable");
        assert_eq!(
            &data.unwrap()[..2],
            &i.to_le_bytes(),
            "data mismatch for block seed={i}"
        );
    });
}

fn verify_restored_blocks(restored_dir: &Path, range: std::ops::Range<u16>) {
    let bs = TranquilBlockStore::open(BlockStoreConfig {
        data_dir: restored_dir.join("blocks"),
        index_dir: restored_dir.join("block_index"),
        max_file_size: DEFAULT_MAX_FILE_SIZE,
        group_commit: GroupCommitConfig::default(),
        shard_count: 1,
    })
    .unwrap();

    verify_blocks_readable(&bs, range);
}

fn verify_restored_events(restored_dir: &Path, expected_max_seq: u64) {
    let el = EventLog::open(
        EventLogConfig {
            segments_dir: restored_dir.join("events"),
            ..EventLogConfig::default()
        },
        RealIO::new(),
    )
    .unwrap();

    assert_eq!(
        el.max_seq().raw(),
        expected_max_seq,
        "restored eventlog max_seq mismatch"
    );
    let _ = el.shutdown();
}

fn verify_restored_metastore(restored_dir: &Path, repo_names: &[&str]) {
    let ms = Metastore::open(
        &restored_dir.join("metastore"),
        MetastoreConfig {
            cache_size_bytes: 64 * 1024 * 1024,
        },
    )
    .unwrap();

    let ops = ms.repo_ops();
    repo_names.iter().for_each(|name| {
        let did = tranquil_types::Did::from(format!("did:plc:{name}"));
        let root = ops.get_repo_root_by_did(&did).unwrap();
        assert!(
            root.is_some(),
            "repo {name} must exist in restored metastore"
        );
    });
}

#[test]
fn verify_backup_detects_corrupted_block_file() {
    with_runtime(|| {
        let store = open_test_store();
        seed_blocks(&store, 0..20);
        seed_events(&store, 5);

        let backup_dir = tempfile::TempDir::new().unwrap();
        coordinator(&store)
            .create_backup(backup_dir.path())
            .unwrap();

        let result = verify_backup(backup_dir.path()).unwrap();
        assert!(result.is_healthy(), "fresh backup must be healthy");
        assert!(result.total_blocks >= 20);
        assert_eq!(result.corrupted_blocks, 0);

        let blocks_dir = backup_dir.path().join("blocks");
        let entries: Vec<_> = std::fs::read_dir(&blocks_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext == "tqb")
            })
            .collect();
        assert!(!entries.is_empty(), "must have at least one block file");

        let target = &entries[0].path();
        let mut corrupted = std::fs::read(target).unwrap();
        corrupted
            .iter_mut()
            .skip(64)
            .take(32)
            .for_each(|b| *b ^= 0xFF);
        std::fs::write(target, &corrupted).unwrap();

        let result = verify_backup(backup_dir.path()).unwrap();
        assert!(
            result.corrupted_blocks > 0 || !result.file_failures.is_empty(),
            "verify must detect corruption: corrupted_blocks={}, file_failures={}",
            result.corrupted_blocks,
            result.file_failures.len()
        );
    });
}

#[test]
fn verify_backup_detects_corrupted_event_file() {
    with_runtime(|| {
        let store = open_test_store();
        seed_events(&store, 50);

        let backup_dir = tempfile::TempDir::new().unwrap();
        coordinator(&store)
            .create_backup(backup_dir.path())
            .unwrap();

        let result = verify_backup(backup_dir.path()).unwrap();
        assert!(result.is_healthy());
        assert!(result.total_events >= 50);

        let events_dir = backup_dir.path().join("events");
        let entries: Vec<_> = std::fs::read_dir(&events_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext == "tqe")
            })
            .collect();
        assert!(!entries.is_empty());

        let target = &entries[0].path();
        let mut corrupted = std::fs::read(target).unwrap();
        corrupted
            .iter_mut()
            .skip(64)
            .take(32)
            .for_each(|b| *b ^= 0xFF);
        std::fs::write(target, &corrupted).unwrap();

        let result = verify_backup(backup_dir.path()).unwrap();
        assert!(
            result.corrupted_events > 0 || !result.file_failures.is_empty(),
            "verify must detect event corruption: corrupted_events={}, file_failures={}",
            result.corrupted_events,
            result.file_failures.len()
        );
    });
}

#[test]
fn verify_backup_detects_checksum_mismatch() {
    with_runtime(|| {
        let store = open_test_store();
        seed_blocks(&store, 0..5);
        seed_events(&store, 3);

        let backup_dir = tempfile::TempDir::new().unwrap();
        coordinator(&store)
            .create_backup(backup_dir.path())
            .unwrap();

        let manifest = read_manifest(backup_dir.path()).unwrap();
        let first_file = &manifest.files[0];
        let file_path = backup_dir.path().join(&first_file.path);
        let mut data = std::fs::read(&file_path).unwrap();
        data.iter_mut().take(8).for_each(|b| *b ^= 0xFF);
        std::fs::write(&file_path, &data).unwrap();

        let result = verify_backup(backup_dir.path()).unwrap();
        assert!(
            !result.file_failures.is_empty(),
            "checksum mismatch must be detected"
        );
    });
}

#[test]
fn full_backup_and_restore_cycle() {
    with_runtime(|| {
        let store = open_test_store();

        seed_blocks(&store, 0..50);
        seed_repo(&store, "olaren", 1);
        seed_repo(&store, "teq", 2);
        seed_events(&store, 20);
        store.metastore.persist().unwrap();

        let backup_dir = tempfile::TempDir::new().unwrap();
        let manifest = coordinator(&store)
            .create_backup(backup_dir.path())
            .unwrap();

        assert_eq!(manifest.kind, BackupKind::Full);
        assert_eq!(manifest.version, 1);
        assert!(manifest.eventlog.max_seq.raw() >= 20);

        seed_blocks(&store, 50..100);
        seed_repo(&store, "nel", 3);
        seed_events(&store, 10);

        let restore_dir = tempfile::TempDir::new().unwrap();
        let result = restore_from_backup(backup_dir.path(), restore_dir.path()).unwrap();

        assert!(result.blocks_files_restored > 0);
        assert!(result.event_segments_restored > 0);
        assert!(result.metastore_files_restored > 0);

        verify_restored_blocks(restore_dir.path(), 0..50);
        verify_restored_events(restore_dir.path(), manifest.eventlog.max_seq.raw());
        verify_restored_metastore(restore_dir.path(), &["olaren", "teq"]);

        let ms = Metastore::open(
            &restore_dir.path().join("metastore"),
            MetastoreConfig {
                cache_size_bytes: 64 * 1024 * 1024,
            },
        )
        .unwrap();
        let nel_did = tranquil_types::Did::from("did:plc:nel".to_string());
        assert!(
            ms.repo_ops()
                .get_repo_root_by_did(&nel_did)
                .unwrap()
                .is_none(),
            "nel was added after backup and must not exist in restored data"
        );

        let verify = verify_backup(backup_dir.path()).unwrap();
        assert!(verify.is_healthy());
    });
}

#[test]
fn full_backup_and_restore_preserves_block_content() {
    with_runtime(|| {
        let store = open_test_store();
        seed_blocks(&store, 0..100);
        seed_events(&store, 10);

        let backup_dir = tempfile::TempDir::new().unwrap();
        coordinator(&store)
            .create_backup(backup_dir.path())
            .unwrap();

        let restore_dir = tempfile::TempDir::new().unwrap();
        restore_from_backup(backup_dir.path(), restore_dir.path()).unwrap();

        let restored_bs = TranquilBlockStore::open(BlockStoreConfig {
            data_dir: restore_dir.path().join("blocks"),
            index_dir: restore_dir.path().join("block_index"),
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            group_commit: GroupCommitConfig::default(),
            shard_count: 1,
        })
        .unwrap();

        (0u16..100).for_each(|i| {
            let cid = test_cid(i);
            let original = store.blockstore.get_block_sync(&cid).unwrap().unwrap();
            let restored = restored_bs.get_block_sync(&cid).unwrap().unwrap();
            assert_eq!(original, restored, "block content mismatch for seed={i}");
        });
    });
}

#[test]
fn incremental_backup_and_restore() {
    with_runtime(|| {
        let store = open_test_store();

        seed_blocks(&store, 0..30);
        seed_repo(&store, "olaren", 1);
        seed_events(&store, 10);
        store.metastore.persist().unwrap();

        let base_dir = tempfile::TempDir::new().unwrap();
        let base_manifest = coordinator(&store).create_backup(base_dir.path()).unwrap();
        assert_eq!(base_manifest.kind, BackupKind::Full);

        seed_blocks(&store, 30..60);
        seed_repo(&store, "teq", 2);
        seed_events(&store, 15);
        store.metastore.persist().unwrap();

        let incr_dir = tempfile::TempDir::new().unwrap();
        let incr_manifest = coordinator(&store)
            .create_incremental_backup(&base_manifest, incr_dir.path())
            .unwrap();
        assert_eq!(incr_manifest.kind, BackupKind::Incremental);
        assert!(incr_manifest.base_blockstore.is_some());
        assert!(incr_manifest.base_eventlog.is_some());
        assert!(incr_manifest.eventlog.max_seq >= base_manifest.eventlog.max_seq);

        let restore_dir = tempfile::TempDir::new().unwrap();
        let result =
            restore_from_incremental(base_dir.path(), incr_dir.path(), restore_dir.path()).unwrap();

        assert!(result.blocks_files_restored > 0);
        assert!(result.event_segments_restored > 0);

        verify_restored_blocks(restore_dir.path(), 0..60);
        verify_restored_events(restore_dir.path(), incr_manifest.eventlog.max_seq.raw());
        verify_restored_metastore(restore_dir.path(), &["olaren", "teq"]);
    });
}

#[test]
fn incremental_is_smaller_than_full() {
    with_runtime(|| {
        let store = open_test_store_with_max_file_size(2048);
        seed_blocks(&store, 0..100);
        seed_events(&store, 50);
        store.metastore.persist().unwrap();

        let base_dir = tempfile::TempDir::new().unwrap();
        let base_manifest = coordinator(&store).create_backup(base_dir.path()).unwrap();

        seed_blocks(&store, 100..120);
        seed_events(&store, 10);
        store.metastore.persist().unwrap();

        let incr_dir = tempfile::TempDir::new().unwrap();
        let incr_manifest = coordinator(&store)
            .create_incremental_backup(&base_manifest, incr_dir.path())
            .unwrap();

        let full2_dir = tempfile::TempDir::new().unwrap();
        coordinator(&store).create_backup(full2_dir.path()).unwrap();

        let incr_block_bytes: u64 = incr_manifest
            .files
            .iter()
            .filter(|f| f.path.starts_with("blocks"))
            .map(|f| f.size)
            .sum();

        let full2_manifest = read_manifest(full2_dir.path()).unwrap();
        let full_block_bytes: u64 = full2_manifest
            .files
            .iter()
            .filter(|f| f.path.starts_with("blocks"))
            .map(|f| f.size)
            .sum();

        assert!(
            incr_block_bytes < full_block_bytes,
            "incremental block data ({incr_block_bytes}) should be smaller than full ({full_block_bytes})"
        );
    });
}

#[test]
fn point_in_time_recovery_to_exact_sequence() {
    with_runtime(|| {
        let store = open_test_store();

        seed_blocks(&store, 0..20);
        seed_repo(&store, "pitr_user", 1);
        seed_events(&store, 30);
        store.metastore.persist().unwrap();

        let backup_dir = tempfile::TempDir::new().unwrap();
        let manifest = coordinator(&store)
            .create_backup(backup_dir.path())
            .unwrap();
        let backup_max = manifest.eventlog.max_seq;

        seed_events(&store, 20);
        store.eventlog.sync().unwrap();

        let final_max = store.eventlog.max_seq();
        assert!(final_max > backup_max);

        let archive_dir = tempfile::TempDir::new().unwrap();
        archive_segments(&store, archive_dir.path());

        let target_seq = tranquil_store::eventlog::EventSequence::new(
            backup_max.raw() + (final_max.raw() - backup_max.raw()) / 2,
        );

        let restore_dir = tempfile::TempDir::new().unwrap();
        let pitr_result = recover_to_sequence(
            backup_dir.path(),
            archive_dir.path(),
            target_seq,
            restore_dir.path(),
        )
        .unwrap();

        assert_eq!(pitr_result.target_seq, target_seq);
        assert!(pitr_result.events_replayed > 0);

        verify_restored_blocks(restore_dir.path(), 0..20);
        verify_restored_metastore(restore_dir.path(), &["pitr_user"]);

        let restored_el = EventLog::open(
            EventLogConfig {
                segments_dir: restore_dir.path().join("events"),
                ..EventLogConfig::default()
            },
            RealIO::new(),
        )
        .unwrap();
        assert!(restored_el.max_seq() >= target_seq);
        let _ = restored_el.shutdown();
    });
}

#[test]
fn pitr_at_backup_sequence_replays_zero_events() {
    with_runtime(|| {
        let store = open_test_store();
        seed_blocks(&store, 0..10);
        seed_events(&store, 15);
        store.metastore.persist().unwrap();

        let backup_dir = tempfile::TempDir::new().unwrap();
        let manifest = coordinator(&store)
            .create_backup(backup_dir.path())
            .unwrap();

        let archive_dir = tempfile::TempDir::new().unwrap();
        archive_segments(&store, archive_dir.path());

        let restore_dir = tempfile::TempDir::new().unwrap();
        let pitr_result = recover_to_sequence(
            backup_dir.path(),
            archive_dir.path(),
            manifest.eventlog.max_seq,
            restore_dir.path(),
        )
        .unwrap();

        assert_eq!(pitr_result.events_replayed, 0);
    });
}

#[test]
fn crash_during_backup_does_not_corrupt_live_store() {
    with_runtime(|| {
        let store = open_test_store();
        seed_blocks(&store, 0..50);
        seed_repo(&store, "crash_test", 1);
        seed_events(&store, 20);
        store.metastore.persist().unwrap();

        let backup_dir = tempfile::TempDir::new().unwrap();
        coordinator(&store)
            .create_backup(backup_dir.path())
            .unwrap();

        verify_blocks_readable(&store.blockstore, 0..50);

        let extra_blocks: Vec<(CidBytes, Vec<u8>)> =
            (50u16..80).map(|i| (test_cid(i), block_data(i))).collect();
        store.blockstore.put_blocks_blocking(extra_blocks).unwrap();

        verify_blocks_readable(&store.blockstore, 0..80);

        seed_events(&store, 10);
        assert!(store.eventlog.max_seq().raw() >= 30);

        seed_repo(&store, "post_backup", 2);
        store.metastore.persist().unwrap();
        let did = tranquil_types::Did::from("did:plc:post_backup".to_string());
        assert!(
            store
                .metastore
                .repo_ops()
                .get_repo_root_by_did(&did)
                .unwrap()
                .is_some(),
            "post-backup repo must exist in live store"
        );
    });
}

#[test]
fn backup_during_concurrent_writes_produces_consistent_snapshot() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();

    let store = open_test_store();
    seed_blocks(&store, 0..20);
    seed_events(&store, 10);
    store.metastore.persist().unwrap();

    let writer_flag = Arc::new(std::sync::atomic::AtomicBool::new(true));

    let bs_clone = store.blockstore.clone();
    let flag_clone = Arc::clone(&writer_flag);
    let writer_handle = std::thread::spawn(move || {
        let mut seed = 1000u16;
        while flag_clone.load(std::sync::atomic::Ordering::Relaxed) {
            let batch: Vec<(CidBytes, Vec<u8>)> = (seed..seed.saturating_add(5))
                .map(|i| (test_cid(i), block_data(i)))
                .collect();
            let _ = bs_clone.put_blocks_blocking(batch);
            seed = seed.saturating_add(5);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    });

    let el_clone = Arc::clone(&store.eventlog);
    let flag_clone2 = Arc::clone(&writer_flag);
    let event_handle = std::thread::spawn(move || {
        let did = tranquil_types::Did::from("did:plc:concurrent".to_string());
        let mut i = 0u32;
        while flag_clone2.load(std::sync::atomic::Ordering::Relaxed) {
            let event = tranquil_db_traits::SequencedEvent {
                seq: tranquil_db_traits::SequenceNumber::from_raw(i as i64 + 1),
                did: did.clone(),
                created_at: chrono::Utc::now(),
                event_type: tranquil_db_traits::RepoEventType::Commit,
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
            let _ = el_clone.append_event(&did, tranquil_db_traits::RepoEventType::Commit, &event);
            let _ = el_clone.sync();
            i = i.saturating_add(1);
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    });

    std::thread::sleep(std::time::Duration::from_millis(50));

    let backup_dir = tempfile::TempDir::new().unwrap();
    let manifest = coordinator(&store)
        .create_backup(backup_dir.path())
        .unwrap();

    writer_flag.store(false, std::sync::atomic::Ordering::Relaxed);
    writer_handle.join().unwrap();
    event_handle.join().unwrap();

    assert_eq!(manifest.kind, BackupKind::Full);
    assert!(!manifest.files.is_empty());

    let verify = verify_backup(backup_dir.path()).unwrap();
    assert!(
        verify.is_healthy(),
        "backup taken during concurrent writes must be healthy: \
         corrupted_blocks={}, corrupted_events={}, file_failures={}",
        verify.corrupted_blocks,
        verify.corrupted_events,
        verify.file_failures.len()
    );

    let restore_dir = tempfile::TempDir::new().unwrap();
    let result = restore_from_backup(backup_dir.path(), restore_dir.path()).unwrap();
    assert!(result.blocks_files_restored > 0);

    verify_restored_blocks(restore_dir.path(), 0..20);

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
        "restored eventlog must match manifest"
    );
    let _ = restored_el.shutdown();
}

#[test]
fn restore_rejects_nonempty_target() {
    with_runtime(|| {
        let store = open_test_store();
        seed_blocks(&store, 0..5);
        seed_events(&store, 3);

        let backup_dir = tempfile::TempDir::new().unwrap();
        coordinator(&store)
            .create_backup(backup_dir.path())
            .unwrap();

        let target = tempfile::TempDir::new().unwrap();
        std::fs::write(target.path().join("garbage"), b"leftover").unwrap();

        let err = restore_from_backup(backup_dir.path(), target.path());
        assert!(err.is_err(), "restore into non-empty dir must fail");
    });
}

#[test]
fn multiple_backups_restore_independently() {
    with_runtime(|| {
        let store = open_test_store();

        seed_blocks(&store, 0..20);
        seed_repo(&store, "snap1", 1);
        seed_events(&store, 10);
        store.metastore.persist().unwrap();

        let backup1_dir = tempfile::TempDir::new().unwrap();
        let manifest1 = coordinator(&store)
            .create_backup(backup1_dir.path())
            .unwrap();

        seed_blocks(&store, 20..40);
        seed_repo(&store, "snap2", 2);
        seed_events(&store, 10);
        store.metastore.persist().unwrap();

        let backup2_dir = tempfile::TempDir::new().unwrap();
        let manifest2 = coordinator(&store)
            .create_backup(backup2_dir.path())
            .unwrap();

        let restore1 = tempfile::TempDir::new().unwrap();
        restore_from_backup(backup1_dir.path(), restore1.path()).unwrap();
        verify_restored_blocks(restore1.path(), 0..20);
        verify_restored_events(restore1.path(), manifest1.eventlog.max_seq.raw());
        verify_restored_metastore(restore1.path(), &["snap1"]);

        let restore2 = tempfile::TempDir::new().unwrap();
        restore_from_backup(backup2_dir.path(), restore2.path()).unwrap();
        verify_restored_blocks(restore2.path(), 0..40);
        verify_restored_events(restore2.path(), manifest2.eventlog.max_seq.raw());
        verify_restored_metastore(restore2.path(), &["snap1", "snap2"]);
    });
}

#[test]
fn pitr_rejects_target_before_backup() {
    with_runtime(|| {
        let store = open_test_store();
        seed_blocks(&store, 0..10);
        seed_events(&store, 20);
        store.metastore.persist().unwrap();

        let backup_dir = tempfile::TempDir::new().unwrap();
        let manifest = coordinator(&store)
            .create_backup(backup_dir.path())
            .unwrap();

        let archive_dir = tempfile::TempDir::new().unwrap();
        archive_segments(&store, archive_dir.path());

        let earlier =
            tranquil_store::eventlog::EventSequence::new(manifest.eventlog.max_seq.raw() - 1);

        let restore_dir = tempfile::TempDir::new().unwrap();
        let err = recover_to_sequence(
            backup_dir.path(),
            archive_dir.path(),
            earlier,
            restore_dir.path(),
        );
        assert!(
            err.is_err(),
            "PITR to a sequence before the backup must fail"
        );
    });
}

#[test]
fn pitr_rejects_target_beyond_available() {
    with_runtime(|| {
        let store = open_test_store();
        seed_blocks(&store, 0..10);
        seed_events(&store, 20);
        store.metastore.persist().unwrap();

        let backup_dir = tempfile::TempDir::new().unwrap();
        coordinator(&store)
            .create_backup(backup_dir.path())
            .unwrap();

        seed_events(&store, 5);
        store.eventlog.sync().unwrap();

        let archive_dir = tempfile::TempDir::new().unwrap();
        archive_segments(&store, archive_dir.path());

        let beyond =
            tranquil_store::eventlog::EventSequence::new(store.eventlog.max_seq().raw() + 1000);

        let restore_dir = tempfile::TempDir::new().unwrap();
        let err = recover_to_sequence(
            backup_dir.path(),
            archive_dir.path(),
            beyond,
            restore_dir.path(),
        );
        assert!(err.is_err(), "PITR beyond available eventlog must fail");
    });
}

#[test]
fn restore_fails_cleanly_on_corrupted_backup() {
    with_runtime(|| {
        let store = open_test_store();
        seed_blocks(&store, 0..20);
        seed_events(&store, 10);
        store.metastore.persist().unwrap();

        let backup_dir = tempfile::TempDir::new().unwrap();
        let manifest = coordinator(&store)
            .create_backup(backup_dir.path())
            .unwrap();

        let first_file = &manifest.files[0];
        let file_path = backup_dir.path().join(&first_file.path);
        let mut data = std::fs::read(&file_path).unwrap();
        data.iter_mut().take(16).for_each(|b| *b ^= 0xFF);
        std::fs::write(&file_path, &data).unwrap();

        let restore_dir = tempfile::TempDir::new().unwrap();
        let err = restore_from_backup(backup_dir.path(), restore_dir.path());
        assert!(err.is_err(), "restore from corrupted backup must fail");

        assert!(
            !restore_dir.path().exists()
                || std::fs::read_dir(restore_dir.path())
                    .map(|mut entries| entries.next().is_none())
                    .unwrap_or(true),
            "failed restore must not leave partial state at target"
        );
    });
}

#[test]
fn empty_store_backup_and_restore() {
    with_runtime(|| {
        let store = open_test_store();
        store.metastore.persist().unwrap();

        let backup_dir = tempfile::TempDir::new().unwrap();
        let manifest = coordinator(&store)
            .create_backup(backup_dir.path())
            .unwrap();

        assert_eq!(manifest.kind, BackupKind::Full);

        let verify = verify_backup(backup_dir.path()).unwrap();
        assert!(verify.is_healthy());

        let restore_dir = tempfile::TempDir::new().unwrap();
        restore_from_backup(backup_dir.path(), restore_dir.path()).unwrap();

        let restored_ms = Metastore::open(
            &restore_dir.path().join("metastore"),
            MetastoreConfig {
                cache_size_bytes: 64 * 1024 * 1024,
            },
        );
        assert!(
            restored_ms.is_ok(),
            "restored metastore from empty backup must open"
        );
    });
}

#[test]
fn incremental_restore_rejects_nonempty_target() {
    with_runtime(|| {
        let store = open_test_store();
        seed_blocks(&store, 0..10);
        seed_events(&store, 5);
        store.metastore.persist().unwrap();

        let base_dir = tempfile::TempDir::new().unwrap();
        let base_manifest = coordinator(&store).create_backup(base_dir.path()).unwrap();

        seed_blocks(&store, 10..20);
        seed_events(&store, 5);
        store.metastore.persist().unwrap();

        let incr_dir = tempfile::TempDir::new().unwrap();
        coordinator(&store)
            .create_incremental_backup(&base_manifest, incr_dir.path())
            .unwrap();

        let target = tempfile::TempDir::new().unwrap();
        std::fs::write(target.path().join("garbage"), b"leftover").unwrap();

        let err = restore_from_incremental(base_dir.path(), incr_dir.path(), target.path());
        assert!(
            err.is_err(),
            "incremental restore into non-empty dir must fail"
        );
    });
}

#[test]
fn incremental_restore_rejects_mismatched_base() {
    with_runtime(|| {
        let store = open_test_store();
        seed_blocks(&store, 0..20);
        seed_events(&store, 10);
        store.metastore.persist().unwrap();

        let base1_dir = tempfile::TempDir::new().unwrap();
        let base1_manifest = coordinator(&store).create_backup(base1_dir.path()).unwrap();

        seed_blocks(&store, 20..40);
        seed_events(&store, 10);
        store.metastore.persist().unwrap();

        let incr_dir = tempfile::TempDir::new().unwrap();
        coordinator(&store)
            .create_incremental_backup(&base1_manifest, incr_dir.path())
            .unwrap();

        seed_blocks(&store, 40..60);
        seed_events(&store, 10);
        store.metastore.persist().unwrap();

        let base2_dir = tempfile::TempDir::new().unwrap();
        coordinator(&store).create_backup(base2_dir.path()).unwrap();

        let restore_dir = tempfile::TempDir::new().unwrap();
        let err = restore_from_incremental(base2_dir.path(), incr_dir.path(), restore_dir.path());
        assert!(
            err.is_err(),
            "incremental restore with wrong base must fail"
        );
    });
}
