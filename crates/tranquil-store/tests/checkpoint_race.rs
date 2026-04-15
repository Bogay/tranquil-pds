mod common;

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tranquil_store::PostBlockstoreHook;
use tranquil_store::blockstore::{
    BlockStoreConfig, BlocksSynced, CidBytes, GroupCommitConfig, TranquilBlockStore,
};

struct SlowHook;

impl PostBlockstoreHook for SlowHook {
    fn on_blocks_synced(&self, _proof: &BlocksSynced) -> io::Result<()> {
        std::thread::sleep(std::time::Duration::from_millis(1));
        Ok(())
    }
}

fn refcount(store: &TranquilBlockStore, cid: &CidBytes) -> Option<u32> {
    store.block_index().get(cid).map(|e| e.refcount.raw())
}

fn race_config(dir: &std::path::Path) -> BlockStoreConfig {
    BlockStoreConfig {
        data_dir: dir.join("data"),
        index_dir: dir.join("index"),
        max_file_size: 256 * 1024,
        group_commit: GroupCommitConfig {
            checkpoint_interval_ms: 10,
            checkpoint_write_threshold: 20,
            ..GroupCommitConfig::default()
        },
        shard_count: 4,
    }
}

fn cid_for(shard: u8, seq: u32) -> CidBytes {
    let mut cid = [0u8; 36];
    cid[0] = 0x01;
    cid[1] = 0x71;
    cid[2] = 0x12;
    cid[3] = 0x20;
    cid[4] = shard;
    cid[8..12].copy_from_slice(&seq.to_le_bytes());
    (12..36).for_each(|i| cid[i] = (seq as u8).wrapping_add(i as u8));
    cid
}

fn write_phase(base: &std::path::Path, use_hook: bool) -> Vec<CidBytes> {
    let config = race_config(base);
    let hook: Option<Arc<dyn PostBlockstoreHook>> = use_hook.then(|| Arc::new(SlowHook) as _);
    let store = Arc::new(TranquilBlockStore::open_with_hook(config, hook).unwrap());

    let running = Arc::new(AtomicBool::new(true));
    let total_cycles = Arc::new(AtomicU64::new(0));

    let writers: Vec<_> = (0..4u8)
        .map(|shard| {
            let store = Arc::clone(&store);
            let running = Arc::clone(&running);
            let total_cycles = Arc::clone(&total_cycles);
            std::thread::spawn(move || {
                let mut targets = Vec::new();
                let mut seq = 0u32;
                while running.load(Ordering::Relaxed) {
                    let cid = cid_for(shard, seq);
                    store
                        .put_blocks_blocking(vec![(cid, vec![shard; 60])])
                        .unwrap();
                    store
                        .put_blocks_blocking(vec![(cid, vec![shard; 60])])
                        .unwrap();
                    store.apply_commit_blocking(vec![], vec![cid]).unwrap();
                    targets.push(cid);
                    seq += 1;
                    total_cycles.fetch_add(1, Ordering::Relaxed);
                }
                targets
            })
        })
        .collect();

    while total_cycles.load(Ordering::Relaxed) < 500 {
        std::thread::yield_now();
    }

    running.store(false, Ordering::Relaxed);

    let all_targets: Vec<CidBytes> = writers
        .into_iter()
        .flat_map(|w| w.join().unwrap())
        .collect();

    all_targets.iter().for_each(|cid| {
        assert_eq!(refcount(&store, cid), Some(1), "pre-crash sanity");
    });

    let store = Arc::try_unwrap(store).ok().unwrap();
    std::mem::forget(store);

    all_targets
}

fn verify_phase(base: &std::path::Path, targets: &[CidBytes]) -> usize {
    let config = race_config(base);
    let store = TranquilBlockStore::open(config).unwrap();
    let bad = targets
        .iter()
        .filter(|cid| refcount(&store, cid) != Some(1))
        .count();
    drop(store);
    bad
}

#[test]
fn crash_recovery_preserves_refcounts() {
    common::with_runtime(|| {
        let mut corrupted = 0u32;
        let total = 20u32;

        (0..total).for_each(|_| {
            let dir = tempfile::TempDir::new().unwrap();
            let exe = std::env::current_exe().unwrap();
            let dir_str = dir.path().to_str().unwrap();

            let output = std::process::Command::new(&exe)
                .arg("--exact")
                .arg("__crash_write_phase")
                .env("CRASH_TEST_DIR", dir_str)
                .env("CRASH_TEST_HOOK", "0")
                .output()
                .unwrap();

            assert!(output.status.success() || output.status.code() == Some(0));

            let target_bytes = std::fs::read(dir.path().join("targets.bin")).unwrap();
            let targets: Vec<CidBytes> = target_bytes
                .chunks_exact(36)
                .map(|chunk| {
                    let mut cid = [0u8; 36];
                    cid.copy_from_slice(chunk);
                    cid
                })
                .collect();

            if verify_phase(dir.path(), &targets) > 0 {
                corrupted += 1;
            }
        });

        assert_eq!(
            corrupted, 0,
            "{corrupted}/{total} iterations had refcount corruption after crash recovery"
        );
    });
}

#[test]
fn crash_with_slow_hook_preserves_refcounts() {
    common::with_runtime(|| {
        let mut corrupted = 0u32;
        let total = 20u32;

        (0..total).for_each(|_| {
            let dir = tempfile::TempDir::new().unwrap();
            let exe = std::env::current_exe().unwrap();
            let dir_str = dir.path().to_str().unwrap();

            let output = std::process::Command::new(&exe)
                .arg("--exact")
                .arg("__crash_write_phase")
                .env("CRASH_TEST_DIR", dir_str)
                .env("CRASH_TEST_HOOK", "1")
                .output()
                .unwrap();

            assert!(output.status.success() || output.status.code() == Some(0));

            let target_bytes = std::fs::read(dir.path().join("targets.bin")).unwrap();
            let targets: Vec<CidBytes> = target_bytes
                .chunks_exact(36)
                .map(|chunk| {
                    let mut cid = [0u8; 36];
                    cid.copy_from_slice(chunk);
                    cid
                })
                .collect();

            if verify_phase(dir.path(), &targets) > 0 {
                corrupted += 1;
            }
        });

        assert_eq!(
            corrupted, 0,
            "{corrupted}/{total} iterations had refcount corruption after crash with slow hook"
        );
    });
}

#[test]
fn __crash_write_phase() {
    let dir = match std::env::var("CRASH_TEST_DIR") {
        Ok(d) => d,
        Err(_) => return,
    };
    let use_hook = std::env::var("CRASH_TEST_HOOK")
        .map(|v| v == "1")
        .unwrap_or(false);
    let base = std::path::Path::new(&dir);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();

    let targets = write_phase(base, use_hook);

    let target_bytes: Vec<u8> = targets.iter().flat_map(|cid| cid.iter().copied()).collect();
    std::fs::write(base.join("targets.bin"), &target_bytes).unwrap();

    unsafe { libc::_exit(0) }
}
