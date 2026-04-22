use std::io::BufRead;
use std::path::Path;

use jacquard_repo::storage::BlockStore;
use tranquil_store::blockstore::{BlockStoreConfig, GroupCommitConfig, TranquilBlockStore};

const POST_DROP_FD_TOLERANCE: i64 = 2;

fn fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .map(|it| it.count())
        .unwrap_or(0)
}

fn log_rlimit(label: &str) {
    if let Ok(f) = std::fs::File::open("/proc/self/limits") {
        let reader = std::io::BufReader::new(f);
        reader
            .lines()
            .map_while(Result::ok)
            .find(|l| l.contains("open files"))
            .into_iter()
            .for_each(|l| eprintln!("[{label}] {l}"));
    }
}

fn config_for(dir: &Path, max_file_size: u64) -> BlockStoreConfig {
    BlockStoreConfig {
        data_dir: dir.join("data"),
        index_dir: dir.join("index"),
        max_file_size,
        group_commit: GroupCommitConfig {
            checkpoint_interval_ms: 100,
            checkpoint_write_threshold: 10,
            ..GroupCommitConfig::default()
        },
        shard_count: 1,
    }
}

fn tiny_block(seed: u64) -> Vec<u8> {
    let bytes = seed.to_le_bytes();
    (0..64)
        .map(|i| bytes[i % 8] ^ (i as u8).wrapping_mul(31))
        .collect()
}

#[tokio::test]
async fn fds_stable_within_store_lifetime() {
    log_rlimit("start");
    let dir = tempfile::TempDir::new().unwrap();
    let cfg = config_for(dir.path(), 4096);
    let base = fd_count() as i64;
    eprintln!("baseline fds: {base}");

    let store = TranquilBlockStore::open(cfg.clone()).expect("open");
    let after_open = fd_count() as i64;
    eprintln!("after open: {after_open} fds, delta {}", after_open - base);

    for i in 0..20_000u64 {
        let data = tiny_block(i);
        store.put(&data).await.expect("put");
        if i.is_multiple_of(2_000) {
            let fds = fd_count() as i64;
            eprintln!("after {i} puts: {fds} fds, delta {}", fds - base);
        }
    }

    let final_fds = fd_count() as i64;
    eprintln!("final: {final_fds} fds, delta {}", final_fds - base);

    drop(store);
    let after_drop = fd_count() as i64;
    let delta = after_drop - base;
    eprintln!("after drop: {after_drop} fds, delta {delta}");

    assert!(
        delta <= POST_DROP_FD_TOLERANCE,
        "fd leak after store drop: baseline {base}, after_drop {after_drop}, delta {delta}"
    );
}

#[tokio::test]
async fn fds_stable_across_reopens() {
    log_rlimit("start");
    let dir = tempfile::TempDir::new().unwrap();
    let cfg = config_for(dir.path(), 4096);
    let base = fd_count() as i64;
    eprintln!("baseline: {base}");

    for cycle in 0..20usize {
        let store = TranquilBlockStore::open(cfg.clone()).expect("open");
        for i in 0..2_000u64 {
            let data = tiny_block((cycle as u64) * 10_000 + i);
            store.put(&data).await.expect("put");
        }
        let before_drop = fd_count() as i64;
        drop(store);
        let after_drop = fd_count() as i64;
        let delta = after_drop - base;
        eprintln!(
            "cycle {cycle}: before_drop {before_drop}, after_drop {after_drop}, delta {delta}"
        );
        assert!(
            delta <= POST_DROP_FD_TOLERANCE,
            "fd leak across reopens at cycle {cycle}: baseline {base}, after_drop {after_drop}, delta {delta}"
        );
    }
}
