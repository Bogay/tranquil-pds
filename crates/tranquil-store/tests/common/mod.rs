#![allow(dead_code)]

use std::collections::HashSet;
use std::sync::Arc;

use tranquil_store::RealIO;
use tranquil_store::blockstore::{
    BlockStoreConfig, CidBytes, DEFAULT_MAX_FILE_SIZE, GroupCommitConfig, TranquilBlockStore,
};
use tranquil_store::eventlog::{EventLog, EventLogConfig};
use tranquil_store::metastore::{Metastore, MetastoreConfig};
use tranquil_types::{CidLink, Did, Handle};
use uuid::Uuid;

pub const NAMES: &[&str] = &["olaren", "teq", "nel", "lyna", "bailey"];

pub fn test_cid(seed: u32) -> CidBytes {
    let le = seed.to_le_bytes();
    std::array::from_fn(|i| match i {
        0 => 0x01,
        1 => 0x71,
        2 => 0x12,
        3 => 0x20,
        4..8 => le[i - 4],
        _ => (seed as u8).wrapping_add(i as u8),
    })
}

pub fn block_data(seed: u32) -> Vec<u8> {
    let tag = seed.to_le_bytes();
    std::iter::repeat(tag).flatten().take(80).collect()
}

pub fn test_did(seed: u64) -> Did {
    let name = NAMES[(seed as usize) % NAMES.len()];
    Did::from(format!("did:plc:{name}{seed}"))
}

pub fn test_handle(seed: u64) -> Handle {
    let name = NAMES[(seed as usize) % NAMES.len()];
    Handle::new(format!("{name}{seed}.test")).unwrap()
}

pub fn test_cid_link(seed: u8) -> CidLink {
    let digest: [u8; 32] = std::array::from_fn(|i| seed.wrapping_add(i as u8));
    let mh = multihash::Multihash::<64>::wrap(0x12, &digest).unwrap();
    let c = cid::Cid::new_v1(0x71, mh);
    CidLink::from_cid(&c)
}

pub fn test_uuid(seed: u64) -> Uuid {
    Uuid::from_u128(seed as u128 | 0x4000_0000_0000_0000_8000_0000_0000_0000)
}

pub fn small_blockstore_config(dir: &std::path::Path) -> BlockStoreConfig {
    BlockStoreConfig {
        data_dir: dir.join("data"),
        index_dir: dir.join("index"),
        max_file_size: 1024,
        group_commit: GroupCommitConfig::default(),
        shard_count: 1,
    }
}

pub fn default_blockstore_config(dir: &std::path::Path) -> BlockStoreConfig {
    BlockStoreConfig {
        data_dir: dir.join("data"),
        index_dir: dir.join("index"),
        max_file_size: DEFAULT_MAX_FILE_SIZE,
        group_commit: GroupCommitConfig::default(),
        shard_count: 1,
    }
}

pub fn with_runtime<F: FnOnce()>(f: F) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    f();
}

pub fn advance_epoch(store: &TranquilBlockStore) {
    store.apply_commit_blocking(vec![], vec![]).unwrap();
}

pub fn collect_all_dead(store: &TranquilBlockStore) -> HashSet<CidBytes> {
    let result = store.collect_dead_blocks(0).unwrap();
    result
        .candidates
        .values()
        .flat_map(|v| v.iter().copied())
        .collect()
}

pub fn compact_all_sealed(store: &TranquilBlockStore) {
    let Ok(files) = store.list_data_files() else {
        return;
    };
    files
        .iter()
        .copied()
        .take(files.len().saturating_sub(1))
        .for_each(|fid| {
            let _ = store.compact_file(fid, 0);
        });
}

pub struct TestStores {
    pub blockstore: TranquilBlockStore,
    pub eventlog: Arc<EventLog<RealIO>>,
    pub metastore: Metastore,
}

pub fn open_test_stores(
    base: &std::path::Path,
    max_file_size: u64,
    cache_size_bytes: u64,
) -> TestStores {
    let bs_data = base.join("blockstore/data");
    let bs_index = base.join("blockstore/index");
    let segments_dir = base.join("eventlog/segments");
    let metastore_dir = base.join("metastore");

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

    let metastore = Metastore::open(&metastore_dir, MetastoreConfig { cache_size_bytes }).unwrap();

    TestStores {
        blockstore,
        eventlog,
        metastore,
    }
}

pub fn assert_store_consistent(stores: &TestStores, context: &str) {
    let options = tranquil_store::consistency::ConsistencyCheckOptions {
        check_block_references: false,
        ..Default::default()
    };
    let report = tranquil_store::consistency::verify_store_consistency_with_options(
        &stores.blockstore,
        &stores.metastore,
        &stores.eventlog,
        options,
    );
    assert!(report.is_consistent(), "{context}: {report}",);
}

pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self {
            state: seed.wrapping_mul(6364136223846793005).wrapping_add(1),
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.state
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 16) as u32
    }

    pub fn range_u32(&mut self, max: u32) -> u32 {
        self.next_u32() % max
    }
}
