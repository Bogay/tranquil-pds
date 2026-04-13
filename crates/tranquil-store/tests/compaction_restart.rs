mod common;

use std::path::Path;
use std::sync::Arc;

use common::{
    collect_refcounts, compact_by_liveness, compact_lowest_liveness, test_cid,
    tiny_blockstore_config, with_runtime,
};
use tranquil_store::RealIO;
use tranquil_store::blockstore::{CidBytes, TranquilBlockStore};
use tranquil_store::eventlog::{EventLog, EventLogBridge, EventLogConfig};
use tranquil_store::metastore::handler::HandlerPool;
use tranquil_store::metastore::partitions::Partition;
use tranquil_store::metastore::{Metastore, MetastoreConfig};

struct FullStack {
    blockstore: TranquilBlockStore,
    _pool: Arc<HandlerPool>,
    _event_log: Arc<EventLog<RealIO>>,
}

fn open_full_stack(base_dir: &Path) -> FullStack {
    let metastore_dir = base_dir.join("metastore");
    let segments_dir = base_dir.join("eventlog").join("segments");
    let blockstore_data = base_dir.join("blockstore").join("data");
    let blockstore_index = base_dir.join("blockstore").join("index");

    [&metastore_dir, &segments_dir, &blockstore_data, &blockstore_index]
        .iter()
        .for_each(|d| std::fs::create_dir_all(d).unwrap());

    let metastore = Metastore::open(&metastore_dir, MetastoreConfig::default()).unwrap();

    let blockstore = TranquilBlockStore::open(tranquil_store::blockstore::BlockStoreConfig {
        data_dir: blockstore_data,
        index_dir: blockstore_index,
        max_file_size: 512,
        group_commit: tranquil_store::blockstore::GroupCommitConfig::default(),
        shard_count: 1,
    })
    .unwrap();

    let event_log = Arc::new(
        EventLog::open(
            EventLogConfig {
                segments_dir,
                ..EventLogConfig::default()
            },
            RealIO::new(),
        )
        .unwrap(),
    );

    let bridge = Arc::new(EventLogBridge::new(Arc::clone(&event_log)));

    let was_clean = tranquil_store::consistency::had_clean_shutdown(base_dir);
    tranquil_store::consistency::remove_clean_shutdown_marker(base_dir).ok();

    let indexes = metastore.partition(Partition::Indexes).clone();
    let event_ops = metastore.event_ops(Arc::clone(&bridge));
    let recovered = event_ops
        .recover_metastore_mutations(&indexes)
        .unwrap();
    if recovered > 0 {
        eprintln!("replayed {recovered} metastore mutations from eventlog");
    }

    if !was_clean || recovered > 0 {
        let report = tranquil_store::consistency::verify_store_consistency(
            &blockstore,
            &metastore,
            &event_log,
        );
        report.log_findings();
        if report.has_repairable_issues() {
            let repair = tranquil_store::consistency::repair_known_issues(&blockstore, &report);
            if repair.orphan_files_removed > 0 {
                eprintln!("removed {} orphan files", repair.orphan_files_removed);
            }
        }
    }

    let pool = Arc::new(HandlerPool::spawn::<RealIO>(
        metastore,
        bridge,
        Some(blockstore.clone()),
        None,
    ));

    FullStack {
        blockstore,
        _pool: pool,
        _event_log: event_log,
    }
}

fn close_full_stack(stack: FullStack, base_dir: &Path) {
    let rt = tokio::runtime::Handle::current();
    rt.block_on(stack._pool.close());
    if let Err(e) = stack._event_log.shutdown() {
        eprintln!("eventlog shutdown: {e}");
    }
    tranquil_store::consistency::write_clean_shutdown_marker(base_dir).ok();
    drop(stack.blockstore);
}

fn verify_blocks_and_refcounts(
    store: &TranquilBlockStore,
    live_cids: &[CidBytes],
    expected_refcounts: Option<&[(u32, u32)]>,
    label: &str,
) {
    let missing: Vec<u32> = live_cids
        .iter()
        .filter(|cid| store.get_block_sync(cid).unwrap().is_none())
        .map(|cid| u32::from_le_bytes([cid[4], cid[5], cid[6], cid[7]]))
        .collect();

    assert!(
        missing.is_empty(),
        "{label}: live blocks missing after reopen: {missing:?}"
    );

    match expected_refcounts {
        Some(expected) => {
            let actual = collect_refcounts(store, live_cids);
            let mismatches: Vec<_> = expected
                .iter()
                .zip(actual.iter())
                .filter(|((_, exp_rc), (_, act_rc))| exp_rc != act_rc)
                .map(|((seed, exp), (_, act))| format!("seed {seed}: before={exp} after={act}"))
                .collect();

            assert!(
                mismatches.is_empty(),
                "{label}: refcounts changed across reopen:\n{}",
                mismatches.join("\n"),
            );
        }
        None => {
            live_cids.iter().for_each(|cid| {
                let rc = store
                    .block_index()
                    .get(cid)
                    .map(|e| e.refcount.raw())
                    .unwrap_or(0);
                assert!(
                    rc > 0,
                    "{label}: refcount dropped to 0 for seed {}",
                    u32::from_le_bytes([cid[4], cid[5], cid[6], cid[7]])
                );
            });
        }
    }
}

#[test]
fn hundreds_of_compaction_cycles() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();

        let live_cids: Vec<CidBytes> = (0..15u32).map(test_cid).collect();

        {
            let store = TranquilBlockStore::open(tiny_blockstore_config(dir.path())).unwrap();

            live_cids.iter().for_each(|cid| {
                store
                    .put_blocks_blocking(vec![(*cid, vec![0xAA; 80])])
                    .unwrap();
            });

            (0..500u32).for_each(|round| {
                let churn = test_cid(2000 + round);
                store
                    .put_blocks_blocking(vec![(churn, vec![0xDD; 80])])
                    .unwrap();
                store.apply_commit_blocking(vec![], vec![churn]).unwrap();

                if round % 3 == 0 {
                    compact_lowest_liveness(&store);
                }
            });

            (0..200).for_each(|_| compact_by_liveness(&store));

            live_cids.iter().for_each(|cid| {
                assert!(
                    store.get_block_sync(cid).unwrap().is_some(),
                    "sanity: block present before drop"
                );
            });

            drop(store);
        }

        let store = TranquilBlockStore::open(tiny_blockstore_config(dir.path())).unwrap();
        verify_blocks_and_refcounts(&store, &live_cids, None, "500 churn + 200 compact rounds");
    });
}

#[test]
fn commit_style_decrements() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();

        let shared_nodes: Vec<CidBytes> = (0..10u32).map(test_cid).collect();

        let refcounts_before = {
            let store = TranquilBlockStore::open(tiny_blockstore_config(dir.path())).unwrap();

            shared_nodes.iter().for_each(|cid| {
                store
                    .put_blocks_blocking(vec![(*cid, vec![0xAA; 80])])
                    .unwrap();
            });

            let mut prev_commit = test_cid(5000);
            store
                .put_blocks_blocking(vec![(prev_commit, vec![0xCC; 80])])
                .unwrap();

            (0..500u32).for_each(|round| {
                let new_commit = test_cid(5001 + round);
                let new_mst_node = test_cid(6000 + round);
                let old_mst_node = test_cid(7000 + round);

                store
                    .put_blocks_blocking(vec![
                        (new_commit, vec![0xBB; 80]),
                        (new_mst_node, vec![0xCC; 60]),
                        (old_mst_node, vec![0xDD; 60]),
                    ])
                    .unwrap();

                store
                    .apply_commit_blocking(vec![], vec![prev_commit, old_mst_node])
                    .unwrap();

                if round > 0 {
                    let prev_mst = test_cid(6000 + round - 1);
                    store
                        .apply_commit_blocking(vec![], vec![prev_mst])
                        .unwrap();
                }

                prev_commit = new_commit;

                if round % 2 == 0 {
                    compact_lowest_liveness(&store);
                }
            });

            (0..300).for_each(|_| {
                compact_by_liveness(&store);
                std::thread::sleep(std::time::Duration::from_millis(1));
            });

            shared_nodes.iter().for_each(|cid| {
                assert!(
                    store.get_block_sync(cid).unwrap().is_some(),
                    "sanity: shared node present before drop"
                );
            });

            let rc = collect_refcounts(&store, &shared_nodes);
            drop(store);
            rc
        };

        let store = TranquilBlockStore::open(tiny_blockstore_config(dir.path())).unwrap();
        verify_blocks_and_refcounts(
            &store,
            &shared_nodes,
            Some(&refcounts_before),
            "500 commits + 300 compact rounds",
        );
    });
}

#[test]
fn extreme_file_churn_with_dedup_hits() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();

        let live_cids: Vec<CidBytes> = (0..8u32).map(test_cid).collect();
        let live_data: Vec<u8> = vec![0xAA; 80];

        let refcounts_before = {
            let store = TranquilBlockStore::open(tiny_blockstore_config(dir.path())).unwrap();

            live_cids.iter().for_each(|cid| {
                store
                    .put_blocks_blocking(vec![(*cid, live_data.clone())])
                    .unwrap();
            });

            (0..300u32).for_each(|round| {
                let churn = test_cid(3000 + round);
                store
                    .put_blocks_blocking(vec![(churn, vec![0xEE; 80])])
                    .unwrap();
                store.apply_commit_blocking(vec![], vec![churn]).unwrap();

                if round % 50 == 0 {
                    live_cids.iter().for_each(|cid| {
                        store
                            .put_blocks_blocking(vec![(*cid, live_data.clone())])
                            .unwrap();
                    });
                }

                if round % 2 == 0 {
                    compact_lowest_liveness(&store);
                }
            });

            (0..200).for_each(|_| compact_by_liveness(&store));

            let rc = collect_refcounts(&store, &live_cids);
            drop(store);
            rc
        };

        let store = TranquilBlockStore::open(tiny_blockstore_config(dir.path())).unwrap();
        verify_blocks_and_refcounts(
            &store,
            &live_cids,
            Some(&refcounts_before),
            "300 churn + dedup re-puts + 200 compacts",
        );
    });
}

#[test]
fn long_idle_compaction_only_phase() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();

        let live_cids: Vec<CidBytes> = (0..20u32).map(test_cid).collect();

        {
            let store = TranquilBlockStore::open(tiny_blockstore_config(dir.path())).unwrap();

            live_cids.iter().for_each(|cid| {
                store
                    .put_blocks_blocking(vec![(*cid, vec![0xAA; 80])])
                    .unwrap();
            });

            (0..100u32).for_each(|round| {
                let churn = test_cid(4000 + round);
                store
                    .put_blocks_blocking(vec![(churn, vec![0xFF; 80])])
                    .unwrap();
                store.apply_commit_blocking(vec![], vec![churn]).unwrap();
            });

            (0..500).for_each(|_| {
                compact_by_liveness(&store);
                std::thread::sleep(std::time::Duration::from_millis(1));
            });

            live_cids.iter().for_each(|cid| {
                assert!(
                    store.get_block_sync(cid).unwrap().is_some(),
                    "sanity: block present before drop"
                );
            });

            drop(store);
        }

        let store = TranquilBlockStore::open(tiny_blockstore_config(dir.path())).unwrap();
        verify_blocks_and_refcounts(
            &store,
            &live_cids,
            None,
            "idle with 500 compaction-only rounds",
        );
    });
}

#[test]
fn multiple_restart_cycles_blockstore() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();

        let live_cids: Vec<CidBytes> = (0..10u32).map(test_cid).collect();

        {
            let store = TranquilBlockStore::open(tiny_blockstore_config(dir.path())).unwrap();
            live_cids.iter().for_each(|cid| {
                store
                    .put_blocks_blocking(vec![(*cid, vec![0xAA; 80])])
                    .unwrap();
            });
            (0..50u32).for_each(|round| {
                let churn = test_cid(8000 + round);
                store
                    .put_blocks_blocking(vec![(churn, vec![0xBB; 80])])
                    .unwrap();
                store.apply_commit_blocking(vec![], vec![churn]).unwrap();
            });
            drop(store);
        }

        (0..10u32).for_each(|cycle| {
            {
                let store =
                    TranquilBlockStore::open(tiny_blockstore_config(dir.path())).unwrap();

                (0..50u32).for_each(|round| {
                    let churn = test_cid(9000 + cycle * 100 + round);
                    store
                        .put_blocks_blocking(vec![(churn, vec![0xCC; 80])])
                        .unwrap();
                    store.apply_commit_blocking(vec![], vec![churn]).unwrap();
                    compact_lowest_liveness(&store);
                });

                (0..50).for_each(|_| compact_by_liveness(&store));

                live_cids.iter().for_each(|cid| {
                    assert!(
                        store.get_block_sync(cid).unwrap().is_some(),
                        "cycle {cycle}: block missing before drop"
                    );
                });

                drop(store);
            }

            let store = TranquilBlockStore::open(tiny_blockstore_config(dir.path())).unwrap();
            verify_blocks_and_refcounts(
                &store,
                &live_cids,
                None,
                &format!("blockstore restart cycle {cycle}"),
            );
        });
    });
}

#[test]
fn full_stack_compaction_restart_preserves_refcounts() {
    with_runtime(|| {
        let base = tempfile::TempDir::new().unwrap();
        let base_dir = base.path().to_path_buf();

        let live_cids: Vec<CidBytes> = (0..15u32).map(test_cid).collect();

        let refcounts_before = {
            let stack = open_full_stack(&base_dir);

            live_cids.iter().for_each(|cid| {
                stack
                    .blockstore
                    .put_blocks_blocking(vec![(*cid, vec![0xAA; 80])])
                    .unwrap();
            });

            (0..500u32).for_each(|round| {
                let churn = test_cid(2000 + round);
                stack
                    .blockstore
                    .put_blocks_blocking(vec![(churn, vec![0xDD; 80])])
                    .unwrap();
                stack
                    .blockstore
                    .apply_commit_blocking(vec![], vec![churn])
                    .unwrap();

                if round % 3 == 0 {
                    compact_lowest_liveness(&stack.blockstore);
                }
            });

            (0..200).for_each(|_| compact_by_liveness(&stack.blockstore));

            let rc = collect_refcounts(&stack.blockstore, &live_cids);

            live_cids.iter().for_each(|cid| {
                assert!(
                    stack.blockstore.get_block_sync(cid).unwrap().is_some(),
                    "sanity: block present before shutdown"
                );
            });

            close_full_stack(stack, &base_dir);
            rc
        };

        let stack = open_full_stack(&base_dir);
        verify_blocks_and_refcounts(
            &stack.blockstore,
            &live_cids,
            Some(&refcounts_before),
            "full stack restart",
        );
        close_full_stack(stack, &base_dir);
    });
}

#[test]
fn full_stack_multiple_restart_cycles() {
    with_runtime(|| {
        let base = tempfile::TempDir::new().unwrap();
        let base_dir = base.path().to_path_buf();

        let live_cids: Vec<CidBytes> = (0..10u32).map(test_cid).collect();

        {
            let stack = open_full_stack(&base_dir);
            live_cids.iter().for_each(|cid| {
                stack
                    .blockstore
                    .put_blocks_blocking(vec![(*cid, vec![0xAA; 80])])
                    .unwrap();
            });
            close_full_stack(stack, &base_dir);
        }

        (0..10u32).for_each(|cycle| {
            let refcounts_before = {
                let stack = open_full_stack(&base_dir);

                (0..50u32).for_each(|round| {
                    let churn = test_cid(5000 + cycle * 100 + round);
                    stack
                        .blockstore
                        .put_blocks_blocking(vec![(churn, vec![0xBB; 80])])
                        .unwrap();
                    stack
                        .blockstore
                        .apply_commit_blocking(vec![], vec![churn])
                        .unwrap();
                    compact_lowest_liveness(&stack.blockstore);
                });

                (0..30).for_each(|_| compact_by_liveness(&stack.blockstore));

                let rc = collect_refcounts(&stack.blockstore, &live_cids);

                live_cids.iter().for_each(|cid| {
                    assert!(
                        stack.blockstore.get_block_sync(cid).unwrap().is_some(),
                        "cycle {cycle}: block missing before shutdown"
                    );
                });

                close_full_stack(stack, &base_dir);
                rc
            };

            let stack = open_full_stack(&base_dir);
            verify_blocks_and_refcounts(
                &stack.blockstore,
                &live_cids,
                Some(&refcounts_before),
                &format!("full stack cycle {cycle}"),
            );
            close_full_stack(stack, &base_dir);
        });
    });
}
