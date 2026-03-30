mod common;

use std::sync::Arc;

use rayon::prelude::*;
use tokio::sync::oneshot;
use tranquil_db_traits::{
    ApplyCommitInput, Backlink, BacklinkPath, CommitEventData, RecordDelete, RecordUpsert,
    RepoEventType,
};
use tranquil_store::eventlog::{EventLogBridge, EventSequence};
use tranquil_store::metastore::handler::{CommitRequest, HandlerPool, MetastoreRequest};
use tranquil_store::metastore::partitions::Partition;
use tranquil_store::{sim_seed_range, sim_single_seed};
use tranquil_types::{AtUri, CidLink, Nsid, Rkey};

use common::{
    NAMES, open_test_stores, test_cid_link, test_did, test_handle, test_uuid, with_runtime,
};

const CACHE_SIZE: u64 = 16 * 1024 * 1024;
const MAX_FILE_SIZE: u64 = tranquil_store::blockstore::DEFAULT_MAX_FILE_SIZE;

fn collection_nsid(idx: u64) -> Nsid {
    let collections = [
        "app.bsky.feed.post",
        "app.bsky.feed.like",
        "app.bsky.graph.follow",
        "app.bsky.feed.repost",
    ];
    Nsid::new(collections[(idx as usize) % collections.len()]).unwrap()
}

fn test_rkey(idx: u64) -> Rkey {
    Rkey::new(format!("3k{idx:06x}")).unwrap()
}

fn test_at_uri(did: &tranquil_types::Did, collection: &Nsid, rkey: &Rkey) -> AtUri {
    AtUri::new(format!(
        "at://{}/{}/{}",
        did.as_str(),
        collection.as_str(),
        rkey.as_str()
    ))
    .unwrap()
}

fn block_cid_bytes(seed: u64) -> Vec<u8> {
    let digest: [u8; 32] = std::array::from_fn(|i| ((seed + i as u64) & 0xFF) as u8);
    let mh = multihash::Multihash::<64>::wrap(0x12, &digest).unwrap();
    cid::Cid::new_v1(0x71, mh).to_bytes()
}

fn build_commit_event(
    did: &tranquil_types::Did,
    prev_cid: &CidLink,
    new_cid: &CidLink,
    rev: &str,
) -> CommitEventData {
    CommitEventData {
        did: did.clone(),
        event_type: RepoEventType::Commit,
        commit_cid: Some(new_cid.clone()),
        prev_cid: Some(prev_cid.clone()),
        ops: None,
        blobs: None,
        blocks: None,
        prev_data_cid: None,
        rev: Some(rev.to_owned()),
    }
}

struct MetastoreTestHarness {
    metastore: tranquil_store::metastore::Metastore,
    eventlog: Arc<tranquil_store::eventlog::EventLog<tranquil_store::RealIO>>,
}

impl MetastoreTestHarness {
    fn open(base: &std::path::Path) -> Self {
        let stores = open_test_stores(base, MAX_FILE_SIZE, CACHE_SIZE);
        Self {
            metastore: stores.metastore,
            eventlog: stores.eventlog,
        }
    }

    fn bridge(&self) -> Arc<EventLogBridge<tranquil_store::RealIO>> {
        Arc::new(EventLogBridge::new(Arc::clone(&self.eventlog)))
    }

    fn apply_commit(
        &self,
        input: ApplyCommitInput,
    ) -> Result<tranquil_db_traits::ApplyCommitResult, tranquil_db_traits::ApplyCommitError> {
        let bridge = self.bridge();
        let commit_ops = self.metastore.commit_ops(bridge);
        commit_ops.apply_commit(input)
    }

    fn create_repo(&self, idx: u64) -> (uuid::Uuid, tranquil_types::Did, CidLink) {
        let uid = test_uuid(idx);
        let did = test_did(idx);
        let handle = test_handle(idx);
        let cid = test_cid_link((idx & 0xFF) as u8);
        self.metastore
            .repo_ops()
            .create_repo(
                self.metastore.database(),
                uid,
                &did,
                &handle,
                &cid,
                &format!("rev0_{idx}"),
            )
            .unwrap_or_else(|e| panic!("create_repo idx={idx}: {e:?}"));
        (uid, did, cid)
    }

    fn recover_mutations(&self) {
        let bridge = self.bridge();
        let event_ops = self.metastore.event_ops(bridge);
        let indexes = self.metastore.partition(Partition::Indexes).clone();
        let _ = event_ops.recover_metastore_mutations(&indexes).unwrap();
    }

    fn read_cursor(&self) -> Option<u64> {
        let bridge = self.bridge();
        let event_ops = self.metastore.event_ops(bridge);
        event_ops.read_last_applied_cursor().unwrap()
    }
}

#[test]
fn sim_apply_commit_crash_before_batch_commit_is_invisible() {
    with_runtime(|| {
        sim_seed_range().into_par_iter().for_each(|seed| {
            let dir = tempfile::TempDir::new().unwrap();
            let name = NAMES[(seed as usize) % NAMES.len()];
            let record_count = (seed % 5) + 1;

            {
                let h = MetastoreTestHarness::open(dir.path());
                let (uid, did, root_cid) = h.create_repo(seed);
                h.metastore
                    .persist()
                    .unwrap_or_else(|e| panic!("seed={seed} persist after create: {e:?}"));

                let new_cid = test_cid_link(((seed + 50) & 0xFF) as u8);
                let rev = format!("rev1_{name}{seed}");

                let upserts: Vec<RecordUpsert> = (0..record_count)
                    .map(|i| {
                        let idx = seed * 100 + i;
                        RecordUpsert {
                            collection: collection_nsid(idx),
                            rkey: test_rkey(idx),
                            cid: test_cid_link(((idx + 10) & 0xFF) as u8),
                        }
                    })
                    .collect();

                let input = ApplyCommitInput {
                    user_id: uid,
                    did: did.clone(),
                    expected_root_cid: Some(root_cid.clone()),
                    new_root_cid: new_cid.clone(),
                    new_rev: rev.to_owned(),
                    record_upserts: upserts,
                    record_deletes: vec![],
                    backlinks_to_add: vec![],
                    backlinks_to_remove: vec![],
                    new_block_cids: vec![],
                    obsolete_block_cids: vec![],
                    commit_event: build_commit_event(&did, &root_cid, &new_cid, &rev),
                };

                let _ = h.apply_commit(input);
            }

            {
                let h = MetastoreTestHarness::open(dir.path());
                h.recover_mutations();

                let uid = test_uuid(seed);
                let meta = h
                    .metastore
                    .repo_ops()
                    .get_repo_meta(uid)
                    .unwrap_or_else(|e| panic!("seed={seed} get_repo_meta: {e:?}"));
                assert!(
                    meta.is_some(),
                    "seed={seed} repo must survive crash (was persisted before commit)"
                );

                let cursor = h.read_cursor();
                let eventlog_max = h.eventlog.max_seq();

                let expected_record_count = i64::try_from(record_count).unwrap();

                match eventlog_max == EventSequence::BEFORE_ALL {
                    true => {
                        let (_, repo_meta) = meta.unwrap();
                        assert_eq!(
                            repo_meta.repo_rev,
                            format!("rev0_{seed}"),
                            "seed={seed} repo rev must be initial if eventlog empty"
                        );
                    }
                    false => {
                        assert!(
                            cursor.is_some(),
                            "seed={seed} cursor must exist if events were recovered"
                        );
                    }
                }

                let record_ops = h.metastore.record_ops();
                let count = record_ops
                    .count_records(uid)
                    .unwrap_or_else(|e| panic!("seed={seed} count_records: {e:?}"));

                match cursor {
                    Some(c) if c > 0 => {
                        assert_eq!(
                            count, expected_record_count,
                            "seed={seed} after recovery, records must match committed count"
                        );
                    }
                    _ => {
                        assert!(
                            count == 0 || count == expected_record_count,
                            "seed={seed} records must be 0 (not committed) or full (recovered): got {count}"
                        );
                    }
                }
            }
        });
    });
}

#[test]
fn sim_apply_commit_atomicity_all_or_nothing() {
    with_runtime(|| {
        sim_seed_range().into_par_iter().for_each(|seed| {
            let dir = tempfile::TempDir::new().unwrap();
            let record_count = (seed % 8) + 2;
            let name = NAMES[(seed as usize) % NAMES.len()];

            {
                let h = MetastoreTestHarness::open(dir.path());
                let (uid, did, root_cid) = h.create_repo(seed);
                h.metastore
                    .persist()
                    .unwrap_or_else(|e| panic!("seed={seed} persist after create: {e:?}"));

                let new_cid = test_cid_link(((seed + 77) & 0xFF) as u8);
                let rev = format!("rev1_{name}{seed}");
                let collection = collection_nsid(seed);

                let upserts: Vec<RecordUpsert> = (0..record_count)
                    .map(|i| RecordUpsert {
                        collection: collection.clone(),
                        rkey: test_rkey(seed * 100 + i),
                        cid: test_cid_link(((seed * 100 + i + 10) & 0xFF) as u8),
                    })
                    .collect();

                let backlink_count = std::cmp::min(record_count, 3);
                let backlinks: Vec<Backlink> = (0..backlink_count)
                    .map(|i| {
                        let idx = seed * 100 + i;
                        let src_uri = test_at_uri(&did, &collection, &test_rkey(idx));
                        let target_did = test_did(seed + 999);
                        let target_uri = test_at_uri(
                            &target_did,
                            &Nsid::new("app.bsky.feed.post").unwrap(),
                            &test_rkey(idx + 5000),
                        );
                        Backlink {
                            uri: src_uri,
                            path: BacklinkPath::Subject,
                            link_to: target_uri.as_str().to_owned(),
                        }
                    })
                    .collect();

                let block_count = std::cmp::min(record_count, 4);
                let new_block_cids: Vec<Vec<u8>> = (0..block_count)
                    .map(|i| block_cid_bytes(seed * 100 + i + 30))
                    .collect();

                let input = ApplyCommitInput {
                    user_id: uid,
                    did: did.clone(),
                    expected_root_cid: Some(root_cid.clone()),
                    new_root_cid: new_cid.clone(),
                    new_rev: rev.to_owned(),
                    record_upserts: upserts,
                    record_deletes: vec![],
                    backlinks_to_add: backlinks,
                    backlinks_to_remove: vec![],
                    new_block_cids,
                    obsolete_block_cids: vec![],
                    commit_event: build_commit_event(&did, &root_cid, &new_cid, &rev),
                };

                let result = h.apply_commit(input);
                assert!(
                    result.is_ok(),
                    "seed={seed} apply_commit must succeed: {:?}",
                    result.err()
                );
                h.metastore
                    .persist()
                    .unwrap_or_else(|e| panic!("seed={seed} persist: {e:?}"));
            }

            {
                let h = MetastoreTestHarness::open(dir.path());
                h.recover_mutations();
                let uid = test_uuid(seed);

                let (_, repo_meta) = h
                    .metastore
                    .repo_ops()
                    .get_repo_meta(uid)
                    .unwrap_or_else(|e| panic!("seed={seed} get_repo_meta: {e:?}"))
                    .unwrap_or_else(|| panic!("seed={seed} repo meta missing"));
                let rev = format!("rev1_{name}{seed}");
                assert_eq!(
                    repo_meta.repo_rev, rev,
                    "seed={seed} repo rev must match committed value"
                );

                let count = h
                    .metastore
                    .record_ops()
                    .count_records(uid)
                    .unwrap_or_else(|e| panic!("seed={seed} count_records: {e:?}"));
                let expected = i64::try_from(record_count).unwrap();
                assert_eq!(
                    count, expected,
                    "seed={seed} all records must be visible after recovery"
                );

                let cursor = h.read_cursor();
                assert!(
                    cursor.is_some() && cursor.unwrap() > 0,
                    "seed={seed} cursor must advance after successful commit"
                );

                let eventlog_max = h.eventlog.max_seq();
                assert!(
                    eventlog_max.raw() > 0,
                    "seed={seed} eventlog must have at least one event"
                );
            }
        });
    });
}

#[test]
fn sim_crash_recovery_cursor_tracks_last_durable_commit() {
    with_runtime(|| {
        sim_seed_range().into_par_iter().for_each(|seed| {
            let dir = tempfile::TempDir::new().unwrap();
            let commit_count = (seed % 5) + 2;
            let crash_after = seed % commit_count;

            let persisted_record_count = {
                let h = MetastoreTestHarness::open(dir.path());
                let (uid, did, root_cid) = h.create_repo(seed);
                h.metastore
                    .persist()
                    .unwrap_or_else(|e| panic!("seed={seed} persist after create: {e:?}"));

                (0..commit_count)
                    .fold((root_cid, 0i64), |(prev_cid, persisted), commit_idx| {
                        let new_cid =
                            test_cid_link(((seed + commit_idx + 50) & 0xFF) as u8);
                        let rev = format!("rev{commit_idx}_{seed}");
                        let collection = collection_nsid(seed + commit_idx);
                        let rkey = test_rkey(seed * 1000 + commit_idx);

                        let input = ApplyCommitInput {
                            user_id: uid,
                            did: did.clone(),
                            expected_root_cid: Some(prev_cid.clone()),
                            new_root_cid: new_cid.clone(),
                            new_rev: rev.to_owned(),
                            record_upserts: vec![RecordUpsert {
                                collection,
                                rkey,
                                cid: test_cid_link(
                                    ((seed + commit_idx + 80) & 0xFF) as u8,
                                ),
                            }],
                            record_deletes: vec![],
                            backlinks_to_add: vec![],
                            backlinks_to_remove: vec![],
                            new_block_cids: vec![],
                            obsolete_block_cids: vec![],
                            commit_event: build_commit_event(
                                &did, &prev_cid, &new_cid, &rev,
                            ),
                        };

                        let result = h.apply_commit(input).unwrap_or_else(|e| {
                            panic!("seed={seed} commit {commit_idx}: {e:?}")
                        });
                        assert!(
                            result.seq > 0,
                            "seed={seed} commit {commit_idx} seq must be positive"
                        );

                        let new_persisted = match commit_idx <= crash_after {
                            true => {
                                h.metastore.persist().unwrap_or_else(|e| {
                                    panic!("seed={seed} persist at {commit_idx}: {e:?}")
                                });
                                h.eventlog.sync().unwrap_or_else(|e| {
                                    panic!("seed={seed} sync at {commit_idx}: {e:?}")
                                });
                                i64::try_from(commit_idx + 1).unwrap()
                            }
                            false => persisted,
                        };
                        (new_cid, new_persisted)
                    })
                    .1
            };

            {
                let h = MetastoreTestHarness::open(dir.path());
                h.recover_mutations();
                let uid = test_uuid(seed);

                let _ = h
                    .metastore
                    .repo_ops()
                    .get_repo_meta(uid)
                    .unwrap_or_else(|e| panic!("seed={seed} get_repo_meta: {e:?}"))
                    .unwrap_or_else(|| panic!("seed={seed} repo meta missing"));

                let cursor = h.read_cursor();
                assert!(
                    cursor.is_some(),
                    "seed={seed} cursor must exist after commits + recovery"
                );

                let record_count = h
                    .metastore
                    .record_ops()
                    .count_records(uid)
                    .unwrap_or_else(|e| panic!("seed={seed} count_records: {e:?}"));
                let max_expected = i64::try_from(commit_count).unwrap();
                assert!(
                    record_count >= persisted_record_count,
                    "seed={seed} recovered records ({record_count}) must be >= persisted count ({persisted_record_count})"
                );
                assert!(
                    record_count <= max_expected,
                    "seed={seed} records ({record_count}) must not exceed total commits ({commit_count})"
                );
            }
        });
    });
}

#[test]
fn sim_multi_commit_crash_cycle_consistency() {
    with_runtime(|| {
        sim_seed_range().into_par_iter().for_each(|seed| {
            let dir = tempfile::TempDir::new().unwrap();
            let cycles = ((seed % 4) as usize) + 2;

            let (uid, did) = {
                let h = MetastoreTestHarness::open(dir.path());
                let (uid, did, _) = h.create_repo(seed);
                h.metastore
                    .persist()
                    .unwrap_or_else(|e| panic!("seed={seed} initial persist: {e:?}"));
                (uid, did)
            };

            let (total_records, last_rev) = (0..cycles).fold(
                (0i64, String::new()),
                |(prev_total, _), cycle| {
                    let records_this_cycle = (seed.wrapping_add(cycle as u64) % 4) + 1;

                    let h = MetastoreTestHarness::open(dir.path());
                    h.recover_mutations();

                    let repo_info = h
                        .metastore
                        .repo_ops()
                        .get_repo(uid)
                        .unwrap_or_else(|e| {
                            panic!("seed={seed} cycle={cycle} get_repo: {e:?}")
                        });
                    assert!(
                        repo_info.is_some(),
                        "seed={seed} cycle={cycle} repo must exist"
                    );
                    let current_cid = repo_info.unwrap().repo_root_cid;

                    let actual_records = h
                        .metastore
                        .record_ops()
                        .count_records(uid)
                        .unwrap_or_else(|e| {
                            panic!("seed={seed} cycle={cycle} count_records: {e:?}")
                        });
                    assert!(
                        actual_records >= prev_total,
                        "seed={seed} cycle={cycle} records ({actual_records}) must be >= previous total ({prev_total})"
                    );

                    let collection = collection_nsid(seed + cycle as u64);
                    let upserts: Vec<RecordUpsert> = (0..records_this_cycle)
                        .map(|i| {
                            let idx = seed * 10000 + (cycle as u64) * 100 + i;
                            RecordUpsert {
                                collection: collection.clone(),
                                rkey: test_rkey(idx),
                                cid: test_cid_link(((idx + 20) & 0xFF) as u8),
                            }
                        })
                        .collect();

                    let new_cid =
                        test_cid_link(((seed + cycle as u64 + 100) & 0xFF) as u8);
                    let rev = format!("rev{cycle}_{seed}");

                    let input = ApplyCommitInput {
                        user_id: uid,
                        did: did.clone(),
                        expected_root_cid: Some(current_cid.clone()),
                        new_root_cid: new_cid.clone(),
                        new_rev: rev.to_owned(),
                        record_upserts: upserts,
                        record_deletes: vec![],
                        backlinks_to_add: vec![],
                        backlinks_to_remove: vec![],
                        new_block_cids: vec![],
                        obsolete_block_cids: vec![],
                        commit_event: build_commit_event(
                            &did, &current_cid, &new_cid, &rev,
                        ),
                    };

                    h.apply_commit(input).unwrap_or_else(|e| {
                        panic!("seed={seed} cycle={cycle} apply_commit: {e:?}")
                    });
                    h.metastore.persist().unwrap_or_else(|e| {
                        panic!("seed={seed} cycle={cycle} persist: {e:?}")
                    });
                    h.eventlog.sync().unwrap_or_else(|e| {
                        panic!("seed={seed} cycle={cycle} sync: {e:?}")
                    });

                    let new_total =
                        actual_records + i64::try_from(records_this_cycle).unwrap();
                    (new_total, rev)
                },
            );

            {
                let h = MetastoreTestHarness::open(dir.path());
                h.recover_mutations();
                let (_, repo_meta) = h
                    .metastore
                    .repo_ops()
                    .get_repo_meta(uid)
                    .unwrap_or_else(|e| panic!("seed={seed} final get_repo_meta: {e:?}"))
                    .unwrap_or_else(|| panic!("seed={seed} final repo meta missing"));
                assert_eq!(
                    repo_meta.repo_rev, last_rev,
                    "seed={seed} final rev must match last committed"
                );

                let final_count = h
                    .metastore
                    .record_ops()
                    .count_records(uid)
                    .unwrap_or_else(|e| panic!("seed={seed} final count_records: {e:?}"));
                assert_eq!(
                    final_count, total_records,
                    "seed={seed} final record count must match oracle"
                );

                let cursor = h
                    .read_cursor()
                    .unwrap_or_else(|| panic!("seed={seed} cursor missing after full recovery"));
                let eventlog_max = h.eventlog.max_seq();
                assert_eq!(
                    cursor,
                    eventlog_max.raw(),
                    "seed={seed} cursor must equal eventlog max after full recovery"
                );
            }
        });
    });
}

#[test]
fn sim_handler_pool_shutdown_with_inflight_commits() {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let seed_range = match sim_single_seed() {
        Some(s) => s..s + 1,
        None => 0..std::cmp::min(sim_seed_range().end, 100),
    };

    seed_range.into_par_iter().for_each(|seed| {
        let dir = tempfile::TempDir::new().unwrap();
        let stores = open_test_stores(dir.path(), MAX_FILE_SIZE, CACHE_SIZE);
        let bridge = Arc::new(EventLogBridge::new(Arc::clone(&stores.eventlog)));
        let name = NAMES[(seed as usize) % NAMES.len()];

        let repo_count = (seed % 5) + 2;
        let repos: Vec<(uuid::Uuid, tranquil_types::Did, CidLink)> = (0..repo_count)
            .map(|i| {
                let idx = seed * 100 + i;
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
                        &format!("rev0_{name}{idx}"),
                    )
                    .unwrap_or_else(|e| panic!("seed={seed} create_repo idx={idx}: {e:?}"));
                (uid, did, cid)
            })
            .collect();

        stores
            .metastore
            .persist()
            .unwrap_or_else(|e| panic!("seed={seed} persist: {e:?}"));

        let pool = HandlerPool::spawn(stores.metastore.clone(), Arc::clone(&bridge), None, Some(2));

        let receivers: Vec<(u64, oneshot::Receiver<_>)> = repos
            .iter()
            .enumerate()
            .map(|(i, (uid, did, root_cid))| {
                let idx = seed * 100 + i as u64;
                let new_cid = test_cid_link(((seed + i as u64 + 50) & 0xFF) as u8);
                let rev = format!("rev1_{name}{idx}");
                let input = ApplyCommitInput {
                    user_id: *uid,
                    did: did.clone(),
                    expected_root_cid: Some(root_cid.clone()),
                    new_root_cid: new_cid.clone(),
                    new_rev: rev.to_owned(),
                    record_upserts: vec![RecordUpsert {
                        collection: collection_nsid(seed + i as u64),
                        rkey: test_rkey(idx),
                        cid: test_cid_link(((seed + i as u64 + 30) & 0xFF) as u8),
                    }],
                    record_deletes: vec![],
                    backlinks_to_add: vec![],
                    backlinks_to_remove: vec![],
                    new_block_cids: vec![],
                    obsolete_block_cids: vec![],
                    commit_event: build_commit_event(did, root_cid, &new_cid, &rev),
                };
                let (tx, rx) = oneshot::channel();
                pool.send(MetastoreRequest::Commit(Box::new(
                    CommitRequest::ApplyCommit {
                        input: Box::new(input),
                        tx,
                    },
                )))
                .unwrap_or_else(|e| panic!("seed={seed} idx={idx} send: {e:?}"));
                (idx, rx)
            })
            .collect();

        receivers.into_iter().for_each(|(idx, rx)| {
            let result = rt.block_on(rx);
            match result {
                Ok(Ok(commit_result)) => {
                    assert!(
                        commit_result.seq > 0,
                        "seed={seed} idx={idx} commit seq must be positive"
                    );
                }
                Ok(Err(e)) => {
                    panic!("seed={seed} idx={idx} commit failed: {e:?}");
                }
                Err(_) => {
                    panic!("seed={seed} idx={idx} channel dropped before response");
                }
            }
        });

        rt.block_on(pool.close());

        stores
            .metastore
            .persist()
            .unwrap_or_else(|e| panic!("seed={seed} final persist: {e:?}"));
        stores
            .eventlog
            .sync()
            .unwrap_or_else(|e| panic!("seed={seed} final sync: {e:?}"));

        drop(pool);
        drop(bridge);
        drop(stores);

        let h = MetastoreTestHarness::open(dir.path());
        h.recover_mutations();

        (0..repo_count).for_each(|i| {
            let idx = seed * 100 + i;
            let uid = test_uuid(idx);
            let expected_rev = format!("rev1_{name}{idx}");

            let meta = h
                .metastore
                .repo_ops()
                .get_repo_meta(uid)
                .unwrap_or_else(|e| panic!("seed={seed} idx={idx} get_repo_meta: {e:?}"));
            assert!(
                meta.is_some(),
                "seed={seed} repo idx={idx} must exist after pool shutdown"
            );
            let (_, rm) = meta.unwrap();
            assert_eq!(
                rm.repo_rev, expected_rev,
                "seed={seed} repo idx={idx} rev must match committed value"
            );

            let count = h
                .metastore
                .record_ops()
                .count_records(uid)
                .unwrap_or_else(|e| panic!("seed={seed} idx={idx} count_records: {e:?}"));
            assert_eq!(
                count, 1,
                "seed={seed} repo idx={idx} must have 1 record after commit"
            );
        });
    });
}

#[test]
fn sim_record_deletes_through_crash_recovery() {
    with_runtime(|| {
        sim_seed_range().into_par_iter().for_each(|seed| {
            let dir = tempfile::TempDir::new().unwrap();
            let insert_count = (seed % 6) + 2;
            let delete_count = (seed % insert_count) + 1;

            {
                let h = MetastoreTestHarness::open(dir.path());
                let (uid, did, root_cid) = h.create_repo(seed);
                h.metastore
                    .persist()
                    .unwrap_or_else(|e| panic!("seed={seed} persist after create: {e:?}"));

                let collection = collection_nsid(seed);

                let upserts: Vec<RecordUpsert> = (0..insert_count)
                    .map(|i| {
                        let idx = seed * 100 + i;
                        RecordUpsert {
                            collection: collection.clone(),
                            rkey: test_rkey(idx),
                            cid: test_cid_link(((idx + 10) & 0xFF) as u8),
                        }
                    })
                    .collect();

                let mid_cid = test_cid_link(((seed + 60) & 0xFF) as u8);
                let rev1 = format!("rev1_{seed}");
                let insert_input = ApplyCommitInput {
                    user_id: uid,
                    did: did.clone(),
                    expected_root_cid: Some(root_cid.clone()),
                    new_root_cid: mid_cid.clone(),
                    new_rev: rev1.clone(),
                    record_upserts: upserts,
                    record_deletes: vec![],
                    backlinks_to_add: vec![],
                    backlinks_to_remove: vec![],
                    new_block_cids: vec![],
                    obsolete_block_cids: vec![],
                    commit_event: build_commit_event(&did, &root_cid, &mid_cid, &rev1),
                };
                h.apply_commit(insert_input)
                    .unwrap_or_else(|e| panic!("seed={seed} insert commit: {e:?}"));
                h.metastore
                    .persist()
                    .unwrap_or_else(|e| panic!("seed={seed} persist after insert: {e:?}"));
                h.eventlog
                    .sync()
                    .unwrap_or_else(|e| panic!("seed={seed} sync after insert: {e:?}"));

                let deletes: Vec<RecordDelete> = (0..delete_count)
                    .map(|i| {
                        let idx = seed * 100 + i;
                        RecordDelete {
                            collection: collection.clone(),
                            rkey: test_rkey(idx),
                        }
                    })
                    .collect();

                let final_cid = test_cid_link(((seed + 70) & 0xFF) as u8);
                let rev2 = format!("rev2_{seed}");
                let delete_input = ApplyCommitInput {
                    user_id: uid,
                    did: did.clone(),
                    expected_root_cid: Some(mid_cid.clone()),
                    new_root_cid: final_cid.clone(),
                    new_rev: rev2.clone(),
                    record_upserts: vec![],
                    record_deletes: deletes,
                    backlinks_to_add: vec![],
                    backlinks_to_remove: vec![],
                    new_block_cids: vec![],
                    obsolete_block_cids: vec![],
                    commit_event: build_commit_event(&did, &mid_cid, &final_cid, &rev2),
                };
                h.apply_commit(delete_input)
                    .unwrap_or_else(|e| panic!("seed={seed} delete commit: {e:?}"));
            }

            {
                let h = MetastoreTestHarness::open(dir.path());
                h.recover_mutations();
                let uid = test_uuid(seed);
                let collection = collection_nsid(seed);

                let (_, repo_meta) = h
                    .metastore
                    .repo_ops()
                    .get_repo_meta(uid)
                    .unwrap_or_else(|e| panic!("seed={seed} get_repo_meta: {e:?}"))
                    .unwrap_or_else(|| panic!("seed={seed} repo meta missing"));

                let cursor = h.read_cursor();
                let eventlog_max = h.eventlog.max_seq();

                match eventlog_max.raw() > 0 && cursor.is_some() {
                    true => {
                        assert_eq!(
                            repo_meta.repo_rev,
                            format!("rev2_{seed}"),
                            "seed={seed} rev must reflect delete commit after recovery"
                        );

                        let surviving = i64::try_from(insert_count - delete_count).unwrap();
                        let count = h
                            .metastore
                            .record_ops()
                            .count_records(uid)
                            .unwrap_or_else(|e| panic!("seed={seed} count_records: {e:?}"));
                        assert_eq!(
                            count, surviving,
                            "seed={seed} record count must reflect deletes after recovery"
                        );

                        (0..delete_count).for_each(|i| {
                            let idx = seed * 100 + i;
                            let rkey = test_rkey(idx);
                            let cid = h
                                .metastore
                                .record_ops()
                                .get_record_cid(uid, &collection, &rkey)
                                .unwrap_or_else(|e| {
                                    panic!("seed={seed} get_record_cid idx={idx}: {e:?}")
                                });
                            assert!(
                                cid.is_none(),
                                "seed={seed} record idx={idx} must be deleted after recovery"
                            );
                        });

                        (delete_count..insert_count).for_each(|i| {
                            let idx = seed * 100 + i;
                            let rkey = test_rkey(idx);
                            let cid = h
                                .metastore
                                .record_ops()
                                .get_record_cid(uid, &collection, &rkey)
                                .unwrap_or_else(|e| {
                                    panic!("seed={seed} get_record_cid idx={idx}: {e:?}")
                                });
                            assert!(
                                cid.is_some(),
                                "seed={seed} record idx={idx} must survive (not deleted)"
                            );
                        });
                    }
                    false => {
                        let count = h
                            .metastore
                            .record_ops()
                            .count_records(uid)
                            .unwrap_or_else(|e| panic!("seed={seed} count_records: {e:?}"));
                        let inserted = i64::try_from(insert_count).unwrap();
                        let surviving = i64::try_from(insert_count - delete_count).unwrap();
                        assert!(
                            count == inserted || count == surviving,
                            "seed={seed} records must be {inserted} (insert only) or {surviving} (deletes applied): got {count}"
                        );
                    }
                }
            }
        });
    });
}

#[test]
fn sim_obsolete_block_cids_through_crash_recovery() {
    with_runtime(|| {
        sim_seed_range().into_par_iter().for_each(|seed| {
            let dir = tempfile::TempDir::new().unwrap();
            let block_count = (seed % 6) + 2;
            let obsolete_count = (seed % block_count) + 1;

            {
                let h = MetastoreTestHarness::open(dir.path());
                let (uid, did, root_cid) = h.create_repo(seed);
                h.metastore
                    .persist()
                    .unwrap_or_else(|e| panic!("seed={seed} persist after create: {e:?}"));

                let new_blocks: Vec<Vec<u8>> = (0..block_count)
                    .map(|i| block_cid_bytes(seed * 100 + i))
                    .collect();

                let mid_cid = test_cid_link(((seed + 60) & 0xFF) as u8);
                let rev1 = format!("rev1_{seed}");
                let insert_input = ApplyCommitInput {
                    user_id: uid,
                    did: did.clone(),
                    expected_root_cid: Some(root_cid.clone()),
                    new_root_cid: mid_cid.clone(),
                    new_rev: rev1.clone(),
                    record_upserts: vec![RecordUpsert {
                        collection: collection_nsid(seed),
                        rkey: test_rkey(seed),
                        cid: test_cid_link(((seed + 10) & 0xFF) as u8),
                    }],
                    record_deletes: vec![],
                    backlinks_to_add: vec![],
                    backlinks_to_remove: vec![],
                    new_block_cids: new_blocks,
                    obsolete_block_cids: vec![],
                    commit_event: build_commit_event(&did, &root_cid, &mid_cid, &rev1),
                };
                h.apply_commit(insert_input)
                    .unwrap_or_else(|e| panic!("seed={seed} insert commit: {e:?}"));
                h.metastore
                    .persist()
                    .unwrap_or_else(|e| panic!("seed={seed} persist after insert: {e:?}"));
                h.eventlog
                    .sync()
                    .unwrap_or_else(|e| panic!("seed={seed} sync after insert: {e:?}"));

                let obsolete: Vec<Vec<u8>> = (0..obsolete_count)
                    .map(|i| block_cid_bytes(seed * 100 + i))
                    .collect();

                let final_cid = test_cid_link(((seed + 70) & 0xFF) as u8);
                let rev2 = format!("rev2_{seed}");
                let obsolete_input = ApplyCommitInput {
                    user_id: uid,
                    did: did.clone(),
                    expected_root_cid: Some(mid_cid.clone()),
                    new_root_cid: final_cid.clone(),
                    new_rev: rev2.clone(),
                    record_upserts: vec![],
                    record_deletes: vec![],
                    backlinks_to_add: vec![],
                    backlinks_to_remove: vec![],
                    new_block_cids: vec![],
                    obsolete_block_cids: obsolete,
                    commit_event: build_commit_event(&did, &mid_cid, &final_cid, &rev2),
                };
                h.apply_commit(obsolete_input)
                    .unwrap_or_else(|e| panic!("seed={seed} obsolete commit: {e:?}"));
            }

            {
                let h = MetastoreTestHarness::open(dir.path());
                h.recover_mutations();
                let uid = test_uuid(seed);

                let (_, repo_meta) = h
                    .metastore
                    .repo_ops()
                    .get_repo_meta(uid)
                    .unwrap_or_else(|e| panic!("seed={seed} get_repo_meta: {e:?}"))
                    .unwrap_or_else(|| panic!("seed={seed} repo meta missing"));

                let cursor = h.read_cursor();
                let eventlog_max = h.eventlog.max_seq();

                let total_blocks = h
                    .metastore
                    .user_block_ops()
                    .count_user_blocks(uid)
                    .unwrap_or_else(|e| panic!("seed={seed} count_user_blocks: {e:?}"));

                match eventlog_max.raw() > 0 && cursor.is_some() {
                    true => {
                        assert_eq!(
                            repo_meta.repo_rev,
                            format!("rev2_{seed}"),
                            "seed={seed} rev must reflect obsolete commit after recovery"
                        );

                        let expected_remaining =
                            i64::try_from(block_count - obsolete_count).unwrap();
                        assert_eq!(
                            total_blocks, expected_remaining,
                            "seed={seed} block count must reflect obsolete removals after recovery"
                        );
                    }
                    false => {
                        let all_blocks = i64::try_from(block_count).unwrap();
                        let after_obsolete =
                            i64::try_from(block_count - obsolete_count).unwrap();
                        assert!(
                            total_blocks == all_blocks || total_blocks == after_obsolete,
                            "seed={seed} blocks must be {all_blocks} (insert only) or {after_obsolete} (obsolete applied): got {total_blocks}"
                        );
                    }
                }
            }
        });
    });
}
