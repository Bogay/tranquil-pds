use std::path::Path;

use proptest::prelude::*;
use rayon::prelude::*;
use tranquil_store::metastore::recovery::{
    BacklinkMutation, CommitMutationSet, RecordMutationDelete, RecordMutationUpsert,
};
use tranquil_store::metastore::{Metastore, MetastoreConfig};
use tranquil_store::{sim_proptest_cases, sim_seed_range};
use tranquil_types::{CidLink, Did, Handle};
use uuid::Uuid;

const NAMES: &[&str] = &["olaren", "teq", "nel", "lyna", "bailey"];

fn test_config() -> MetastoreConfig {
    MetastoreConfig {
        cache_size_bytes: 16 * 1024 * 1024,
    }
}

fn open_metastore(path: &Path) -> Metastore {
    Metastore::open(path, test_config()).unwrap()
}

fn test_did(seed: u64) -> Did {
    let name = NAMES[(seed as usize) % NAMES.len()];
    Did::from(format!("did:plc:{name}{seed}"))
}

fn test_handle(seed: u64) -> Handle {
    let name = NAMES[(seed as usize) % NAMES.len()];
    Handle::new(format!("{name}{seed}.test")).unwrap()
}

fn test_cid_link(seed: u8) -> CidLink {
    let digest: [u8; 32] = std::array::from_fn(|i| seed.wrapping_add(i as u8));
    let mh = multihash::Multihash::<64>::wrap(0x12, &digest).unwrap();
    let c = cid::Cid::new_v1(0x71, mh);
    CidLink::from_cid(&c)
}

fn test_uuid(seed: u64) -> Uuid {
    Uuid::from_u128(seed as u128 | 0x4000_0000_0000_0000_8000_0000_0000_0000)
}

fn arb_mutation_set() -> impl Strategy<Value = CommitMutationSet> {
    let arb_upsert = (
        "[a-z\\.]{5,20}",
        "[a-z0-9]{3,10}",
        prop::collection::vec(any::<u8>(), 4..36),
    )
        .prop_map(|(collection, rkey, cid_bytes)| RecordMutationUpsert {
            collection,
            rkey,
            cid_bytes,
        });

    let arb_delete = ("[a-z\\.]{5,20}", "[a-z0-9]{3,10}")
        .prop_map(|(collection, rkey)| RecordMutationDelete { collection, rkey });

    let arb_backlink = (
        "at://did:plc:[a-z]{3,8}/[a-z\\.]{5,20}/[a-z0-9]{3,8}",
        0u8..4,
        "at://did:plc:[a-z]{3,8}/[a-z\\.]{5,20}/[a-z0-9]{3,8}",
    )
        .prop_map(|(uri, path, link_to)| BacklinkMutation { uri, path, link_to });

    (
        prop::collection::vec(any::<u8>(), 0..64),
        "[a-z0-9]{1,16}",
        prop::collection::vec(arb_upsert, 0..20),
        prop::collection::vec(arb_delete, 0..20),
        prop::collection::vec(prop::collection::vec(any::<u8>(), 4..36), 0..20),
        prop::collection::vec(prop::collection::vec(any::<u8>(), 4..36), 0..20),
        prop::collection::vec(arb_backlink, 0..5),
        prop::collection::vec("at://did:plc:[a-z]{3,8}/[a-z\\.]{5,20}/[a-z0-9]{3,8}", 0..5),
    )
        .prop_map(
            |(
                new_root_cid,
                new_rev,
                record_upserts,
                record_deletes,
                block_inserts,
                block_deletes,
                backlink_adds,
                backlink_remove_uris,
            )| {
                CommitMutationSet {
                    new_root_cid,
                    new_rev,
                    record_upserts,
                    record_deletes,
                    block_inserts,
                    block_deletes,
                    backlink_adds,
                    backlink_remove_uris,
                }
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(sim_proptest_cases()))]

    #[test]
    fn mutation_set_roundtrip_fuzz(ms in arb_mutation_set()) {
        let serialized = ms.serialize().unwrap();
        let recovered = CommitMutationSet::deserialize(&serialized).unwrap();
        prop_assert_eq!(recovered, ms);
    }

    #[test]
    fn mutation_set_rejects_corrupt_version(ms in arb_mutation_set()) {
        let mut bytes = ms.serialize().unwrap();
        bytes[0] = 0xFF;
        prop_assert!(CommitMutationSet::deserialize(&bytes).is_none());
    }

    #[test]
    fn mutation_set_truncation_detected(
        ms in arb_mutation_set(),
        truncate_at in 0usize..64,
    ) {
        let bytes = ms.serialize().unwrap();
        let cut = truncate_at.min(bytes.len().saturating_sub(1));
        match cut {
            0 => prop_assert!(CommitMutationSet::deserialize(&bytes[..0]).is_none()),
            n => {
                let truncated = &bytes[..n];
                match CommitMutationSet::deserialize(truncated) {
                    None => {}
                    Some(recovered) => prop_assert_eq!(recovered, ms),
                }
            }
        }
    }
}

#[test]
fn metastore_survives_abrupt_drop() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let dir = tempfile::TempDir::new().unwrap();
        let user_count = (seed % 5) + 1;

        let user_ids: Vec<Uuid> = (0..user_count).map(|i| test_uuid(seed * 100 + i)).collect();

        {
            let ms = open_metastore(dir.path());
            let repo_ops = ms.repo_ops();
            let db = ms.database();

            user_ids.iter().enumerate().for_each(|(i, &uid)| {
                let idx = seed * 100 + i as u64;
                let did = test_did(idx);
                let handle = test_handle(idx);
                let cid = test_cid_link((idx & 0xFF) as u8);
                let rev = format!("rev{idx}");
                repo_ops
                    .create_repo(db, uid, &did, &handle, &cid, &rev)
                    .unwrap();
            });
        }

        {
            let ms = open_metastore(dir.path());
            let repo_ops = ms.repo_ops();

            user_ids.iter().enumerate().for_each(|(i, &uid)| {
                let result = repo_ops.get_repo_meta(uid).unwrap();
                assert!(
                    result.is_some(),
                    "seed={seed} user {i} repo_meta missing after abrupt drop"
                );
                let (_, meta) = result.unwrap();
                let expected_rev = format!("rev{}", seed * 100 + i as u64);
                assert_eq!(
                    meta.repo_rev, expected_rev,
                    "seed={seed} user {i} rev mismatch"
                );
            });
        }
    });
}

#[test]
fn metastore_multi_crash_cycle() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let dir = tempfile::TempDir::new().unwrap();
        let cycles = (seed % 4) + 2;
        let mut expected_repos: Vec<(Uuid, u64)> = Vec::new();

        (0..cycles).for_each(|cycle| {
            let new_per_cycle = (seed.wrapping_add(cycle) % 3) + 1;

            {
                let ms = open_metastore(dir.path());

                expected_repos.iter().for_each(|(uid, idx)| {
                    let meta = ms.repo_ops().get_repo_meta(*uid).unwrap();
                    assert!(
                        meta.is_some(),
                        "seed={seed} cycle={cycle} user idx={idx} missing before new writes"
                    );
                });

                let repo_ops = ms.repo_ops();
                let db = ms.database();
                (0..new_per_cycle).for_each(|i| {
                    let idx = seed * 1000 + cycle * 100 + i;
                    let uid = test_uuid(idx);
                    let did = test_did(idx);
                    let handle = test_handle(idx);
                    let cid = test_cid_link((idx & 0xFF) as u8);
                    repo_ops
                        .create_repo(db, uid, &did, &handle, &cid, &format!("rev{idx}"))
                        .unwrap();
                    expected_repos.push((uid, idx));
                });
            }
        });

        {
            let ms = open_metastore(dir.path());
            expected_repos.iter().for_each(|(uid, idx)| {
                let meta = ms.repo_ops().get_repo_meta(*uid).unwrap();
                assert!(
                    meta.is_some(),
                    "seed={seed} final verify: user idx={idx} missing"
                );
            });
        }
    });
}

#[test]
fn metastore_persisted_survives_unpersisted_lost() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let dir = tempfile::TempDir::new().unwrap();
        let batch_size = (seed % 5) + 2;

        {
            let ms = open_metastore(dir.path());
            let db = ms.database();
            let repo_ops = ms.repo_ops();

            (0..batch_size).for_each(|i| {
                let idx = seed * 100 + i;
                repo_ops
                    .create_repo(
                        db,
                        test_uuid(idx),
                        &test_did(idx),
                        &test_handle(idx),
                        &test_cid_link((idx & 0xFF) as u8),
                        &format!("rev{idx}"),
                    )
                    .unwrap();
            });

            ms.persist().unwrap();

            let extra_idx = seed * 100 + batch_size;
            repo_ops
                .create_repo(
                    db,
                    test_uuid(extra_idx),
                    &test_did(extra_idx),
                    &test_handle(extra_idx),
                    &test_cid_link((extra_idx & 0xFF) as u8),
                    &format!("rev{extra_idx}"),
                )
                .unwrap();
        }

        {
            let ms = open_metastore(dir.path());
            let repo_ops = ms.repo_ops();

            (0..batch_size).for_each(|i| {
                let idx = seed * 100 + i;
                let meta = repo_ops.get_repo_meta(test_uuid(idx)).unwrap();
                assert!(
                    meta.is_some(),
                    "seed={seed} persisted user idx={idx} must survive crash"
                );
            });
        }
    });
}

#[test]
fn metastore_user_hashes_reload_after_crash() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let dir = tempfile::TempDir::new().unwrap();
        let count = (seed % 5) + 1;
        let name = NAMES[(seed as usize) % NAMES.len()];

        let entries: Vec<(Uuid, u64)> = (0..count)
            .map(|i| {
                let idx = seed * 100 + i;
                (test_uuid(idx), idx)
            })
            .collect();

        {
            let ms = open_metastore(dir.path());
            let db = ms.database();
            let repo_ops = ms.repo_ops();

            entries.iter().for_each(|&(uid, idx)| {
                repo_ops
                    .create_repo(
                        db,
                        uid,
                        &test_did(idx),
                        &test_handle(idx),
                        &test_cid_link((idx & 0xFF) as u8),
                        &format!("rev{idx}"),
                    )
                    .unwrap();
            });
        }

        {
            let ms = open_metastore(dir.path());

            entries.iter().for_each(|&(uid, idx)| {
                let hash = ms.user_hashes().get(&uid);
                assert!(
                    hash.is_some(),
                    "seed={seed} name={name} user_hash for idx={idx} not reloaded after crash"
                );
            });
        }
    });
}

#[test]
fn metastore_handle_lookup_survives_crash() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let dir = tempfile::TempDir::new().unwrap();
        let idx = seed;
        let uid = test_uuid(idx);
        let did = test_did(idx);
        let handle = test_handle(idx);

        {
            let ms = open_metastore(dir.path());
            ms.repo_ops()
                .create_repo(
                    ms.database(),
                    uid,
                    &did,
                    &handle,
                    &test_cid_link((idx & 0xFF) as u8),
                    &format!("rev{idx}"),
                )
                .unwrap();
        }

        {
            let ms = open_metastore(dir.path());
            let resolved = ms.repo_ops().lookup_handle(&handle).unwrap();
            assert!(
                resolved.is_some(),
                "seed={seed} handle '{}' not resolvable after crash",
                handle.as_str()
            );
        }
    });
}
