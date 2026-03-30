mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use cid::Cid;
use common::{advance_epoch, compact_all_sealed};
use futures::StreamExt;
use jacquard_common::types::string::Did;
use jacquard_common::types::tid::Ticker;
use jacquard_repo::car::{parse_car_bytes, write_car_bytes};
use jacquard_repo::commit::Commit;
use jacquard_repo::mst::Mst;
use jacquard_repo::repo::CommitData;
use jacquard_repo::storage::BlockStore;
use multihash::Multihash;
use sha2::{Digest, Sha256};
use tranquil_store::blockstore::{
    BlockStoreConfig, DEFAULT_MAX_FILE_SIZE, GroupCommitConfig, TranquilBlockStore,
};

const DAG_CBOR_CODEC: u64 = 0x71;
const SHA2_256_CODE: u64 = 0x12;

fn test_config(dir: &std::path::Path) -> BlockStoreConfig {
    BlockStoreConfig {
        data_dir: dir.join("data"),
        index_dir: dir.join("index"),
        max_file_size: DEFAULT_MAX_FILE_SIZE,
        group_commit: GroupCommitConfig::default(),
        shard_count: 1,
    }
}

fn make_record(value: &str) -> Vec<u8> {
    serde_ipld_dagcbor::to_vec(&BTreeMap::from([
        ("$type", "app.bsky.feed.post"),
        ("text", value),
    ]))
    .unwrap()
}

fn compute_cid(data: &[u8]) -> Cid {
    let hash = Sha256::digest(data);
    let multihash = Multihash::wrap(SHA2_256_CODE, &hash).unwrap();
    Cid::new_v1(DAG_CBOR_CODEC, multihash)
}

fn test_signing_key() -> k256::ecdsa::SigningKey {
    k256::ecdsa::SigningKey::random(&mut rand::thread_rng())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mst_insert_commit_and_car_round_trip() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = TranquilBlockStore::open(test_config(dir.path())).unwrap();
    let storage = Arc::new(store.clone());
    let mut mst = Mst::new(storage.clone());

    let records: Vec<(String, Cid, Vec<u8>)> = (0..100u32)
        .map(|i| {
            let data = make_record(&format!("post number {i}"));
            let cid = compute_cid(&data);
            (format!("app.bsky.feed.post/{i:010}"), cid, data)
        })
        .collect();

    let mut record_blocks = BTreeMap::new();
    for (key, cid, data) in &records {
        record_blocks.insert(*cid, Bytes::from(data.clone()));
        storage.put(data).await.unwrap();
        mst = mst.add(key, *cid).await.unwrap();
    }

    let mst_root = mst.persist().await.unwrap();

    futures::stream::iter(&records)
        .for_each(|(key, expected_cid, _)| {
            let mst = &mst;
            async move {
                let found = mst.get(key).await.unwrap();
                assert_eq!(found, Some(*expected_cid), "record {key} missing from MST");
            }
        })
        .await;

    let signing_key = test_signing_key();
    let did = Did::new("did:plc:testuser123").unwrap();
    let mut ticker = Ticker::new();
    let rev = ticker.next(None);

    let commit = Commit::new_unsigned(did, mst_root, rev.clone(), None)
        .sign(&signing_key)
        .unwrap();
    let commit_cbor = commit.to_cbor().unwrap();
    let commit_cid = compute_cid(&commit_cbor);
    let commit_bytes = Bytes::from(commit_cbor);

    let empty_mst = Mst::new(storage.clone());
    let diff = empty_mst.diff(&mst).await.unwrap();

    let mut all_blocks = diff.new_mst_blocks.clone();
    all_blocks.insert(commit_cid, commit_bytes);
    all_blocks.extend(record_blocks);

    let commit_data = CommitData {
        cid: commit_cid,
        rev,
        since: None,
        prev: None,
        data: mst_root,
        prev_data: None,
        blocks: all_blocks.clone(),
        relevant_blocks: BTreeMap::new(),
        deleted_cids: Vec::new(),
    };

    store.apply_commit(commit_data).await.unwrap();

    let car_bytes = write_car_bytes(commit_cid, all_blocks).await.unwrap();
    let parsed = parse_car_bytes(&car_bytes).await.unwrap();

    assert_eq!(parsed.root, commit_cid);
    assert!(parsed.blocks.contains_key(&commit_cid));
    assert!(parsed.blocks.contains_key(&mst_root));

    records.iter().for_each(|(_, record_cid, _)| {
        assert!(
            parsed.blocks.contains_key(record_cid),
            "record block {record_cid} missing from CAR"
        );
    });

    let parsed_commit = Commit::from_cbor(parsed.blocks.get(&commit_cid).unwrap()).unwrap();
    assert_eq!(*parsed_commit.data(), mst_root);

    let loaded_mst = Mst::load(storage.clone(), mst_root, None);
    futures::stream::iter(&records)
        .for_each(|(key, expected_cid, _)| {
            let loaded_mst = &loaded_mst;
            async move {
                let found = loaded_mst.get(key).await.unwrap();
                assert_eq!(
                    found,
                    Some(*expected_cid),
                    "record {key} missing after reload"
                );
            }
        })
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mst_create_update_delete_with_refcounts() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = TranquilBlockStore::open(test_config(dir.path())).unwrap();
    let storage = Arc::new(store.clone());

    let record_a_v1 = make_record("version 1 of record A");
    let record_a_v2 = make_record("version 2 of record A");
    let record_b = make_record("record B to be deleted");
    let record_c = make_record("record C stays forever");
    let record_shared = make_record("shared content");

    let cid_a_v1 = storage.put(&record_a_v1).await.unwrap();
    let cid_a_v2 = compute_cid(&record_a_v2);
    let cid_b = storage.put(&record_b).await.unwrap();
    let cid_c = storage.put(&record_c).await.unwrap();
    let cid_shared = storage.put(&record_shared).await.unwrap();

    let mut mst = Mst::new(storage.clone());
    mst = mst.add("app.bsky.feed.post/aaaa", cid_a_v1).await.unwrap();
    mst = mst.add("app.bsky.feed.post/bbbb", cid_b).await.unwrap();
    mst = mst.add("app.bsky.feed.post/cccc", cid_c).await.unwrap();
    mst = mst
        .add("app.bsky.feed.post/dddd", cid_shared)
        .await
        .unwrap();
    mst = mst
        .add("app.bsky.feed.post/eeee", cid_shared)
        .await
        .unwrap();

    let mst_root_v1 = mst.persist().await.unwrap();

    let signing_key = test_signing_key();
    let mut ticker = Ticker::new();
    let rev1 = ticker.next(None);

    let commit_v1 = Commit::new_unsigned(
        Did::new("did:plc:testuser123").unwrap(),
        mst_root_v1,
        rev1.clone(),
        None,
    )
    .sign(&signing_key)
    .unwrap();
    let commit_v1_cbor = commit_v1.to_cbor().unwrap();
    let commit_v1_cid = compute_cid(&commit_v1_cbor);

    let empty_mst = Mst::new(storage.clone());
    let diff_v1 = empty_mst.diff(&mst).await.unwrap();

    let mut blocks_v1 = diff_v1.new_mst_blocks.clone();
    blocks_v1.insert(commit_v1_cid, Bytes::from(commit_v1_cbor));

    store
        .apply_commit(CommitData {
            cid: commit_v1_cid,
            rev: rev1.clone(),
            since: None,
            prev: None,
            data: mst_root_v1,
            prev_data: None,
            blocks: blocks_v1,
            relevant_blocks: BTreeMap::new(),
            deleted_cids: Vec::new(),
        })
        .await
        .unwrap();

    let old_mst = mst.clone();
    mst = mst.add("app.bsky.feed.post/aaaa", cid_a_v2).await.unwrap();
    mst = mst.delete("app.bsky.feed.post/bbbb").await.unwrap();
    mst = mst.delete("app.bsky.feed.post/eeee").await.unwrap();

    let mst_root_v2 = mst.persist().await.unwrap();

    let diff_v2 = old_mst.diff(&mst).await.unwrap();

    let rev2 = ticker.next(Some(rev1.clone()));
    let commit_v2 = Commit::new_unsigned(
        Did::new("did:plc:testuser123").unwrap(),
        mst_root_v2,
        rev2.clone(),
        Some(commit_v1_cid),
    )
    .sign(&signing_key)
    .unwrap();
    let commit_v2_cbor = commit_v2.to_cbor().unwrap();
    let commit_v2_cid = compute_cid(&commit_v2_cbor);

    let mut blocks_v2 = diff_v2.new_mst_blocks.clone();
    blocks_v2.insert(commit_v2_cid, Bytes::from(commit_v2_cbor));
    blocks_v2.insert(cid_a_v2, Bytes::from(record_a_v2.clone()));

    let mut deleted: Vec<Cid> = diff_v2.removed_mst_blocks.clone();
    deleted.extend(diff_v2.removed_cids.iter());

    store
        .apply_commit(CommitData {
            cid: commit_v2_cid,
            rev: rev2,
            since: Some(rev1),
            prev: Some(commit_v1_cid),
            data: mst_root_v2,
            prev_data: Some(mst_root_v1),
            blocks: blocks_v2,
            relevant_blocks: BTreeMap::new(),
            deleted_cids: deleted,
        })
        .await
        .unwrap();

    let retrieved_a_v2 = store.get(&cid_a_v2).await.unwrap();
    assert!(retrieved_a_v2.is_some(), "updated record A v2 should exist");
    assert_eq!(&retrieved_a_v2.unwrap()[..], &record_a_v2);

    assert!(
        store.has(&cid_a_v1).await.unwrap(),
        "cid_a_v1 should still exist, tombstoned but not GC'd"
    );
    assert!(
        store.has(&cid_b).await.unwrap(),
        "cid_b should still exist, tombstoned but not GC'd"
    );

    assert!(
        store.has(&cid_c).await.unwrap(),
        "untouched record C should still exist"
    );
    let retrieved_c = store.get(&cid_c).await.unwrap().unwrap();
    assert_eq!(&retrieved_c[..], &record_c);

    assert!(
        store.has(&cid_shared).await.unwrap(),
        "shared-content block should still exist, tombstoned but not GC'd"
    );

    let loaded_mst = Mst::load(storage.clone(), mst_root_v2, None);
    let expected_entries: Vec<(&str, Option<Cid>)> = vec![
        ("app.bsky.feed.post/aaaa", Some(cid_a_v2)),
        ("app.bsky.feed.post/bbbb", None),
        ("app.bsky.feed.post/cccc", Some(cid_c)),
        ("app.bsky.feed.post/dddd", Some(cid_shared)),
        ("app.bsky.feed.post/eeee", None),
    ];

    futures::stream::iter(expected_entries)
        .for_each(|(key, expected)| {
            let loaded_mst = &loaded_mst;
            async move {
                assert_eq!(loaded_mst.get(key).await.unwrap(), expected);
            }
        })
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mst_survives_gc_after_structural_mutations() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = TranquilBlockStore::open(BlockStoreConfig {
        data_dir: dir.path().join("data"),
        index_dir: dir.path().join("index"),
        max_file_size: 64 * 1024,
        group_commit: GroupCommitConfig::default(),
        shard_count: 1,
    })
    .unwrap();
    let storage = Arc::new(store.clone());

    let record_count = 5_000u32;
    let records: Vec<(String, Vec<u8>)> = (0..record_count)
        .map(|i| {
            let key = format!("app.bsky.feed.post/{i:010}");
            let data = make_record(&format!("post {i} padding {}", "x".repeat(64)));
            (key, data)
        })
        .collect();

    let mut mst = Mst::new(storage.clone());
    let mut record_cids: BTreeMap<String, Cid> = BTreeMap::new();

    for (key, data) in &records {
        let cid = storage.put(data).await.unwrap();
        record_cids.insert(key.clone(), cid);
        mst = mst.add(key, cid).await.unwrap();
    }

    let mst_root_v1 = mst.persist().await.unwrap();

    let signing_key = test_signing_key();
    let did = Did::new("did:plc:testgcmst").unwrap();
    let mut ticker = Ticker::new();
    let rev1 = ticker.next(None);

    let commit_v1 = Commit::new_unsigned(did.clone(), mst_root_v1, rev1.clone(), None)
        .sign(&signing_key)
        .unwrap();
    let commit_v1_cbor = commit_v1.to_cbor().unwrap();
    let commit_v1_cid = compute_cid(&commit_v1_cbor);

    let empty_mst = Mst::new(storage.clone());
    let diff_v1 = empty_mst.diff(&mst).await.unwrap();
    let mut blocks_v1 = diff_v1.new_mst_blocks.clone();
    blocks_v1.insert(commit_v1_cid, Bytes::from(commit_v1_cbor));

    store
        .apply_commit(CommitData {
            cid: commit_v1_cid,
            rev: rev1.clone(),
            since: None,
            prev: None,
            data: mst_root_v1,
            prev_data: None,
            blocks: blocks_v1,
            relevant_blocks: BTreeMap::new(),
            deleted_cids: Vec::new(),
        })
        .await
        .unwrap();

    let delete_indices: Vec<u32> = (0..record_count)
        .filter(|i| i % 3 == 0 || i % 7 == 0)
        .collect();
    let keep_indices: Vec<u32> = (0..record_count)
        .filter(|i| i % 3 != 0 && i % 7 != 0)
        .collect();

    let old_mst = mst.clone();
    for &i in &delete_indices {
        let key = format!("app.bsky.feed.post/{i:010}");
        mst = mst.delete(&key).await.unwrap();
    }

    let mst_root_v2 = mst.persist().await.unwrap();
    let diff_v2 = old_mst.diff(&mst).await.unwrap();

    let rev2 = ticker.next(Some(rev1.clone()));
    let commit_v2 =
        Commit::new_unsigned(did.clone(), mst_root_v2, rev2.clone(), Some(commit_v1_cid))
            .sign(&signing_key)
            .unwrap();
    let commit_v2_cbor = commit_v2.to_cbor().unwrap();
    let commit_v2_cid = compute_cid(&commit_v2_cbor);

    let mut blocks_v2 = diff_v2.new_mst_blocks.clone();
    blocks_v2.insert(commit_v2_cid, Bytes::from(commit_v2_cbor));

    let mut deleted: Vec<Cid> = diff_v2.removed_mst_blocks.clone();
    deleted.extend(diff_v2.removed_cids.iter());

    store
        .apply_commit(CommitData {
            cid: commit_v2_cid,
            rev: rev2.clone(),
            since: Some(rev1.clone()),
            prev: Some(commit_v1_cid),
            data: mst_root_v2,
            prev_data: Some(mst_root_v1),
            blocks: blocks_v2,
            relevant_blocks: BTreeMap::new(),
            deleted_cids: deleted,
        })
        .await
        .unwrap();

    let gc_store = store.clone();
    tokio::task::spawn_blocking(move || {
        advance_epoch(&gc_store);
        std::thread::sleep(std::time::Duration::from_millis(10));
        advance_epoch(&gc_store);
        compact_all_sealed(&gc_store);
        advance_epoch(&gc_store);
        std::thread::sleep(std::time::Duration::from_millis(10));
        compact_all_sealed(&gc_store);
    })
    .await
    .unwrap();

    let post_gc_mst = Mst::load(storage.clone(), mst_root_v2, None);

    let surviving_leaves = post_gc_mst.leaves().await.unwrap();
    assert_eq!(
        surviving_leaves.len(),
        keep_indices.len(),
        "leaf count mismatch after GC: expected {} surviving records, got {}",
        keep_indices.len(),
        surviving_leaves.len()
    );

    futures::stream::iter(&keep_indices)
        .for_each(|&i| {
            let post_gc_mst = &post_gc_mst;
            let record_cids = &record_cids;
            let storage = &storage;
            async move {
                let key = format!("app.bsky.feed.post/{i:010}");
                let expected_cid = record_cids[&key];
                let found = post_gc_mst
                    .get(&key)
                    .await
                    .unwrap_or_else(|e| panic!("MST traversal failed for {key} after GC: {e}"));
                assert_eq!(
                    found,
                    Some(expected_cid),
                    "record {key} missing from MST after GC compaction"
                );

                let block = storage
                    .get(&expected_cid)
                    .await
                    .unwrap_or_else(|e| panic!("block read failed for {key} (cid={expected_cid}) after GC: {e}"));
                assert!(
                    block.is_some(),
                    "record block for {key} (cid={expected_cid}) was collected by GC despite being reachable"
                );
            }
        })
        .await;

    futures::stream::iter(&delete_indices)
        .for_each(|&i| {
            let post_gc_mst = &post_gc_mst;
            async move {
                let key = format!("app.bsky.feed.post/{i:010}");
                let found = post_gc_mst.get(&key).await.unwrap();
                assert_eq!(
                    found, None,
                    "deleted record {key} still present in MST after GC"
                );
            }
        })
        .await;

    let all_node_cids = post_gc_mst.collect_node_cids().await.unwrap();
    futures::stream::iter(all_node_cids)
        .for_each(|node_cid| {
            let storage = &storage;
            async move {
                let block = storage.get(&node_cid).await.unwrap();
                assert!(
                    block.is_some(),
                    "MST internal node {node_cid} was collected by GC despite being reachable from root"
                );
            }
        })
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mst_survives_multiple_mutation_gc_cycles() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = TranquilBlockStore::open(BlockStoreConfig {
        data_dir: dir.path().join("data"),
        index_dir: dir.path().join("index"),
        max_file_size: 64 * 1024,
        group_commit: GroupCommitConfig::default(),
        shard_count: 1,
    })
    .unwrap();
    let storage = Arc::new(store.clone());

    let collections = [
        "app.bsky.feed.post",
        "app.bsky.feed.like",
        "app.bsky.feed.repost",
        "app.bsky.graph.follow",
        "app.bsky.graph.block",
    ];
    let per_collection = 600u32;
    let records: Vec<(String, Vec<u8>)> = collections
        .iter()
        .flat_map(|col| {
            (0..per_collection).map(move |i| {
                let key = format!("{col}/{i:010}");
                let data = make_record(&format!("{col} record {i} padding {}", "y".repeat(64)));
                (key, data)
            })
        })
        .collect();

    let mut mst = Mst::new(storage.clone());
    let mut live_cids: BTreeMap<String, Cid> = BTreeMap::new();

    for (key, data) in &records {
        let cid = storage.put(data).await.unwrap();
        live_cids.insert(key.clone(), cid);
        mst = mst.add(key, cid).await.unwrap();
    }

    let mst_root = mst.persist().await.unwrap();

    let signing_key = test_signing_key();
    let did = Did::new("did:plc:testcycles").unwrap();
    let mut ticker = Ticker::new();
    let rev = ticker.next(None);

    let commit = Commit::new_unsigned(did.clone(), mst_root, rev.clone(), None)
        .sign(&signing_key)
        .unwrap();
    let commit_cbor = commit.to_cbor().unwrap();
    let commit_cid = compute_cid(&commit_cbor);

    let empty_mst = Mst::new(storage.clone());
    let diff = empty_mst.diff(&mst).await.unwrap();
    let mut blocks = diff.new_mst_blocks.clone();
    blocks.insert(commit_cid, Bytes::from(commit_cbor));

    store
        .apply_commit(CommitData {
            cid: commit_cid,
            rev: rev.clone(),
            since: None,
            prev: None,
            data: mst_root,
            prev_data: None,
            blocks,
            relevant_blocks: BTreeMap::new(),
            deleted_cids: Vec::new(),
        })
        .await
        .unwrap();

    let mut prev_rev = rev;
    let mut prev_cid = commit_cid;
    let mut prev_root = mst_root;

    let cycles = 15u32;
    let mut cycle_seed = 0u32;

    for cycle in 0..cycles {
        let old_mst = mst.clone();

        let delete_keys: Vec<String> = live_cids
            .keys()
            .enumerate()
            .filter(|(idx, _)| {
                let hash = (*idx as u32)
                    .wrapping_mul(2654435761)
                    .wrapping_add(cycle_seed);
                hash.is_multiple_of(5)
            })
            .map(|(_, k)| k.clone())
            .collect();

        for key in &delete_keys {
            mst = mst.delete(key).await.unwrap();
            live_cids.remove(key);
        }

        let add_count = delete_keys.len().min(200);
        let new_records: Vec<(String, Vec<u8>)> = (0..add_count)
            .map(|i| {
                cycle_seed = cycle_seed.wrapping_add(1);
                let key = format!("app.bsky.feed.post/new_{cycle}_{i:06}");
                let data = make_record(&format!("new record cycle {cycle} item {i}"));
                (key, data)
            })
            .collect();

        for (key, data) in &new_records {
            let cid = storage.put(data).await.unwrap();
            live_cids.insert(key.clone(), cid);
            mst = mst.add(key, cid).await.unwrap();
        }

        let new_root = mst.persist().await.unwrap();
        let diff = old_mst.diff(&mst).await.unwrap();

        let rev = ticker.next(Some(prev_rev.clone()));
        let commit = Commit::new_unsigned(did.clone(), new_root, rev.clone(), Some(prev_cid))
            .sign(&signing_key)
            .unwrap();
        let commit_cbor = commit.to_cbor().unwrap();
        let new_commit_cid = compute_cid(&commit_cbor);

        let mut commit_blocks = diff.new_mst_blocks.clone();
        commit_blocks.insert(new_commit_cid, Bytes::from(commit_cbor));
        new_records.iter().for_each(|(_, data)| {
            let cid = compute_cid(data);
            commit_blocks.insert(cid, Bytes::from(data.clone()));
        });

        let mut deleted: Vec<Cid> = diff.removed_mst_blocks.clone();
        deleted.extend(diff.removed_cids.iter());

        store
            .apply_commit(CommitData {
                cid: new_commit_cid,
                rev: rev.clone(),
                since: Some(prev_rev.clone()),
                prev: Some(prev_cid),
                data: new_root,
                prev_data: Some(prev_root),
                blocks: commit_blocks,
                relevant_blocks: BTreeMap::new(),
                deleted_cids: deleted,
            })
            .await
            .unwrap();

        let gc_store = store.clone();
        tokio::task::spawn_blocking(move || {
            advance_epoch(&gc_store);
            std::thread::sleep(std::time::Duration::from_millis(10));
            advance_epoch(&gc_store);
            compact_all_sealed(&gc_store);
        })
        .await
        .unwrap();

        prev_rev = rev;
        prev_cid = new_commit_cid;
        prev_root = new_root;
        cycle_seed = cycle_seed.wrapping_add(7);
    }

    let final_mst = Mst::load(storage.clone(), prev_root, None);

    let final_leaves = final_mst.leaves().await.unwrap();
    assert_eq!(
        final_leaves.len(),
        live_cids.len(),
        "after {cycles} mutation+GC cycles: expected {} leaves, got {}",
        live_cids.len(),
        final_leaves.len()
    );

    futures::stream::iter(live_cids.iter())
        .for_each(|(key, expected_cid)| {
            let final_mst = &final_mst;
            let storage = &storage;
            let expected_cid = *expected_cid;
            async move {
                let found = final_mst.get(key.as_str()).await.unwrap_or_else(|e| {
                    panic!("MST traversal failed for {key} after {cycles} GC cycles: {e}")
                });
                assert_eq!(
                    found,
                    Some(expected_cid),
                    "record {key} missing from MST after {cycles} mutation+GC cycles"
                );

                let block = storage.get(&expected_cid).await.unwrap();
                assert!(
                    block.is_some(),
                    "record block for {key} (cid={expected_cid}) was collected by GC"
                );
            }
        })
        .await;

    let all_node_cids = final_mst.collect_node_cids().await.unwrap();
    futures::stream::iter(all_node_cids)
        .for_each(|node_cid| {
            let storage = &storage;
            async move {
                let block = storage.get(&node_cid).await.unwrap();
                assert!(
                    block.is_some(),
                    "MST internal node {node_cid} was collected by GC after {cycles} cycles"
                );
            }
        })
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mst_survives_gc_with_split_batches_and_tiny_files() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = TranquilBlockStore::open(BlockStoreConfig {
        data_dir: dir.path().join("data"),
        index_dir: dir.path().join("index"),
        max_file_size: 4096,
        group_commit: GroupCommitConfig::default(),
        shard_count: 1,
    })
    .unwrap();
    let storage = Arc::new(store.clone());

    let record_count = 50u32;
    let records: Vec<(String, Vec<u8>)> = (0..record_count)
        .map(|i| {
            let key = format!("app.bsky.feed.post/{i:010}");
            let data = make_record(&format!("post {i} padding {}", "x".repeat(64)));
            (key, data)
        })
        .collect();

    let mut mst = Mst::new(storage.clone());
    let mut record_cids: BTreeMap<String, Cid> = BTreeMap::new();

    for (key, data) in &records {
        let cid = storage.put(data).await.unwrap();
        record_cids.insert(key.clone(), cid);
        mst = mst.add(key, cid).await.unwrap();
    }

    let mst_root_v1 = mst.persist().await.unwrap();

    let signing_key = test_signing_key();
    let did = Did::new("did:plc:testsplitbatch").unwrap();
    let mut ticker = Ticker::new();
    let rev1 = ticker.next(None);

    let commit_v1 = Commit::new_unsigned(did.clone(), mst_root_v1, rev1.clone(), None)
        .sign(&signing_key)
        .unwrap();
    let commit_v1_cbor = commit_v1.to_cbor().unwrap();
    let commit_v1_cid = compute_cid(&commit_v1_cbor);

    let empty_mst = Mst::new(storage.clone());
    let diff_v1 = empty_mst.diff(&mst).await.unwrap();
    let mut blocks_v1 = diff_v1.new_mst_blocks.clone();
    blocks_v1.insert(commit_v1_cid, Bytes::from(commit_v1_cbor));

    store
        .apply_commit(CommitData {
            cid: commit_v1_cid,
            rev: rev1.clone(),
            since: None,
            prev: None,
            data: mst_root_v1,
            prev_data: None,
            blocks: blocks_v1,
            relevant_blocks: BTreeMap::new(),
            deleted_cids: Vec::new(),
        })
        .await
        .unwrap();

    let mut prev_rev = rev1;
    let mut prev_cid = commit_v1_cid;
    let mut prev_root = mst_root_v1;

    for cycle in 0..10u32 {
        let delete_keys: Vec<String> = record_cids
            .keys()
            .enumerate()
            .filter(|(idx, _)| {
                let hash = (*idx as u32).wrapping_mul(2654435761).wrapping_add(cycle);
                hash % 4 == 0
            })
            .map(|(_, k)| k.clone())
            .collect();

        for key in &delete_keys {
            mst = mst.delete(key).await.unwrap();
            record_cids.remove(key);
        }

        let add_count = delete_keys.len().min(10);
        let new_records: Vec<(String, Vec<u8>)> = (0..add_count)
            .map(|i| {
                let key = format!("app.bsky.feed.post/cyc{cycle}_{i:06}");
                let data = make_record(&format!("cycle {cycle} record {i}"));
                (key, data)
            })
            .collect();

        for (key, data) in &new_records {
            let cid = storage.put(data).await.unwrap();
            record_cids.insert(key.clone(), cid);
            mst = mst.add(key, cid).await.unwrap();
        }

        let new_root = mst.persist().await.unwrap();

        let old_settled = Mst::load(storage.clone(), prev_root, None);
        let new_settled = Mst::load(storage.clone(), new_root, None);
        let (old_nodes, new_nodes, old_leaves, new_leaves) = tokio::try_join!(
            old_settled.collect_node_cids(),
            new_settled.collect_node_cids(),
            old_settled.leaves(),
            new_settled.leaves(),
        )
        .unwrap();
        let old_set: std::collections::BTreeSet<Cid> = old_nodes.into_iter().collect();
        let new_set: std::collections::BTreeSet<Cid> = new_nodes.into_iter().collect();
        let old_leaf_set: std::collections::BTreeSet<Cid> =
            old_leaves.iter().map(|(_, c)| *c).collect();
        let new_leaf_set: std::collections::BTreeSet<Cid> =
            new_leaves.iter().map(|(_, c)| *c).collect();
        let obsolete: Vec<Cid> = std::iter::once(prev_cid)
            .chain(old_set.difference(&new_set).copied())
            .chain(old_leaf_set.difference(&new_leaf_set).copied())
            .collect();

        let rev = ticker.next(Some(prev_rev.clone()));
        let commit = Commit::new_unsigned(did.clone(), new_root, rev.clone(), Some(prev_cid))
            .sign(&signing_key)
            .unwrap();
        let commit_cbor = commit.to_cbor().unwrap();
        let new_commit_cid = compute_cid(&commit_cbor);

        storage.put(&commit_cbor).await.unwrap();

        store.decrement_refs(&obsolete).await.unwrap();

        let gc_store = store.clone();
        tokio::task::spawn_blocking(move || {
            advance_epoch(&gc_store);
            std::thread::sleep(std::time::Duration::from_millis(10));
            advance_epoch(&gc_store);
            compact_all_sealed(&gc_store);
        })
        .await
        .unwrap();

        let verify_mst = Mst::load(storage.clone(), new_root, None);
        let verify_nodes = verify_mst
            .collect_node_cids()
            .await
            .unwrap_or_else(|e| panic!("cycle {cycle}: MST node walk failed after GC: {e}"));

        futures::stream::iter(verify_nodes)
            .for_each(|node_cid| {
                let storage = &storage;
                async move {
                    let block = storage.get(&node_cid).await.unwrap();
                    assert!(
                        block.is_some(),
                        "cycle {cycle}: MST node {node_cid} missing after GC"
                    );
                }
            })
            .await;

        prev_rev = rev;
        prev_cid = new_commit_cid;
        prev_root = new_root;
    }

    let final_mst = Mst::load(storage.clone(), prev_root, None);
    let final_leaves = final_mst.leaves().await.unwrap();
    assert_eq!(final_leaves.len(), record_cids.len());
}
