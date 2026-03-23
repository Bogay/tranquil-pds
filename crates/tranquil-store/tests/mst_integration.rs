use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use cid::Cid;
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
