mod common;
mod firehose;
mod helpers;

use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use cid::Cid;
use common::*;
use firehose::FirehoseConsumer;
use helpers::build_car_with_signature;
use iroh_car::CarReader;
use jacquard_repo::commit::Commit;
use jacquard_repo::mst::Mst;
use jacquard_repo::storage::{BlockStore, MemoryBlockStore};
use k256::ecdsa::SigningKey;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tranquil_db_traits::{EventBlocks, RepoEventType, SequenceNumber, SequencedEvent};
use tranquil_scopes::RepoAction;
use tranquil_types::Did;

async fn car_to_blocks(car_bytes: &[u8]) -> (Vec<Cid>, BTreeMap<Cid, Bytes>) {
    let mut reader = CarReader::new(Cursor::new(car_bytes))
        .await
        .expect("parse CAR");
    let roots = reader.header().roots().to_vec();
    let mut blocks = BTreeMap::new();
    while let Ok(Some((cid, data))) = reader.next_block().await {
        blocks.insert(cid, Bytes::from(data));
    }
    (roots, blocks)
}

async fn create_post(client: &reqwest::Client, token: &str, did: &str, rkey: &str, text: &str) {
    let now = chrono::Utc::now().to_rfc3339();
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            base_url().await
        ))
        .bearer_auth(token)
        .json(&json!({
            "repo": did,
            "collection": "app.bsky.feed.post",
            "rkey": rkey,
            "record": {
                "$type": "app.bsky.feed.post",
                "text": text,
                "createdAt": now,
            }
        }))
        .send()
        .await
        .expect("createRecord");
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn getrepo_car_roundtrips_mst_structure_and_records() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let expected_records: Vec<(String, String)> = (0..20)
        .map(|i| {
            let rkey = format!("3krtp{:08}", i);
            let text = format!("roundtrip record {i}");
            (rkey, text)
        })
        .collect();
    for (rkey, text) in &expected_records {
        create_post(&client, &token, &did, rkey, text).await;
    }

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getRepo",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("getRepo");
    assert_eq!(res.status(), StatusCode::OK);
    let car_bytes = res.bytes().await.unwrap();

    let (roots, block_map) = car_to_blocks(&car_bytes).await;
    assert_eq!(roots.len(), 1, "CAR must have exactly one root");
    let commit_cid = roots[0];
    let storage = Arc::new(MemoryBlockStore::new_from_blocks(block_map));

    let commit_bytes = storage
        .get(&commit_cid)
        .await
        .unwrap()
        .expect("CAR contains commit block");
    let commit = Commit::from_cbor(&commit_bytes).expect("parse commit");
    let data_cid = *commit.data();

    let mst = Mst::load(storage.clone(), data_cid, None);
    let loaded_root = mst.get_pointer().await.expect("load root");
    assert_eq!(loaded_root, data_cid, "loaded MST pointer == commit.data()");

    for (rkey, _) in &expected_records {
        let path = format!("app.bsky.feed.post/{rkey}");
        let leaf = mst
            .get(&path)
            .await
            .expect("mst.get")
            .unwrap_or_else(|| panic!("record {path} missing from exported MST"));
        let leaf_bytes = storage
            .get(&leaf)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("record block {leaf} missing from CAR"));
        assert!(!leaf_bytes.is_empty(), "record bytes empty");
    }
}

#[tokio::test]
async fn concurrent_swap_commit_writes_serialize() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    create_post(&client, &token, &did, "3kswap00000001", "anchor").await;

    let latest_res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getLatestCommit",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("getLatestCommit");
    assert_eq!(latest_res.status(), StatusCode::OK);
    let latest: Value = latest_res.json().await.unwrap();
    let swap_cid = latest["cid"].as_str().unwrap().to_string();

    let now = chrono::Utc::now().to_rfc3339();
    let payload_a = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": "3kswap00000002",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "writer A",
            "createdAt": now,
        },
        "swapCommit": swap_cid,
    });
    let payload_b = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": "3kswap00000003",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "writer B",
            "createdAt": now,
        },
        "swapCommit": swap_cid,
    });

    let base = base_url().await;
    let (res_a, res_b) = tokio::join!(
        client
            .post(format!("{base}/xrpc/com.atproto.repo.putRecord"))
            .bearer_auth(&token)
            .json(&payload_a)
            .send(),
        client
            .post(format!("{base}/xrpc/com.atproto.repo.putRecord"))
            .bearer_auth(&token)
            .json(&payload_b)
            .send(),
    );
    let status_a = res_a.expect("A send").status();
    let status_b = res_b.expect("B send").status();

    let ok_a = status_a == StatusCode::OK;
    let ok_b = status_b == StatusCode::OK;
    assert!(
        ok_a ^ ok_b,
        "exactly one swap_commit write must succeed: status_a={status_a}, status_b={status_b}"
    );
}

#[tokio::test]
async fn imported_repo_emits_commit_event_with_valid_car() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let (car_bytes, _car_root_cid) = build_car_with_signature(&did, &signing_key);

    let import_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.importRepo",
            base_url().await
        ))
        .bearer_auth(&token)
        .header("Content-Type", "application/vnd.ipld.car")
        .body(car_bytes)
        .send()
        .await
        .expect("importRepo");
    assert_eq!(
        import_res.status(),
        StatusCode::OK,
        "import failed: {:?}",
        import_res.text().await.unwrap_or_default()
    );

    let repos = get_test_repos().await;
    let typed_did = Did::new(did.clone()).unwrap();
    let events = repos
        .repo
        .get_events_since_seq(SequenceNumber::ZERO, None)
        .await
        .expect("events");
    let our: Vec<&SequencedEvent> = events
        .iter()
        .filter(|e| e.did == typed_did && e.event_type == RepoEventType::Commit)
        .collect();
    let last = our.last().expect("at least one commit event after import");

    let inline = match last.blocks.as_ref().expect("blocks present") {
        EventBlocks::Inline(v) => v,
        _ => panic!("expected inline blocks"),
    };
    assert!(
        !inline.is_empty(),
        "import event inline blocks must not be empty"
    );

    let have_commit = inline.iter().any(|b| {
        let cid = Cid::read_bytes(b.cid_bytes.as_slice()).unwrap();
        last.commit_cid
            .as_ref()
            .and_then(|c| c.to_cid())
            .map(|commit_cid| cid == commit_cid)
            .unwrap_or(false)
    });
    assert!(have_commit, "import event CAR must include commit block");
}

#[tokio::test]
async fn firehose_commit_block_bytes_roundtrip_to_same_cid() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let repos = get_test_repos().await;
    let cursor = repos.repo.get_max_seq().await.unwrap().as_i64();
    let consumer = FirehoseConsumer::connect_with_cursor(app_port(), cursor).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    create_post(&client, &token, &did, "3krt001", "round-trip me").await;
    let frames = consumer
        .wait_for_commits(&did, 1, Duration::from_secs(10))
        .await;
    let frame = frames.last().expect("frame");

    let (_, block_map) = car_to_blocks(&frame.blocks).await;
    use sha2::{Digest, Sha256};
    for (cid, bytes) in &block_map {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let hash = hasher.finalize();
        let mh = multihash::Multihash::wrap(0x12, hash.as_slice()).expect("wrap");
        let recomputed = Cid::new_v1(cid.codec(), mh);
        assert_eq!(
            recomputed, *cid,
            "CAR block {cid} bytes do not hash back to same CID"
        );
    }
}

#[tokio::test]
async fn firehose_commit_car_contains_new_record_bytes_for_every_create() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let repos = get_test_repos().await;
    let cursor = repos.repo.get_max_seq().await.unwrap().as_i64();
    let consumer = FirehoseConsumer::connect_with_cursor(app_port(), cursor).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let now = chrono::Utc::now().to_rfc3339();
    let writes: Vec<Value> = (0..8)
        .map(|i| {
            json!({
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "rkey": format!("3krec{:08}", i),
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": format!("rec {i}"),
                    "createdAt": now,
                }
            })
        })
        .collect();
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.applyWrites",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&json!({ "repo": did, "writes": writes }))
        .send()
        .await
        .expect("applyWrites");
    assert_eq!(res.status(), StatusCode::OK);

    let frames = consumer
        .wait_for_commits(&did, 1, Duration::from_secs(10))
        .await;
    let frame = frames.last().expect("frame");

    let (_, block_map) = car_to_blocks(&frame.blocks).await;
    for op in &frame.ops {
        if op.action == RepoAction::Create {
            let cid = op.cid.expect("create cid");
            assert!(
                block_map.contains_key(&cid),
                "record CID {cid} for path {} missing from CAR",
                op.path
            );
        }
    }
}
