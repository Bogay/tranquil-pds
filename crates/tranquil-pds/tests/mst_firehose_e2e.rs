mod common;
mod firehose;

use std::collections::BTreeMap;
use std::io::Cursor;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use cid::Cid;
use common::*;
use firehose::{FirehoseConsumer, ParsedCommitFrame};
use iroh_car::CarReader;
use jacquard_common::smol_str::SmolStr;
use jacquard_repo::commit::Commit;
use jacquard_repo::mst::{Mst, VerifiedWriteOp};
use jacquard_repo::storage::{BlockStore, MemoryBlockStore};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tranquil_scopes::RepoAction;

async fn car_to_blocks(car_bytes: &[u8]) -> BTreeMap<Cid, Bytes> {
    let mut reader = CarReader::new(Cursor::new(car_bytes))
        .await
        .expect("parse CAR header");
    let mut blocks = BTreeMap::new();
    while let Ok(Some((cid, data))) = reader.next_block().await {
        blocks.insert(cid, Bytes::from(data));
    }
    blocks
}

fn op_to_verified(op: &firehose::ParsedRepoOp) -> Result<VerifiedWriteOp, String> {
    let key = SmolStr::new(&op.path);
    match op.action {
        RepoAction::Create => {
            let cid = op.cid.ok_or("create op missing cid")?;
            Ok(VerifiedWriteOp::Create { key, cid })
        }
        RepoAction::Update => {
            let cid = op.cid.ok_or("update op missing cid")?;
            let prev = op.prev.ok_or("update op missing prev")?;
            Ok(VerifiedWriteOp::Update { key, cid, prev })
        }
        RepoAction::Delete => {
            let prev = op.prev.ok_or("delete op missing prev")?;
            Ok(VerifiedWriteOp::Delete { key, prev })
        }
    }
}

async fn verify_frame_forward(frame: &ParsedCommitFrame) -> Result<(), String> {
    let prev_data = frame
        .prev_data
        .ok_or_else(|| "frame missing prev_data (v1.1 required)".to_string())?;

    let blocks = car_to_blocks(&frame.blocks).await;
    let storage = Arc::new(MemoryBlockStore::new_from_blocks(blocks));

    let commit_bytes = storage
        .get(&frame.commit)
        .await
        .map_err(|e| format!("get commit: {e:?}"))?
        .ok_or_else(|| format!("CAR missing commit {}", frame.commit))?;
    let commit = Commit::from_cbor(&commit_bytes).map_err(|e| format!("parse commit: {e:?}"))?;
    let expected = *commit.data();

    let mut mst = Mst::load(storage, prev_data, None);
    for op in &frame.ops {
        let path = &op.path;
        match op.action {
            RepoAction::Create | RepoAction::Update => {
                let cid = op.cid.ok_or_else(|| format!("{path}: op missing cid"))?;
                mst = mst
                    .add(path, cid)
                    .await
                    .map_err(|e| format!("forward {path}: {e:?}"))?;
            }
            RepoAction::Delete => {
                mst = mst
                    .delete(path)
                    .await
                    .map_err(|e| format!("forward delete {path}: {e:?}"))?;
            }
        }
    }
    let computed = mst.persist().await.map_err(|e| format!("persist: {e:?}"))?;
    if computed != expected {
        return Err(format!(
            "root mismatch expected={expected} computed={computed}"
        ));
    }
    Ok(())
}

async fn verify_frame_inverse(frame: &ParsedCommitFrame) -> Result<(), String> {
    let prev_data = frame
        .prev_data
        .ok_or_else(|| "frame missing prev_data (v1.1 required)".to_string())?;

    let blocks = car_to_blocks(&frame.blocks).await;
    let storage = Arc::new(MemoryBlockStore::new_from_blocks(blocks));

    let commit_bytes = storage
        .get(&frame.commit)
        .await
        .map_err(|e| format!("get commit: {e:?}"))?
        .ok_or_else(|| format!("CAR missing commit {}", frame.commit))?;
    let commit = Commit::from_cbor(&commit_bytes).map_err(|e| format!("parse commit: {e:?}"))?;
    let new_data = *commit.data();

    let mut mst = Mst::load(storage, new_data, None);
    for op in &frame.ops {
        let verified = op_to_verified(op)?;
        let inverted = mst
            .invert_op(verified.clone())
            .await
            .map_err(|e| format!("invert {verified:?}: {e:?}"))?;
        if !inverted {
            return Err(format!("op not invertible: {verified:?}"));
        }
    }
    let computed_prev = mst
        .get_pointer()
        .await
        .map_err(|e| format!("get_pointer: {e:?}"))?;
    if computed_prev != prev_data {
        return Err(format!(
            "inverse root mismatch expected={prev_data} computed={computed_prev}"
        ));
    }
    Ok(())
}

async fn create_record(client: &reqwest::Client, token: &str, did: &str, rkey: &str, text: &str) {
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

async fn put_record(client: &reqwest::Client, token: &str, did: &str, rkey: &str, text: &str) {
    let now = chrono::Utc::now().to_rfc3339();
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
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
        .expect("putRecord");
    assert_eq!(res.status(), StatusCode::OK);
}

async fn delete_record(client: &reqwest::Client, token: &str, did: &str, rkey: &str) {
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.deleteRecord",
            base_url().await
        ))
        .bearer_auth(token)
        .json(&json!({
            "repo": did,
            "collection": "app.bsky.feed.post",
            "rkey": rkey,
        }))
        .send()
        .await
        .expect("deleteRecord");
    assert_eq!(res.status(), StatusCode::OK);
}

async fn apply_writes_batch(client: &reqwest::Client, token: &str, did: &str, writes: Vec<Value>) {
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.applyWrites",
            base_url().await
        ))
        .bearer_auth(token)
        .json(&json!({ "repo": did, "writes": writes }))
        .send()
        .await
        .expect("applyWrites");
    assert_eq!(res.status(), StatusCode::OK);
}

fn rkey_for(i: usize) -> String {
    format!("3ke2e{:08}", i)
}

#[tokio::test]
async fn websocket_firehose_frames_pass_inductive_forward_and_inverse() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let repos = get_test_repos().await;
    let cursor = repos.repo.get_max_seq().await.unwrap().as_i64();
    let consumer = FirehoseConsumer::connect_with_cursor(app_port(), cursor).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let now = chrono::Utc::now().to_rfc3339();
    let seed: Vec<Value> = (0..120)
        .map(|i| {
            json!({
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "rkey": rkey_for(i),
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": format!("e2e {i}"),
                    "createdAt": now,
                }
            })
        })
        .collect();
    for chunk in seed.chunks(40) {
        apply_writes_batch(&client, &token, &did, chunk.to_vec()).await;
    }
    for i in (0..120).step_by(6) {
        put_record(&client, &token, &did, &rkey_for(i), &format!("upd {i}")).await;
    }
    for i in (2..120).step_by(11) {
        delete_record(&client, &token, &did, &rkey_for(i)).await;
    }
    create_record(&client, &token, &did, "3ke2efinal001", "final").await;

    let target_commits = 3 + 20 + 11 + 1;
    let frames = consumer
        .wait_for_commits(&did, target_commits, Duration::from_secs(90))
        .await;
    assert!(
        frames.len() >= target_commits,
        "expected {} commit frames, got {}",
        target_commits,
        frames.len()
    );

    let mut forward_failures = Vec::new();
    let mut inverse_failures = Vec::new();
    for frame in &frames {
        if frame.prev_data.is_none() {
            continue;
        }
        if frame.ops.is_empty() {
            continue;
        }
        if let Err(msg) = verify_frame_forward(frame).await {
            forward_failures.push(format!("seq={}: {msg}", frame.seq));
        }
        if let Err(msg) = verify_frame_inverse(frame).await {
            inverse_failures.push(format!("seq={}: {msg}", frame.seq));
        }
    }
    assert!(
        forward_failures.is_empty(),
        "forward verification failures:\n  - {}",
        forward_failures.join("\n  - ")
    );
    assert!(
        inverse_failures.is_empty(),
        "inverse verification failures:\n  - {}",
        inverse_failures.join("\n  - ")
    );
}

#[tokio::test]
async fn websocket_firehose_car_root_matches_commit_cid() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let repos = get_test_repos().await;
    let cursor = repos.repo.get_max_seq().await.unwrap().as_i64();
    let consumer = FirehoseConsumer::connect_with_cursor(app_port(), cursor).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    for i in 0..4 {
        create_record(&client, &token, &did, &rkey_for(i), "ck").await;
    }

    let frames = consumer
        .wait_for_commits(&did, 4, Duration::from_secs(10))
        .await;

    for frame in &frames {
        let mut reader = CarReader::new(Cursor::new(&frame.blocks))
            .await
            .expect("CAR header");
        let roots = reader.header().roots();
        assert_eq!(roots.len(), 1, "CAR must have exactly one root");
        assert_eq!(
            roots[0], frame.commit,
            "CAR root must equal frame commit CID"
        );
        let mut found = false;
        while let Ok(Some((cid, _))) = reader.next_block().await {
            if cid == frame.commit {
                found = true;
            }
        }
        assert!(found, "CAR body must contain commit block");
    }
}

#[tokio::test]
async fn websocket_firehose_resumption_from_cursor_yields_valid_frames() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let repos = get_test_repos().await;

    for i in 0..5 {
        create_record(&client, &token, &did, &rkey_for(i), "pre").await;
    }

    let resume_cursor = repos.repo.get_max_seq().await.unwrap().as_i64();

    for i in 5..12 {
        create_record(&client, &token, &did, &rkey_for(i), "post").await;
    }

    let consumer = FirehoseConsumer::connect_with_cursor(app_port(), resume_cursor).await;
    let frames = consumer
        .wait_for_commits(&did, 7, Duration::from_secs(20))
        .await;
    assert!(
        frames.len() >= 7,
        "expected 7+ frames after cursor resume, got {}",
        frames.len()
    );

    for frame in &frames {
        if frame.prev_data.is_none() || frame.ops.is_empty() {
            continue;
        }
        verify_frame_forward(frame)
            .await
            .unwrap_or_else(|e| panic!("resumed frame seq={} invalid: {e}", frame.seq));
    }
}

#[tokio::test]
async fn websocket_firehose_ops_include_prev_field_for_update_delete() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let repos = get_test_repos().await;
    let cursor = repos.repo.get_max_seq().await.unwrap().as_i64();
    let consumer = FirehoseConsumer::connect_with_cursor(app_port(), cursor).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    create_record(&client, &token, &did, "3ke2eprev01", "v1").await;
    put_record(&client, &token, &did, "3ke2eprev01", "v2").await;
    delete_record(&client, &token, &did, "3ke2eprev01").await;

    let frames = consumer
        .wait_for_commits(&did, 3, Duration::from_secs(10))
        .await;
    assert!(frames.len() >= 3);

    for frame in &frames {
        for op in &frame.ops {
            match op.action {
                RepoAction::Create => {
                    assert!(op.cid.is_some(), "create must have cid");
                    assert!(op.prev.is_none(), "create must not have prev");
                }
                RepoAction::Update => {
                    assert!(op.cid.is_some(), "update must have cid");
                    assert!(
                        op.prev.is_some(),
                        "v1.1 update must carry prev CID (seq={})",
                        frame.seq
                    );
                }
                RepoAction::Delete => {
                    assert!(op.cid.is_none(), "delete must have null cid");
                    assert!(
                        op.prev.is_some(),
                        "v1.1 delete must carry prev CID (seq={})",
                        frame.seq
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn websocket_firehose_rebuild_new_mst_from_car_matches_commit_data() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let repos = get_test_repos().await;
    let cursor = repos.repo.get_max_seq().await.unwrap().as_i64();
    let consumer = FirehoseConsumer::connect_with_cursor(app_port(), cursor).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let now = chrono::Utc::now().to_rfc3339();
    let writes: Vec<Value> = (0..30)
        .map(|i| {
            json!({
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "rkey": rkey_for(i),
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": format!("rb {i}"),
                    "createdAt": now,
                }
            })
        })
        .collect();
    apply_writes_batch(&client, &token, &did, writes).await;

    let frames = consumer
        .wait_for_commits(&did, 1, Duration::from_secs(10))
        .await;
    let last = frames.last().expect("frame");

    let blocks = car_to_blocks(&last.blocks).await;
    let storage = Arc::new(MemoryBlockStore::new_from_blocks(blocks));
    let commit_bytes = storage
        .get(&last.commit)
        .await
        .unwrap()
        .expect("commit block");
    let commit = Commit::from_cbor(&commit_bytes).unwrap();

    let new_root_cid = *commit.data();
    let mst = Mst::load(storage, new_root_cid, None);
    let rehydrated_cid = mst.get_pointer().await.expect("rebuild mst");
    assert_eq!(
        rehydrated_cid, new_root_cid,
        "MST loaded from CAR must yield same root as commit.data()"
    );

    for op in &last.ops {
        if op.action == RepoAction::Create {
            let expected_cid = op.cid.unwrap();
            let got = mst
                .get(&op.path)
                .await
                .expect("mst.get")
                .unwrap_or_else(|| panic!("key {} missing from rebuilt tree", op.path));
            assert_eq!(got, expected_cid, "record CID mismatch for {}", op.path);
            let _ = Cid::from_str(&expected_cid.to_string()).unwrap();
        }
    }
}
