mod common;
mod firehose;

use cid::Cid;
use common::*;
use firehose::{FirehoseConsumer, ParsedCommitFrame};
use iroh_car::CarReader;
use jacquard_repo::commit::Commit;
use reqwest::StatusCode;
use serde_json::{Value, json};
use std::io::Cursor;
use std::str::FromStr;
use tranquil_scopes::RepoAction;

mod helpers;

async fn create_post_record(client: &reqwest::Client, token: &str, did: &str, text: &str) -> Value {
    let payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": text,
            "createdAt": chrono::Utc::now().to_rfc3339(),
        }
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            base_url().await
        ))
        .bearer_auth(token)
        .json(&payload)
        .send()
        .await
        .expect("Failed to create post");
    assert_eq!(res.status(), StatusCode::OK);
    res.json().await.expect("Invalid JSON from createRecord")
}

async fn get_latest_commit(client: &reqwest::Client, token: &str, did: &str) -> Value {
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getLatestCommit?did={}",
            base_url().await,
            did
        ))
        .bearer_auth(token)
        .send()
        .await
        .expect("Failed to get latest commit");
    assert_eq!(res.status(), StatusCode::OK);
    res.json().await.expect("Invalid JSON from getLatestCommit")
}

#[tokio::test]
async fn test_create_record_cid_matches_firehose() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let repos = get_test_repos().await;
    let cursor = repos.repo.get_max_seq().await.unwrap().as_i64();
    let consumer = FirehoseConsumer::connect_with_cursor(app_port(), cursor).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let api_response = create_post_record(&client, &token, &did, "CID match test").await;
    let api_commit_cid = api_response["commit"]["cid"].as_str().unwrap();
    let api_commit_rev = api_response["commit"]["rev"].as_str().unwrap();
    let api_record_cid = api_response["cid"].as_str().unwrap();

    let frames = consumer
        .wait_for_commits(&did, 1, std::time::Duration::from_secs(10))
        .await;
    let frame = &frames[0];

    assert_eq!(
        api_commit_cid,
        frame.commit.to_string(),
        "API commit CID must match firehose commit CID"
    );
    assert_eq!(
        api_commit_rev, frame.rev,
        "API commit rev must match firehose rev"
    );
    assert_eq!(frame.ops.len(), 1, "Expected exactly 1 op");
    assert_eq!(
        api_record_cid,
        frame.ops[0].cid.unwrap().to_string(),
        "API record CID must match firehose op CID"
    );
    assert_eq!(frame.ops[0].action, RepoAction::Create);
    assert!(frame.ops[0].prev.is_none(), "Create op must have no prev");

    let latest = get_latest_commit(&client, &token, &did).await;
    assert_eq!(
        latest["cid"].as_str().unwrap(),
        api_commit_cid,
        "getLatestCommit CID must match"
    );
    assert_eq!(
        latest["rev"].as_str().unwrap(),
        api_commit_rev,
        "getLatestCommit rev must match"
    );
}

#[tokio::test]
async fn test_update_record_prev_matches_old_cid() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let v1_payload = json!({
        "repo": did,
        "collection": "app.bsky.actor.profile",
        "rkey": "self",
        "record": {
            "$type": "app.bsky.actor.profile",
            "displayName": "Profile v1",
        }
    });
    let v1_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&v1_payload)
        .send()
        .await
        .expect("Failed to create profile v1");
    assert_eq!(v1_res.status(), StatusCode::OK);
    let v1_body: Value = v1_res.json().await.unwrap();
    let v1_cid_str = v1_body["cid"].as_str().unwrap();
    let v1_cid = Cid::from_str(v1_cid_str).unwrap();

    let repos = get_test_repos().await;
    let cursor = repos.repo.get_max_seq().await.unwrap().as_i64();
    let consumer = FirehoseConsumer::connect_with_cursor(app_port(), cursor).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let v2_payload = json!({
        "repo": did,
        "collection": "app.bsky.actor.profile",
        "rkey": "self",
        "record": {
            "$type": "app.bsky.actor.profile",
            "displayName": "Profile v2",
        }
    });
    let v2_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&v2_payload)
        .send()
        .await
        .expect("Failed to update profile v2");
    assert_eq!(v2_res.status(), StatusCode::OK);
    let v2_body: Value = v2_res.json().await.unwrap();
    let v2_cid_str = v2_body["cid"].as_str().unwrap();
    let v2_cid = Cid::from_str(v2_cid_str).unwrap();

    let frames = consumer
        .wait_for_commits(&did, 1, std::time::Duration::from_secs(10))
        .await;
    let frame = &frames[0];

    let profile_op = frame
        .ops
        .iter()
        .find(|op| op.path.contains("app.bsky.actor.profile"))
        .expect("No profile op found");

    assert_eq!(profile_op.action, RepoAction::Update);
    assert_eq!(
        profile_op.prev,
        Some(v1_cid),
        "Update op.prev must be the old CID"
    );
    assert_eq!(
        profile_op.cid,
        Some(v2_cid),
        "Update op.cid must be the new CID"
    );
    assert!(
        frame.prev_data.is_some(),
        "Update commit must have prevData"
    );
}

#[tokio::test]
async fn test_delete_record_prev_set_cid_none() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let create_body = create_post_record(&client, &token, &did, "To be deleted").await;
    let record_cid = Cid::from_str(create_body["cid"].as_str().unwrap()).unwrap();
    let uri = create_body["uri"].as_str().unwrap();
    let parts: Vec<&str> = uri.split('/').collect();
    let collection = parts[parts.len() - 2];
    let rkey = parts[parts.len() - 1];

    let repos = get_test_repos().await;
    let cursor = repos.repo.get_max_seq().await.unwrap().as_i64();
    let consumer = FirehoseConsumer::connect_with_cursor(app_port(), cursor).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let delete_payload = json!({
        "repo": did,
        "collection": collection,
        "rkey": rkey,
    });
    let del_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.deleteRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to delete record");
    assert_eq!(del_res.status(), StatusCode::OK);

    let frames = consumer
        .wait_for_commits(&did, 1, std::time::Duration::from_secs(10))
        .await;
    let frame = &frames[0];

    assert_eq!(frame.ops.len(), 1, "Expected exactly 1 delete op");
    let op = &frame.ops[0];
    assert_eq!(op.action, RepoAction::Delete);
    assert!(op.cid.is_none(), "Delete op.cid must be None");
    assert_eq!(
        op.prev,
        Some(record_cid),
        "Delete op.prev must be the original CID"
    );
}

#[tokio::test]
async fn test_five_record_commit_chain_integrity() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let repos = get_test_repos().await;
    let cursor = repos.repo.get_max_seq().await.unwrap().as_i64();
    let consumer = FirehoseConsumer::connect_with_cursor(app_port(), cursor).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let texts = [
        "Chain post 0",
        "Chain post 1",
        "Chain post 2",
        "Chain post 3",
        "Chain post 4",
    ];
    for text in &texts {
        create_post_record(&client, &token, &did, text).await;
    }

    let mut frames = consumer
        .wait_for_commits(&did, 5, std::time::Duration::from_secs(15))
        .await;
    frames.sort_by_key(|f| f.seq);

    let revs: Vec<&str> = frames.iter().map(|f| f.rev.as_str()).collect();
    let unique_revs: std::collections::HashSet<&&str> = revs.iter().collect();
    assert_eq!(
        unique_revs.len(),
        5,
        "All rev values must be distinct, got: {:?}",
        revs
    );

    let seqs: Vec<i64> = frames.iter().map(|f| f.seq).collect();
    seqs.windows(2).for_each(|pair| {
        assert!(
            pair[1] > pair[0],
            "Seq values must be strictly monotonically increasing: {} <= {}",
            pair[1],
            pair[0]
        );
    });

    frames.iter().enumerate().skip(1).for_each(|(i, frame)| {
        assert_eq!(
            frame.since.as_deref(),
            Some(frames[i - 1].rev.as_str()),
            "Frame {} since must equal frame {} rev",
            i,
            i - 1
        );
    });

    let latest = get_latest_commit(&client, &token, &did).await;
    let final_frame = frames.last().unwrap();
    assert_eq!(
        latest["cid"].as_str().unwrap(),
        final_frame.commit.to_string(),
        "getLatestCommit CID must match final frame"
    );
    assert_eq!(
        latest["rev"].as_str().unwrap(),
        final_frame.rev,
        "getLatestCommit rev must match final frame"
    );
}

#[tokio::test]
async fn test_apply_writes_single_commit_multiple_ops() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let repos = get_test_repos().await;
    let cursor = repos.repo.get_max_seq().await.unwrap().as_i64();
    let consumer = FirehoseConsumer::connect_with_cursor(app_port(), cursor).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let now = chrono::Utc::now().to_rfc3339();
    let writes: Vec<Value> = (0..3)
        .map(|i| {
            json!({
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": format!("Batch post {}", i),
                    "createdAt": now,
                }
            })
        })
        .collect();

    let payload = json!({
        "repo": did,
        "writes": writes,
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.applyWrites",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&payload)
        .send()
        .await
        .expect("Failed to applyWrites");
    assert_eq!(res.status(), StatusCode::OK);
    let api_body: Value = res.json().await.unwrap();
    let api_results = api_body["results"].as_array().expect("No results array");
    assert_eq!(api_results.len(), 3, "Expected 3 results from applyWrites");

    let frames = consumer
        .wait_for_commits(&did, 1, std::time::Duration::from_secs(10))
        .await;
    assert_eq!(
        frames.len(),
        1,
        "applyWrites should produce exactly 1 commit"
    );
    let frame = &frames[0];
    assert_eq!(frame.ops.len(), 3, "Commit should contain 3 ops");

    frame.ops.iter().for_each(|op| {
        assert_eq!(op.action, RepoAction::Create, "All ops should be Create");
    });

    api_results.iter().enumerate().for_each(|(i, result)| {
        let api_cid = result["cid"].as_str().expect("No cid in result");
        let frame_cid = frame.ops[i].cid.expect("No cid in op").to_string();
        assert_eq!(
            api_cid, frame_cid,
            "API result[{}] CID must match firehose op[{}] CID",
            i, i
        );
    });
}

#[tokio::test]
async fn test_firehose_commit_signature_verification() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let key_bytes = helpers::get_user_signing_key(&did)
        .await
        .expect("Failed to get signing key");
    let signing_key =
        k256::ecdsa::SigningKey::from_slice(&key_bytes).expect("Invalid signing key bytes");
    let pubkey_bytes = signing_key.verifying_key().to_encoded_point(true);
    let pubkey = jacquard_common::types::crypto::PublicKey {
        codec: jacquard_common::types::crypto::KeyCodec::Secp256k1,
        bytes: std::borrow::Cow::Owned(pubkey_bytes.as_bytes().to_vec()),
    };

    let repos = get_test_repos().await;
    let cursor = repos.repo.get_max_seq().await.unwrap().as_i64();
    let consumer = FirehoseConsumer::connect_with_cursor(app_port(), cursor).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let _api_response =
        create_post_record(&client, &token, &did, "Signature verification test").await;

    let frames = consumer
        .wait_for_commits(&did, 1, std::time::Duration::from_secs(10))
        .await;
    let frame = &frames[0];

    let mut car_reader = CarReader::new(Cursor::new(&frame.blocks))
        .await
        .expect("Failed to parse CAR");
    let mut blocks = std::collections::HashMap::new();
    while let Ok(Some((cid, data))) = car_reader.next_block().await {
        blocks.insert(cid, data);
    }

    let commit_block = blocks
        .get(&frame.commit)
        .expect("Commit block not found in CAR");

    let commit = Commit::from_cbor(commit_block).expect("Failed to parse commit from CBOR");

    commit
        .verify(&pubkey)
        .expect("Commit signature verification failed");

    assert_eq!(
        commit.rev().to_string(),
        frame.rev,
        "Commit rev must match frame rev"
    );
    assert_eq!(
        commit.did().as_str(),
        did,
        "Commit DID must match account DID"
    );
}

#[tokio::test]
async fn test_cursor_backfill_completeness() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let repos = get_test_repos().await;
    let baseline_seq = repos.repo.get_max_seq().await.unwrap().as_i64();

    let mut expected_cids: Vec<String> = Vec::with_capacity(5);
    let texts = [
        "Backfill 0",
        "Backfill 1",
        "Backfill 2",
        "Backfill 3",
        "Backfill 4",
    ];
    for text in &texts {
        let body = create_post_record(&client, &token, &did, text).await;
        expected_cids.push(body["commit"]["cid"].as_str().unwrap().to_string());
    }

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let consumer = FirehoseConsumer::connect_with_cursor(app_port(), baseline_seq).await;

    let frames = consumer
        .wait_for_commits(&did, 5, std::time::Duration::from_secs(15))
        .await;

    let mut sorted_frames: Vec<ParsedCommitFrame> = frames;
    sorted_frames.sort_by_key(|f| f.seq);

    let received_cids: Vec<String> = sorted_frames.iter().map(|f| f.commit.to_string()).collect();

    expected_cids.iter().for_each(|expected| {
        assert!(
            received_cids.contains(expected),
            "Missing commit {} in backfill",
            expected
        );
    });

    let seqs: Vec<i64> = sorted_frames.iter().map(|f| f.seq).collect();
    let unique_seqs: std::collections::HashSet<&i64> = seqs.iter().collect();
    assert_eq!(
        unique_seqs.len(),
        seqs.len(),
        "No duplicate seq values allowed in backfill"
    );
}

#[tokio::test]
async fn test_multi_account_seq_interleaving() {
    let client = client();
    let (alice_token, alice_did) = create_account_and_login(&client).await;
    let (bob_token, bob_did) = create_account_and_login(&client).await;

    let repos = get_test_repos().await;
    let cursor = repos.repo.get_max_seq().await.unwrap().as_i64();
    let consumer = FirehoseConsumer::connect_with_cursor(app_port(), cursor).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let _a1 = create_post_record(&client, &alice_token, &alice_did, "Alice post 1").await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let _b1 = create_post_record(&client, &bob_token, &bob_did, "Bob post 1").await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let _a2 = create_post_record(&client, &alice_token, &alice_did, "Alice post 2").await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let _b2 = create_post_record(&client, &bob_token, &bob_did, "Bob post 2").await;

    let alice_frames = consumer
        .wait_for_commits(&alice_did, 2, std::time::Duration::from_secs(10))
        .await;
    let bob_frames = consumer
        .wait_for_commits(&bob_did, 2, std::time::Duration::from_secs(10))
        .await;

    let mut all_commits = consumer.all_commits();
    all_commits.sort_by_key(|f| f.seq);

    let global_seqs: Vec<i64> = all_commits.iter().map(|f| f.seq).collect();
    global_seqs.windows(2).for_each(|pair| {
        assert!(
            pair[1] > pair[0],
            "Global seq must be strictly monotonically increasing: {} <= {}",
            pair[1],
            pair[0]
        );
    });

    let mut alice_sorted: Vec<ParsedCommitFrame> = alice_frames;
    alice_sorted.sort_by_key(|f| f.seq);
    assert_eq!(alice_sorted.len(), 2);
    assert!(
        alice_sorted[1].since.is_some(),
        "Alice's second commit must have since"
    );
    assert_eq!(
        alice_sorted[1].since.as_deref(),
        Some(alice_sorted[0].rev.as_str()),
        "Alice's since chain must be self-consistent"
    );

    let mut bob_sorted: Vec<ParsedCommitFrame> = bob_frames;
    bob_sorted.sort_by_key(|f| f.seq);
    assert_eq!(bob_sorted.len(), 2);
    assert!(
        bob_sorted[1].since.is_some(),
        "Bob's second commit must have since"
    );
    assert_eq!(
        bob_sorted[1].since.as_deref(),
        Some(bob_sorted[0].rev.as_str()),
        "Bob's since chain must be self-consistent"
    );
}
