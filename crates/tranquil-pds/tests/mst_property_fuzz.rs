mod common;
mod mst_verify;

use std::collections::HashMap;
use std::str::FromStr;

use cid::Cid;
use common::*;
use jacquard_common::smol_str::SmolStr;
use jacquard_repo::commit::Commit;
use jacquard_repo::mst::{Mst, VerifiedWriteOp};
use jacquard_repo::storage::BlockStore;
use mst_verify::{extract_event_blocks, inline_to_store};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tranquil_db_traits::{RepoEventType, SequenceNumber, SequencedEvent};
use tranquil_types::Did;

const COLLECTIONS: &[&str] = &[
    "app.bsky.feed.post",
    "app.bsky.feed.like",
    "app.bsky.graph.follow",
    "app.bsky.feed.repost",
];

#[derive(Copy, Clone, Debug)]
enum FuzzOp {
    Create,
    Update,
    Delete,
}

fn pick_op(rng: &mut StdRng, have_keys: bool) -> FuzzOp {
    match (have_keys, rng.gen_range(0..10)) {
        (false, _) => FuzzOp::Create,
        (_, 0..=5) => FuzzOp::Create,
        (_, 6..=7) => FuzzOp::Update,
        _ => FuzzOp::Delete,
    }
}

fn random_rkey(rng: &mut StdRng) -> String {
    let tid_char_pool = b"234567abcdefghijklmnopqrstuvwxyz";
    let mut out = Vec::with_capacity(13);
    (0..13).for_each(|_| {
        let c = tid_char_pool[rng.gen_range(0..tid_char_pool.len())];
        out.push(c);
    });
    String::from_utf8(out).unwrap()
}

fn random_collection(rng: &mut StdRng) -> &'static str {
    COLLECTIONS[rng.gen_range(0..COLLECTIONS.len())]
}

fn record_for_collection(col: &str, text: &str, now: &str) -> Value {
    match col {
        "app.bsky.feed.post" | "app.bsky.feed.repost" | "app.bsky.feed.like" => json!({
            "$type": col,
            "text": text,
            "createdAt": now,
        }),
        _ => json!({
            "$type": col,
            "subject": format!("did:plc:synthetic{text}"),
            "createdAt": now,
        }),
    }
}

async fn verify_commit_forward_and_inverse(event: &SequencedEvent) -> Result<(), String> {
    let prev_data = event
        .prev_data_cid
        .as_ref()
        .and_then(|c| c.to_cid())
        .ok_or("no prev_data_cid")?;
    let commit_cid = event
        .commit_cid
        .as_ref()
        .and_then(|c| c.to_cid())
        .ok_or("no commit_cid")?;
    let inline = extract_event_blocks(event)?;
    let ops = event
        .ops
        .as_ref()
        .and_then(|v| v.as_array())
        .ok_or("ops not array")?;

    let storage = inline_to_store(inline);
    let commit_bytes = storage
        .get(&commit_cid)
        .await
        .map_err(|e| format!("get commit: {e:?}"))?
        .ok_or("missing commit block")?;
    let commit = Commit::from_cbor(&commit_bytes).map_err(|e| format!("parse commit: {e:?}"))?;
    let new_data = *commit.data();

    let mut forward = Mst::load(storage.clone(), prev_data, None);
    for op in ops {
        let action = op["action"].as_str().ok_or("op.action")?;
        let path = op["path"].as_str().ok_or("op.path")?;
        match action {
            "create" | "update" => {
                let cid = Cid::from_str(op["cid"].as_str().ok_or("op.cid")?)
                    .map_err(|e| format!("{e:?}"))?;
                forward = forward
                    .add(path, cid)
                    .await
                    .map_err(|e| format!("fwd add {path}: {e:?}"))?;
            }
            "delete" => {
                forward = forward
                    .delete(path)
                    .await
                    .map_err(|e| format!("fwd delete {path}: {e:?}"))?;
            }
            other => return Err(format!("unknown action {other}")),
        }
    }
    let got = forward
        .persist()
        .await
        .map_err(|e| format!("persist: {e:?}"))?;
    if got != new_data {
        return Err(format!("forward root mismatch exp={new_data} got={got}"));
    }

    let mut inverse = Mst::load(storage, new_data, None);
    for op in ops {
        let action = op["action"].as_str().ok_or("op.action")?;
        let path = op["path"].as_str().ok_or("op.path")?;
        let key = SmolStr::new(path);
        let verified = match action {
            "create" => {
                let cid = Cid::from_str(op["cid"].as_str().ok_or("op.cid")?)
                    .map_err(|e| format!("{e:?}"))?;
                VerifiedWriteOp::Create { key, cid }
            }
            "update" => {
                let cid = Cid::from_str(op["cid"].as_str().ok_or("op.cid")?)
                    .map_err(|e| format!("{e:?}"))?;
                let prev = Cid::from_str(op["prev"].as_str().ok_or("op.prev")?)
                    .map_err(|e| format!("{e:?}"))?;
                VerifiedWriteOp::Update { key, cid, prev }
            }
            "delete" => {
                let prev = Cid::from_str(op["prev"].as_str().ok_or("op.prev")?)
                    .map_err(|e| format!("{e:?}"))?;
                VerifiedWriteOp::Delete { key, prev }
            }
            other => return Err(format!("unknown action {other}")),
        };
        let inverted = inverse
            .invert_op(verified.clone())
            .await
            .map_err(|e| format!("invert {verified:?}: {e:?}"))?;
        if !inverted {
            return Err(format!("op not invertible: {verified:?}"));
        }
    }
    let got_prev = inverse
        .get_pointer()
        .await
        .map_err(|e| format!("get_pointer: {e:?}"))?;
    if got_prev != prev_data {
        return Err(format!(
            "inverse root mismatch exp={prev_data} got={got_prev}"
        ));
    }
    Ok(())
}

async fn fuzz_run_with_seed(seed: u64, steps: usize) -> Vec<String> {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let mut rng = StdRng::seed_from_u64(seed);

    let mut live_keys: HashMap<String, String> = HashMap::new();

    for step in 0..steps {
        let now = chrono::Utc::now().to_rfc3339();
        let op = pick_op(&mut rng, !live_keys.is_empty());
        match op {
            FuzzOp::Create => {
                let col = random_collection(&mut rng);
                let rkey = random_rkey(&mut rng);
                let path = format!("{col}/{rkey}");
                if live_keys.contains_key(&path) {
                    continue;
                }
                let record = record_for_collection(col, &format!("s{seed}-n{step}"), &now);
                let res = client
                    .post(format!(
                        "{}/xrpc/com.atproto.repo.createRecord",
                        base_url().await
                    ))
                    .bearer_auth(&token)
                    .json(&json!({
                        "repo": did,
                        "collection": col,
                        "rkey": rkey,
                        "record": record,
                    }))
                    .send()
                    .await
                    .expect("createRecord");
                if res.status() == StatusCode::OK {
                    live_keys.insert(path, col.to_string());
                }
            }
            FuzzOp::Update => {
                let keys: Vec<&String> = live_keys.keys().collect();
                if keys.is_empty() {
                    continue;
                }
                let path = keys[rng.gen_range(0..keys.len())].clone();
                let col = live_keys.get(&path).unwrap().clone();
                let rkey = path.split('/').nth(1).unwrap().to_string();
                let record = record_for_collection(&col, &format!("s{seed}-u{step}"), &now);
                let res = client
                    .post(format!(
                        "{}/xrpc/com.atproto.repo.putRecord",
                        base_url().await
                    ))
                    .bearer_auth(&token)
                    .json(&json!({
                        "repo": did,
                        "collection": col,
                        "rkey": rkey,
                        "record": record,
                    }))
                    .send()
                    .await
                    .expect("putRecord");
                assert_eq!(res.status(), StatusCode::OK, "putRecord failed");
            }
            FuzzOp::Delete => {
                let keys: Vec<String> = live_keys.keys().cloned().collect();
                if keys.is_empty() {
                    continue;
                }
                let path = keys[rng.gen_range(0..keys.len())].clone();
                let col = live_keys.get(&path).unwrap().clone();
                let rkey = path.split('/').nth(1).unwrap().to_string();
                let res = client
                    .post(format!(
                        "{}/xrpc/com.atproto.repo.deleteRecord",
                        base_url().await
                    ))
                    .bearer_auth(&token)
                    .json(&json!({
                        "repo": did,
                        "collection": col,
                        "rkey": rkey,
                    }))
                    .send()
                    .await
                    .expect("deleteRecord");
                if res.status() == StatusCode::OK {
                    live_keys.remove(&path);
                }
            }
        }
    }

    let repos = get_test_repos().await;
    let typed_did = Did::new(did.clone()).unwrap();
    let events = repos
        .repo
        .get_events_since_seq(SequenceNumber::ZERO, None)
        .await
        .expect("get_events_since_seq");

    let our: Vec<SequencedEvent> = events
        .into_iter()
        .filter(|e| {
            e.did == typed_did
                && e.event_type == RepoEventType::Commit
                && e.prev_data_cid.is_some()
                && e.ops
                    .as_ref()
                    .and_then(|v| v.as_array())
                    .is_some_and(|a| !a.is_empty())
        })
        .collect();

    let mut failures = Vec::new();
    for event in &our {
        if let Err(msg) = verify_commit_forward_and_inverse(event).await {
            failures.push(format!(
                "seed={seed} seq={} ops={:?}: {msg}",
                event.seq.as_i64(),
                event
                    .ops
                    .as_ref()
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
            ));
        }
    }
    failures
}

#[tokio::test]
async fn mst_property_fuzz_seed_1() {
    let failures = fuzz_run_with_seed(1, 150).await;
    assert!(
        failures.is_empty(),
        "fuzz seed=1 found {} invalid commits:\n  - {}",
        failures.len(),
        failures.join("\n  - ")
    );
}

#[tokio::test]
async fn mst_property_fuzz_seed_42() {
    let failures = fuzz_run_with_seed(42, 150).await;
    assert!(
        failures.is_empty(),
        "fuzz seed=42 found {} invalid commits:\n  - {}",
        failures.len(),
        failures.join("\n  - ")
    );
}

#[tokio::test]
async fn mst_property_fuzz_seed_9001() {
    let failures = fuzz_run_with_seed(9001, 150).await;
    assert!(
        failures.is_empty(),
        "fuzz seed=9001 found {} invalid commits:\n  - {}",
        failures.len(),
        failures.join("\n  - ")
    );
}

#[tokio::test]
async fn mst_property_fuzz_deep_tree_seed_7() {
    let failures = fuzz_run_with_seed(7, 400).await;
    assert!(
        failures.is_empty(),
        "fuzz deep seed=7 found {} invalid commits:\n  - {}",
        failures.len(),
        failures.join("\n  - ")
    );
}
