mod common;
mod mst_verify;

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

use cid::Cid;
use common::*;
use jacquard_common::smol_str::SmolStr;
use jacquard_repo::commit::Commit;
use jacquard_repo::mst::{Mst, VerifiedWriteOp};
use jacquard_repo::storage::{BlockStore, MemoryBlockStore};
use mst_verify::{extract_event_blocks, inline_to_store};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tranquil_db_traits::{RepoEventType, SequenceNumber, SequencedEvent};
use tranquil_types::Did;

async fn new_commit_data_cid(
    storage: &Arc<MemoryBlockStore>,
    commit_cid: &Cid,
) -> Result<Cid, String> {
    let commit_bytes = storage
        .get(commit_cid)
        .await
        .map_err(|e| format!("get commit: {e:?}"))?
        .ok_or_else(|| format!("CAR missing commit block {commit_cid}"))?;
    let commit = Commit::from_cbor(&commit_bytes).map_err(|e| format!("parse commit: {e:?}"))?;
    Ok(*commit.data())
}

fn ops_json(event: &SequencedEvent) -> Result<&Vec<Value>, String> {
    event
        .ops
        .as_ref()
        .and_then(|v| v.as_array())
        .ok_or_else(|| "event.ops not an array".into())
}

fn parse_op_to_verified(op: &Value) -> Result<VerifiedWriteOp, String> {
    let action = op["action"].as_str().ok_or("op.action missing")?;
    let path = op["path"].as_str().ok_or("op.path missing")?;
    let key = SmolStr::new(path);
    match action {
        "create" => {
            let cid_str = op["cid"].as_str().ok_or("create missing cid")?;
            let cid = Cid::from_str(cid_str).map_err(|e| format!("parse cid: {e:?}"))?;
            Ok(VerifiedWriteOp::Create { key, cid })
        }
        "update" => {
            let cid_str = op["cid"].as_str().ok_or("update missing cid")?;
            let cid = Cid::from_str(cid_str).map_err(|e| format!("parse cid: {e:?}"))?;
            let prev_str = op["prev"].as_str().ok_or("update missing prev")?;
            let prev = Cid::from_str(prev_str).map_err(|e| format!("parse prev: {e:?}"))?;
            Ok(VerifiedWriteOp::Update { key, cid, prev })
        }
        "delete" => {
            let prev_str = op["prev"].as_str().ok_or("delete missing prev")?;
            let prev = Cid::from_str(prev_str).map_err(|e| format!("parse prev: {e:?}"))?;
            Ok(VerifiedWriteOp::Delete { key, prev })
        }
        other => Err(format!("unknown op action: {other}")),
    }
}

async fn verify_inductive_forward(event: &SequencedEvent) -> Result<(Cid, Cid), String> {
    let prev_data_cid = event
        .prev_data_cid
        .as_ref()
        .and_then(|c| c.to_cid())
        .ok_or_else(|| "event missing prev_data_cid".to_string())?;
    let commit_cid = event
        .commit_cid
        .as_ref()
        .and_then(|c| c.to_cid())
        .ok_or_else(|| "event missing commit_cid".to_string())?;

    let storage = inline_to_store(extract_event_blocks(event)?);
    let expected_new_data = new_commit_data_cid(&storage, &commit_cid).await?;

    let mut mst = Mst::load(storage.clone(), prev_data_cid, None);
    for op_value in ops_json(event)? {
        let action = op_value["action"].as_str().ok_or("op.action missing")?;
        let path = op_value["path"].as_str().ok_or("op.path missing")?;
        match action {
            "create" | "update" => {
                let cid = Cid::from_str(op_value["cid"].as_str().ok_or("op.cid missing")?)
                    .map_err(|e| format!("parse op.cid: {e:?}"))?;
                mst = mst
                    .add(path, cid)
                    .await
                    .map_err(|e| format!("mst.add({path}): {e:?}"))?;
            }
            "delete" => {
                mst = mst
                    .delete(path)
                    .await
                    .map_err(|e| format!("mst.delete({path}): {e:?}"))?;
            }
            other => return Err(format!("unknown op action: {other}")),
        }
    }
    let computed = mst
        .persist()
        .await
        .map_err(|e| format!("mst.persist: {e:?}"))?;
    Ok((expected_new_data, computed))
}

async fn verify_inductive_inverse(event: &SequencedEvent) -> Result<(Cid, Cid), String> {
    let prev_data_cid = event
        .prev_data_cid
        .as_ref()
        .and_then(|c| c.to_cid())
        .ok_or_else(|| "event missing prev_data_cid".to_string())?;
    let commit_cid = event
        .commit_cid
        .as_ref()
        .and_then(|c| c.to_cid())
        .ok_or_else(|| "event missing commit_cid".to_string())?;

    let storage = inline_to_store(extract_event_blocks(event)?);
    let new_data_cid = new_commit_data_cid(&storage, &commit_cid).await?;

    let mut mst = Mst::load(storage.clone(), new_data_cid, None);
    for op_value in ops_json(event)?.iter().rev() {
        let verified = parse_op_to_verified(op_value)?;
        let inverted = mst
            .invert_op(verified.clone())
            .await
            .map_err(|e| format!("invert_op({verified:?}): {e:?}"))?;
        if !inverted {
            return Err(format!("op not invertible: {verified:?}"));
        }
    }
    let computed_prev = mst
        .get_pointer()
        .await
        .map_err(|e| format!("get_pointer: {e:?}"))?;
    Ok((prev_data_cid, computed_prev))
}

fn report_failures(total: usize, failures: &[String], mode: &str) {
    assert!(
        failures.is_empty(),
        "{} of {total} {mode} commit events failed inductive verification:\n  - {}",
        failures.len(),
        failures.join("\n  - "),
    );
}

async fn apply_writes_batch(client: &reqwest::Client, token: &str, did: &str, writes: Vec<Value>) {
    let payload = json!({ "repo": did, "writes": writes });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.applyWrites",
            base_url().await
        ))
        .bearer_auth(token)
        .json(&payload)
        .send()
        .await
        .expect("applyWrites request failed");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "applyWrites failed: {:?}",
        res.text().await
    );
}

async fn create_record(client: &reqwest::Client, token: &str, did: &str, col: &str, rkey: &str) {
    let now = chrono::Utc::now().to_rfc3339();
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            base_url().await
        ))
        .bearer_auth(token)
        .json(&json!({
            "repo": did,
            "collection": col,
            "rkey": rkey,
            "record": {
                "$type": col,
                "text": format!("post {rkey}"),
                "createdAt": now,
            }
        }))
        .send()
        .await
        .expect("createRecord request failed");
    assert_eq!(res.status(), StatusCode::OK, "createRecord failed");
}

async fn put_record(
    client: &reqwest::Client,
    token: &str,
    did: &str,
    col: &str,
    rkey: &str,
    text: &str,
) {
    let now = chrono::Utc::now().to_rfc3339();
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(token)
        .json(&json!({
            "repo": did,
            "collection": col,
            "rkey": rkey,
            "record": {
                "$type": col,
                "text": text,
                "createdAt": now,
            }
        }))
        .send()
        .await
        .expect("putRecord request failed");
    assert_eq!(res.status(), StatusCode::OK, "putRecord failed");
}

async fn delete_record(client: &reqwest::Client, token: &str, did: &str, col: &str, rkey: &str) {
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.deleteRecord",
            base_url().await
        ))
        .bearer_auth(token)
        .json(&json!({ "repo": did, "collection": col, "rkey": rkey }))
        .send()
        .await
        .expect("deleteRecord request failed");
    assert_eq!(res.status(), StatusCode::OK, "deleteRecord failed");
}

const COLLECTION: &str = "app.bsky.feed.post";
fn rkey_for(prefix: &str, i: usize) -> String {
    format!("3k{prefix}{:08}", i)
}

async fn our_commit_events(did: &str) -> Vec<SequencedEvent> {
    let repos = get_test_repos().await;
    let typed_did = Did::new(did.to_string()).unwrap();
    let events = repos
        .repo
        .get_events_since_seq(SequenceNumber::ZERO, None)
        .await
        .expect("get_events_since_seq");
    events
        .into_iter()
        .filter(|e| e.did == typed_did && e.event_type == RepoEventType::Commit)
        .collect()
}

#[tokio::test]
async fn inductive_forward_verifies_delete_commits() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let now = chrono::Utc::now().to_rfc3339();
    const N_CREATE: usize = 200;

    let all_writes: Vec<Value> = (0..N_CREATE)
        .map(|i| {
            json!({
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": COLLECTION,
                "rkey": rkey_for("del", i),
                "value": {
                    "$type": COLLECTION,
                    "text": format!("record {i}"),
                    "createdAt": now,
                }
            })
        })
        .collect();
    for chunk in all_writes.chunks(50) {
        apply_writes_batch(&client, &token, &did, chunk.to_vec()).await;
    }

    let delete_indices: Vec<usize> = (10..N_CREATE).step_by(7).collect();
    for i in &delete_indices {
        delete_record(&client, &token, &did, COLLECTION, &rkey_for("del", *i)).await;
    }

    let our = our_commit_events(&did).await;
    let delete_events: Vec<&SequencedEvent> = our
        .iter()
        .filter(|e| {
            ops_json(e)
                .map(|arr| arr.iter().any(|op| op["action"].as_str() == Some("delete")))
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(delete_events.len(), delete_indices.len());

    let mut failures = Vec::new();
    for e in &delete_events {
        match verify_inductive_forward(e).await {
            Ok((exp, got)) if exp == got => {}
            Ok((exp, got)) => failures.push(format!(
                "seq={}: root mismatch exp={exp} got={got}",
                e.seq.as_i64()
            )),
            Err(msg) => failures.push(format!("seq={}: {msg}", e.seq.as_i64())),
        }
    }
    report_failures(delete_events.len(), &failures, "delete forward");
}

#[tokio::test]
async fn inductive_forward_verifies_create_commits() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    for i in 0..60usize {
        create_record(&client, &token, &did, COLLECTION, &rkey_for("cre", i)).await;
    }

    let our = our_commit_events(&did).await;
    let create_events: Vec<&SequencedEvent> = our
        .iter()
        .filter(|e| {
            ops_json(e)
                .map(|arr| arr.iter().all(|op| op["action"].as_str() == Some("create")))
                .unwrap_or(false)
                && e.prev_data_cid.is_some()
        })
        .collect();
    assert!(!create_events.is_empty());

    let mut failures = Vec::new();
    for e in &create_events {
        match verify_inductive_forward(e).await {
            Ok((exp, got)) if exp == got => {}
            Ok((exp, got)) => failures.push(format!(
                "seq={}: root mismatch exp={exp} got={got}",
                e.seq.as_i64()
            )),
            Err(msg) => failures.push(format!("seq={}: {msg}", e.seq.as_i64())),
        }
    }
    report_failures(create_events.len(), &failures, "create forward");
}

#[tokio::test]
async fn inductive_forward_verifies_update_commits() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let now = chrono::Utc::now().to_rfc3339();
    let creates: Vec<Value> = (0..80)
        .map(|i| {
            json!({
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": COLLECTION,
                "rkey": rkey_for("upd", i),
                "value": {
                    "$type": COLLECTION,
                    "text": format!("original {i}"),
                    "createdAt": now,
                }
            })
        })
        .collect();
    for chunk in creates.chunks(40) {
        apply_writes_batch(&client, &token, &did, chunk.to_vec()).await;
    }

    for i in (0..80).step_by(3) {
        put_record(
            &client,
            &token,
            &did,
            COLLECTION,
            &rkey_for("upd", i),
            &format!("updated {i}"),
        )
        .await;
    }

    let our = our_commit_events(&did).await;
    let update_events: Vec<&SequencedEvent> = our
        .iter()
        .filter(|e| {
            ops_json(e)
                .map(|arr| arr.iter().any(|op| op["action"].as_str() == Some("update")))
                .unwrap_or(false)
        })
        .collect();
    assert!(!update_events.is_empty());

    let mut failures = Vec::new();
    for e in &update_events {
        match verify_inductive_forward(e).await {
            Ok((exp, got)) if exp == got => {}
            Ok((exp, got)) => failures.push(format!(
                "seq={}: root mismatch exp={exp} got={got}",
                e.seq.as_i64()
            )),
            Err(msg) => failures.push(format!("seq={}: {msg}", e.seq.as_i64())),
        }
    }
    report_failures(update_events.len(), &failures, "update forward");
}

#[tokio::test]
async fn inductive_forward_verifies_mixed_applywrites() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let now = chrono::Utc::now().to_rfc3339();
    let seed: Vec<Value> = (0..120)
        .map(|i| {
            json!({
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": COLLECTION,
                "rkey": rkey_for("mix", i),
                "value": {
                    "$type": COLLECTION,
                    "text": format!("seed {i}"),
                    "createdAt": now,
                }
            })
        })
        .collect();
    for chunk in seed.chunks(40) {
        apply_writes_batch(&client, &token, &did, chunk.to_vec()).await;
    }

    let mixed: Vec<Value> = (0..40)
        .flat_map(|i| {
            vec![
                json!({
                    "$type": "com.atproto.repo.applyWrites#create",
                    "collection": COLLECTION,
                    "rkey": rkey_for("mxc", i),
                    "value": {
                        "$type": COLLECTION,
                        "text": format!("new {i}"),
                        "createdAt": now,
                    }
                }),
                json!({
                    "$type": "com.atproto.repo.applyWrites#update",
                    "collection": COLLECTION,
                    "rkey": rkey_for("mix", i),
                    "value": {
                        "$type": COLLECTION,
                        "text": format!("updated-mix {i}"),
                        "createdAt": now,
                    }
                }),
                json!({
                    "$type": "com.atproto.repo.applyWrites#delete",
                    "collection": COLLECTION,
                    "rkey": rkey_for("mix", i + 60),
                }),
            ]
        })
        .collect();
    apply_writes_batch(&client, &token, &did, mixed).await;

    let our = our_commit_events(&did).await;
    let last = our
        .iter()
        .rfind(|e| e.prev_data_cid.is_some())
        .expect("at least one non-genesis commit");

    let actions: Vec<&str> = ops_json(last)
        .unwrap()
        .iter()
        .filter_map(|op| op["action"].as_str())
        .collect();
    assert!(actions.contains(&"create"));
    assert!(actions.contains(&"update"));
    assert!(actions.contains(&"delete"));

    let (exp, got) = verify_inductive_forward(last)
        .await
        .expect("mixed applyWrites forward verify");
    assert_eq!(exp, got, "mixed applyWrites commit forward-verify mismatch");
}

#[tokio::test]
async fn inductive_inverse_verifies_every_commit() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let now = chrono::Utc::now().to_rfc3339();
    let seed: Vec<Value> = (0..100)
        .map(|i| {
            json!({
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": COLLECTION,
                "rkey": rkey_for("inv", i),
                "value": {
                    "$type": COLLECTION,
                    "text": format!("seed {i}"),
                    "createdAt": now,
                }
            })
        })
        .collect();
    for chunk in seed.chunks(50) {
        apply_writes_batch(&client, &token, &did, chunk.to_vec()).await;
    }
    for i in (0..100).step_by(5) {
        put_record(
            &client,
            &token,
            &did,
            COLLECTION,
            &rkey_for("inv", i),
            &format!("upd {i}"),
        )
        .await;
    }
    for i in (2..100).step_by(11) {
        delete_record(&client, &token, &did, COLLECTION, &rkey_for("inv", i)).await;
    }

    let our = our_commit_events(&did).await;
    let non_genesis: Vec<&SequencedEvent> = our
        .iter()
        .filter(|e| e.prev_data_cid.is_some() && ops_json(e).is_ok())
        .collect();
    assert!(!non_genesis.is_empty());

    let mut failures = Vec::new();
    for e in &non_genesis {
        match verify_inductive_inverse(e).await {
            Ok((exp, got)) if exp == got => {}
            Ok((exp, got)) => failures.push(format!(
                "seq={}: inverse root mismatch exp={exp} got={got}",
                e.seq.as_i64()
            )),
            Err(msg) => failures.push(format!("seq={}: {msg}", e.seq.as_i64())),
        }
    }
    report_failures(non_genesis.len(), &failures, "any inverse");
}

#[tokio::test]
async fn inductive_inverse_handles_same_rkey_in_batch() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let now = chrono::Utc::now().to_rfc3339();
    let rkey = rkey_for("dup", 0);
    create_record(&client, &token, &did, COLLECTION, &rkey).await;

    let writes = vec![
        json!({
            "$type": "com.atproto.repo.applyWrites#update",
            "collection": COLLECTION,
            "rkey": rkey,
            "value": {
                "$type": COLLECTION,
                "text": "v1",
                "createdAt": now,
            }
        }),
        json!({
            "$type": "com.atproto.repo.applyWrites#update",
            "collection": COLLECTION,
            "rkey": rkey,
            "value": {
                "$type": COLLECTION,
                "text": "v2",
                "createdAt": now,
            }
        }),
    ];
    apply_writes_batch(&client, &token, &did, writes).await;

    let our = our_commit_events(&did).await;
    let dup_event = our
        .iter()
        .find(|e| {
            ops_json(e)
                .map(|arr| {
                    arr.iter()
                        .filter(|op| op["action"].as_str() == Some("update"))
                        .count()
                        == 2
                })
                .unwrap_or(false)
        })
        .expect("commit event with two same-rkey updates");

    let (exp, got) = verify_inductive_inverse(dup_event)
        .await
        .expect("inverse verify should succeed for same-rkey batch");
    assert_eq!(
        exp, got,
        "inverse root mismatch for same-rkey batch: exp={exp} got={got}"
    );
}

#[tokio::test]
async fn prev_cid_chain_walks_to_genesis() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    for i in 0..8 {
        create_record(&client, &token, &did, COLLECTION, &rkey_for("cha", i)).await;
    }

    let our = our_commit_events(&did).await;
    assert!(our.len() >= 2);

    let last = our.last().unwrap();
    let mut current_prev: Option<Cid> = last.prev_cid.as_ref().and_then(|c| c.to_cid());
    let head_commit_cid = last
        .commit_cid
        .as_ref()
        .and_then(|c| c.to_cid())
        .expect("head commit_cid");

    let by_commit: BTreeMap<Cid, &SequencedEvent> = our
        .iter()
        .filter_map(|e| {
            e.commit_cid
                .as_ref()
                .and_then(|c| c.to_cid())
                .map(|c| (c, e))
        })
        .collect();

    let mut visited = 1;
    while let Some(prev) = current_prev {
        let e = by_commit
            .get(&prev)
            .unwrap_or_else(|| panic!("prev commit {prev} missing from event list"));
        visited += 1;
        current_prev = e.prev_cid.as_ref().and_then(|c| c.to_cid());
    }
    assert!(
        visited >= 2,
        "chain too short: visited={visited}, head_commit={head_commit_cid}"
    );
    assert_eq!(
        visited,
        our.len(),
        "chain did not reach genesis: walked {visited}, have {}",
        our.len()
    );
}

#[tokio::test]
async fn record_bytes_present_in_car_for_creates() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let now = chrono::Utc::now().to_rfc3339();
    let writes: Vec<Value> = (0..5)
        .map(|i| {
            json!({
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": COLLECTION,
                "rkey": rkey_for("rec", i),
                "value": {
                    "$type": COLLECTION,
                    "text": format!("rec {i}"),
                    "createdAt": now,
                }
            })
        })
        .collect();
    apply_writes_batch(&client, &token, &did, writes).await;

    let our = our_commit_events(&did).await;
    let latest = our.iter().rfind(|e| e.prev_data_cid.is_some()).unwrap();

    let inline = extract_event_blocks(latest).unwrap();
    let have_cids: std::collections::HashSet<Cid> = inline
        .iter()
        .map(|b| Cid::read_bytes(b.cid_bytes.as_slice()).unwrap())
        .collect();

    for op in ops_json(latest).unwrap() {
        if op["action"].as_str() == Some("create")
            && let Some(cid_str) = op["cid"].as_str()
        {
            let cid = Cid::from_str(cid_str).unwrap();
            assert!(
                have_cids.contains(&cid),
                "create op record CID {cid} not present in CAR inline blocks"
            );
        }
    }
}
