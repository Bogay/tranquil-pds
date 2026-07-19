mod common;
mod helpers;
use chrono::Utc;
use common::*;
use helpers::*;
use reqwest::StatusCode;
use serde_json::json;
use std::sync::LazyLock;
use tranquil_types::{Did, Nsid, Rkey};

static COLLECTION: LazyLock<Nsid> =
    LazyLock::new(|| Nsid::new("app.bsky.feed.post".to_string()).expect("valid NSID"));

async fn create_record(did: &Did, jwt: &str, rkey: &Rkey, text: String) -> cid::Cid {
    create_record_at(did, jwt, rkey, text, Utc::now().to_rfc3339()).await
}

async fn create_record_at(
    did: &Did,
    jwt: &str,
    rkey: &Rkey,
    text: String,
    created_at: String,
) -> cid::Cid {
    let res = client()
        .post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            base_url().await
        ))
        .bearer_auth(jwt)
        .json(&json!({
            "repo": did,
            "collection": &*COLLECTION,
            "rkey": rkey,
            "record": {
                "$type": &*COLLECTION,
                "text": text,
                "createdAt": created_at
            }
        }))
        .send()
        .await
        .expect("Failed to send createRecord");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "createRecord for {rkey} didn't return 200: {:?}",
        res.text().await
    );
    let body: serde_json::Value = res.json().await.expect("createRecord response isn't JSON");
    let cid_str = body["cid"]
        .as_str()
        .expect("createRecord response missing cid");
    cid::Cid::try_from(cid_str).expect("createRecord returned an invalid cid")
}

async fn refcount_of(cid: &cid::Cid) -> u32 {
    get_test_block_store()
        .await
        .as_tranquil_store()
        .expect("tranquil-store backend selected but block_store isn't TranquilStore")
        .refcount_of(cid)
        .expect("refcount_of failed")
        .unwrap_or(0)
}

async fn delete_record(did: &Did, jwt: &str, rkey: &Rkey) {
    let res = client()
        .post(format!(
            "{}/xrpc/com.atproto.repo.deleteRecord",
            base_url().await
        ))
        .bearer_auth(jwt)
        .json(&json!({
            "repo": did,
            "collection": &*COLLECTION,
            "rkey": rkey,
        }))
        .send()
        .await
        .expect("Failed to send deleteRecord");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "deleteRecord for {rkey} didn't return 200: {:?}",
        res.text().await
    );
}

async fn assert_record_gone(did: &Did, rkey: &Rkey) {
    let res = client()
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", COLLECTION.as_str()),
            ("rkey", rkey.as_str()),
        ])
        .send()
        .await
        .expect("Failed to send getRecord");
    assert!(
        !res.status().is_success(),
        "deleted record {rkey} is still resolvable via getRecord: {}",
        res.status()
    );
}

async fn user_id_for(did: &Did) -> uuid::Uuid {
    get_test_repos()
        .await
        .user
        .get_id_by_did(did)
        .await
        .expect("DB error looking up the user id")
        .expect("User not found")
}

#[tokio::test]
async fn deleting_from_a_populated_repo_keeps_user_blocks_equal_to_reachable_set() {
    let (did, jwt) = setup_new_user("user-blocks-reachability").await;
    let did = Did::new(did).expect("setup_new_user returned a valid DID");
    let user_id = user_id_for(&did).await;

    let record_count = 64usize;
    let now_ms = Utc::now().timestamp_millis();
    let rkeys: Vec<Rkey> = (0..record_count)
        .map(|i| Rkey::new(format!("reach_{}_{:04}", now_ms, i)).expect("valid rkey"))
        .collect();

    futures::future::join_all(
        rkeys
            .iter()
            .enumerate()
            .map(|(i, rkey)| create_record(&did, &jwt, rkey, format!("seed record {}", i))),
    )
    .await;

    assert_user_blocks_matches_repo(user_id, "64 creates").await;

    let target = &rkeys[record_count / 2];
    delete_record(&did, &jwt, target).await;

    assert_user_blocks_matches_repo(user_id, "deleting one record").await;
    assert_record_gone(&did, target).await;
}

#[tokio::test]
async fn applying_a_multi_op_batch_keeps_user_blocks_equal_to_reachable_set() {
    let (did, jwt) = setup_new_user("user-blocks-apply-writes").await;
    let did = Did::new(did).expect("setup_new_user returned a valid DID");
    let user_id = user_id_for(&did).await;

    let now_ms = Utc::now().timestamp_millis();
    let rkeys: Vec<Rkey> = (0..3)
        .map(|i| Rkey::new(format!("batch_{}_{}", now_ms, i)).expect("valid rkey"))
        .collect();
    let created_at = "2026-01-01T00:00:00Z".to_string();

    futures::future::join_all(
        rkeys.iter().map(|rkey| {
            create_record_at(&did, &jwt, rkey, "shared".to_string(), created_at.clone())
        }),
    )
    .await;
    assert_user_blocks_matches_repo(user_id, "three records sharing one leaf block").await;

    let writes = json!({
        "repo": did,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#delete",
                "collection": &*COLLECTION,
                "rkey": rkeys[0],
            },
            {
                "$type": "com.atproto.repo.applyWrites#update",
                "collection": &*COLLECTION,
                "rkey": rkeys[1],
                "value": {
                    "$type": &*COLLECTION,
                    "text": "updated in the same commit",
                    "createdAt": created_at
                },
            },
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": &*COLLECTION,
                "rkey": Rkey::new(format!("batch_{}_new", now_ms)).expect("valid rkey"),
                "value": {
                    "$type": &*COLLECTION,
                    "text": "created in the same commit",
                    "createdAt": created_at
                },
            },
        ]
    });
    let res = client()
        .post(format!(
            "{}/xrpc/com.atproto.repo.applyWrites",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&writes)
        .send()
        .await
        .expect("Failed to send applyWrites");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "applyWrites didn't return 200: {:?}",
        res.text().await
    );

    assert_user_blocks_matches_repo(user_id, "a delete, update, & create in one commit").await;
    assert_record_gone(&did, &rkeys[0]).await;
}

#[tokio::test]
async fn emptying_the_repo_keeps_user_blocks_equal_to_reachable_set() {
    let (did, jwt) = setup_new_user("user-blocks-empty-tree").await;
    let did = Did::new(did).expect("setup_new_user returned a valid DID");
    let user_id = user_id_for(&did).await;

    let now_ms = Utc::now().timestamp_millis();
    let only = Rkey::new(format!("empty_{}_only", now_ms)).expect("valid rkey");

    create_record(&did, &jwt, &only, "the only record".to_string()).await;
    assert_user_blocks_matches_repo(user_id, "creating the only record").await;

    delete_record(&did, &jwt, &only).await;
    assert_user_blocks_matches_repo(user_id, "deleting the last record").await;
    assert_record_gone(&did, &only).await;
}

#[tokio::test]
async fn reverting_the_tree_to_a_stored_shape_still_records_its_blocks() {
    let (did, jwt) = setup_new_user("user-blocks-resurrect").await;
    let did = Did::new(did).expect("setup_new_user returned a valid DID");
    let user_id = user_id_for(&did).await;

    let now_ms = Utc::now().timestamp_millis();
    let kept = Rkey::new(format!("resurrect_{}_kept", now_ms)).expect("valid rkey");
    let churned = Rkey::new(format!("resurrect_{}_churned", now_ms)).expect("valid rkey");

    create_record(&did, &jwt, &kept, "first record".to_string()).await;
    assert_user_blocks_matches_repo(user_id, "creating the first record").await;

    create_record(&did, &jwt, &churned, "second record".to_string()).await;
    assert_user_blocks_matches_repo(user_id, "creating the second record").await;

    delete_record(&did, &jwt, &churned).await;
    assert_user_blocks_matches_repo(user_id, "deleting back to the one-record tree").await;

    create_record(&did, &jwt, &churned, "second record".to_string()).await;
    assert_user_blocks_matches_repo(user_id, "recreating the deleted record").await;
}

#[tokio::test]
async fn deleting_one_of_two_identical_records_keeps_the_shared_block() {
    let (did, jwt) = setup_new_user("user-blocks-shared-leaf").await;
    let did = Did::new(did).expect("setup_new_user returned a valid DID");
    let user_id = user_id_for(&did).await;

    let now_ms = Utc::now().timestamp_millis();
    let kept = Rkey::new(format!("shared_{}_kept", now_ms)).expect("valid rkey");
    let dropped = Rkey::new(format!("shared_{}_dropped", now_ms)).expect("valid rkey");
    let created_at = "2026-01-01T00:00:00Z".to_string();

    let shared = create_record_at(
        &did,
        &jwt,
        &kept,
        "identical content".to_string(),
        created_at.clone(),
    )
    .await;
    assert_eq!(
        create_record_at(
            &did,
            &jwt,
            &dropped,
            "identical content".to_string(),
            created_at,
        )
        .await,
        shared,
        "two records with identical content must produce one block"
    );
    assert_user_blocks_matches_repo(user_id, "creating two identical records").await;

    delete_record(&did, &jwt, &dropped).await;

    assert_user_blocks_matches_repo(user_id, "deleting one of two identical records").await;

    if is_store_backend() {
        assert_eq!(
            refcount_of(&shared).await,
            1,
            "deleting one of two records sharing a block must drop exactly one reference"
        );
    }

    delete_record(&did, &jwt, &kept).await;
    assert_user_blocks_matches_repo(user_id, "deleting the second of two identical records").await;

    if is_store_backend() {
        assert_eq!(
            refcount_of(&shared).await,
            0,
            "the shared block must reach refcount 0 once the last record referencing it is gone"
        );
    }
}

#[tokio::test]
async fn deleting_two_identical_records_in_one_commit_drops_both_references() {
    let (did, jwt) = setup_new_user("user-blocks-shared-leaf-batch").await;
    let did = Did::new(did).expect("setup_new_user returned a valid DID");
    let user_id = user_id_for(&did).await;

    let now_ms = Utc::now().timestamp_millis();
    let first = Rkey::new(format!("batchshared_{}_first", now_ms)).expect("valid rkey");
    let second = Rkey::new(format!("batchshared_{}_second", now_ms)).expect("valid rkey");
    let created_at = "2026-01-01T00:00:00Z".to_string();

    let shared = create_record_at(
        &did,
        &jwt,
        &first,
        "identical content".to_string(),
        created_at.clone(),
    )
    .await;
    create_record_at(
        &did,
        &jwt,
        &second,
        "identical content".to_string(),
        created_at,
    )
    .await;
    assert_user_blocks_matches_repo(user_id, "creating two identical records").await;

    let res = client()
        .post(format!(
            "{}/xrpc/com.atproto.repo.applyWrites",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&json!({
            "repo": did,
            "writes": [
                {
                    "$type": "com.atproto.repo.applyWrites#delete",
                    "collection": &*COLLECTION,
                    "rkey": first,
                },
                {
                    "$type": "com.atproto.repo.applyWrites#delete",
                    "collection": &*COLLECTION,
                    "rkey": second,
                },
            ]
        }))
        .send()
        .await
        .expect("Failed to send applyWrites");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "applyWrites didn't return 200: {:?}",
        res.text().await
    );

    assert_user_blocks_matches_repo(user_id, "deleting both identical records in one commit").await;

    if is_store_backend() {
        assert_eq!(
            refcount_of(&shared).await,
            0,
            "one commit dropping both references to a block must decrement it twice"
        );
    }
}
