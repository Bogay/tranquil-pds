mod common;
mod helpers;
use chrono::Utc;
use common::*;
use helpers::*;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tranquil_types::Did;

#[tokio::test]
async fn test_delete_record_marks_blocks_obsolete() {
    let client = client();
    let base = base_url().await;
    let repos = get_test_repos().await;
    let (did, jwt) = setup_new_user("gc-after-delete").await;

    let user_id = repos
        .user
        .get_id_by_did(&Did::new(did.clone()).unwrap())
        .await
        .expect("DB error")
        .expect("User not found");

    let count_baseline = repos
        .repo
        .count_user_blocks(user_id)
        .await
        .expect("count_user_blocks failed");

    let collection = "app.bsky.feed.post";
    let rkey = format!("gc_test_{}", Utc::now().timestamp_millis());
    let create_payload = json!({
        "repo": did,
        "collection": collection,
        "rkey": rkey,
        "record": {
            "$type": collection,
            "text": "this record is destined for deletion",
            "createdAt": Utc::now().to_rfc3339()
        }
    });

    let create_res = client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", base))
        .bearer_auth(&jwt)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to send createRecord");
    assert_eq!(
        create_res.status(),
        StatusCode::OK,
        "createRecord did not return 200"
    );
    let create_body: Value = create_res
        .json()
        .await
        .expect("createRecord response was not JSON");
    let record_uri = create_body["uri"]
        .as_str()
        .expect("createRecord response missing uri")
        .to_string();
    let record_cid = create_body["cid"]
        .as_str()
        .expect("createRecord response missing cid")
        .to_string();

    let count_after_create = repos
        .repo
        .count_user_blocks(user_id)
        .await
        .expect("count_user_blocks failed");
    assert!(
        count_after_create > count_baseline,
        "user_blocks count did not grow after createRecord (baseline={}, after_create={})",
        count_baseline,
        count_after_create
    );

    let delete_payload = json!({
        "repo": did,
        "collection": collection,
        "rkey": rkey,
    });
    let delete_res = client
        .post(format!("{}/xrpc/com.atproto.repo.deleteRecord", base))
        .bearer_auth(&jwt)
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to send deleteRecord");
    assert_eq!(
        delete_res.status(),
        StatusCode::OK,
        "deleteRecord did not return 200: {:?}",
        delete_res.text().await
    );

    let count_after_delete = repos
        .repo
        .count_user_blocks(user_id)
        .await
        .expect("count_user_blocks failed");

    assert!(
        count_after_delete < count_after_create,
        "user_blocks count did not shrink after deleteRecord \
         (baseline={}, after_create={}, after_delete={}). \
         The delete path produced no obsolete CIDs beyond the prior commit root, \
         which is the regression this test guards against.",
        count_baseline,
        count_after_create,
        count_after_delete
    );

    let get_res = client
        .get(format!("{}/xrpc/com.atproto.repo.getRecord", base))
        .query(&[
            ("repo", did.as_str()),
            ("collection", collection),
            ("rkey", rkey.as_str()),
        ])
        .send()
        .await
        .expect("Failed to send getRecord");
    assert!(
        !get_res.status().is_success(),
        "deleted record is still resolvable via getRecord (status={}); uri={} cid={}",
        get_res.status(),
        record_uri,
        record_cid
    );
}

#[tokio::test]
async fn test_update_record_marks_old_record_block_obsolete() {
    let client = client();
    let base = base_url().await;
    let repos = get_test_repos().await;
    let (did, jwt) = setup_new_user("gc-after-update").await;

    let user_id = repos
        .user
        .get_id_by_did(&Did::new(did.clone()).unwrap())
        .await
        .expect("DB error")
        .expect("User not found");

    let collection = "app.bsky.feed.post";
    let rkey = format!("gc_update_{}", Utc::now().timestamp_millis());

    let put_v1 = json!({
        "repo": did,
        "collection": collection,
        "rkey": rkey,
        "record": {
            "$type": collection,
            "text": "first version",
            "createdAt": Utc::now().to_rfc3339()
        }
    });
    let res = client
        .post(format!("{}/xrpc/com.atproto.repo.putRecord", base))
        .bearer_auth(&jwt)
        .json(&put_v1)
        .send()
        .await
        .expect("Failed to send putRecord v1");
    assert_eq!(res.status(), StatusCode::OK, "first putRecord failed");

    let count_after_create = repos
        .repo
        .count_user_blocks(user_id)
        .await
        .expect("count_user_blocks failed");

    let put_v2 = json!({
        "repo": did,
        "collection": collection,
        "rkey": rkey,
        "record": {
            "$type": collection,
            "text": "second version with new content",
            "createdAt": Utc::now().to_rfc3339()
        }
    });
    let res = client
        .post(format!("{}/xrpc/com.atproto.repo.putRecord", base))
        .bearer_auth(&jwt)
        .json(&put_v2)
        .send()
        .await
        .expect("Failed to send putRecord v2");
    assert_eq!(res.status(), StatusCode::OK, "second putRecord failed");

    let count_after_update = repos
        .repo
        .count_user_blocks(user_id)
        .await
        .expect("count_user_blocks failed");

    assert!(
        count_after_update <= count_after_create + 1,
        "user_blocks count grew by more than 1 after putRecord update \
         (after_create={}, after_update={}). The previous version's record block \
         should have been marked obsolete; instead it appears to be leaking.",
        count_after_create,
        count_after_update
    );
}

#[tokio::test]
async fn test_delete_in_populated_repo_marks_merged_subtree_blocks_obsolete() {
    let client = client();
    let base = base_url().await;
    let repos = get_test_repos().await;
    let (did, jwt) = setup_new_user("gc-merge").await;

    let user_id = repos
        .user
        .get_id_by_did(&Did::new(did.clone()).unwrap())
        .await
        .expect("DB error")
        .expect("User not found");

    let collection = "app.bsky.feed.post";
    let record_count = 64usize;
    let now_ms = Utc::now().timestamp_millis();

    let rkeys: Vec<String> = (0..record_count)
        .map(|i| format!("gc_merge_{}_{:04}", now_ms, i))
        .collect();

    let create_results =
        futures::future::try_join_all(rkeys.iter().enumerate().map(|(i, rkey)| {
            let client = client.clone();
            let jwt = jwt.clone();
            let did = did.clone();
            let base = base.to_string();
            let payload = json!({
                "repo": did,
                "collection": collection,
                "rkey": rkey,
                "record": {
                    "$type": collection,
                    "text": format!("seed record {}", i),
                    "createdAt": Utc::now().to_rfc3339()
                }
            });
            async move {
                let res = client
                    .post(format!("{}/xrpc/com.atproto.repo.createRecord", base))
                    .bearer_auth(&jwt)
                    .json(&payload)
                    .send()
                    .await
                    .expect("Failed to send createRecord");
                if res.status() != StatusCode::OK {
                    return Err(format!("seed createRecord failed: {}", res.status()));
                }
                Ok::<(), String>(())
            }
        }))
        .await;
    create_results.expect("seeding records failed");

    let count_after_seed = repos
        .repo
        .count_user_blocks(user_id)
        .await
        .expect("count_user_blocks failed");

    let target_rkey = &rkeys[record_count / 2];
    let delete_payload = json!({
        "repo": did,
        "collection": collection,
        "rkey": target_rkey,
    });
    let delete_res = client
        .post(format!("{}/xrpc/com.atproto.repo.deleteRecord", base))
        .bearer_auth(&jwt)
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to send deleteRecord");
    assert_eq!(
        delete_res.status(),
        StatusCode::OK,
        "deleteRecord did not return 200: {:?}",
        delete_res.text().await
    );

    let count_after_delete = repos
        .repo
        .count_user_blocks(user_id)
        .await
        .expect("count_user_blocks failed");
    assert!(
        count_after_delete < count_after_seed,
        "user_blocks did not shrink after deleting from a populated repo \
         (after_seed={}, after_delete={}). The path-walk-based obsolete \
         calculation does not capture sibling subtree blocks orphaned by \
         delete-merge; only an MST-diff-based calculation does.",
        count_after_seed,
        count_after_delete
    );

    let get_res = client
        .get(format!("{}/xrpc/com.atproto.repo.getRecord", base))
        .query(&[
            ("repo", did.as_str()),
            ("collection", collection),
            ("rkey", target_rkey.as_str()),
        ])
        .send()
        .await
        .expect("Failed to send getRecord");
    assert!(
        !get_res.status().is_success(),
        "deleted record is still resolvable via getRecord (status={})",
        get_res.status(),
    );
}

#[tokio::test]
async fn test_delete_decrements_tranquil_store_refcounts() {
    if !is_store_backend() {
        eprintln!(
            "skipping test_delete_decrements_tranquil_store_refcounts: \
             only meaningful with the tranquil-store backend"
        );
        return;
    }

    let client = client();
    let base = base_url().await;
    let block_store = get_test_block_store().await;
    let store = block_store
        .as_tranquil_store()
        .expect("tranquil-store backend selected but block_store is not TranquilStore");
    let (did, jwt) = setup_new_user("gc-store-decrement").await;

    let collection = "app.bsky.feed.post";
    let rkey = format!("gc_store_{}", Utc::now().timestamp_millis());

    let create_res = client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", base))
        .bearer_auth(&jwt)
        .json(&json!({
            "repo": did,
            "collection": collection,
            "rkey": rkey,
            "record": {
                "$type": collection,
                "text": "destined for refcount decrement",
                "createdAt": Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .expect("Failed to send createRecord");
    assert_eq!(create_res.status(), StatusCode::OK, "createRecord failed");
    let create_body: Value = create_res.json().await.expect("createRecord not JSON");
    let record_cid_str = create_body["cid"]
        .as_str()
        .expect("createRecord response missing cid")
        .to_string();
    let record_cid = cid::Cid::try_from(record_cid_str.as_str()).expect("invalid record cid");

    let refcount_after_create = store
        .refcount_of(&record_cid)
        .expect("refcount_of failed")
        .expect("record cid not in blockstore index after create");
    assert!(
        refcount_after_create > 0,
        "record cid had refcount 0 immediately after create (cid={})",
        record_cid_str
    );

    let delete_res = client
        .post(format!("{}/xrpc/com.atproto.repo.deleteRecord", base))
        .bearer_auth(&jwt)
        .json(&json!({
            "repo": did,
            "collection": collection,
            "rkey": rkey,
        }))
        .send()
        .await
        .expect("Failed to send deleteRecord");
    assert_eq!(
        delete_res.status(),
        StatusCode::OK,
        "deleteRecord did not return 200: {:?}",
        delete_res.text().await
    );

    let refcount_after_delete = store
        .refcount_of(&record_cid)
        .expect("refcount_of failed")
        .expect("record cid slot vanished entirely after delete");
    assert_eq!(
        refcount_after_delete, 0,
        "record cid still has nonzero refcount after deleteRecord \
         (cid={}, before_delete={}, after_delete={}). The hash_index \
         decrement that drives on-disk reclamation is the regression \
         this test guards against.",
        record_cid_str, refcount_after_create, refcount_after_delete
    );
}
