mod common;
mod helpers;
use chrono::Utc;
use common::*;
use helpers::*;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tranquil_types::{Did, Nsid, Rkey};

#[tokio::test]
async fn test_delete_record_marks_blocks_obsolete() {
    let client = client();
    let base = base_url().await;
    let repos = get_test_repos().await;
    let (did, jwt) = setup_new_user("gc-after-delete").await;
    let did = Did::new(did).expect("setup_new_user returned a valid DID");

    let user_id = repos
        .user
        .get_id_by_did(&did)
        .await
        .expect("DB error")
        .expect("User not found");

    let collection = Nsid::new("app.bsky.feed.post".to_string()).expect("valid NSID");
    let rkey = Rkey::new(format!("gc_test_{}", Utc::now().timestamp_millis())).expect("valid rkey");
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

    assert_user_blocks_matches_repo(user_id, "createRecord").await;

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

    assert_user_blocks_matches_repo(user_id, "deleteRecord").await;

    let get_res = client
        .get(format!("{}/xrpc/com.atproto.repo.getRecord", base))
        .query(&[
            ("repo", did.as_str()),
            ("collection", collection.as_str()),
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
    let did = Did::new(did).expect("setup_new_user returned a valid DID");

    let user_id = repos
        .user
        .get_id_by_did(&did)
        .await
        .expect("DB error")
        .expect("User not found");

    let collection = Nsid::new("app.bsky.feed.post".to_string()).expect("valid NSID");
    let rkey =
        Rkey::new(format!("gc_update_{}", Utc::now().timestamp_millis())).expect("valid rkey");

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

    assert_user_blocks_matches_repo(user_id, "the first putRecord").await;

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

    assert_user_blocks_matches_repo(user_id, "the second putRecord").await;
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
    let did = Did::new(did).expect("setup_new_user returned a valid DID");

    let collection = Nsid::new("app.bsky.feed.post".to_string()).expect("valid NSID");
    let rkey =
        Rkey::new(format!("gc_store_{}", Utc::now().timestamp_millis())).expect("valid rkey");

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
