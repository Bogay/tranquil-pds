mod common;
mod helpers;

use cid::Cid;
use common::*;
use helpers::*;
use jacquard_repo::commit::Commit;
use jacquard_repo::storage::BlockStore;
use serde_json::json;
use std::str::FromStr;
use tranquil_types::Did;

#[tokio::test]
async fn repair_fails_loud_on_missing_leaf_block() {
    let client = client();
    let repos = get_test_repos().await;
    let block_store = get_test_block_store().await;
    let state = get_test_app_state().await;

    let Some(pg) = block_store.as_postgres() else {
        eprintln!(
            "repair_fails_loud_on_missing_leaf_block: requires postgres backend, skipping under store backend"
        );
        return;
    };
    let pool = pg.pool();

    let (did, jwt) = setup_new_user("repair-leaf-loss").await;
    let writes: Vec<serde_json::Value> = (0..6)
        .map(|i| {
            json!({
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "rkey": format!("leafloss{i:05}"),
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": format!("repair leaf loss {i}"),
                    "createdAt": "2026-01-01T00:00:00.000Z"
                }
            })
        })
        .collect();
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.applyWrites",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&json!({ "repo": did, "validate": false, "writes": writes }))
        .send()
        .await
        .expect("applyWrites send");
    assert_eq!(
        res.status(),
        reqwest::StatusCode::OK,
        "applyWrites failed: {:?}",
        res.text().await
    );

    let user_id = repos
        .user
        .get_id_by_did(&Did::new(did.clone()).unwrap())
        .await
        .expect("DB error")
        .expect("user not found");

    let root_str = repos
        .repo
        .get_repo_root_cid_by_user_id(user_id)
        .await
        .expect("DB error")
        .expect("repo root not found");
    let commit_cid = Cid::from_str(&root_str).expect("parse commit cid");
    let commit_bytes = block_store
        .get(&commit_cid)
        .await
        .expect("read commit")
        .expect("commit present");
    let mst_root_cid = Commit::from_cbor(&commit_bytes).expect("parse commit").data;

    let records = repos
        .repo
        .get_all_records(user_id)
        .await
        .expect("get_all_records");
    assert!(!records.is_empty(), "repo must contain records");
    let leaf_cid = Cid::from_str(records[0].record_cid.as_str()).expect("parse leaf cid");
    assert!(
        block_store
            .get(&leaf_cid)
            .await
            .expect("read leaf")
            .is_some(),
        "leaf must be present before corruption"
    );

    repos
        .repo
        .delete_user_blocks(user_id, &[leaf_cid.to_bytes()])
        .await
        .expect("clear leaf user_blocks row");

    sqlx::query("DELETE FROM blocks WHERE cid = $1")
        .bind(mst_root_cid.to_bytes())
        .execute(pool)
        .await
        .expect("delete mst root node block");
    sqlx::query("DELETE FROM blocks WHERE cid = $1")
        .bind(leaf_cid.to_bytes())
        .execute(pool)
        .await
        .expect("delete leaf record block");

    assert!(
        block_store
            .get(&mst_root_cid)
            .await
            .expect("read")
            .is_none(),
        "mst root node must be gone to force a structural repair"
    );
    assert!(
        block_store.get(&leaf_cid).await.expect("read").is_none(),
        "leaf block must be gone to simulate data loss"
    );

    let err = tranquil_pds::repo_ops::repair_repo_structure(state, user_id)
        .await
        .expect_err("repair must fail loud when a leaf block is unrecoverable");
    let detail = format!("{err:?}");
    assert!(
        detail.contains("leaf data loss"),
        "expected an unrecoverable-leaf-loss error, got: {detail}"
    );

    assert!(
        block_store
            .get(&mst_root_cid)
            .await
            .expect("read")
            .is_some(),
        "structural repair must still re-insert the regenerable MST node"
    );

    let recorded = repos
        .repo
        .get_user_block_cids_since_rev(user_id, &tranquil_types::Tid::from(String::new()))
        .await
        .expect("read user_blocks");
    assert!(
        !recorded.contains(&leaf_cid.to_bytes()),
        "missing leaf must not be phantom-inserted into user_blocks"
    );
}
