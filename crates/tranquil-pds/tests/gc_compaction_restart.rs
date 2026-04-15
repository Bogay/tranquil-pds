mod common;

use chrono::Utc;
use common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};

fn run_compaction(store: &tranquil_store::blockstore::TranquilBlockStore) {
    let liveness = store.compaction_liveness(0).unwrap();
    liveness
        .iter()
        .filter(|(_, info)| info.total_blocks > 0 && info.ratio() < 0.95)
        .map(|(&fid, _)| fid)
        .collect::<Vec<_>>()
        .into_iter()
        .for_each(|fid| match store.compact_file(fid, 0) {
            Ok(_) => {}
            Err(tranquil_store::blockstore::CompactionError::ActiveFileCannotBeCompacted) => {}
            Err(e) => eprintln!("compaction: {e}"),
        });
}

#[tokio::test]
async fn mst_blocks_survive_full_store_reopen() {
    if !is_store_backend() {
        eprintln!("skipping: only meaningful with tranquil-store backend");
        return;
    }

    let client = client();
    let base = base_url().await;
    let block_store = get_test_block_store().await;

    let store = block_store
        .as_tranquil_store()
        .expect("expected tranquil-store backend");

    let (jwt, did) = create_account_and_login(&client).await;

    let mut posts = Vec::new();
    for i in 0..30 {
        let res = client
            .post(format!("{base}/xrpc/com.atproto.repo.createRecord"))
            .bearer_auth(&jwt)
            .json(&json!({
                "repo": did,
                "collection": "app.bsky.feed.post",
                "record": {
                    "$type": "app.bsky.feed.post",
                    "text": format!("compaction test post {i}"),
                    "createdAt": Utc::now().to_rfc3339()
                }
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body: Value = res.json().await.unwrap();
        posts.push((
            body["uri"].as_str().unwrap().to_string(),
            body["cid"].as_str().unwrap().to_string(),
        ));
    }

    for (uri, cid) in &posts[..20] {
        let res = client
            .post(format!("{base}/xrpc/com.atproto.repo.createRecord"))
            .bearer_auth(&jwt)
            .json(&json!({
                "repo": did,
                "collection": "app.bsky.feed.like",
                "record": {
                    "$type": "app.bsky.feed.like",
                    "subject": { "uri": uri, "cid": cid },
                    "createdAt": Utc::now().to_rfc3339()
                }
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "like failed for {uri}");
    }

    let data_dir = store.data_dir().to_path_buf();
    let index_dir = data_dir.parent().unwrap().join("index");

    let store_clone = store.clone();
    tokio::task::spawn_blocking(move || {
        (0..40).for_each(|_| run_compaction(&store_clone));
    })
    .await
    .unwrap();

    let repo_root_str: String = get_test_repos()
        .await
        .repo
        .get_repo_root_by_did(&tranquil_types::Did::new(did.clone()).unwrap())
        .await
        .expect("db error")
        .expect("no repo root")
        .to_string();

    let head_cid = cid::Cid::try_from(repo_root_str.as_str()).expect("invalid cid");

    let car_blocks = tranquil_pds::scheduled::collect_current_repo_blocks(block_store, &head_cid)
        .await
        .expect("collect blocks");

    let block_count_before = car_blocks.len();

    let max_file_size = store
        .list_data_files()
        .ok()
        .and_then(|_| Some(4 * 1024 * 1024u64))
        .unwrap_or(4 * 1024 * 1024);

    let reopened_missing = tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Handle::current();
        let _guard = rt.enter();

        let config = tranquil_store::blockstore::BlockStoreConfig {
            data_dir: data_dir.clone(),
            index_dir,
            max_file_size,
            group_commit: tranquil_store::blockstore::GroupCommitConfig::default(),
            shard_count: 1,
        };
        let fresh =
            tranquil_store::blockstore::TranquilBlockStore::open(config).expect("reopen failed");

        let missing: Vec<String> = car_blocks
            .iter()
            .filter_map(|cid_bytes| {
                if cid_bytes.len() < 36 {
                    return None;
                }
                let mut arr = [0u8; 36];
                arr.copy_from_slice(&cid_bytes[..36]);
                match fresh.get_block_sync(&arr) {
                    Ok(Some(_)) => None,
                    Ok(None) => Some(format!(
                        "missing {}",
                        cid::Cid::try_from(cid_bytes.as_slice())
                            .map(|c| c.to_string())
                            .unwrap_or_else(|_| hex::encode(cid_bytes))
                    )),
                    Err(e) => Some(format!("error: {e}")),
                }
            })
            .collect();

        drop(fresh);
        missing
    })
    .await
    .unwrap();

    assert!(
        reopened_missing.is_empty(),
        "{} of {block_count_before} blocks missing after blockstore reopen:\n{}",
        reopened_missing.len(),
        reopened_missing
            .iter()
            .take(20)
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n"),
    );
}
