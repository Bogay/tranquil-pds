mod common;
use chrono::Utc;
use common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tranquil_db_traits::{Backlink, BacklinkPath};
use tranquil_pds::types::{AtUri, Did, Nsid};

#[tokio::test]
async fn test_apply_writes_create() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let now = Utc::now().to_rfc3339();
    let payload = json!({
        "repo": did,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "Batch created post 1",
                    "createdAt": now
                }
            },
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "Batch created post 2",
                    "createdAt": now
                }
            }
        ]
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
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert!(body["commit"]["cid"].is_string());
    assert!(body["results"].is_array());
    let results = body["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    assert!(results[0]["uri"].is_string());
    assert!(results[0]["cid"].is_string());
}

#[tokio::test]
async fn test_apply_writes_update() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let now = Utc::now().to_rfc3339();
    let rkey = format!("batch_update_{}", Utc::now().timestamp_millis());
    let create_payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": rkey,
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "Original post",
            "createdAt": now
        }
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to create");
    assert_eq!(res.status(), StatusCode::OK);
    let update_payload = json!({
        "repo": did,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#update",
                "collection": "app.bsky.feed.post",
                "rkey": rkey,
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "Updated post via applyWrites",
                    "createdAt": now
                }
            }
        ]
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.applyWrites",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&update_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    let results = body["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0]["uri"].is_string());
}

#[tokio::test]
async fn test_apply_writes_delete() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let now = Utc::now().to_rfc3339();
    let rkey = format!("batch_delete_{}", Utc::now().timestamp_millis());
    let create_payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": rkey,
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "Post to delete",
            "createdAt": now
        }
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to create");
    assert_eq!(res.status(), StatusCode::OK);
    let delete_payload = json!({
        "repo": did,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#delete",
                "collection": "app.bsky.feed.post",
                "rkey": rkey
            }
        ]
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.applyWrites",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let get_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkey", rkey.as_str()),
        ])
        .send()
        .await
        .expect("Failed to verify");
    assert_eq!(get_res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_apply_writes_mixed_operations() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let now = Utc::now().to_rfc3339();
    let rkey_to_delete = format!("mixed_del_{}", Utc::now().timestamp_millis());
    let rkey_to_update = format!("mixed_upd_{}", Utc::now().timestamp_millis());
    let setup_payload = json!({
        "repo": did,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "rkey": rkey_to_delete,
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "To be deleted",
                    "createdAt": now
                }
            },
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "rkey": rkey_to_update,
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "To be updated",
                    "createdAt": now
                }
            }
        ]
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.applyWrites",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&setup_payload)
        .send()
        .await
        .expect("Failed to setup");
    assert_eq!(res.status(), StatusCode::OK);
    let mixed_payload = json!({
        "repo": did,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "New post",
                    "createdAt": now
                }
            },
            {
                "$type": "com.atproto.repo.applyWrites#update",
                "collection": "app.bsky.feed.post",
                "rkey": rkey_to_update,
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "Updated text",
                    "createdAt": now
                }
            },
            {
                "$type": "com.atproto.repo.applyWrites#delete",
                "collection": "app.bsky.feed.post",
                "rkey": rkey_to_delete
            }
        ]
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.applyWrites",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&mixed_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    let results = body["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
}

#[tokio::test]
async fn test_apply_writes_no_auth() {
    let client = client();
    let payload = json!({
        "repo": "did:plc:test",
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "Test",
                    "createdAt": "2025-01-01T00:00:00Z"
                }
            }
        ]
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.applyWrites",
            base_url().await
        ))
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_apply_writes_empty_writes() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let payload = json!({
        "repo": did,
        "writes": []
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
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_apply_writes_delete_then_create_same_rkey() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let now = Utc::now().to_rfc3339();
    let rkey = format!("recreate_{}", Utc::now().timestamp_millis());

    let create_payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": rkey,
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "original",
            "createdAt": now
        }
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to create");
    assert_eq!(res.status(), StatusCode::OK);

    let recreate_payload = json!({
        "repo": did,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#delete",
                "collection": "app.bsky.feed.post",
                "rkey": rkey
            },
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "rkey": rkey,
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "recreated",
                    "createdAt": now
                }
            }
        ]
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.applyWrites",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&recreate_payload)
        .send()
        .await
        .expect("Failed to send applyWrites");
    assert_eq!(res.status(), StatusCode::OK);

    let get_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkey", rkey.as_str()),
        ])
        .send()
        .await
        .expect("Failed to fetch record");
    assert_eq!(
        get_res.status(),
        StatusCode::OK,
        "repo.getRecord must return the recreated record, not 404"
    );
    let body: Value = get_res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["value"]["text"], json!("recreated"));

    let list_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
        ])
        .send()
        .await
        .expect("Failed to list records");
    assert_eq!(list_res.status(), StatusCode::OK);
    let list_body: Value = list_res.json().await.expect("listRecords not valid JSON");
    let records = list_body["records"]
        .as_array()
        .expect("records must be array");
    let expected_uri = format!("at://{}/app.bsky.feed.post/{}", did, rkey);
    assert!(
        records.iter().any(|r| r["uri"] == json!(expected_uri)),
        "listRecords must include the recreated rkey"
    );
}

#[tokio::test]
async fn test_apply_writes_create_then_delete_same_rkey() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let now = Utc::now().to_rfc3339();
    let rkey = format!("transient_{}", Utc::now().timestamp_millis());

    let payload = json!({
        "repo": did,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "rkey": rkey,
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "transient",
                    "createdAt": now
                }
            },
            {
                "$type": "com.atproto.repo.applyWrites#delete",
                "collection": "app.bsky.feed.post",
                "rkey": rkey
            }
        ]
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
        .expect("Failed to send applyWrites");
    assert_eq!(res.status(), StatusCode::OK);

    let get_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkey", rkey.as_str()),
        ])
        .send()
        .await
        .expect("Failed to fetch record");
    assert_eq!(
        get_res.status(),
        StatusCode::NOT_FOUND,
        "create+delete on same rkey must leave no record"
    );

    let list_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
        ])
        .send()
        .await
        .expect("Failed to list records");
    assert_eq!(list_res.status(), StatusCode::OK);
    let list_body: Value = list_res.json().await.expect("listRecords not valid JSON");
    let records = list_body["records"]
        .as_array()
        .expect("records must be array");
    let expected_uri = format!("at://{}/app.bsky.feed.post/{}", did, rkey);
    assert!(
        !records.iter().any(|r| r["uri"] == json!(expected_uri)),
        "listRecords must not include a created-then-deleted rkey"
    );
}

async fn repo_id_for_did(did: &str) -> uuid::Uuid {
    let repos = get_test_repos().await;
    let parsed = Did::new(did).expect("valid did");
    repos
        .user
        .get_id_by_did(&parsed)
        .await
        .expect("lookup user_id")
        .expect("user exists")
}

async fn follow_uris_pointing_to(repo_id: uuid::Uuid, target_did: &str) -> Vec<String> {
    let repos = get_test_repos().await;
    let probe = Backlink {
        uri: AtUri::from_parts("did:plc:probe", "app.bsky.graph.follow", "probe"),
        path: BacklinkPath::Subject,
        link_to: target_did.to_string(),
    };
    let collection = Nsid::new("app.bsky.graph.follow").expect("valid nsid");
    repos
        .backlink
        .get_backlink_conflicts(repo_id, &collection, &[probe])
        .await
        .expect("backlink query")
        .into_iter()
        .map(|u| u.as_str().to_string())
        .collect()
}

#[tokio::test]
async fn test_apply_writes_update_then_update_same_rkey() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let now = Utc::now().to_rfc3339();
    let rkey = format!("double_update_{}", Utc::now().timestamp_millis());

    let create_payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": rkey,
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "v0",
            "createdAt": now
        }
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to create");
    assert_eq!(res.status(), StatusCode::OK);

    let payload = json!({
        "repo": did,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#update",
                "collection": "app.bsky.feed.post",
                "rkey": rkey,
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "v1",
                    "createdAt": now
                }
            },
            {
                "$type": "com.atproto.repo.applyWrites#update",
                "collection": "app.bsky.feed.post",
                "rkey": rkey,
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "v2",
                    "createdAt": now
                }
            }
        ]
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
        .expect("Failed to send applyWrites");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    let final_cid = body["results"]
        .as_array()
        .and_then(|r| r.last())
        .and_then(|r| r["cid"].as_str())
        .expect("last result must carry a cid")
        .to_string();

    let get_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkey", rkey.as_str()),
        ])
        .send()
        .await
        .expect("Failed to fetch record");
    assert_eq!(get_res.status(), StatusCode::OK);
    let stored: Value = get_res.json().await.expect("Response was not valid JSON");
    assert_eq!(stored["value"]["text"], json!("v2"));
    assert_eq!(stored["cid"], json!(final_cid));
}

#[tokio::test]
async fn test_apply_writes_update_then_delete_same_rkey() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let now = Utc::now().to_rfc3339();
    let rkey = format!("update_delete_{}", Utc::now().timestamp_millis());

    let create_payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": rkey,
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "v0",
            "createdAt": now
        }
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to create");
    assert_eq!(res.status(), StatusCode::OK);

    let payload = json!({
        "repo": did,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#update",
                "collection": "app.bsky.feed.post",
                "rkey": rkey,
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "v1",
                    "createdAt": now
                }
            },
            {
                "$type": "com.atproto.repo.applyWrites#delete",
                "collection": "app.bsky.feed.post",
                "rkey": rkey
            }
        ]
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
        .expect("Failed to send applyWrites");
    assert_eq!(res.status(), StatusCode::OK);

    let get_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkey", rkey.as_str()),
        ])
        .send()
        .await
        .expect("Failed to fetch record");
    assert_eq!(get_res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_apply_writes_delete_then_update_same_rkey_rejected() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let now = Utc::now().to_rfc3339();
    let rkey = format!("delete_update_{}", Utc::now().timestamp_millis());

    let create_payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": rkey,
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "v0",
            "createdAt": now
        }
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to seed record");
    assert_eq!(res.status(), StatusCode::OK);

    let payload = json!({
        "repo": did,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#delete",
                "collection": "app.bsky.feed.post",
                "rkey": rkey
            },
            {
                "$type": "com.atproto.repo.applyWrites#update",
                "collection": "app.bsky.feed.post",
                "rkey": rkey,
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "v1",
                    "createdAt": now
                }
            }
        ]
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
        .expect("Failed to send applyWrites");
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "update of a record deleted earlier in the same batch must be rejected"
    );

    let get_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkey", rkey.as_str()),
        ])
        .send()
        .await
        .expect("Failed to fetch record");
    assert_eq!(get_res.status(), StatusCode::OK);
    let body: Value = get_res.json().await.expect("Response was not valid JSON");
    assert_eq!(
        body["value"]["text"],
        json!("v0"),
        "rejected batch must leave the seed record untouched"
    );
}

#[tokio::test]
async fn test_apply_writes_create_update_delete_same_rkey() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let now = Utc::now().to_rfc3339();
    let rkey = format!("triple_{}", Utc::now().timestamp_millis());

    let payload = json!({
        "repo": did,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "rkey": rkey,
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "v0",
                    "createdAt": now
                }
            },
            {
                "$type": "com.atproto.repo.applyWrites#update",
                "collection": "app.bsky.feed.post",
                "rkey": rkey,
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "v1",
                    "createdAt": now
                }
            },
            {
                "$type": "com.atproto.repo.applyWrites#delete",
                "collection": "app.bsky.feed.post",
                "rkey": rkey
            }
        ]
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
        .expect("Failed to send applyWrites");
    assert_eq!(res.status(), StatusCode::OK);

    let get_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkey", rkey.as_str()),
        ])
        .send()
        .await
        .expect("Failed to fetch record");
    assert_eq!(get_res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_apply_writes_distinct_rkeys_not_conflated() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let now = Utc::now().to_rfc3339();
    let stamp = Utc::now().timestamp_millis();
    let rkey_a = format!("distinct_a_{}", stamp);
    let rkey_b = format!("distinct_b_{}", stamp);

    let create_a = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": rkey_a,
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "a0",
            "createdAt": now
        }
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&create_a)
        .send()
        .await
        .expect("Failed to seed rkey_a");
    assert_eq!(res.status(), StatusCode::OK);

    let payload = json!({
        "repo": did,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#delete",
                "collection": "app.bsky.feed.post",
                "rkey": rkey_a
            },
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "rkey": rkey_a,
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "a1",
                    "createdAt": now
                }
            },
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "rkey": rkey_b,
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "b",
                    "createdAt": now
                }
            }
        ]
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
        .expect("Failed to send applyWrites");
    assert_eq!(res.status(), StatusCode::OK);

    let fetch = |rkey: String| {
        let did = did.clone();
        let client = client.clone();
        async move {
            let res = client
                .get(format!(
                    "{}/xrpc/com.atproto.repo.getRecord",
                    base_url().await
                ))
                .query(&[
                    ("repo", did.as_str()),
                    ("collection", "app.bsky.feed.post"),
                    ("rkey", rkey.as_str()),
                ])
                .send()
                .await
                .expect("Failed to fetch record");
            assert_eq!(res.status(), StatusCode::OK);
            let body: Value = res.json().await.expect("Response was not valid JSON");
            body["value"]["text"].as_str().unwrap().to_string()
        }
    };

    assert_eq!(fetch(rkey_a.clone()).await, "a1");
    assert_eq!(fetch(rkey_b.clone()).await, "b");
}

#[tokio::test]
async fn test_apply_writes_follow_create_then_delete_no_orphan_backlink() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let now = Utc::now().to_rfc3339();
    let rkey = format!("follow_orphan_{}", Utc::now().timestamp_millis());
    let target = "did:plc:orphantargettestabcdefgh";

    let payload = json!({
        "repo": did,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.graph.follow",
                "rkey": rkey,
                "value": {
                    "$type": "app.bsky.graph.follow",
                    "subject": target,
                    "createdAt": now
                }
            },
            {
                "$type": "com.atproto.repo.applyWrites#delete",
                "collection": "app.bsky.graph.follow",
                "rkey": rkey
            }
        ]
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
        .expect("Failed to send applyWrites");
    assert_eq!(res.status(), StatusCode::OK);

    let repo_id = repo_id_for_did(&did).await;
    let lingering = follow_uris_pointing_to(repo_id, target).await;
    assert!(
        lingering.is_empty(),
        "follow record was deleted in same batch but backlink survived: {:?}",
        lingering
    );
}

#[tokio::test]
async fn test_apply_writes_follow_update_update_final_link_wins() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let now = Utc::now().to_rfc3339();
    let rkey = format!("follow_doubleupdate_{}", Utc::now().timestamp_millis());
    let target_initial = "did:plc:initialtarget1234567890";
    let target_intermediate = "did:plc:intermediatetarget12345";
    let target_final = "did:plc:finaltarget1234567890ab";

    let create_payload = json!({
        "repo": did,
        "collection": "app.bsky.graph.follow",
        "rkey": rkey,
        "record": {
            "$type": "app.bsky.graph.follow",
            "subject": target_initial,
            "createdAt": now
        }
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to create initial follow");
    assert_eq!(res.status(), StatusCode::OK);

    let payload = json!({
        "repo": did,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#update",
                "collection": "app.bsky.graph.follow",
                "rkey": rkey,
                "value": {
                    "$type": "app.bsky.graph.follow",
                    "subject": target_intermediate,
                    "createdAt": now
                }
            },
            {
                "$type": "com.atproto.repo.applyWrites#update",
                "collection": "app.bsky.graph.follow",
                "rkey": rkey,
                "value": {
                    "$type": "app.bsky.graph.follow",
                    "subject": target_final,
                    "createdAt": now
                }
            }
        ]
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
        .expect("Failed to send applyWrites");
    assert_eq!(res.status(), StatusCode::OK);

    let repo_id = repo_id_for_did(&did).await;
    let expected_uri = format!("at://{}/app.bsky.graph.follow/{}", did, rkey);

    let final_links = follow_uris_pointing_to(repo_id, target_final).await;
    assert_eq!(
        final_links,
        vec![expected_uri.clone()],
        "backlink must point to final subject"
    );

    let intermediate_links = follow_uris_pointing_to(repo_id, target_intermediate).await;
    assert!(
        intermediate_links.is_empty(),
        "intermediate subject must not retain a backlink: {:?}",
        intermediate_links
    );

    let initial_links = follow_uris_pointing_to(repo_id, target_initial).await;
    assert!(
        initial_links.is_empty(),
        "initial subject backlink must be cleared: {:?}",
        initial_links
    );
}

#[tokio::test]
async fn test_apply_writes_create_create_same_rkey_rejected() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let now = Utc::now().to_rfc3339();
    let rkey = format!("dup_create_{}", Utc::now().timestamp_millis());

    let payload = json!({
        "repo": did,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "rkey": rkey,
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "first",
                    "createdAt": now
                }
            },
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "rkey": rkey,
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "second",
                    "createdAt": now
                }
            }
        ]
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
        .expect("Failed to send applyWrites");
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "duplicate create on same rkey within a batch must be rejected"
    );

    let get_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkey", rkey.as_str()),
        ])
        .send()
        .await
        .expect("Failed to fetch record");
    assert_eq!(
        get_res.status(),
        StatusCode::NOT_FOUND,
        "rejected batch must not have produced a record"
    );
}

#[tokio::test]
async fn test_apply_writes_update_then_create_same_rkey_rejected() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let now = Utc::now().to_rfc3339();
    let rkey = format!("update_create_{}", Utc::now().timestamp_millis());

    let create_payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": rkey,
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "v0",
            "createdAt": now
        }
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to seed record");
    assert_eq!(res.status(), StatusCode::OK);

    let payload = json!({
        "repo": did,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#update",
                "collection": "app.bsky.feed.post",
                "rkey": rkey,
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "v1",
                    "createdAt": now
                }
            },
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "rkey": rkey,
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "v2",
                    "createdAt": now
                }
            }
        ]
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
        .expect("Failed to send applyWrites");
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "create over a record live in this batch must be rejected"
    );

    let get_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkey", rkey.as_str()),
        ])
        .send()
        .await
        .expect("Failed to fetch record");
    assert_eq!(get_res.status(), StatusCode::OK);
    let body: Value = get_res.json().await.expect("Response was not valid JSON");
    assert_eq!(
        body["value"]["text"],
        json!("v0"),
        "rejected batch must leave the seed record untouched"
    );
}

#[tokio::test]
async fn test_create_record_rejects_existing_rkey() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let now = Utc::now().to_rfc3339();
    let rkey = format!("existing_{}", Utc::now().timestamp_millis());

    let seed = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": rkey,
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "first",
            "createdAt": now
        }
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&seed)
        .send()
        .await
        .expect("Failed initial create");
    assert_eq!(res.status(), StatusCode::OK);

    let dup = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": rkey,
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "second",
            "createdAt": now
        }
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&dup)
        .send()
        .await
        .expect("Failed duplicate create");
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "createRecord on an existing rkey must be rejected"
    );

    let get_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkey", rkey.as_str()),
        ])
        .send()
        .await
        .expect("Failed to fetch record");
    assert_eq!(get_res.status(), StatusCode::OK);
    let body: Value = get_res.json().await.expect("Response was not valid JSON");
    assert_eq!(
        body["value"]["text"],
        json!("first"),
        "duplicate create must not have overwritten the original"
    );
}
