mod common;
mod helpers;
use common::*;
use helpers::*;

use chrono::Utc;
use reqwest::StatusCode;
use serde_json::{Value, json};
use std::time::Duration;

async fn create_post_with_rkey(
    client: &reqwest::Client,
    did: &str,
    jwt: &str,
    rkey: &str,
    text: &str,
) -> (String, String) {
    let payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": rkey,
        "record": {
            "$type": "app.bsky.feed.post",
            "text": text,
            "createdAt": Utc::now().to_rfc3339()
        }
    });

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(jwt)
        .json(&payload)
        .send()
        .await
        .expect("Failed to create record");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    (
        body["uri"].as_str().unwrap().to_string(),
        body["cid"].as_str().unwrap().to_string(),
    )
}

#[tokio::test]
async fn test_list_records_default_order() {
    let client = client();
    let (did, jwt) = setup_new_user("list-default-order").await;

    create_post_with_rkey(&client, &did, &jwt, "aaaa", "First post").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    create_post_with_rkey(&client, &did, &jwt, "bbbb", "Second post").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    create_post_with_rkey(&client, &did, &jwt, "cccc", "Third post").await;

    let res = client
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

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let records = body["records"].as_array().unwrap();

    assert_eq!(records.len(), 3);
    let rkeys: Vec<&str> = records
        .iter()
        .map(|r| r["uri"].as_str().unwrap().split('/').last().unwrap())
        .collect();

    assert_eq!(rkeys, vec!["cccc", "bbbb", "aaaa"], "Default order should be DESC (newest first)");
}

#[tokio::test]
async fn test_list_records_reverse_true() {
    let client = client();
    let (did, jwt) = setup_new_user("list-reverse").await;

    create_post_with_rkey(&client, &did, &jwt, "aaaa", "First post").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    create_post_with_rkey(&client, &did, &jwt, "bbbb", "Second post").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    create_post_with_rkey(&client, &did, &jwt, "cccc", "Third post").await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("reverse", "true"),
        ])
        .send()
        .await
        .expect("Failed to list records");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let records = body["records"].as_array().unwrap();

    let rkeys: Vec<&str> = records
        .iter()
        .map(|r| r["uri"].as_str().unwrap().split('/').last().unwrap())
        .collect();

    assert_eq!(rkeys, vec!["aaaa", "bbbb", "cccc"], "reverse=true should give ASC order (oldest first)");
}

#[tokio::test]
async fn test_list_records_cursor_pagination() {
    let client = client();
    let (did, jwt) = setup_new_user("list-cursor").await;

    for i in 0..5 {
        create_post_with_rkey(&client, &did, &jwt, &format!("post{:02}", i), &format!("Post {}", i)).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("limit", "2"),
        ])
        .send()
        .await
        .expect("Failed to list records");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let records = body["records"].as_array().unwrap();
    assert_eq!(records.len(), 2);

    let cursor = body["cursor"].as_str().expect("Should have cursor with more records");

    let res2 = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("limit", "2"),
            ("cursor", cursor),
        ])
        .send()
        .await
        .expect("Failed to list records with cursor");

    assert_eq!(res2.status(), StatusCode::OK);
    let body2: Value = res2.json().await.unwrap();
    let records2 = body2["records"].as_array().unwrap();
    assert_eq!(records2.len(), 2);

    let all_uris: Vec<&str> = records
        .iter()
        .chain(records2.iter())
        .map(|r| r["uri"].as_str().unwrap())
        .collect();
    let unique_uris: std::collections::HashSet<&str> = all_uris.iter().copied().collect();
    assert_eq!(all_uris.len(), unique_uris.len(), "Cursor pagination should not repeat records");
}

#[tokio::test]
async fn test_list_records_rkey_start() {
    let client = client();
    let (did, jwt) = setup_new_user("list-rkey-start").await;

    create_post_with_rkey(&client, &did, &jwt, "aaaa", "First").await;
    create_post_with_rkey(&client, &did, &jwt, "bbbb", "Second").await;
    create_post_with_rkey(&client, &did, &jwt, "cccc", "Third").await;
    create_post_with_rkey(&client, &did, &jwt, "dddd", "Fourth").await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkeyStart", "bbbb"),
            ("reverse", "true"),
        ])
        .send()
        .await
        .expect("Failed to list records");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let records = body["records"].as_array().unwrap();

    let rkeys: Vec<&str> = records
        .iter()
        .map(|r| r["uri"].as_str().unwrap().split('/').last().unwrap())
        .collect();

    for rkey in &rkeys {
        assert!(*rkey >= "bbbb", "rkeyStart should filter records >= start");
    }
}

#[tokio::test]
async fn test_list_records_rkey_end() {
    let client = client();
    let (did, jwt) = setup_new_user("list-rkey-end").await;

    create_post_with_rkey(&client, &did, &jwt, "aaaa", "First").await;
    create_post_with_rkey(&client, &did, &jwt, "bbbb", "Second").await;
    create_post_with_rkey(&client, &did, &jwt, "cccc", "Third").await;
    create_post_with_rkey(&client, &did, &jwt, "dddd", "Fourth").await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkeyEnd", "cccc"),
            ("reverse", "true"),
        ])
        .send()
        .await
        .expect("Failed to list records");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let records = body["records"].as_array().unwrap();

    let rkeys: Vec<&str> = records
        .iter()
        .map(|r| r["uri"].as_str().unwrap().split('/').last().unwrap())
        .collect();

    for rkey in &rkeys {
        assert!(*rkey <= "cccc", "rkeyEnd should filter records <= end");
    }
}

#[tokio::test]
async fn test_list_records_rkey_range() {
    let client = client();
    let (did, jwt) = setup_new_user("list-rkey-range").await;

    create_post_with_rkey(&client, &did, &jwt, "aaaa", "First").await;
    create_post_with_rkey(&client, &did, &jwt, "bbbb", "Second").await;
    create_post_with_rkey(&client, &did, &jwt, "cccc", "Third").await;
    create_post_with_rkey(&client, &did, &jwt, "dddd", "Fourth").await;
    create_post_with_rkey(&client, &did, &jwt, "eeee", "Fifth").await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkeyStart", "bbbb"),
            ("rkeyEnd", "dddd"),
            ("reverse", "true"),
        ])
        .send()
        .await
        .expect("Failed to list records");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let records = body["records"].as_array().unwrap();

    let rkeys: Vec<&str> = records
        .iter()
        .map(|r| r["uri"].as_str().unwrap().split('/').last().unwrap())
        .collect();

    for rkey in &rkeys {
        assert!(*rkey >= "bbbb" && *rkey <= "dddd", "Range should be inclusive, got {}", rkey);
    }
    assert!(!rkeys.is_empty(), "Should have at least some records in range");
}

#[tokio::test]
async fn test_list_records_limit_clamping_max() {
    let client = client();
    let (did, jwt) = setup_new_user("list-limit-max").await;

    for i in 0..5 {
        create_post_with_rkey(&client, &did, &jwt, &format!("post{:02}", i), &format!("Post {}", i)).await;
    }

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("limit", "1000"),
        ])
        .send()
        .await
        .expect("Failed to list records");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let records = body["records"].as_array().unwrap();
    assert!(records.len() <= 100, "Limit should be clamped to max 100");
}

#[tokio::test]
async fn test_list_records_limit_clamping_min() {
    let client = client();
    let (did, jwt) = setup_new_user("list-limit-min").await;

    create_post_with_rkey(&client, &did, &jwt, "aaaa", "Post").await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("limit", "0"),
        ])
        .send()
        .await
        .expect("Failed to list records");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let records = body["records"].as_array().unwrap();
    assert!(records.len() >= 1, "Limit should be clamped to min 1");
}

#[tokio::test]
async fn test_list_records_empty_collection() {
    let client = client();
    let (did, _jwt) = setup_new_user("list-empty").await;

    let res = client
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

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let records = body["records"].as_array().unwrap();
    assert!(records.is_empty(), "Empty collection should return empty array");
    assert!(body["cursor"].is_null(), "Empty collection should have no cursor");
}

#[tokio::test]
async fn test_list_records_exact_limit() {
    let client = client();
    let (did, jwt) = setup_new_user("list-exact-limit").await;

    for i in 0..10 {
        create_post_with_rkey(&client, &did, &jwt, &format!("post{:02}", i), &format!("Post {}", i)).await;
    }

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("limit", "5"),
        ])
        .send()
        .await
        .expect("Failed to list records");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let records = body["records"].as_array().unwrap();
    assert_eq!(records.len(), 5, "Should return exactly 5 records when limit=5");
}

#[tokio::test]
async fn test_list_records_cursor_exhaustion() {
    let client = client();
    let (did, jwt) = setup_new_user("list-cursor-exhaust").await;

    for i in 0..3 {
        create_post_with_rkey(&client, &did, &jwt, &format!("post{:02}", i), &format!("Post {}", i)).await;
    }

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("limit", "10"),
        ])
        .send()
        .await
        .expect("Failed to list records");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let records = body["records"].as_array().unwrap();
    assert_eq!(records.len(), 3);
}

#[tokio::test]
async fn test_list_records_repo_not_found() {
    let client = client();

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", "did:plc:nonexistent12345"),
            ("collection", "app.bsky.feed.post"),
        ])
        .send()
        .await
        .expect("Failed to list records");

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_list_records_includes_cid() {
    let client = client();
    let (did, jwt) = setup_new_user("list-includes-cid").await;

    create_post_with_rkey(&client, &did, &jwt, "test", "Test post").await;

    let res = client
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

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let records = body["records"].as_array().unwrap();

    for record in records {
        assert!(record["uri"].is_string(), "Record should have uri");
        assert!(record["cid"].is_string(), "Record should have cid");
        assert!(record["value"].is_object(), "Record should have value");
        let cid = record["cid"].as_str().unwrap();
        assert!(cid.starts_with("bafy"), "CID should be valid");
    }
}

#[tokio::test]
async fn test_list_records_cursor_with_reverse() {
    let client = client();
    let (did, jwt) = setup_new_user("list-cursor-reverse").await;

    for i in 0..5 {
        create_post_with_rkey(&client, &did, &jwt, &format!("post{:02}", i), &format!("Post {}", i)).await;
    }

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords",
            base_url().await
        ))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("limit", "2"),
            ("reverse", "true"),
        ])
        .send()
        .await
        .expect("Failed to list records");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let records = body["records"].as_array().unwrap();
    let first_rkeys: Vec<&str> = records
        .iter()
        .map(|r| r["uri"].as_str().unwrap().split('/').last().unwrap())
        .collect();

    assert_eq!(first_rkeys, vec!["post00", "post01"], "First page with reverse should start from oldest");

    if let Some(cursor) = body["cursor"].as_str() {
        let res2 = client
            .get(format!(
                "{}/xrpc/com.atproto.repo.listRecords",
                base_url().await
            ))
            .query(&[
                ("repo", did.as_str()),
                ("collection", "app.bsky.feed.post"),
                ("limit", "2"),
                ("reverse", "true"),
                ("cursor", cursor),
            ])
            .send()
            .await
            .expect("Failed to list records with cursor");

        let body2: Value = res2.json().await.unwrap();
        let records2 = body2["records"].as_array().unwrap();
        let second_rkeys: Vec<&str> = records2
            .iter()
            .map(|r| r["uri"].as_str().unwrap().split('/').last().unwrap())
            .collect();

        assert_eq!(second_rkeys, vec!["post02", "post03"], "Second page should continue in ASC order");
    }
}
