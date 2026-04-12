mod common;
mod helpers;
use common::*;
use helpers::*;
use reqwest::StatusCode;
use std::sync::Once;

static SET_SEMAPHORE: Once = Once::new();

fn ensure_low_semaphore() {
    SET_SEMAPHORE.call_once(|| unsafe {
        std::env::set_var("MAX_CONCURRENT_REPO_EXPORTS", "1");
    });
}

#[tokio::test]
async fn test_get_repo_succeeds_with_many_records() {
    ensure_low_semaphore();
    let client = client();
    let (did, jwt) = setup_new_user("sync-batched-car").await;

    let create_futures = (0..20).map(|i| {
        let client = &client;
        let did = &did;
        let jwt = &jwt;
        async move {
            create_post(client, did, jwt, &format!("Batch test post {}", i)).await;
        }
    });
    futures::future::join_all(create_futures).await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getRepo",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to send getRepo request");

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok()),
        Some("application/vnd.ipld.car")
    );
    let car_bytes = res.bytes().await.expect("Failed to read response body");
    assert!(
        car_bytes.len() > 200,
        "CAR with 20 records should have substantial data, got {} bytes",
        car_bytes.len()
    );
}

#[tokio::test]
async fn test_get_repo_semaphore_rejects_excess_concurrency() {
    ensure_low_semaphore();
    let client = client();
    let (did, jwt) = setup_new_user("sync-semaphore").await;

    for i in 0..50 {
        create_post(&client, &did, &jwt, &format!("Padding post {}", i)).await;
    }

    let base = base_url().await;
    let concurrent_requests = 10;

    let request_futures = (0..concurrent_requests).map(|_| {
        let client = client.clone();
        let did = did.clone();
        async move {
            client
                .get(format!("{}/xrpc/com.atproto.sync.getRepo", base))
                .query(&[("did", did.as_str())])
                .send()
                .await
                .expect("Failed to send request")
                .status()
        }
    });

    let statuses: Vec<StatusCode> = futures::future::join_all(request_futures).await;
    let ok_count = statuses.iter().filter(|s| **s == StatusCode::OK).count();
    let rejected_count = statuses
        .iter()
        .filter(|s| **s == StatusCode::SERVICE_UNAVAILABLE)
        .count();

    assert!(ok_count >= 1, "at least one request should succeed");
    assert!(
        rejected_count > 0,
        "semaphore=1 with {} concurrent requests, expected some 503 rejections",
        concurrent_requests
    );
    assert!(
        ok_count + rejected_count == statuses.len(),
        "expected only 200 or 503 responses: {:?}",
        statuses
    );
}

#[tokio::test]
async fn test_get_repo_since_not_affected_by_semaphore() {
    ensure_low_semaphore();
    let client = client();
    let (did, jwt) = setup_new_user("sync-since-no-sem").await;
    create_post(&client, &did, &jwt, "First post").await;

    let latest_res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getLatestCommit",
            base_url().await
        ))
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to get latest commit");
    let body: serde_json::Value = latest_res.json().await.unwrap();
    let rev = body["rev"].as_str().unwrap();

    create_post(&client, &did, &jwt, "Second post").await;

    let base = base_url().await;
    let request_futures = (0..10).map(|_| {
        let client = client.clone();
        let did = did.clone();
        let rev = rev.to_string();
        async move {
            client
                .get(format!("{}/xrpc/com.atproto.sync.getRepo", base))
                .query(&[("did", did.as_str()), ("since", rev.as_str())])
                .send()
                .await
                .expect("Failed to send request")
                .status()
        }
    });

    let statuses: Vec<StatusCode> = futures::future::join_all(request_futures).await;
    assert!(
        statuses.iter().all(|s| *s == StatusCode::OK),
        "getRepo with since should bypass semaphore, got: {:?}",
        statuses
    );
}
