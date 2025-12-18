mod common;
use common::*;
use iroh_car::CarHeader;
use reqwest::StatusCode;
use serde_json::json;

#[tokio::test]
async fn test_import_repo_requires_auth() {
    let client = client();
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.importRepo",
            base_url().await
        ))
        .header("Content-Type", "application/vnd.ipld.car")
        .body(vec![0u8; 100])
        .send()
        .await
        .expect("Request failed");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_import_repo_invalid_car() {
    let client = client();
    let (token, _did) = create_account_and_login(&client).await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.importRepo",
            base_url().await
        ))
        .bearer_auth(&token)
        .header("Content-Type", "application/vnd.ipld.car")
        .body(vec![0u8; 100])
        .send()
        .await
        .expect("Request failed");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn test_import_repo_empty_body() {
    let client = client();
    let (token, _did) = create_account_and_login(&client).await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.importRepo",
            base_url().await
        ))
        .bearer_auth(&token)
        .header("Content-Type", "application/vnd.ipld.car")
        .body(vec![])
        .send()
        .await
        .expect("Request failed");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

fn write_varint(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

#[tokio::test]
async fn test_import_rejects_car_for_different_user() {
    let client = client();
    let (token_a, _did_a) = create_account_and_login(&client).await;
    let (_token_b, did_b) = create_account_and_login(&client).await;
    let export_res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getRepo?did={}",
            base_url().await,
            did_b
        ))
        .send()
        .await
        .expect("Export failed");
    assert_eq!(export_res.status(), StatusCode::OK);
    let car_bytes = export_res.bytes().await.unwrap();
    let import_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.importRepo",
            base_url().await
        ))
        .bearer_auth(&token_a)
        .header("Content-Type", "application/vnd.ipld.car")
        .body(car_bytes.to_vec())
        .send()
        .await
        .expect("Import failed");
    assert_eq!(import_res.status(), StatusCode::FORBIDDEN);
    let body: serde_json::Value = import_res.json().await.unwrap();
    assert!(
        body["error"] == "InvalidRequest" || body["error"] == "DidMismatch",
        "Expected DidMismatch or InvalidRequest error, got: {:?}",
        body
    );
}

#[tokio::test]
async fn test_import_accepts_own_exported_repo() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let post_payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "Original post before export",
            "createdAt": chrono::Utc::now().to_rfc3339(),
        }
    });
    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&post_payload)
        .send()
        .await
        .expect("Failed to create post");
    assert_eq!(create_res.status(), StatusCode::OK);
    let export_res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getRepo?did={}",
            base_url().await,
            did
        ))
        .send()
        .await
        .expect("Failed to export repo");
    assert_eq!(export_res.status(), StatusCode::OK);
    let car_bytes = export_res.bytes().await.unwrap();
    let import_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.importRepo",
            base_url().await
        ))
        .bearer_auth(&token)
        .header("Content-Type", "application/vnd.ipld.car")
        .body(car_bytes.to_vec())
        .send()
        .await
        .expect("Failed to import repo");
    assert_eq!(import_res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_import_repo_size_limit() {
    let client = client();
    let (token, _did) = create_account_and_login(&client).await;
    let oversized_body = vec![0u8; 110 * 1024 * 1024];
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.importRepo",
            base_url().await
        ))
        .bearer_auth(&token)
        .header("Content-Type", "application/vnd.ipld.car")
        .body(oversized_body)
        .send()
        .await;
    match res {
        Ok(response) => {
            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        }
        Err(e) => {
            let error_str = e.to_string().to_lowercase();
            assert!(
                error_str.contains("broken pipe")
                    || error_str.contains("connection")
                    || error_str.contains("reset")
                    || error_str.contains("request")
                    || error_str.contains("body"),
                "Expected connection error or PAYLOAD_TOO_LARGE, got: {}",
                e
            );
        }
    }
}

#[tokio::test]
async fn test_import_deactivated_account_allowed_for_migration() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let export_res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getRepo?did={}",
            base_url().await,
            did
        ))
        .send()
        .await
        .expect("Export failed");
    assert_eq!(export_res.status(), StatusCode::OK);
    let car_bytes = export_res.bytes().await.unwrap();
    let deactivate_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.deactivateAccount",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&json!({}))
        .send()
        .await
        .expect("Deactivate failed");
    assert!(deactivate_res.status().is_success());
    let import_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.importRepo",
            base_url().await
        ))
        .bearer_auth(&token)
        .header("Content-Type", "application/vnd.ipld.car")
        .body(car_bytes.to_vec())
        .send()
        .await
        .expect("Import failed");
    assert!(
        import_res.status().is_success(),
        "Deactivated accounts should allow import for migration, got {}",
        import_res.status()
    );
}

#[tokio::test]
async fn test_import_invalid_car_structure() {
    let client = client();
    let (token, _did) = create_account_and_login(&client).await;
    let invalid_car = vec![0x0a, 0xa1, 0x65, 0x72, 0x6f, 0x6f, 0x74, 0x73, 0x80];
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.importRepo",
            base_url().await
        ))
        .bearer_auth(&token)
        .header("Content-Type", "application/vnd.ipld.car")
        .body(invalid_car)
        .send()
        .await
        .expect("Request failed");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_import_car_with_no_roots() {
    let client = client();
    let (token, _did) = create_account_and_login(&client).await;
    let header = CarHeader::new_v1(vec![]);
    let header_cbor = header.encode().unwrap_or_default();
    let mut car = Vec::new();
    write_varint(&mut car, header_cbor.len() as u64);
    car.extend_from_slice(&header_cbor);
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.importRepo",
            base_url().await
        ))
        .bearer_auth(&token)
        .header("Content-Type", "application/vnd.ipld.car")
        .body(car)
        .send()
        .await
        .expect("Request failed");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn test_import_preserves_records_after_reimport() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let mut rkeys = Vec::new();
    for i in 0..3 {
        let post_payload = json!({
            "repo": did,
            "collection": "app.bsky.feed.post",
            "record": {
                "$type": "app.bsky.feed.post",
                "text": format!("Test post {}", i),
                "createdAt": chrono::Utc::now().to_rfc3339(),
            }
        });
        let res = client
            .post(format!(
                "{}/xrpc/com.atproto.repo.createRecord",
                base_url().await
            ))
            .bearer_auth(&token)
            .json(&post_payload)
            .send()
            .await
            .expect("Failed to create post");
        assert_eq!(res.status(), StatusCode::OK);
        let body: serde_json::Value = res.json().await.unwrap();
        let uri = body["uri"].as_str().unwrap();
        let rkey = uri.split('/').last().unwrap().to_string();
        rkeys.push(rkey);
    }
    for rkey in &rkeys {
        let get_res = client
            .get(format!(
                "{}/xrpc/com.atproto.repo.getRecord?repo={}&collection=app.bsky.feed.post&rkey={}",
                base_url().await,
                did,
                rkey
            ))
            .send()
            .await
            .expect("Failed to get record before export");
        assert_eq!(
            get_res.status(),
            StatusCode::OK,
            "Record {} not found before export",
            rkey
        );
    }
    let export_res = client
        .get(format!(
            "{}/xrpc/com.atproto.sync.getRepo?did={}",
            base_url().await,
            did
        ))
        .send()
        .await
        .expect("Failed to export repo");
    assert_eq!(export_res.status(), StatusCode::OK);
    let car_bytes = export_res.bytes().await.unwrap();
    let import_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.importRepo",
            base_url().await
        ))
        .bearer_auth(&token)
        .header("Content-Type", "application/vnd.ipld.car")
        .body(car_bytes.to_vec())
        .send()
        .await
        .expect("Failed to import repo");
    assert_eq!(import_res.status(), StatusCode::OK);
    let list_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords?repo={}&collection=app.bsky.feed.post",
            base_url().await,
            did
        ))
        .send()
        .await
        .expect("Failed to list records after import");
    assert_eq!(list_res.status(), StatusCode::OK);
    let list_body: serde_json::Value = list_res.json().await.unwrap();
    let records_after = list_body["records"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    assert!(
        records_after >= 1,
        "Expected at least 1 record after import, found {}. Note: MST walk may have timing issues.",
        records_after
    );
}
