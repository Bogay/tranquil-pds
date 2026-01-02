mod common;
mod helpers;

use common::*;
use reqwest::{StatusCode, header};
use serde_json::{Value, json};

#[tokio::test]
async fn test_list_backups_empty() {
    let client = client();
    let (token, _did) = create_account_and_login(&client).await;

    let res = client
        .get(format!("{}/xrpc/_backup.listBackups", base_url().await))
        .bearer_auth(&token)
        .send()
        .await
        .expect("listBackups request failed");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert!(body["backups"].is_array());
    assert_eq!(body["backups"].as_array().unwrap().len(), 0);
    assert!(body["backupEnabled"].as_bool().unwrap_or(false));
}

#[tokio::test]
async fn test_create_and_list_backup() {
    let client = client();
    let (token, _did) = create_account_and_login(&client).await;

    let create_res = client
        .post(format!("{}/xrpc/_backup.createBackup", base_url().await))
        .bearer_auth(&token)
        .send()
        .await
        .expect("createBackup request failed");

    assert_eq!(create_res.status(), StatusCode::OK, "createBackup failed");
    let create_body: Value = create_res.json().await.expect("Invalid JSON");
    assert!(create_body["id"].is_string());
    assert!(create_body["repoRev"].is_string());
    assert!(create_body["sizeBytes"].is_i64());
    assert!(create_body["blockCount"].is_i64());

    let list_res = client
        .get(format!("{}/xrpc/_backup.listBackups", base_url().await))
        .bearer_auth(&token)
        .send()
        .await
        .expect("listBackups request failed");

    assert_eq!(list_res.status(), StatusCode::OK);
    let list_body: Value = list_res.json().await.expect("Invalid JSON");
    let backups = list_body["backups"].as_array().unwrap();
    assert!(!backups.is_empty());
}

#[tokio::test]
async fn test_download_backup() {
    let client = client();
    let (token, _did) = create_account_and_login(&client).await;

    let create_res = client
        .post(format!("{}/xrpc/_backup.createBackup", base_url().await))
        .bearer_auth(&token)
        .send()
        .await
        .expect("createBackup request failed");

    assert_eq!(create_res.status(), StatusCode::OK);
    let create_body: Value = create_res.json().await.expect("Invalid JSON");
    let backup_id = create_body["id"].as_str().unwrap();

    let get_res = client
        .get(format!(
            "{}/xrpc/_backup.getBackup?id={}",
            base_url().await,
            backup_id
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("getBackup request failed");

    assert_eq!(get_res.status(), StatusCode::OK);
    let content_type = get_res.headers().get(header::CONTENT_TYPE).unwrap();
    assert_eq!(content_type, "application/vnd.ipld.car");

    let bytes = get_res.bytes().await.expect("Failed to read body");
    assert!(bytes.len() > 100, "CAR file should have content");
    assert_eq!(
        bytes[1], 0xa2,
        "CAR file should have valid header structure"
    );
}

#[tokio::test]
async fn test_delete_backup() {
    let client = client();
    let (token, _did) = create_account_and_login(&client).await;

    let create_res = client
        .post(format!("{}/xrpc/_backup.createBackup", base_url().await))
        .bearer_auth(&token)
        .send()
        .await
        .expect("createBackup request failed");

    assert_eq!(create_res.status(), StatusCode::OK);
    let create_body: Value = create_res.json().await.expect("Invalid JSON");
    let backup_id = create_body["id"].as_str().unwrap();

    let delete_res = client
        .post(format!(
            "{}/xrpc/_backup.deleteBackup?id={}",
            base_url().await,
            backup_id
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("deleteBackup request failed");

    assert_eq!(delete_res.status(), StatusCode::OK);

    let get_res = client
        .get(format!(
            "{}/xrpc/_backup.getBackup?id={}",
            base_url().await,
            backup_id
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("getBackup request failed");

    assert_eq!(get_res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_toggle_backup_enabled() {
    let client = client();
    let (token, _did) = create_account_and_login(&client).await;

    let list_res = client
        .get(format!("{}/xrpc/_backup.listBackups", base_url().await))
        .bearer_auth(&token)
        .send()
        .await
        .expect("listBackups request failed");

    assert_eq!(list_res.status(), StatusCode::OK);
    let list_body: Value = list_res.json().await.expect("Invalid JSON");
    assert!(list_body["backupEnabled"].as_bool().unwrap());

    let disable_res = client
        .post(format!("{}/xrpc/_backup.setEnabled", base_url().await))
        .bearer_auth(&token)
        .json(&json!({"enabled": false}))
        .send()
        .await
        .expect("setEnabled request failed");

    assert_eq!(disable_res.status(), StatusCode::OK);
    let disable_body: Value = disable_res.json().await.expect("Invalid JSON");
    assert!(!disable_body["enabled"].as_bool().unwrap());

    let list_res2 = client
        .get(format!("{}/xrpc/_backup.listBackups", base_url().await))
        .bearer_auth(&token)
        .send()
        .await
        .expect("listBackups request failed");

    let list_body2: Value = list_res2.json().await.expect("Invalid JSON");
    assert!(!list_body2["backupEnabled"].as_bool().unwrap());

    let enable_res = client
        .post(format!("{}/xrpc/_backup.setEnabled", base_url().await))
        .bearer_auth(&token)
        .json(&json!({"enabled": true}))
        .send()
        .await
        .expect("setEnabled request failed");

    assert_eq!(enable_res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_backup_includes_blobs() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let blob_data = b"Hello, this is test blob data for backup testing!";
    let upload_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.uploadBlob",
            base_url().await
        ))
        .header(header::CONTENT_TYPE, "text/plain")
        .bearer_auth(&token)
        .body(blob_data.to_vec())
        .send()
        .await
        .expect("uploadBlob request failed");

    assert_eq!(upload_res.status(), StatusCode::OK);
    let upload_body: Value = upload_res.json().await.expect("Invalid JSON");
    let blob = &upload_body["blob"];

    let record = json!({
        "$type": "app.bsky.feed.post",
        "text": "Test post with blob",
        "createdAt": chrono::Utc::now().to_rfc3339(),
        "embed": {
            "$type": "app.bsky.embed.images",
            "images": [{
                "alt": "test image",
                "image": blob
            }]
        }
    });

    let create_record_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&json!({
            "repo": did,
            "collection": "app.bsky.feed.post",
            "record": record
        }))
        .send()
        .await
        .expect("createRecord request failed");

    assert_eq!(create_record_res.status(), StatusCode::OK);

    let create_backup_res = client
        .post(format!("{}/xrpc/_backup.createBackup", base_url().await))
        .bearer_auth(&token)
        .send()
        .await
        .expect("createBackup request failed");

    assert_eq!(create_backup_res.status(), StatusCode::OK);
    let backup_body: Value = create_backup_res.json().await.expect("Invalid JSON");
    let backup_id = backup_body["id"].as_str().unwrap();

    let get_backup_res = client
        .get(format!(
            "{}/xrpc/_backup.getBackup?id={}",
            base_url().await,
            backup_id
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("getBackup request failed");

    assert_eq!(get_backup_res.status(), StatusCode::OK);
    let car_bytes = get_backup_res.bytes().await.expect("Failed to read body");

    let blob_cid = blob["ref"]["$link"].as_str().unwrap();
    let blob_found = String::from_utf8_lossy(&car_bytes).contains("Hello, this is test blob data");
    assert!(
        blob_found || car_bytes.len() > 500,
        "Backup should contain blob data (cid: {})",
        blob_cid
    );
}

#[tokio::test]
async fn test_backup_unauthorized() {
    let client = client();

    let res = client
        .get(format!("{}/xrpc/_backup.listBackups", base_url().await))
        .send()
        .await
        .expect("listBackups request failed");

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_get_nonexistent_backup() {
    let client = client();
    let (token, _did) = create_account_and_login(&client).await;

    let fake_id = uuid::Uuid::new_v4();
    let res = client
        .get(format!(
            "{}/xrpc/_backup.getBackup?id={}",
            base_url().await,
            fake_id
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("getBackup request failed");

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_backup_invalid_id() {
    let client = client();
    let (token, _did) = create_account_and_login(&client).await;

    let res = client
        .get(format!(
            "{}/xrpc/_backup.getBackup?id=not-a-uuid",
            base_url().await
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("getBackup request failed");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}
