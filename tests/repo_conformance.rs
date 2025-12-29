mod common;
mod helpers;
use chrono::Utc;
use common::*;
use helpers::*;
use reqwest::StatusCode;
use serde_json::{Value, json};

#[tokio::test]
async fn test_create_record_response_schema() {
    let client = client();
    let (did, jwt) = setup_new_user("conform-create").await;
    let now = Utc::now().to_rfc3339();

    let payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "Testing conformance",
            "createdAt": now
        }
    });

    let res = client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", base_url().await))
        .bearer_auth(&jwt)
        .json(&payload)
        .send()
        .await
        .expect("Failed to create record");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();

    assert!(body["uri"].is_string(), "response must have uri");
    assert!(body["cid"].is_string(), "response must have cid");
    assert!(body["cid"].as_str().unwrap().starts_with("bafy"), "cid must be valid");

    assert!(body["commit"].is_object(), "response must have commit object");
    let commit = &body["commit"];
    assert!(commit["cid"].is_string(), "commit must have cid");
    assert!(commit["cid"].as_str().unwrap().starts_with("bafy"), "commit.cid must be valid");
    assert!(commit["rev"].is_string(), "commit must have rev");

    assert!(body["validationStatus"].is_string(), "response must have validationStatus when validate defaults to true");
    assert_eq!(body["validationStatus"], "valid", "validationStatus should be 'valid'");
}

#[tokio::test]
async fn test_create_record_no_validation_status_when_validate_false() {
    let client = client();
    let (did, jwt) = setup_new_user("conform-create-noval").await;
    let now = Utc::now().to_rfc3339();

    let payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "validate": false,
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "Testing without validation",
            "createdAt": now
        }
    });

    let res = client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", base_url().await))
        .bearer_auth(&jwt)
        .json(&payload)
        .send()
        .await
        .expect("Failed to create record");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();

    assert!(body["uri"].is_string());
    assert!(body["commit"].is_object());
    assert!(body["validationStatus"].is_null(), "validationStatus should be omitted when validate=false");
}

#[tokio::test]
async fn test_put_record_response_schema() {
    let client = client();
    let (did, jwt) = setup_new_user("conform-put").await;
    let now = Utc::now().to_rfc3339();

    let payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": "conformance-put",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "Testing putRecord conformance",
            "createdAt": now
        }
    });

    let res = client
        .post(format!("{}/xrpc/com.atproto.repo.putRecord", base_url().await))
        .bearer_auth(&jwt)
        .json(&payload)
        .send()
        .await
        .expect("Failed to put record");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();

    assert!(body["uri"].is_string(), "response must have uri");
    assert!(body["cid"].is_string(), "response must have cid");

    assert!(body["commit"].is_object(), "response must have commit object");
    let commit = &body["commit"];
    assert!(commit["cid"].is_string(), "commit must have cid");
    assert!(commit["rev"].is_string(), "commit must have rev");

    assert_eq!(body["validationStatus"], "valid", "validationStatus should be 'valid'");
}

#[tokio::test]
async fn test_delete_record_response_schema() {
    let client = client();
    let (did, jwt) = setup_new_user("conform-delete").await;
    let now = Utc::now().to_rfc3339();

    let create_payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": "to-delete",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "This will be deleted",
            "createdAt": now
        }
    });
    let create_res = client
        .post(format!("{}/xrpc/com.atproto.repo.putRecord", base_url().await))
        .bearer_auth(&jwt)
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to create record");
    assert_eq!(create_res.status(), StatusCode::OK);

    let delete_payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": "to-delete"
    });
    let delete_res = client
        .post(format!("{}/xrpc/com.atproto.repo.deleteRecord", base_url().await))
        .bearer_auth(&jwt)
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to delete record");

    assert_eq!(delete_res.status(), StatusCode::OK);
    let body: Value = delete_res.json().await.unwrap();

    assert!(body["commit"].is_object(), "response must have commit object when record was deleted");
    let commit = &body["commit"];
    assert!(commit["cid"].is_string(), "commit must have cid");
    assert!(commit["rev"].is_string(), "commit must have rev");
}

#[tokio::test]
async fn test_delete_record_noop_response() {
    let client = client();
    let (did, jwt) = setup_new_user("conform-delete-noop").await;

    let delete_payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": "nonexistent-record"
    });
    let delete_res = client
        .post(format!("{}/xrpc/com.atproto.repo.deleteRecord", base_url().await))
        .bearer_auth(&jwt)
        .json(&delete_payload)
        .send()
        .await
        .expect("Failed to delete record");

    assert_eq!(delete_res.status(), StatusCode::OK);
    let body: Value = delete_res.json().await.unwrap();

    assert!(body["commit"].is_null(), "commit should be omitted on no-op delete");
}

#[tokio::test]
async fn test_apply_writes_response_schema() {
    let client = client();
    let (did, jwt) = setup_new_user("conform-apply").await;
    let now = Utc::now().to_rfc3339();

    let payload = json!({
        "repo": did,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "rkey": "apply-test-1",
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "First post",
                    "createdAt": now
                }
            },
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "rkey": "apply-test-2",
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "Second post",
                    "createdAt": now
                }
            }
        ]
    });

    let res = client
        .post(format!("{}/xrpc/com.atproto.repo.applyWrites", base_url().await))
        .bearer_auth(&jwt)
        .json(&payload)
        .send()
        .await
        .expect("Failed to apply writes");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();

    assert!(body["commit"].is_object(), "response must have commit object");
    let commit = &body["commit"];
    assert!(commit["cid"].is_string(), "commit must have cid");
    assert!(commit["rev"].is_string(), "commit must have rev");

    assert!(body["results"].is_array(), "response must have results array");
    let results = body["results"].as_array().unwrap();
    assert_eq!(results.len(), 2, "should have 2 results");

    for result in results {
        assert!(result["uri"].is_string(), "result must have uri");
        assert!(result["cid"].is_string(), "result must have cid");
        assert_eq!(result["validationStatus"], "valid", "result must have validationStatus");
        assert_eq!(result["$type"], "com.atproto.repo.applyWrites#createResult");
    }
}

#[tokio::test]
async fn test_apply_writes_update_and_delete_results() {
    let client = client();
    let (did, jwt) = setup_new_user("conform-apply-upd").await;
    let now = Utc::now().to_rfc3339();

    let create_payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": "to-update",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "Original",
            "createdAt": now
        }
    });
    client
        .post(format!("{}/xrpc/com.atproto.repo.putRecord", base_url().await))
        .bearer_auth(&jwt)
        .json(&create_payload)
        .send()
        .await
        .expect("setup failed");

    let payload = json!({
        "repo": did,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#update",
                "collection": "app.bsky.feed.post",
                "rkey": "to-update",
                "value": {
                    "$type": "app.bsky.feed.post",
                    "text": "Updated",
                    "createdAt": now
                }
            },
            {
                "$type": "com.atproto.repo.applyWrites#delete",
                "collection": "app.bsky.feed.post",
                "rkey": "to-update"
            }
        ]
    });

    let res = client
        .post(format!("{}/xrpc/com.atproto.repo.applyWrites", base_url().await))
        .bearer_auth(&jwt)
        .json(&payload)
        .send()
        .await
        .expect("Failed to apply writes");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();

    let results = body["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);

    let update_result = &results[0];
    assert_eq!(update_result["$type"], "com.atproto.repo.applyWrites#updateResult");
    assert!(update_result["uri"].is_string());
    assert!(update_result["cid"].is_string());
    assert_eq!(update_result["validationStatus"], "valid");

    let delete_result = &results[1];
    assert_eq!(delete_result["$type"], "com.atproto.repo.applyWrites#deleteResult");
    assert!(delete_result["uri"].is_null(), "delete result should not have uri");
    assert!(delete_result["cid"].is_null(), "delete result should not have cid");
    assert!(delete_result["validationStatus"].is_null(), "delete result should not have validationStatus");
}

#[tokio::test]
async fn test_get_record_error_code() {
    let client = client();
    let (did, _jwt) = setup_new_user("conform-get-err").await;

    let res = client
        .get(format!("{}/xrpc/com.atproto.repo.getRecord", base_url().await))
        .query(&[
            ("repo", did.as_str()),
            ("collection", "app.bsky.feed.post"),
            ("rkey", "nonexistent"),
        ])
        .send()
        .await
        .expect("Failed to get record");

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "RecordNotFound", "error code should be RecordNotFound per atproto spec");
}

#[tokio::test]
async fn test_create_record_unknown_lexicon_default_validation() {
    let client = client();
    let (did, jwt) = setup_new_user("conform-unknown-lex").await;

    let payload = json!({
        "repo": did,
        "collection": "com.example.custom",
        "record": {
            "$type": "com.example.custom",
            "data": "some custom data"
        }
    });

    let res = client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", base_url().await))
        .bearer_auth(&jwt)
        .json(&payload)
        .send()
        .await
        .expect("Failed to create record");

    assert_eq!(res.status(), StatusCode::OK, "unknown lexicon should be allowed with default validation");
    let body: Value = res.json().await.unwrap();

    assert!(body["uri"].is_string());
    assert!(body["cid"].is_string());
    assert!(body["commit"].is_object());
    assert_eq!(body["validationStatus"], "unknown", "validationStatus should be 'unknown' for unknown lexicons");
}

#[tokio::test]
async fn test_create_record_unknown_lexicon_strict_validation() {
    let client = client();
    let (did, jwt) = setup_new_user("conform-unknown-strict").await;

    let payload = json!({
        "repo": did,
        "collection": "com.example.custom",
        "validate": true,
        "record": {
            "$type": "com.example.custom",
            "data": "some custom data"
        }
    });

    let res = client
        .post(format!("{}/xrpc/com.atproto.repo.createRecord", base_url().await))
        .bearer_auth(&jwt)
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "unknown lexicon should fail with validate=true");
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidRecord");
    assert!(body["message"].as_str().unwrap().contains("Lexicon not found"), "error should mention lexicon not found");
}

#[tokio::test]
async fn test_put_record_noop_same_content() {
    let client = client();
    let (did, jwt) = setup_new_user("conform-put-noop").await;
    let now = Utc::now().to_rfc3339();

    let record = json!({
        "$type": "app.bsky.feed.post",
        "text": "This content will not change",
        "createdAt": now
    });

    let payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "rkey": "noop-test",
        "record": record.clone()
    });

    let first_res = client
        .post(format!("{}/xrpc/com.atproto.repo.putRecord", base_url().await))
        .bearer_auth(&jwt)
        .json(&payload)
        .send()
        .await
        .expect("Failed to put record");
    assert_eq!(first_res.status(), StatusCode::OK);
    let first_body: Value = first_res.json().await.unwrap();
    assert!(first_body["commit"].is_object(), "first put should have commit");

    let second_res = client
        .post(format!("{}/xrpc/com.atproto.repo.putRecord", base_url().await))
        .bearer_auth(&jwt)
        .json(&payload)
        .send()
        .await
        .expect("Failed to put record");
    assert_eq!(second_res.status(), StatusCode::OK);
    let second_body: Value = second_res.json().await.unwrap();

    assert!(second_body["commit"].is_null(), "second put with same content should have no commit (no-op)");
    assert_eq!(first_body["cid"], second_body["cid"], "CID should be the same for identical content");
}

#[tokio::test]
async fn test_apply_writes_unknown_lexicon() {
    let client = client();
    let (did, jwt) = setup_new_user("conform-apply-unknown").await;

    let payload = json!({
        "repo": did,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "com.example.custom",
                "rkey": "custom-1",
                "value": {
                    "$type": "com.example.custom",
                    "data": "custom data"
                }
            }
        ]
    });

    let res = client
        .post(format!("{}/xrpc/com.atproto.repo.applyWrites", base_url().await))
        .bearer_auth(&jwt)
        .json(&payload)
        .send()
        .await
        .expect("Failed to apply writes");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();

    let results = body["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["validationStatus"], "unknown", "unknown lexicon should have 'unknown' status");
}
