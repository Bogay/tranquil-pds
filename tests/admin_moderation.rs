mod common;
use common::*;

use reqwest::StatusCode;
use serde_json::{Value, json};

#[tokio::test]
async fn test_get_subject_status_user_success() {
    let client = client();
    let (access_jwt, did) = create_account_and_login(&client).await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.admin.getSubjectStatus",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert!(body["subject"].is_object());
    assert_eq!(body["subject"]["$type"], "com.atproto.admin.defs#repoRef");
    assert_eq!(body["subject"]["did"], did);
}

#[tokio::test]
async fn test_get_subject_status_not_found() {
    let client = client();
    let (access_jwt, _did) = create_account_and_login(&client).await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.admin.getSubjectStatus",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .query(&[("did", "did:plc:nonexistent")])
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["error"], "SubjectNotFound");
}

#[tokio::test]
async fn test_get_subject_status_no_param() {
    let client = client();
    let (access_jwt, _did) = create_account_and_login(&client).await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.admin.getSubjectStatus",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn test_get_subject_status_no_auth() {
    let client = client();

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.admin.getSubjectStatus",
            base_url().await
        ))
        .query(&[("did", "did:plc:test")])
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_update_subject_status_takedown_user() {
    let client = client();
    let (access_jwt, did) = create_account_and_login(&client).await;

    let payload = json!({
        "subject": {
            "$type": "com.atproto.admin.defs#repoRef",
            "did": did
        },
        "takedown": {
            "apply": true,
            "ref": "mod-action-123"
        }
    });

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.admin.updateSubjectStatus",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert!(body["takedown"].is_object());
    assert_eq!(body["takedown"]["applied"], true);
    assert_eq!(body["takedown"]["ref"], "mod-action-123");

    let status_res = client
        .get(format!(
            "{}/xrpc/com.atproto.admin.getSubjectStatus",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to send request");

    let status_body: Value = status_res.json().await.unwrap();
    assert!(status_body["takedown"].is_object());
    assert_eq!(status_body["takedown"]["applied"], true);
    assert_eq!(status_body["takedown"]["ref"], "mod-action-123");
}

#[tokio::test]
async fn test_update_subject_status_remove_takedown() {
    let client = client();
    let (access_jwt, did) = create_account_and_login(&client).await;

    let takedown_payload = json!({
        "subject": {
            "$type": "com.atproto.admin.defs#repoRef",
            "did": did
        },
        "takedown": {
            "apply": true,
            "ref": "mod-action-456"
        }
    });

    let _ = client
        .post(format!(
            "{}/xrpc/com.atproto.admin.updateSubjectStatus",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .json(&takedown_payload)
        .send()
        .await;

    let remove_payload = json!({
        "subject": {
            "$type": "com.atproto.admin.defs#repoRef",
            "did": did
        },
        "takedown": {
            "apply": false
        }
    });

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.admin.updateSubjectStatus",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .json(&remove_payload)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);

    let status_res = client
        .get(format!(
            "{}/xrpc/com.atproto.admin.getSubjectStatus",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to send request");

    let status_body: Value = status_res.json().await.unwrap();
    assert!(status_body["takedown"].is_null() || !status_body["takedown"]["applied"].as_bool().unwrap_or(false));
}

#[tokio::test]
async fn test_update_subject_status_deactivate_user() {
    let client = client();
    let (access_jwt, did) = create_account_and_login(&client).await;

    let payload = json!({
        "subject": {
            "$type": "com.atproto.admin.defs#repoRef",
            "did": did
        },
        "deactivated": {
            "apply": true
        }
    });

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.admin.updateSubjectStatus",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);

    let status_res = client
        .get(format!(
            "{}/xrpc/com.atproto.admin.getSubjectStatus",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .query(&[("did", did.as_str())])
        .send()
        .await
        .expect("Failed to send request");

    let status_body: Value = status_res.json().await.unwrap();
    assert!(status_body["deactivated"].is_object());
    assert_eq!(status_body["deactivated"]["applied"], true);
}

#[tokio::test]
async fn test_update_subject_status_invalid_type() {
    let client = client();
    let (access_jwt, _did) = create_account_and_login(&client).await;

    let payload = json!({
        "subject": {
            "$type": "invalid.type",
            "did": "did:plc:test"
        },
        "takedown": {
            "apply": true
        }
    });

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.admin.updateSubjectStatus",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn test_update_subject_status_no_auth() {
    let client = client();

    let payload = json!({
        "subject": {
            "$type": "com.atproto.admin.defs#repoRef",
            "did": "did:plc:test"
        },
        "takedown": {
            "apply": true
        }
    });

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.admin.updateSubjectStatus",
            base_url().await
        ))
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}
