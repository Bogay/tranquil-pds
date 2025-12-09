mod common;
mod helpers;

use common::*;
use helpers::*;

use reqwest::StatusCode;
use serde_json::{Value, json};

#[tokio::test]
async fn test_moderation_report_lifecycle() {
    let client = client();
    let (alice_did, alice_jwt) = setup_new_user("alice-report").await;
    let (bob_did, bob_jwt) = setup_new_user("bob-report").await;

    let (post_uri, post_cid) =
        create_post(&client, &bob_did, &bob_jwt, "This is a reportable post").await;

    let report_payload = json!({
        "reasonType": "com.atproto.moderation.defs#reasonSpam",
        "reason": "This looks like spam to me",
        "subject": {
            "$type": "com.atproto.repo.strongRef",
            "uri": post_uri,
            "cid": post_cid
        }
    });

    let report_res = client
        .post(format!(
            "{}/xrpc/com.atproto.moderation.createReport",
            base_url().await
        ))
        .bearer_auth(&alice_jwt)
        .json(&report_payload)
        .send()
        .await
        .expect("Failed to create report");

    assert_eq!(report_res.status(), StatusCode::OK);
    let report_body: Value = report_res.json().await.unwrap();
    assert!(report_body["id"].is_number(), "Report should have an ID");
    assert_eq!(report_body["reasonType"], "com.atproto.moderation.defs#reasonSpam");
    assert_eq!(report_body["reportedBy"], alice_did);

    let account_report_payload = json!({
        "reasonType": "com.atproto.moderation.defs#reasonOther",
        "reason": "Suspicious account activity",
        "subject": {
            "$type": "com.atproto.admin.defs#repoRef",
            "did": bob_did
        }
    });

    let account_report_res = client
        .post(format!(
            "{}/xrpc/com.atproto.moderation.createReport",
            base_url().await
        ))
        .bearer_auth(&alice_jwt)
        .json(&account_report_payload)
        .send()
        .await
        .expect("Failed to create account report");

    assert_eq!(account_report_res.status(), StatusCode::OK);
}
