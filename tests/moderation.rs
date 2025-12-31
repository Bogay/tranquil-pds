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
    assert_eq!(
        report_body["reasonType"],
        "com.atproto.moderation.defs#reasonSpam"
    );
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

#[tokio::test]
async fn test_moderation_report_invalid_reason_type() {
    let client = client();
    let (alice_did, alice_jwt) = setup_new_user("alice-invalid-reason").await;
    let report_payload = json!({
        "reasonType": "invalid.reason.type",
        "reason": "Testing invalid reason",
        "subject": {
            "$type": "com.atproto.admin.defs#repoRef",
            "did": alice_did
        }
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.moderation.createReport",
            base_url().await
        ))
        .bearer_auth(&alice_jwt)
        .json(&report_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidRequest");
    assert!(body["message"].as_str().unwrap().contains("reasonType"));
}

#[tokio::test]
async fn test_moderation_report_unauthenticated() {
    let client = client();
    let report_payload = json!({
        "reasonType": "com.atproto.moderation.defs#reasonSpam",
        "reason": "Spam report",
        "subject": {
            "$type": "com.atproto.admin.defs#repoRef",
            "did": "did:plc:test"
        }
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.moderation.createReport",
            base_url().await
        ))
        .json(&report_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_moderation_report_all_reason_types() {
    let client = client();
    let (alice_did, alice_jwt) = setup_new_user("alice-all-reasons").await;
    let (bob_did, _) = setup_new_user("bob-all-reasons").await;
    let reason_types = [
        "com.atproto.moderation.defs#reasonSpam",
        "com.atproto.moderation.defs#reasonViolation",
        "com.atproto.moderation.defs#reasonMisleading",
        "com.atproto.moderation.defs#reasonSexual",
        "com.atproto.moderation.defs#reasonRude",
        "com.atproto.moderation.defs#reasonOther",
        "com.atproto.moderation.defs#reasonAppeal",
    ];
    for reason_type in reason_types {
        let report_payload = json!({
            "reasonType": reason_type,
            "subject": {
                "$type": "com.atproto.admin.defs#repoRef",
                "did": bob_did
            }
        });
        let res = client
            .post(format!(
                "{}/xrpc/com.atproto.moderation.createReport",
                base_url().await
            ))
            .bearer_auth(&alice_jwt)
            .json(&report_payload)
            .send()
            .await
            .expect("Failed to send request");
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "Failed for reason type: {}",
            reason_type
        );
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["reasonType"], reason_type);
        assert_eq!(body["reportedBy"], alice_did);
    }
}

#[tokio::test]
async fn test_moderation_report_takendown_user_can_appeal() {
    let client = client();
    let (admin_jwt, _) = create_admin_account_and_login(&client).await;
    let (target_jwt, target_did) = create_account_and_login(&client).await;
    let takedown_payload = json!({
        "subject": {
            "$type": "com.atproto.admin.defs#repoRef",
            "did": target_did
        },
        "takedown": {
            "applied": true,
            "ref": "mod-action-test"
        }
    });
    let takedown_res = client
        .post(format!(
            "{}/xrpc/com.atproto.admin.updateSubjectStatus",
            base_url().await
        ))
        .bearer_auth(&admin_jwt)
        .json(&takedown_payload)
        .send()
        .await
        .expect("Failed to takedown");
    assert_eq!(takedown_res.status(), StatusCode::OK);
    let appeal_payload = json!({
        "reasonType": "com.atproto.moderation.defs#reasonAppeal",
        "reason": "I believe this takedown was a mistake",
        "subject": {
            "$type": "com.atproto.admin.defs#repoRef",
            "did": target_did
        }
    });
    let appeal_res = client
        .post(format!(
            "{}/xrpc/com.atproto.moderation.createReport",
            base_url().await
        ))
        .bearer_auth(&target_jwt)
        .json(&appeal_payload)
        .send()
        .await
        .expect("Failed to send appeal");
    assert_eq!(
        appeal_res.status(),
        StatusCode::OK,
        "Takendown user should be able to file appeal reports"
    );
    let appeal_body: Value = appeal_res.json().await.unwrap();
    assert_eq!(
        appeal_body["reasonType"],
        "com.atproto.moderation.defs#reasonAppeal"
    );
    assert_eq!(appeal_body["reportedBy"], target_did);
}

#[tokio::test]
async fn test_moderation_report_takendown_user_cannot_file_non_appeal() {
    let client = client();
    let (admin_jwt, _) = create_admin_account_and_login(&client).await;
    let (target_jwt, target_did) = create_account_and_login(&client).await;
    let takedown_payload = json!({
        "subject": {
            "$type": "com.atproto.admin.defs#repoRef",
            "did": target_did
        },
        "takedown": {
            "applied": true,
            "ref": "mod-action-test-non-appeal"
        }
    });
    let takedown_res = client
        .post(format!(
            "{}/xrpc/com.atproto.admin.updateSubjectStatus",
            base_url().await
        ))
        .bearer_auth(&admin_jwt)
        .json(&takedown_payload)
        .send()
        .await
        .expect("Failed to takedown");
    assert_eq!(takedown_res.status(), StatusCode::OK);
    let report_payload = json!({
        "reasonType": "com.atproto.moderation.defs#reasonSpam",
        "reason": "Trying to report spam",
        "subject": {
            "$type": "com.atproto.admin.defs#repoRef",
            "did": "did:plc:test"
        }
    });
    let report_res = client
        .post(format!(
            "{}/xrpc/com.atproto.moderation.createReport",
            base_url().await
        ))
        .bearer_auth(&target_jwt)
        .json(&report_payload)
        .send()
        .await
        .expect("Failed to send report");
    assert_eq!(
        report_res.status(),
        StatusCode::BAD_REQUEST,
        "Takendown user should not be able to file non-appeal reports"
    );
    let body: Value = report_res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidRequest");
    assert!(body["message"].as_str().unwrap().contains("takendown"));
}
