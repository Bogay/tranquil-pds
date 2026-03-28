mod common;
use common::*;
use reqwest::StatusCode;
use serde_json::json;
use tranquil_types::Did;

#[tokio::test]
async fn test_plc_operation_auth() {
    let client = client();
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.requestPlcOperationSignature",
            base_url().await
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.signPlcOperation",
            base_url().await
        ))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.submitPlcOperation",
            base_url().await
        ))
        .json(&json!({ "operation": {} }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let (token, _) = create_account_and_login(&client).await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.requestPlcOperationSignature",
            base_url().await
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_sign_plc_operation_validation() {
    let client = client();
    let (token, _) = create_account_and_login(&client).await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.signPlcOperation",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidRequest");
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.signPlcOperation",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&json!({ "token": "invalid-token-12345" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(body["error"] == "InvalidToken" || body["error"] == "ExpiredToken");
}

#[tokio::test]
async fn test_submit_plc_operation_validation() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let hostname =
        std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| format!("127.0.0.1:{}", app_port()));
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.submitPlcOperation",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&json!({ "operation": { "type": "invalid_type" } }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidRequest");
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.submitPlcOperation",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&json!({
            "operation": { "type": "plc_operation", "rotationKeys": [], "verificationMethods": {},
                "alsoKnownAs": [], "services": {}, "prev": null }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let handle = did.split(':').next_back().unwrap_or("user");
    let res = client.post(format!("{}/xrpc/com.atproto.identity.submitPlcOperation", base_url().await))
        .bearer_auth(&token).json(&json!({
            "operation": { "type": "plc_operation", "rotationKeys": ["did:key:z123"],
                "verificationMethods": { "atproto": "did:key:z456" },
                "alsoKnownAs": [format!("at://{}", handle)],
                "services": { "atproto_pds": { "type": "AtprotoPersonalDataServer", "endpoint": "https://wrong.example.com" } },
                "prev": null, "sig": "fake_signature" }
        })).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let res = client.post(format!("{}/xrpc/com.atproto.identity.submitPlcOperation", base_url().await))
        .bearer_auth(&token).json(&json!({
            "operation": { "type": "plc_operation", "rotationKeys": ["did:key:zWrongRotationKey123"],
                "verificationMethods": { "atproto": "did:key:zWrongVerificationKey456" },
                "alsoKnownAs": [format!("at://{}", handle)],
                "services": { "atproto_pds": { "type": "AtprotoPersonalDataServer", "endpoint": format!("https://{}", hostname) } },
                "prev": null, "sig": "fake_signature" }
        })).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidRequest");
    assert!(
        body["message"]
            .as_str()
            .unwrap_or("")
            .contains("signing key")
            || body["message"].as_str().unwrap_or("").contains("rotation")
    );
    let res = client.post(format!("{}/xrpc/com.atproto.identity.submitPlcOperation", base_url().await))
        .bearer_auth(&token).json(&json!({
            "operation": { "type": "plc_operation", "rotationKeys": ["did:key:z123"],
                "verificationMethods": { "atproto": "did:key:z456" },
                "alsoKnownAs": ["at://totally.wrong.handle"],
                "services": { "atproto_pds": { "type": "AtprotoPersonalDataServer", "endpoint": format!("https://{}", hostname) } },
                "prev": null, "sig": "fake_signature" }
        })).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let res = client.post(format!("{}/xrpc/com.atproto.identity.submitPlcOperation", base_url().await))
        .bearer_auth(&token).json(&json!({
            "operation": { "type": "plc_operation", "rotationKeys": ["did:key:z123"],
                "verificationMethods": { "atproto": "did:key:z456" },
                "alsoKnownAs": ["at://user"],
                "services": { "atproto_pds": { "type": "WrongServiceType", "endpoint": format!("https://{}", hostname) } },
                "prev": null, "sig": "fake_signature" }
        })).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_plc_token_lifecycle() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.requestPlcOperationSignature",
            base_url().await
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let repos = get_test_repos().await;
    let parsed_did = Did::new(did.clone()).unwrap();
    let tokens = repos
        .infra
        .get_plc_tokens_by_did(&parsed_did)
        .await
        .unwrap();
    assert!(
        !tokens.is_empty(),
        "PLC token should be created in database"
    );
    let first = &tokens[0];
    assert_eq!(
        first.token.len(),
        11,
        "Token should be in format xxxxx-xxxxx"
    );
    assert!(first.token.contains('-'), "Token should contain hyphen");
    assert!(
        first.expires_at > chrono::Utc::now(),
        "Token should not be expired"
    );
    let diff = first.expires_at - chrono::Utc::now();
    assert!(
        diff.num_minutes() >= 9 && diff.num_minutes() <= 11,
        "Token should expire in ~10 minutes"
    );
    let token1 = first.token.clone();
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.requestPlcOperationSignature",
            base_url().await
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let tokens2 = repos
        .infra
        .get_plc_tokens_by_did(&parsed_did)
        .await
        .unwrap();
    let token2 = &tokens2[0].token;
    assert_ne!(
        token1, *token2,
        "Second request should generate a new token"
    );
    let count = repos
        .infra
        .count_plc_tokens_by_did(&parsed_did)
        .await
        .unwrap();
    assert_eq!(count, 1, "Should only have one token per user");
}
