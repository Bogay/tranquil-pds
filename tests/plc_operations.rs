mod common;
use common::*;
use reqwest::StatusCode;
use serde_json::json;
use sqlx::PgPool;

#[tokio::test]
async fn test_request_plc_operation_signature_requires_auth() {
    let client = client();
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.requestPlcOperationSignature",
            base_url().await
        ))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_request_plc_operation_signature_success() {
    let client = client();
    let (token, _did) = create_account_and_login(&client).await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.requestPlcOperationSignature",
            base_url().await
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("Request failed");
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_sign_plc_operation_requires_auth() {
    let client = client();
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.signPlcOperation",
            base_url().await
        ))
        .json(&json!({}))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_sign_plc_operation_requires_token() {
    let client = client();
    let (token, _did) = create_account_and_login(&client).await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.signPlcOperation",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&json!({}))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn test_sign_plc_operation_invalid_token() {
    let client = client();
    let (token, _did) = create_account_and_login(&client).await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.signPlcOperation",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&json!({
            "token": "invalid-token-12345"
        }))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(body["error"] == "InvalidToken" || body["error"] == "ExpiredToken");
}

#[tokio::test]
async fn test_submit_plc_operation_requires_auth() {
    let client = client();
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.submitPlcOperation",
            base_url().await
        ))
        .json(&json!({
            "operation": {}
        }))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_submit_plc_operation_invalid_operation() {
    let client = client();
    let (token, _did) = create_account_and_login(&client).await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.submitPlcOperation",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&json!({
            "operation": {
                "type": "invalid_type"
            }
        }))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn test_submit_plc_operation_missing_sig() {
    let client = client();
    let (token, _did) = create_account_and_login(&client).await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.submitPlcOperation",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&json!({
            "operation": {
                "type": "plc_operation",
                "rotationKeys": [],
                "verificationMethods": {},
                "alsoKnownAs": [],
                "services": {},
                "prev": null
            }
        }))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn test_submit_plc_operation_wrong_service_endpoint() {
    let client = client();
    let (token, _did) = create_account_and_login(&client).await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.submitPlcOperation",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&json!({
            "operation": {
                "type": "plc_operation",
                "rotationKeys": ["did:key:z123"],
                "verificationMethods": {"atproto": "did:key:z456"},
                "alsoKnownAs": ["at://wrong.handle"],
                "services": {
                    "atproto_pds": {
                        "type": "AtprotoPersonalDataServer",
                        "endpoint": "https://wrong.example.com"
                    }
                },
                "prev": null,
                "sig": "fake_signature"
            }
        }))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_request_plc_operation_creates_token_in_db() {
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
        .expect("Request failed");
    assert_eq!(res.status(), StatusCode::OK);
    let db_url = get_db_connection_string().await;
    let pool = PgPool::connect(&db_url).await.expect("DB connect failed");
    let row = sqlx::query!(
        r#"
        SELECT t.token, t.expires_at
        FROM plc_operation_tokens t
        JOIN users u ON t.user_id = u.id
        WHERE u.did = $1
        "#,
        did
    )
    .fetch_optional(&pool)
    .await
    .expect("Query failed");
    assert!(row.is_some(), "PLC token should be created in database");
    let row = row.unwrap();
    assert!(
        row.token.len() == 11,
        "Token should be in format xxxxx-xxxxx"
    );
    assert!(row.token.contains('-'), "Token should contain hyphen");
    assert!(
        row.expires_at > chrono::Utc::now(),
        "Token should not be expired"
    );
}

#[tokio::test]
async fn test_request_plc_operation_replaces_existing_token() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let res1 = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.requestPlcOperationSignature",
            base_url().await
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("Request 1 failed");
    assert_eq!(res1.status(), StatusCode::OK);
    let db_url = get_db_connection_string().await;
    let pool = PgPool::connect(&db_url).await.expect("DB connect failed");
    let token1 = sqlx::query_scalar!(
        r#"
        SELECT t.token
        FROM plc_operation_tokens t
        JOIN users u ON t.user_id = u.id
        WHERE u.did = $1
        "#,
        did
    )
    .fetch_one(&pool)
    .await
    .expect("Query failed");
    let res2 = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.requestPlcOperationSignature",
            base_url().await
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("Request 2 failed");
    assert_eq!(res2.status(), StatusCode::OK);
    let token2 = sqlx::query_scalar!(
        r#"
        SELECT t.token
        FROM plc_operation_tokens t
        JOIN users u ON t.user_id = u.id
        WHERE u.did = $1
        "#,
        did
    )
    .fetch_one(&pool)
    .await
    .expect("Query failed");
    assert_ne!(token1, token2, "Second request should generate a new token");
    let count: i64 = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) as "count!"
        FROM plc_operation_tokens t
        JOIN users u ON t.user_id = u.id
        WHERE u.did = $1
        "#,
        did
    )
    .fetch_one(&pool)
    .await
    .expect("Count query failed");
    assert_eq!(count, 1, "Should only have one token per user");
}

#[tokio::test]
async fn test_submit_plc_operation_wrong_verification_method() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let hostname =
        std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| format!("127.0.0.1:{}", app_port()));
    let handle = did.split(':').last().unwrap_or("user");
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.submitPlcOperation",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&json!({
            "operation": {
                "type": "plc_operation",
                "rotationKeys": ["did:key:zWrongRotationKey123"],
                "verificationMethods": {"atproto": "did:key:zWrongVerificationKey456"},
                "alsoKnownAs": [format!("at://{}", handle)],
                "services": {
                    "atproto_pds": {
                        "type": "AtprotoPersonalDataServer",
                        "endpoint": format!("https://{}", hostname)
                    }
                },
                "prev": null,
                "sig": "fake_signature"
            }
        }))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidRequest");
    assert!(
        body["message"]
            .as_str()
            .unwrap_or("")
            .contains("signing key")
            || body["message"].as_str().unwrap_or("").contains("rotation"),
        "Error should mention key mismatch: {:?}",
        body
    );
}

#[tokio::test]
async fn test_submit_plc_operation_wrong_handle() {
    let client = client();
    let (token, _did) = create_account_and_login(&client).await;
    let hostname =
        std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| format!("127.0.0.1:{}", app_port()));
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.submitPlcOperation",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&json!({
            "operation": {
                "type": "plc_operation",
                "rotationKeys": ["did:key:z123"],
                "verificationMethods": {"atproto": "did:key:z456"},
                "alsoKnownAs": ["at://totally.wrong.handle"],
                "services": {
                    "atproto_pds": {
                        "type": "AtprotoPersonalDataServer",
                        "endpoint": format!("https://{}", hostname)
                    }
                },
                "prev": null,
                "sig": "fake_signature"
            }
        }))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn test_submit_plc_operation_wrong_service_type() {
    let client = client();
    let (token, _did) = create_account_and_login(&client).await;
    let hostname =
        std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| format!("127.0.0.1:{}", app_port()));
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.submitPlcOperation",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&json!({
            "operation": {
                "type": "plc_operation",
                "rotationKeys": ["did:key:z123"],
                "verificationMethods": {"atproto": "did:key:z456"},
                "alsoKnownAs": ["at://user"],
                "services": {
                    "atproto_pds": {
                        "type": "WrongServiceType",
                        "endpoint": format!("https://{}", hostname)
                    }
                },
                "prev": null,
                "sig": "fake_signature"
            }
        }))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn test_plc_token_expiry_format() {
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
        .expect("Request failed");
    assert_eq!(res.status(), StatusCode::OK);
    let db_url = get_db_connection_string().await;
    let pool = PgPool::connect(&db_url).await.expect("DB connect failed");
    let row = sqlx::query!(
        r#"
        SELECT t.expires_at
        FROM plc_operation_tokens t
        JOIN users u ON t.user_id = u.id
        WHERE u.did = $1
        "#,
        did
    )
    .fetch_one(&pool)
    .await
    .expect("Query failed");
    let now = chrono::Utc::now();
    let expires = row.expires_at;
    let diff = expires - now;
    assert!(
        diff.num_minutes() >= 9,
        "Token should expire in ~10 minutes, got {} minutes",
        diff.num_minutes()
    );
    assert!(
        diff.num_minutes() <= 11,
        "Token should expire in ~10 minutes, got {} minutes",
        diff.num_minutes()
    );
}
