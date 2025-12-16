mod common;
use common::*;
use k256::ecdsa::SigningKey;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sqlx::PgPool;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn encode_uvarint(mut x: u64) -> Vec<u8> {
    let mut out = Vec::new();
    while x >= 0x80 {
        out.push(((x as u8) & 0x7F) | 0x80);
        x >>= 7;
    }
    out.push(x as u8);
    out
}

fn signing_key_to_did_key(signing_key: &SigningKey) -> String {
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(true);
    let compressed_bytes = point.as_bytes();
    let mut prefixed = vec![0xe7, 0x01];
    prefixed.extend_from_slice(compressed_bytes);
    let encoded = multibase::encode(multibase::Base::Base58Btc, &prefixed);
    format!("did:key:{}", encoded)
}

fn get_multikey_from_signing_key(signing_key: &SigningKey) -> String {
    let public_key = signing_key.verifying_key();
    let compressed = public_key.to_sec1_bytes();
    let mut buf = encode_uvarint(0xE7);
    buf.extend_from_slice(&compressed);
    multibase::encode(multibase::Base::Base58Btc, buf)
}

async fn get_user_signing_key(did: &str) -> Option<Vec<u8>> {
    let db_url = get_db_connection_string().await;
    let pool = PgPool::connect(&db_url).await.ok()?;
    let row = sqlx::query!(
        r#"
        SELECT k.key_bytes, k.encryption_version
        FROM user_keys k
        JOIN users u ON k.user_id = u.id
        WHERE u.did = $1
        "#,
        did
    )
    .fetch_optional(&pool)
    .await
    .ok()??;
    bspds::config::decrypt_key(&row.key_bytes, row.encryption_version).ok()
}

async fn get_plc_token_from_db(did: &str) -> Option<String> {
    let db_url = get_db_connection_string().await;
    let pool = PgPool::connect(&db_url).await.ok()?;
    sqlx::query_scalar!(
        r#"
        SELECT t.token
        FROM plc_operation_tokens t
        JOIN users u ON t.user_id = u.id
        WHERE u.did = $1
        "#,
        did
    )
    .fetch_optional(&pool)
    .await
    .ok()?
}

async fn get_user_handle(did: &str) -> Option<String> {
    let db_url = get_db_connection_string().await;
    let pool = PgPool::connect(&db_url).await.ok()?;
    sqlx::query_scalar!(r#"SELECT handle FROM users WHERE did = $1"#, did)
        .fetch_optional(&pool)
        .await
        .ok()?
}

fn create_mock_last_op(
    _did: &str,
    handle: &str,
    signing_key: &SigningKey,
    pds_endpoint: &str,
) -> Value {
    let did_key = signing_key_to_did_key(signing_key);
    json!({
        "type": "plc_operation",
        "rotationKeys": [did_key.clone()],
        "verificationMethods": {
            "atproto": did_key
        },
        "alsoKnownAs": [format!("at://{}", handle)],
        "services": {
            "atproto_pds": {
                "type": "AtprotoPersonalDataServer",
                "endpoint": pds_endpoint
            }
        },
        "prev": null,
        "sig": "mock_signature_for_testing"
    })
}

fn create_did_document(
    did: &str,
    handle: &str,
    signing_key: &SigningKey,
    pds_endpoint: &str,
) -> Value {
    let multikey = get_multikey_from_signing_key(signing_key);
    json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1"
        ],
        "id": did,
        "alsoKnownAs": [format!("at://{}", handle)],
        "verificationMethod": [{
            "id": format!("{}#atproto", did),
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": multikey
        }],
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": pds_endpoint
        }]
    })
}

async fn setup_mock_plc_for_sign(
    did: &str,
    handle: &str,
    signing_key: &SigningKey,
    pds_endpoint: &str,
) -> MockServer {
    let mock_server = MockServer::start().await;
    let did_encoded = urlencoding::encode(did);
    let last_op = create_mock_last_op(did, handle, signing_key, pds_endpoint);
    Mock::given(method("GET"))
        .and(path(format!("/{}/log/last", did_encoded)))
        .respond_with(ResponseTemplate::new(200).set_body_json(last_op))
        .mount(&mock_server)
        .await;
    mock_server
}

async fn setup_mock_plc_for_submit(
    did: &str,
    handle: &str,
    signing_key: &SigningKey,
    pds_endpoint: &str,
) -> MockServer {
    let mock_server = MockServer::start().await;
    let did_encoded = urlencoding::encode(did);
    let did_doc = create_did_document(did, handle, signing_key, pds_endpoint);
    Mock::given(method("GET"))
        .and(path(format!("/{}", did_encoded)))
        .respond_with(ResponseTemplate::new(200).set_body_json(did_doc.clone()))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/{}", did_encoded)))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;
    mock_server
}

#[tokio::test]
#[ignore = "requires mock PLC server setup that is flaky; run manually with --ignored"]
async fn test_full_plc_operation_flow() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let key_bytes = get_user_signing_key(&did)
        .await
        .expect("Failed to get user signing key");
    let signing_key = SigningKey::from_slice(&key_bytes).expect("Failed to create signing key");
    let handle = get_user_handle(&did)
        .await
        .expect("Failed to get user handle");
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let pds_endpoint = format!("https://{}", hostname);
    let request_res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.requestPlcOperationSignature",
            base_url().await
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("Request failed");
    assert_eq!(request_res.status(), StatusCode::OK);
    let plc_token = get_plc_token_from_db(&did)
        .await
        .expect("PLC token not found in database");
    let mock_plc = setup_mock_plc_for_sign(&did, &handle, &signing_key, &pds_endpoint).await;
    unsafe {
        std::env::set_var("PLC_DIRECTORY_URL", mock_plc.uri());
    }
    let sign_res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.signPlcOperation",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&json!({
            "token": plc_token
        }))
        .send()
        .await
        .expect("Sign request failed");
    let sign_status = sign_res.status();
    let sign_body: Value = sign_res.json().await.unwrap_or(json!({}));
    assert_eq!(
        sign_status,
        StatusCode::OK,
        "Sign PLC operation should succeed. Response: {:?}",
        sign_body
    );
    let operation = sign_body
        .get("operation")
        .expect("Response should contain operation");
    assert!(operation.get("sig").is_some(), "Operation should be signed");
    assert_eq!(
        operation.get("type").and_then(|v| v.as_str()),
        Some("plc_operation")
    );
    assert!(
        operation.get("prev").is_some(),
        "Operation should have prev reference"
    );
}

#[tokio::test]
#[ignore = "requires exclusive env var access; run with: cargo test test_sign_plc_operation_consumes_token -- --ignored --test-threads=1"]
async fn test_sign_plc_operation_consumes_token() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let key_bytes = get_user_signing_key(&did)
        .await
        .expect("Failed to get user signing key");
    let signing_key = SigningKey::from_slice(&key_bytes).expect("Failed to create signing key");
    let handle = get_user_handle(&did)
        .await
        .expect("Failed to get user handle");
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let pds_endpoint = format!("https://{}", hostname);
    let request_res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.requestPlcOperationSignature",
            base_url().await
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("Request failed");
    assert_eq!(request_res.status(), StatusCode::OK);
    let plc_token = get_plc_token_from_db(&did)
        .await
        .expect("PLC token not found in database");
    let mock_plc = setup_mock_plc_for_sign(&did, &handle, &signing_key, &pds_endpoint).await;
    unsafe {
        std::env::set_var("PLC_DIRECTORY_URL", mock_plc.uri());
    }
    let sign_res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.signPlcOperation",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&json!({
            "token": plc_token
        }))
        .send()
        .await
        .expect("Sign request failed");
    assert_eq!(sign_res.status(), StatusCode::OK);
    let sign_res_2 = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.signPlcOperation",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&json!({
            "token": plc_token
        }))
        .send()
        .await
        .expect("Second sign request failed");
    assert_eq!(
        sign_res_2.status(),
        StatusCode::BAD_REQUEST,
        "Using the same token twice should fail"
    );
    let body: Value = sign_res_2.json().await.unwrap();
    assert!(
        body["error"] == "InvalidToken" || body["error"] == "ExpiredToken",
        "Error should indicate invalid/expired token"
    );
}

#[tokio::test]
#[ignore = "requires exclusive env var access; run with: cargo test test_sign_plc_operation_with_custom_fields -- --ignored --test-threads=1"]
async fn test_sign_plc_operation_with_custom_fields() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let key_bytes = get_user_signing_key(&did)
        .await
        .expect("Failed to get user signing key");
    let signing_key = SigningKey::from_slice(&key_bytes).expect("Failed to create signing key");
    let handle = get_user_handle(&did)
        .await
        .expect("Failed to get user handle");
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let pds_endpoint = format!("https://{}", hostname);
    let request_res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.requestPlcOperationSignature",
            base_url().await
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("Request failed");
    assert_eq!(request_res.status(), StatusCode::OK);
    let plc_token = get_plc_token_from_db(&did)
        .await
        .expect("PLC token not found in database");
    let mock_plc = setup_mock_plc_for_sign(&did, &handle, &signing_key, &pds_endpoint).await;
    unsafe {
        std::env::set_var("PLC_DIRECTORY_URL", mock_plc.uri());
    }
    let did_key = signing_key_to_did_key(&signing_key);
    let sign_res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.signPlcOperation",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&json!({
            "token": plc_token,
            "alsoKnownAs": [format!("at://{}", handle), "at://custom.alias.example"],
            "rotationKeys": [did_key.clone(), "did:key:zExtraRotationKey123"]
        }))
        .send()
        .await
        .expect("Sign request failed");
    let sign_status = sign_res.status();
    let sign_body: Value = sign_res.json().await.unwrap_or(json!({}));
    assert_eq!(
        sign_status,
        StatusCode::OK,
        "Sign with custom fields should succeed. Response: {:?}",
        sign_body
    );
    let operation = sign_body.get("operation").expect("Should have operation");
    let also_known_as = operation.get("alsoKnownAs").and_then(|v| v.as_array());
    let rotation_keys = operation.get("rotationKeys").and_then(|v| v.as_array());
    assert!(also_known_as.is_some(), "Should have alsoKnownAs");
    assert!(rotation_keys.is_some(), "Should have rotationKeys");
    assert_eq!(also_known_as.unwrap().len(), 2, "Should have 2 aliases");
    assert_eq!(
        rotation_keys.unwrap().len(),
        2,
        "Should have 2 rotation keys"
    );
}

#[tokio::test]
#[ignore = "requires mock PLC server setup that is flaky; run manually with --ignored"]
async fn test_submit_plc_operation_success() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let key_bytes = get_user_signing_key(&did)
        .await
        .expect("Failed to get user signing key");
    let signing_key = SigningKey::from_slice(&key_bytes).expect("Failed to create signing key");
    let handle = get_user_handle(&did)
        .await
        .expect("Failed to get user handle");
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let pds_endpoint = format!("https://{}", hostname);
    let mock_plc = setup_mock_plc_for_submit(&did, &handle, &signing_key, &pds_endpoint).await;
    unsafe {
        std::env::set_var("PLC_DIRECTORY_URL", mock_plc.uri());
    }
    let did_key = signing_key_to_did_key(&signing_key);
    let operation = json!({
        "type": "plc_operation",
        "rotationKeys": [did_key.clone()],
        "verificationMethods": {
            "atproto": did_key.clone()
        },
        "alsoKnownAs": [format!("at://{}", handle)],
        "services": {
            "atproto_pds": {
                "type": "AtprotoPersonalDataServer",
                "endpoint": pds_endpoint
            }
        },
        "prev": "bafyreiabc123",
        "sig": "test_signature_base64"
    });
    let submit_res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.submitPlcOperation",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&json!({ "operation": operation }))
        .send()
        .await
        .expect("Submit request failed");
    let submit_status = submit_res.status();
    let submit_body: Value = submit_res.json().await.unwrap_or(json!({}));
    assert_eq!(
        submit_status,
        StatusCode::OK,
        "Submit PLC operation should succeed. Response: {:?}",
        submit_body
    );
}

#[tokio::test]
async fn test_submit_plc_operation_wrong_endpoint_rejected() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let key_bytes = get_user_signing_key(&did)
        .await
        .expect("Failed to get user signing key");
    let signing_key = SigningKey::from_slice(&key_bytes).expect("Failed to create signing key");
    let handle = get_user_handle(&did)
        .await
        .expect("Failed to get user handle");
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let pds_endpoint = format!("https://{}", hostname);
    let mock_plc = setup_mock_plc_for_submit(&did, &handle, &signing_key, &pds_endpoint).await;
    unsafe {
        std::env::set_var("PLC_DIRECTORY_URL", mock_plc.uri());
    }
    let did_key = signing_key_to_did_key(&signing_key);
    let operation = json!({
        "type": "plc_operation",
        "rotationKeys": [did_key.clone()],
        "verificationMethods": {
            "atproto": did_key.clone()
        },
        "alsoKnownAs": [format!("at://{}", handle)],
        "services": {
            "atproto_pds": {
                "type": "AtprotoPersonalDataServer",
                "endpoint": "https://wrong-pds.example.com"
            }
        },
        "prev": "bafyreiabc123",
        "sig": "test_signature_base64"
    });
    let submit_res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.submitPlcOperation",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&json!({ "operation": operation }))
        .send()
        .await
        .expect("Submit request failed");
    assert_eq!(
        submit_res.status(),
        StatusCode::BAD_REQUEST,
        "Submit with wrong endpoint should fail"
    );
    let body: Value = submit_res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn test_submit_plc_operation_wrong_signing_key_rejected() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let key_bytes = get_user_signing_key(&did)
        .await
        .expect("Failed to get user signing key");
    let signing_key = SigningKey::from_slice(&key_bytes).expect("Failed to create signing key");
    let handle = get_user_handle(&did)
        .await
        .expect("Failed to get user handle");
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let pds_endpoint = format!("https://{}", hostname);
    let mock_plc = setup_mock_plc_for_submit(&did, &handle, &signing_key, &pds_endpoint).await;
    unsafe {
        std::env::set_var("PLC_DIRECTORY_URL", mock_plc.uri());
    }
    let wrong_key = SigningKey::random(&mut rand::thread_rng());
    let wrong_did_key = signing_key_to_did_key(&wrong_key);
    let correct_did_key = signing_key_to_did_key(&signing_key);
    let operation = json!({
        "type": "plc_operation",
        "rotationKeys": [correct_did_key.clone()],
        "verificationMethods": {
            "atproto": wrong_did_key
        },
        "alsoKnownAs": [format!("at://{}", handle)],
        "services": {
            "atproto_pds": {
                "type": "AtprotoPersonalDataServer",
                "endpoint": pds_endpoint
            }
        },
        "prev": "bafyreiabc123",
        "sig": "test_signature_base64"
    });
    let submit_res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.submitPlcOperation",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&json!({ "operation": operation }))
        .send()
        .await
        .expect("Submit request failed");
    assert_eq!(
        submit_res.status(),
        StatusCode::BAD_REQUEST,
        "Submit with wrong signing key should fail"
    );
    let body: Value = submit_res.json().await.unwrap();
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test]
async fn test_full_sign_and_submit_flow() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let key_bytes = get_user_signing_key(&did)
        .await
        .expect("Failed to get user signing key");
    let signing_key = SigningKey::from_slice(&key_bytes).expect("Failed to create signing key");
    let handle = get_user_handle(&did)
        .await
        .expect("Failed to get user handle");
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let pds_endpoint = format!("https://{}", hostname);
    let request_res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.requestPlcOperationSignature",
            base_url().await
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("Request failed");
    assert_eq!(request_res.status(), StatusCode::OK);
    let plc_token = get_plc_token_from_db(&did)
        .await
        .expect("PLC token not found");
    let mock_server = MockServer::start().await;
    let did_encoded = urlencoding::encode(&did);
    let did_key = signing_key_to_did_key(&signing_key);
    let last_op = json!({
        "type": "plc_operation",
        "rotationKeys": [did_key.clone()],
        "verificationMethods": {
            "atproto": did_key.clone()
        },
        "alsoKnownAs": [format!("at://{}", handle)],
        "services": {
            "atproto_pds": {
                "type": "AtprotoPersonalDataServer",
                "endpoint": pds_endpoint.clone()
            }
        },
        "prev": null,
        "sig": "initial_sig"
    });
    Mock::given(method("GET"))
        .and(path(format!("/{}/log/last", did_encoded)))
        .respond_with(ResponseTemplate::new(200).set_body_json(last_op))
        .mount(&mock_server)
        .await;
    let did_doc = create_did_document(&did, &handle, &signing_key, &pds_endpoint);
    Mock::given(method("GET"))
        .and(path(format!("/{}", did_encoded)))
        .respond_with(ResponseTemplate::new(200).set_body_json(did_doc))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/{}", did_encoded)))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;
    unsafe {
        std::env::set_var("PLC_DIRECTORY_URL", mock_server.uri());
    }
    let sign_res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.signPlcOperation",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&json!({ "token": plc_token }))
        .send()
        .await
        .expect("Sign failed");
    assert_eq!(sign_res.status(), StatusCode::OK);
    let sign_body: Value = sign_res.json().await.unwrap();
    let signed_operation = sign_body
        .get("operation")
        .expect("Response should contain operation")
        .clone();
    assert!(signed_operation.get("sig").is_some());
    assert!(signed_operation.get("prev").is_some());
    let submit_res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.submitPlcOperation",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&json!({ "operation": signed_operation }))
        .send()
        .await
        .expect("Submit failed");
    let submit_status = submit_res.status();
    let submit_body: Value = submit_res.json().await.unwrap_or(json!({}));
    assert_eq!(
        submit_status,
        StatusCode::OK,
        "Full sign and submit flow should succeed. Response: {:?}",
        submit_body
    );
}

#[tokio::test]
#[ignore = "requires exclusive env var access; run with: cargo test test_cross_pds_migration_with_records -- --ignored --test-threads=1"]
async fn test_cross_pds_migration_with_records() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let key_bytes = get_user_signing_key(&did)
        .await
        .expect("Failed to get user signing key");
    let signing_key = SigningKey::from_slice(&key_bytes).expect("Failed to create signing key");
    let handle = get_user_handle(&did)
        .await
        .expect("Failed to get user handle");
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let pds_endpoint = format!("https://{}", hostname);
    let post_payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "Test post before migration",
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
    let create_body: Value = create_res.json().await.unwrap();
    let original_uri = create_body["uri"].as_str().unwrap().to_string();
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
    assert!(
        car_bytes.len() > 100,
        "CAR file should have meaningful content"
    );
    let mock_server = MockServer::start().await;
    let did_encoded = urlencoding::encode(&did);
    let did_doc = create_did_document(&did, &handle, &signing_key, &pds_endpoint);
    Mock::given(method("GET"))
        .and(path(format!("/{}", did_encoded)))
        .respond_with(ResponseTemplate::new(200).set_body_json(did_doc))
        .mount(&mock_server)
        .await;
    unsafe {
        std::env::set_var("PLC_DIRECTORY_URL", mock_server.uri());
        std::env::remove_var("SKIP_IMPORT_VERIFICATION");
    }
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
    let import_status = import_res.status();
    let import_body: Value = import_res.json().await.unwrap_or(json!({}));
    unsafe {
        std::env::set_var("SKIP_IMPORT_VERIFICATION", "true");
    }
    assert_eq!(
        import_status,
        StatusCode::OK,
        "Import with valid DID document should succeed. Response: {:?}",
        import_body
    );
    let get_record_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.getRecord?repo={}&collection=app.bsky.feed.post&rkey={}",
            base_url().await,
            did,
            original_uri.split('/').last().unwrap()
        ))
        .send()
        .await
        .expect("Get record failed");
    assert_eq!(
        get_record_res.status(),
        StatusCode::OK,
        "Record should be retrievable after import"
    );
    let record_body: Value = get_record_res.json().await.unwrap();
    assert_eq!(
        record_body["value"]["text"], "Test post before migration",
        "Record content should match"
    );
}

#[tokio::test]
async fn test_migration_rejects_wrong_did_document() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let wrong_signing_key = SigningKey::random(&mut rand::thread_rng());
    let handle = get_user_handle(&did)
        .await
        .expect("Failed to get user handle");
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let pds_endpoint = format!("https://{}", hostname);
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
    let mock_server = MockServer::start().await;
    let did_encoded = urlencoding::encode(&did);
    let wrong_did_doc = create_did_document(&did, &handle, &wrong_signing_key, &pds_endpoint);
    Mock::given(method("GET"))
        .and(path(format!("/{}", did_encoded)))
        .respond_with(ResponseTemplate::new(200).set_body_json(wrong_did_doc))
        .mount(&mock_server)
        .await;
    unsafe {
        std::env::set_var("PLC_DIRECTORY_URL", mock_server.uri());
        std::env::remove_var("SKIP_IMPORT_VERIFICATION");
    }
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
    let import_status = import_res.status();
    let import_body: Value = import_res.json().await.unwrap_or(json!({}));
    unsafe {
        std::env::set_var("SKIP_IMPORT_VERIFICATION", "true");
    }
    assert_eq!(
        import_status,
        StatusCode::BAD_REQUEST,
        "Import with wrong DID document should fail. Response: {:?}",
        import_body
    );
    assert!(
        import_body["error"] == "InvalidSignature"
            || import_body["message"]
                .as_str()
                .unwrap_or("")
                .contains("signature"),
        "Error should mention signature verification failure"
    );
}

#[tokio::test]
#[ignore = "requires exclusive env var access; run with: cargo test test_full_migration_flow_end_to_end -- --ignored --test-threads=1"]
async fn test_full_migration_flow_end_to_end() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let key_bytes = get_user_signing_key(&did)
        .await
        .expect("Failed to get user signing key");
    let signing_key = SigningKey::from_slice(&key_bytes).expect("Failed to create signing key");
    let handle = get_user_handle(&did)
        .await
        .expect("Failed to get user handle");
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let pds_endpoint = format!("https://{}", hostname);
    let did_key = signing_key_to_did_key(&signing_key);
    for i in 0..3 {
        let post_payload = json!({
            "repo": did,
            "collection": "app.bsky.feed.post",
            "record": {
                "$type": "app.bsky.feed.post",
                "text": format!("Pre-migration post #{}", i),
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
    }
    let request_res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.requestPlcOperationSignature",
            base_url().await
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("Request failed");
    assert_eq!(request_res.status(), StatusCode::OK);
    let plc_token = get_plc_token_from_db(&did)
        .await
        .expect("PLC token not found");
    let mock_server = MockServer::start().await;
    let did_encoded = urlencoding::encode(&did);
    let last_op = json!({
        "type": "plc_operation",
        "rotationKeys": [did_key.clone()],
        "verificationMethods": { "atproto": did_key.clone() },
        "alsoKnownAs": [format!("at://{}", handle)],
        "services": {
            "atproto_pds": {
                "type": "AtprotoPersonalDataServer",
                "endpoint": pds_endpoint.clone()
            }
        },
        "prev": null,
        "sig": "initial_sig"
    });
    Mock::given(method("GET"))
        .and(path(format!("/{}/log/last", did_encoded)))
        .respond_with(ResponseTemplate::new(200).set_body_json(last_op))
        .mount(&mock_server)
        .await;
    let did_doc = create_did_document(&did, &handle, &signing_key, &pds_endpoint);
    Mock::given(method("GET"))
        .and(path(format!("/{}", did_encoded)))
        .respond_with(ResponseTemplate::new(200).set_body_json(did_doc))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/{}", did_encoded)))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;
    unsafe {
        std::env::set_var("PLC_DIRECTORY_URL", mock_server.uri());
    }
    let sign_res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.signPlcOperation",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&json!({ "token": plc_token }))
        .send()
        .await
        .expect("Sign failed");
    assert_eq!(sign_res.status(), StatusCode::OK);
    let sign_body: Value = sign_res.json().await.unwrap();
    let signed_op = sign_body.get("operation").unwrap().clone();
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
    let submit_res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.submitPlcOperation",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&json!({ "operation": signed_op }))
        .send()
        .await
        .expect("Submit failed");
    assert_eq!(submit_res.status(), StatusCode::OK);
    unsafe {
        std::env::remove_var("SKIP_IMPORT_VERIFICATION");
    }
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
    let import_status = import_res.status();
    let import_body: Value = import_res.json().await.unwrap_or(json!({}));
    unsafe {
        std::env::set_var("SKIP_IMPORT_VERIFICATION", "true");
    }
    assert_eq!(
        import_status,
        StatusCode::OK,
        "Full migration flow should succeed. Response: {:?}",
        import_body
    );
    let list_res = client
        .get(format!(
            "{}/xrpc/com.atproto.repo.listRecords?repo={}&collection=app.bsky.feed.post",
            base_url().await,
            did
        ))
        .send()
        .await
        .expect("List failed");
    assert_eq!(list_res.status(), StatusCode::OK);
    let list_body: Value = list_res.json().await.unwrap();
    let records = list_body["records"]
        .as_array()
        .expect("Should have records array");
    assert!(
        records.len() >= 1,
        "Should have at least 1 record after migration, found {}",
        records.len()
    );
}
