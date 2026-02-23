mod common;
mod helpers;
use common::*;
use helpers::*;
use k256::ecdsa::SigningKey;
use reqwest::StatusCode;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn create_did_document(
    did: &str,
    handle: &str,
    signing_key: &SigningKey,
    pds_endpoint: &str,
) -> serde_json::Value {
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

async fn setup_mock_plc_directory(did: &str, did_doc: serde_json::Value) -> MockServer {
    let mock_server = MockServer::start().await;
    let did_encoded = urlencoding::encode(did);
    let did_path = format!("/{}", did_encoded);
    Mock::given(method("GET"))
        .and(path(did_path))
        .respond_with(ResponseTemplate::new(200).set_body_json(did_doc))
        .mount(&mock_server)
        .await;
    mock_server
}

#[tokio::test]
#[ignore = "requires exclusive env var access; run with: cargo test test_import_with_valid_signature_and_mock_plc -- --ignored --test-threads=1"]
async fn test_import_with_valid_signature_and_mock_plc() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let key_bytes = get_user_signing_key(&did)
        .await
        .expect("Failed to get user signing key");
    let signing_key = SigningKey::from_slice(&key_bytes).expect("Failed to create signing key");
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let pds_endpoint = format!("https://{}", hostname);
    let handle = did.split(':').next_back().unwrap_or("user");
    let did_doc = create_did_document(&did, handle, &signing_key, &pds_endpoint);
    let mock_plc = setup_mock_plc_directory(&did, did_doc).await;
    unsafe {
        std::env::set_var("PLC_DIRECTORY_URL", mock_plc.uri());
        std::env::set_var("SKIP_IMPORT_VERIFICATION", "false");
    }
    let (car_bytes, _root_cid) = build_car_with_signature(&did, &signing_key);
    let import_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.importRepo",
            base_url().await
        ))
        .bearer_auth(&token)
        .header("Content-Type", "application/vnd.ipld.car")
        .body(car_bytes)
        .send()
        .await
        .expect("Import request failed");
    let status = import_res.status();
    let body: serde_json::Value = import_res.json().await.unwrap_or(json!({}));
    unsafe {
        std::env::set_var("SKIP_IMPORT_VERIFICATION", "true");
    }
    assert_eq!(
        status,
        StatusCode::OK,
        "Import with valid signature should succeed. Response: {:?}",
        body
    );
}
#[tokio::test]
#[ignore = "requires exclusive env var access; run with: cargo test test_import_with_wrong_signing_key_fails -- --ignored --test-threads=1"]
async fn test_import_with_wrong_signing_key_fails() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let wrong_signing_key = SigningKey::random(&mut rand::thread_rng());
    let key_bytes = get_user_signing_key(&did)
        .await
        .expect("Failed to get user signing key");
    let correct_signing_key =
        SigningKey::from_slice(&key_bytes).expect("Failed to create signing key");
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let pds_endpoint = format!("https://{}", hostname);
    let handle = did.split(':').next_back().unwrap_or("user");
    let did_doc = create_did_document(&did, handle, &correct_signing_key, &pds_endpoint);
    let mock_plc = setup_mock_plc_directory(&did, did_doc).await;
    unsafe {
        std::env::set_var("PLC_DIRECTORY_URL", mock_plc.uri());
        std::env::set_var("SKIP_IMPORT_VERIFICATION", "false");
    }
    let (car_bytes, _root_cid) = build_car_with_signature(&did, &wrong_signing_key);
    let import_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.importRepo",
            base_url().await
        ))
        .bearer_auth(&token)
        .header("Content-Type", "application/vnd.ipld.car")
        .body(car_bytes)
        .send()
        .await
        .expect("Import request failed");
    let status = import_res.status();
    let body: serde_json::Value = import_res.json().await.unwrap_or(json!({}));
    unsafe {
        std::env::set_var("SKIP_IMPORT_VERIFICATION", "true");
    }
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Import with wrong signature should fail. Response: {:?}",
        body
    );
    assert!(
        body["error"] == "InvalidSignature"
            || body["message"].as_str().unwrap_or("").contains("signature"),
        "Error should mention signature: {:?}",
        body
    );
}
#[tokio::test]
#[ignore = "requires exclusive env var access; run with: cargo test test_import_with_did_mismatch_fails -- --ignored --test-threads=1"]
async fn test_import_with_did_mismatch_fails() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let key_bytes = get_user_signing_key(&did)
        .await
        .expect("Failed to get user signing key");
    let signing_key = SigningKey::from_slice(&key_bytes).expect("Failed to create signing key");
    let wrong_did = "did:plc:wrongdidthatdoesnotmatch";
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let pds_endpoint = format!("https://{}", hostname);
    let handle = did.split(':').next_back().unwrap_or("user");
    let did_doc = create_did_document(&did, handle, &signing_key, &pds_endpoint);
    let mock_plc = setup_mock_plc_directory(&did, did_doc).await;
    unsafe {
        std::env::set_var("PLC_DIRECTORY_URL", mock_plc.uri());
        std::env::set_var("SKIP_IMPORT_VERIFICATION", "false");
    }
    let (car_bytes, _root_cid) = build_car_with_signature(wrong_did, &signing_key);
    let import_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.importRepo",
            base_url().await
        ))
        .bearer_auth(&token)
        .header("Content-Type", "application/vnd.ipld.car")
        .body(car_bytes)
        .send()
        .await
        .expect("Import request failed");
    let status = import_res.status();
    let body: serde_json::Value = import_res.json().await.unwrap_or(json!({}));
    unsafe {
        std::env::set_var("SKIP_IMPORT_VERIFICATION", "true");
    }
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "Import with DID mismatch should be forbidden. Response: {:?}",
        body
    );
}
#[tokio::test]
#[ignore = "requires exclusive env var access; run with: cargo test test_import_with_plc_resolution_failure -- --ignored --test-threads=1"]
async fn test_import_with_plc_resolution_failure() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let key_bytes = get_user_signing_key(&did)
        .await
        .expect("Failed to get user signing key");
    let signing_key = SigningKey::from_slice(&key_bytes).expect("Failed to create signing key");
    let mock_plc = MockServer::start().await;
    let did_encoded = urlencoding::encode(&did);
    let did_path = format!("/{}", did_encoded);
    Mock::given(method("GET"))
        .and(path(did_path))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_plc)
        .await;
    unsafe {
        std::env::set_var("PLC_DIRECTORY_URL", mock_plc.uri());
        std::env::set_var("SKIP_IMPORT_VERIFICATION", "false");
    }
    let (car_bytes, _root_cid) = build_car_with_signature(&did, &signing_key);
    let import_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.importRepo",
            base_url().await
        ))
        .bearer_auth(&token)
        .header("Content-Type", "application/vnd.ipld.car")
        .body(car_bytes)
        .send()
        .await
        .expect("Import request failed");
    let status = import_res.status();
    let body: serde_json::Value = import_res.json().await.unwrap_or(json!({}));
    unsafe {
        std::env::set_var("SKIP_IMPORT_VERIFICATION", "true");
    }
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Import with PLC resolution failure should fail. Response: {:?}",
        body
    );
}
#[tokio::test]
#[ignore = "requires exclusive env var access; run with: cargo test test_import_with_no_signing_key_in_did_doc -- --ignored --test-threads=1"]
async fn test_import_with_no_signing_key_in_did_doc() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let key_bytes = get_user_signing_key(&did)
        .await
        .expect("Failed to get user signing key");
    let signing_key = SigningKey::from_slice(&key_bytes).expect("Failed to create signing key");
    let handle = did.split(':').next_back().unwrap_or("user");
    let did_doc_without_key = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "alsoKnownAs": [format!("at://{}", handle)],
        "verificationMethod": [],
        "service": []
    });
    let mock_plc = setup_mock_plc_directory(&did, did_doc_without_key).await;
    unsafe {
        std::env::set_var("PLC_DIRECTORY_URL", mock_plc.uri());
        std::env::set_var("SKIP_IMPORT_VERIFICATION", "false");
    }
    let (car_bytes, _root_cid) = build_car_with_signature(&did, &signing_key);
    let import_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.importRepo",
            base_url().await
        ))
        .bearer_auth(&token)
        .header("Content-Type", "application/vnd.ipld.car")
        .body(car_bytes)
        .send()
        .await
        .expect("Import request failed");
    let status = import_res.status();
    let body: serde_json::Value = import_res.json().await.unwrap_or(json!({}));
    unsafe {
        std::env::set_var("SKIP_IMPORT_VERIFICATION", "true");
    }
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Import with missing signing key should fail. Response: {:?}",
        body
    );
}
