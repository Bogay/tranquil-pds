mod common;
use common::*;
use cid::Cid;
use ipld_core::ipld::Ipld;
use jacquard::types::{integer::LimitedU32, string::Tid};
use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use reqwest::StatusCode;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::BTreeMap;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn make_cid(data: &[u8]) -> Cid {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    let multihash = multihash::Multihash::wrap(0x12, &hash).unwrap();
    Cid::new_v1(0x71, multihash)
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

fn encode_car_block(cid: &Cid, data: &[u8]) -> Vec<u8> {
    let cid_bytes = cid.to_bytes();
    let mut result = Vec::new();
    write_varint(&mut result, (cid_bytes.len() + data.len()) as u64);
    result.extend_from_slice(&cid_bytes);
    result.extend_from_slice(data);
    result
}

fn get_multikey_from_signing_key(signing_key: &SigningKey) -> String {
    let public_key = signing_key.verifying_key();
    let compressed = public_key.to_sec1_bytes();
    fn encode_uvarint(mut x: u64) -> Vec<u8> {
        let mut out = Vec::new();
        while x >= 0x80 {
            out.push(((x as u8) & 0x7F) | 0x80);
            x >>= 7;
        }
        out.push(x as u8);
        out
    }
    let mut buf = encode_uvarint(0xE7);
    buf.extend_from_slice(&compressed);
    multibase::encode(multibase::Base::Base58Btc, buf)
}

fn create_did_document(did: &str, handle: &str, signing_key: &SigningKey, pds_endpoint: &str) -> serde_json::Value {
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

fn create_signed_commit(
    did: &str,
    data_cid: &Cid,
    signing_key: &SigningKey,
) -> (Vec<u8>, Cid) {
    let rev = Tid::now(LimitedU32::MIN).to_string();
    let unsigned = Ipld::Map(BTreeMap::from([
        ("data".to_string(), Ipld::Link(*data_cid)),
        ("did".to_string(), Ipld::String(did.to_string())),
        ("prev".to_string(), Ipld::Null),
        ("rev".to_string(), Ipld::String(rev.clone())),
        ("sig".to_string(), Ipld::Bytes(vec![])),
        ("version".to_string(), Ipld::Integer(3)),
    ]));
    let unsigned_bytes = serde_ipld_dagcbor::to_vec(&unsigned).unwrap();
    let signature: Signature = signing_key.sign(&unsigned_bytes);
    let sig_bytes = signature.to_bytes().to_vec();
    let signed = Ipld::Map(BTreeMap::from([
        ("data".to_string(), Ipld::Link(*data_cid)),
        ("did".to_string(), Ipld::String(did.to_string())),
        ("prev".to_string(), Ipld::Null),
        ("rev".to_string(), Ipld::String(rev)),
        ("sig".to_string(), Ipld::Bytes(sig_bytes)),
        ("version".to_string(), Ipld::Integer(3)),
    ]));
    let signed_bytes = serde_ipld_dagcbor::to_vec(&signed).unwrap();
    let cid = make_cid(&signed_bytes);
    (signed_bytes, cid)
}

fn create_mst_node(entries: Vec<(String, Cid)>) -> (Vec<u8>, Cid) {
    let ipld_entries: Vec<Ipld> = entries
        .into_iter()
        .map(|(key, value_cid)| {
            Ipld::Map(BTreeMap::from([
                ("k".to_string(), Ipld::Bytes(key.into_bytes())),
                ("v".to_string(), Ipld::Link(value_cid)),
                ("p".to_string(), Ipld::Integer(0)),
            ]))
        })
        .collect();
    let node = Ipld::Map(BTreeMap::from([
        ("e".to_string(), Ipld::List(ipld_entries)),
    ]));
    let bytes = serde_ipld_dagcbor::to_vec(&node).unwrap();
    let cid = make_cid(&bytes);
    (bytes, cid)
}

fn create_record() -> (Vec<u8>, Cid) {
    let record = Ipld::Map(BTreeMap::from([
        ("$type".to_string(), Ipld::String("app.bsky.feed.post".to_string())),
        ("text".to_string(), Ipld::String("Test post for verification".to_string())),
        ("createdAt".to_string(), Ipld::String("2024-01-01T00:00:00Z".to_string())),
    ]));
    let bytes = serde_ipld_dagcbor::to_vec(&record).unwrap();
    let cid = make_cid(&bytes);
    (bytes, cid)
}
fn build_car_with_signature(
    did: &str,
    signing_key: &SigningKey,
) -> (Vec<u8>, Cid) {
    let (record_bytes, record_cid) = create_record();
    let (mst_bytes, mst_cid) = create_mst_node(vec![
        ("app.bsky.feed.post/test123".to_string(), record_cid),
    ]);
    let (commit_bytes, commit_cid) = create_signed_commit(did, &mst_cid, signing_key);
    let header = iroh_car::CarHeader::new_v1(vec![commit_cid]);
    let header_bytes = header.encode().unwrap();
    let mut car = Vec::new();
    write_varint(&mut car, header_bytes.len() as u64);
    car.extend_from_slice(&header_bytes);
    car.extend(encode_car_block(&commit_cid, &commit_bytes));
    car.extend(encode_car_block(&mst_cid, &mst_bytes));
    car.extend(encode_car_block(&record_cid, &record_bytes));
    (car, commit_cid)
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
#[tokio::test]
#[ignore = "requires exclusive env var access; run with: cargo test test_import_with_valid_signature_and_mock_plc -- --ignored --test-threads=1"]
async fn test_import_with_valid_signature_and_mock_plc() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let key_bytes = get_user_signing_key(&did).await
        .expect("Failed to get user signing key");
    let signing_key = SigningKey::from_slice(&key_bytes)
        .expect("Failed to create signing key");
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let pds_endpoint = format!("https://{}", hostname);
    let handle = did.split(':').last().unwrap_or("user");
    let did_doc = create_did_document(&did, handle, &signing_key, &pds_endpoint);
    let mock_plc = setup_mock_plc_directory(&did, did_doc).await;
    unsafe {
        std::env::set_var("PLC_DIRECTORY_URL", mock_plc.uri());
        std::env::remove_var("SKIP_IMPORT_VERIFICATION");
    }
    let (car_bytes, _root_cid) = build_car_with_signature(&did, &signing_key);
    let import_res = client
        .post(format!("{}/xrpc/com.atproto.repo.importRepo", base_url().await))
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
    let key_bytes = get_user_signing_key(&did).await
        .expect("Failed to get user signing key");
    let correct_signing_key = SigningKey::from_slice(&key_bytes)
        .expect("Failed to create signing key");
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let pds_endpoint = format!("https://{}", hostname);
    let handle = did.split(':').last().unwrap_or("user");
    let did_doc = create_did_document(&did, handle, &correct_signing_key, &pds_endpoint);
    let mock_plc = setup_mock_plc_directory(&did, did_doc).await;
    unsafe {
        std::env::set_var("PLC_DIRECTORY_URL", mock_plc.uri());
        std::env::remove_var("SKIP_IMPORT_VERIFICATION");
    }
    let (car_bytes, _root_cid) = build_car_with_signature(&did, &wrong_signing_key);
    let import_res = client
        .post(format!("{}/xrpc/com.atproto.repo.importRepo", base_url().await))
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
        body["error"] == "InvalidSignature" || body["message"].as_str().unwrap_or("").contains("signature"),
        "Error should mention signature: {:?}",
        body
    );
}
#[tokio::test]
#[ignore = "requires exclusive env var access; run with: cargo test test_import_with_did_mismatch_fails -- --ignored --test-threads=1"]
async fn test_import_with_did_mismatch_fails() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;
    let key_bytes = get_user_signing_key(&did).await
        .expect("Failed to get user signing key");
    let signing_key = SigningKey::from_slice(&key_bytes)
        .expect("Failed to create signing key");
    let wrong_did = "did:plc:wrongdidthatdoesnotmatch";
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let pds_endpoint = format!("https://{}", hostname);
    let handle = did.split(':').last().unwrap_or("user");
    let did_doc = create_did_document(&did, handle, &signing_key, &pds_endpoint);
    let mock_plc = setup_mock_plc_directory(&did, did_doc).await;
    unsafe {
        std::env::set_var("PLC_DIRECTORY_URL", mock_plc.uri());
        std::env::remove_var("SKIP_IMPORT_VERIFICATION");
    }
    let (car_bytes, _root_cid) = build_car_with_signature(wrong_did, &signing_key);
    let import_res = client
        .post(format!("{}/xrpc/com.atproto.repo.importRepo", base_url().await))
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
    let key_bytes = get_user_signing_key(&did).await
        .expect("Failed to get user signing key");
    let signing_key = SigningKey::from_slice(&key_bytes)
        .expect("Failed to create signing key");
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
        std::env::remove_var("SKIP_IMPORT_VERIFICATION");
    }
    let (car_bytes, _root_cid) = build_car_with_signature(&did, &signing_key);
    let import_res = client
        .post(format!("{}/xrpc/com.atproto.repo.importRepo", base_url().await))
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
    let key_bytes = get_user_signing_key(&did).await
        .expect("Failed to get user signing key");
    let signing_key = SigningKey::from_slice(&key_bytes)
        .expect("Failed to create signing key");
    let handle = did.split(':').last().unwrap_or("user");
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
        std::env::remove_var("SKIP_IMPORT_VERIFICATION");
    }
    let (car_bytes, _root_cid) = build_car_with_signature(&did, &signing_key);
    let import_res = client
        .post(format!("{}/xrpc/com.atproto.repo.importRepo", base_url().await))
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
