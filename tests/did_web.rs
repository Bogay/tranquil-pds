mod common;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::*;
use k256::ecdsa::{SigningKey, signature::Signer};
use reqwest::StatusCode;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_create_self_hosted_did_web() {
    let client = client();
    let handle = format!("sw{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let payload = json!({
        "handle": handle,
        "email": format!("{}@example.com", handle),
        "password": "Testpass123!",
        "didType": "web"
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    if res.status() != StatusCode::OK {
        let body: Value = res.json().await.unwrap_or(json!({"error": "parse failed"}));
        panic!("createAccount failed: {:?}", body);
    }
    let body: Value = res.json().await.expect("Response was not JSON");
    let did = body["did"].as_str().expect("No DID in response");
    assert!(
        did.starts_with("did:web:"),
        "DID should start with did:web:, got: {}",
        did
    );
    assert!(
        did.contains(&handle),
        "DID should contain handle {}, got: {}",
        handle,
        did
    );
    assert!(
        !did.contains(":u:"),
        "Self-hosted did:web should use subdomain format (no :u:), got: {}",
        did
    );
    let jwt = verify_new_account(&client, did).await;
    let res = client
        .get(format!("{}/u/{}/did.json", base_url().await, handle))
        .send()
        .await
        .expect("Failed to fetch DID doc via path");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "Self-hosted did:web should have DID doc served by PDS (via path for backwards compat)"
    );
    let doc: Value = res.json().await.expect("DID doc was not JSON");
    assert_eq!(doc["id"], did);
    assert!(
        doc["verificationMethod"][0]["publicKeyMultibase"].is_string(),
        "DID doc should have publicKeyMultibase"
    );
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&json!({
            "repo": did,
            "collection": "app.bsky.feed.post",
            "record": {
                "$type": "app.bsky.feed.post",
                "text": "Hello from did:web!",
                "createdAt": chrono::Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .expect("Failed to create post");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "Self-hosted did:web account should be able to create records"
    );
}

#[tokio::test]
async fn test_external_did_web_no_local_doc() {
    let client = client();
    let mock_server = MockServer::start().await;
    let mock_uri = mock_server.uri();
    let mock_addr = mock_uri.trim_start_matches("http://");
    let did = format!("did:web:{}", mock_addr.replace(":", "%3A"));
    let handle = format!("xw{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let pds_endpoint = base_url().await.replace("http://", "https://");

    let reserve_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.reserveSigningKey",
            base_url().await
        ))
        .json(&json!({ "did": did }))
        .send()
        .await
        .expect("Failed to reserve signing key");
    assert_eq!(reserve_res.status(), StatusCode::OK);
    let reserve_body: Value = reserve_res.json().await.expect("Response was not JSON");
    let signing_key = reserve_body["signingKey"]
        .as_str()
        .expect("No signingKey returned");
    let public_key_multibase = signing_key
        .strip_prefix("did:key:")
        .expect("signingKey should start with did:key:");

    let did_doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [{
            "id": format!("{}#atproto", did),
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": public_key_multibase
        }],
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": pds_endpoint
        }]
    });
    Mock::given(method("GET"))
        .and(path("/.well-known/did.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(did_doc))
        .mount(&mock_server)
        .await;
    let payload = json!({
        "handle": handle,
        "email": format!("{}@example.com", handle),
        "password": "Testpass123!",
        "didType": "web-external",
        "did": did,
        "signingKey": signing_key
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    if res.status() != StatusCode::OK {
        let body: Value = res.json().await.unwrap_or(json!({"error": "parse failed"}));
        panic!("createAccount failed: {:?}", body);
    }
    let res = client
        .get(format!("{}/u/{}/did.json", base_url().await, handle))
        .send()
        .await
        .expect("Failed to fetch DID doc");
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "External did:web should NOT have DID doc served by PDS"
    );
    let body: Value = res.json().await.expect("Response was not JSON");
    assert!(
        body["message"].as_str().unwrap_or("").contains("External"),
        "Error message should indicate external did:web"
    );
}

#[tokio::test]
async fn test_plc_operations_blocked_for_did_web() {
    let client = client();
    let handle = format!("pb{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let payload = json!({
        "handle": handle,
        "email": format!("{}@example.com", handle),
        "password": "Testpass123!",
        "didType": "web"
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not JSON");
    let did = body["did"].as_str().expect("No DID").to_string();
    let jwt = verify_new_account(&client, &did).await;
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.signPlcOperation",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&json!({
            "token": "fake-token"
        }))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "signPlcOperation should be blocked for did:web users"
    );
    let body: Value = res.json().await.expect("Response was not JSON");
    assert!(
        body["message"].as_str().unwrap_or("").contains("did:plc"),
        "Error should mention did:plc: {:?}",
        body
    );
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.identity.submitPlcOperation",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .json(&json!({
            "operation": {}
        }))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "submitPlcOperation should be blocked for did:web users"
    );
}

#[tokio::test]
async fn test_get_recommended_did_credentials_no_rotation_keys_for_did_web() {
    let client = client();
    let handle = format!("cr{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let payload = json!({
        "handle": handle,
        "email": format!("{}@example.com", handle),
        "password": "Testpass123!",
        "didType": "web"
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not JSON");
    let did = body["did"].as_str().expect("No DID").to_string();
    let jwt = verify_new_account(&client, &did).await;
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.identity.getRecommendedDidCredentials",
            base_url().await
        ))
        .bearer_auth(&jwt)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not JSON");
    let rotation_keys = body["rotationKeys"]
        .as_array()
        .expect("rotationKeys should be an array");
    assert!(
        rotation_keys.is_empty(),
        "did:web should have no rotation keys, got: {:?}",
        rotation_keys
    );
    assert!(
        body["verificationMethods"].is_object(),
        "verificationMethods should be present"
    );
    assert!(body["services"].is_object(), "services should be present");
}

#[tokio::test]
async fn test_did_plc_still_works_with_did_type_param() {
    let client = client();
    let handle = format!("pt{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let payload = json!({
        "handle": handle,
        "email": format!("{}@example.com", handle),
        "password": "Testpass123!",
        "didType": "plc"
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not JSON");
    let did = body["did"].as_str().expect("No DID").to_string();
    assert!(
        did.starts_with("did:plc:"),
        "DID with didType=plc should be did:plc:, got: {}",
        did
    );
}

#[tokio::test]
async fn test_external_did_web_requires_did_field() {
    let client = client();
    let handle = format!("nd{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let payload = json!({
        "handle": handle,
        "email": format!("{}@example.com", handle),
        "password": "Testpass123!",
        "didType": "web-external"
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "web-external without did should fail"
    );
    let body: Value = res.json().await.expect("Response was not JSON");
    assert!(
        body["message"].as_str().unwrap_or("").contains("did"),
        "Error should mention did field is required: {:?}",
        body
    );
}

fn signing_key_to_multibase(signing_key: &SigningKey) -> String {
    let verifying_key = signing_key.verifying_key();
    let compressed = verifying_key.to_sec1_bytes();
    let mut multicodec = vec![0xe7, 0x01];
    multicodec.extend_from_slice(&compressed);
    multibase::encode(multibase::Base::Base58Btc, &multicodec)
}

fn create_service_jwt(signing_key: &SigningKey, did: &str, aud: &str) -> String {
    let header = json!({"alg": "ES256K", "typ": "jwt"});
    let now = chrono::Utc::now().timestamp() as usize;
    let claims = json!({
        "iss": did,
        "sub": did,
        "aud": aud,
        "exp": now + 300,
        "iat": now,
        "lxm": "com.atproto.server.createAccount",
        "jti": uuid::Uuid::new_v4().to_string()
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string());
    let claims_b64 = URL_SAFE_NO_PAD.encode(claims.to_string());
    let message = format!("{}.{}", header_b64, claims_b64);
    let signature: k256::ecdsa::Signature = signing_key.sign(message.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    format!("{}.{}", message, sig_b64)
}

#[tokio::test]
async fn test_did_web_byod_flow() {
    let client = client();
    let mock_server = MockServer::start().await;
    let mock_uri = mock_server.uri();
    let mock_addr = mock_uri.trim_start_matches("http://");
    let unique_id = uuid::Uuid::new_v4().to_string().replace("-", "");
    let did = format!(
        "did:web:{}:byod:{}",
        mock_addr.replace(":", "%3A"),
        unique_id
    );
    let handle = format!("by{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let pds_endpoint = base_url().await.replace("http://", "https://");
    let pds_did = format!("did:web:{}", pds_endpoint.trim_start_matches("https://"));

    let temp_key = SigningKey::random(&mut rand::thread_rng());
    let public_key_multibase = signing_key_to_multibase(&temp_key);

    let did_doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [{
            "id": format!("{}#atproto", did),
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": public_key_multibase
        }],
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": pds_endpoint
        }]
    });
    Mock::given(method("GET"))
        .and(path(format!("/byod/{}/did.json", unique_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(&did_doc))
        .mount(&mock_server)
        .await;

    let service_jwt = create_service_jwt(&temp_key, &did, &pds_did);
    let payload = json!({
        "handle": handle,
        "email": format!("{}@example.com", handle),
        "password": "Testpass123!",
        "did": did
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .header("Authorization", format!("Bearer {}", service_jwt))
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    if res.status() != StatusCode::OK {
        let body: Value = res.json().await.unwrap_or(json!({"error": "parse failed"}));
        panic!("createAccount BYOD failed: {:?}", body);
    }
    let body: Value = res.json().await.expect("Response was not JSON");
    let returned_did = body["did"].as_str().expect("No DID in response");
    assert_eq!(returned_did, did, "Returned DID should match requested DID");
    assert_eq!(
        body["verificationRequired"], true,
        "BYOD accounts should require verification"
    );

    let access_jwt = common::verify_new_account(&client, returned_did).await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.server.checkAccountStatus",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .send()
        .await
        .expect("Failed to check account status");
    assert_eq!(res.status(), StatusCode::OK);
    let status: Value = res.json().await.expect("Response was not JSON");
    assert_eq!(
        status["activated"], false,
        "BYOD account should be deactivated initially"
    );

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.identity.getRecommendedDidCredentials",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .send()
        .await
        .expect("Failed to get recommended credentials");
    assert_eq!(res.status(), StatusCode::OK);
    let creds: Value = res.json().await.expect("Response was not JSON");
    assert!(
        creds["verificationMethods"]["atproto"].is_string(),
        "Should return PDS signing key"
    );
    let pds_signing_key = creds["verificationMethods"]["atproto"]
        .as_str()
        .expect("No atproto verification method");
    assert!(
        pds_signing_key.starts_with("did:key:"),
        "PDS signing key should be did:key format"
    );

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.activateAccount",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .send()
        .await
        .expect("Failed to activate account");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "activateAccount should succeed"
    );

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.server.checkAccountStatus",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .send()
        .await
        .expect("Failed to check account status");
    assert_eq!(res.status(), StatusCode::OK);
    let status: Value = res.json().await.expect("Response was not JSON");
    assert_eq!(
        status["activated"], true,
        "Account should be activated after activateAccount call"
    );

    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            base_url().await
        ))
        .bearer_auth(&access_jwt)
        .json(&json!({
            "repo": did,
            "collection": "app.bsky.feed.post",
            "record": {
                "$type": "app.bsky.feed.post",
                "text": "Hello from BYOD did:web!",
                "createdAt": chrono::Utc::now().to_rfc3339()
            }
        }))
        .send()
        .await
        .expect("Failed to create post");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "Activated BYOD account should be able to create records"
    );
}
