mod common;
use common::*;
use reqwest::StatusCode;
use serde_json::{json, Value};
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path};

// #[tokio::test]
// async fn test_resolve_handle() {
//     let client = client();
//     let params = [
//         ("handle", "bsky.app"),
//     ];
//     let res = client.get(format!("{}/xrpc/com.atproto.identity.resolveHandle", base_url().await))
//         .query(&params)
//         .send()
//         .await
//         .expect("Failed to send request");
//
//     assert_eq!(res.status(), StatusCode::OK);
// }

#[tokio::test]
async fn test_well_known_did() {
    let client = client();
    let res = client.get(format!("{}/.well-known/did.json", base_url().await))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Response was not valid JSON");
    assert!(body["id"].as_str().unwrap().starts_with("did:web:"));
    assert_eq!(body["service"][0]["type"], "AtprotoPersonalDataServer");
}

#[tokio::test]
async fn test_create_did_web_account_and_resolve() {
    let client = client();

    let mock_server = MockServer::start().await;
    let mock_uri = mock_server.uri();
    let mock_addr = mock_uri.trim_start_matches("http://");

    let did = format!("did:web:{}", mock_addr.replace(":", "%3A"));

    let handle = format!("webuser_{}", uuid::Uuid::new_v4());

    let pds_endpoint = "https://localhost";

    let did_doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
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
        "password": "password",
        "did": did
    });

    let res = client.post(format!("{}/xrpc/com.atproto.server.createAccount", base_url().await))
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");

    if res.status() != StatusCode::OK {
        let status = res.status();
        let body: Value = res.json().await.unwrap_or(json!({"error": "could not parse body"}));
        panic!("createAccount failed with status {}: {:?}", status, body);
    }
    let body: Value = res.json().await.expect("createAccount response was not JSON");
    assert_eq!(body["did"], did);

    let res = client.get(format!("{}/u/{}/did.json", base_url().await, handle))
        .send()
        .await
        .expect("Failed to fetch DID doc");

    assert_eq!(res.status(), StatusCode::OK);
    let doc: Value = res.json().await.expect("DID doc was not JSON");

    assert_eq!(doc["id"], did);
    assert_eq!(doc["alsoKnownAs"][0], format!("at://{}", handle));
    assert_eq!(doc["verificationMethod"][0]["controller"], did);
    assert!(doc["verificationMethod"][0]["publicKeyJwk"].is_object());
}

#[tokio::test]
async fn test_create_account_duplicate_handle() {
    let client = client();
    let handle = format!("dupe_{}", uuid::Uuid::new_v4());
    let email = format!("{}@example.com", handle);

    let payload = json!({
        "handle": handle,
        "email": email,
        "password": "password"
    });

    let res = client.post(format!("{}/xrpc/com.atproto.server.createAccount", base_url().await))
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);

    let res = client.post(format!("{}/xrpc/com.atproto.server.createAccount", base_url().await))
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: Value = res.json().await.expect("Response was not JSON");
    assert_eq!(body["error"], "HandleTaken");
}

#[tokio::test]
async fn test_did_web_lifecycle() {
    let client = client();
    let handle = format!("lifecycle_{}", uuid::Uuid::new_v4());
    let did = format!("did:web:localhost:u:{}", handle);
    let email = format!("{}@test.com", handle);

    let create_payload = json!({
        "handle": handle,
        "email": email,
        "password": "password",
        "did": did
    });

    let res = client.post(format!("{}/xrpc/com.atproto.server.createAccount", base_url().await))
        .json(&create_payload)
        .send()
        .await
        .expect("Failed createAccount");

    if res.status() != StatusCode::OK {
        let body: Value = res.json().await.unwrap();
        println!("createAccount failed: {:?}", body);
        panic!("createAccount returned non-200");
    }
    assert_eq!(res.status(), StatusCode::OK);
    let create_body: Value = res.json().await.expect("Not JSON");
    assert_eq!(create_body["did"], did);

    let login_payload = json!({
        "identifier": handle,
        "password": "password"
    });
    let res = client.post(format!("{}/xrpc/com.atproto.server.createSession", base_url().await))
        .json(&login_payload)
        .send()
        .await
        .expect("Failed createSession");

    assert_eq!(res.status(), StatusCode::OK);
    let session_body: Value = res.json().await.expect("Not JSON");
    let _jwt = session_body["accessJwt"].as_str().unwrap();

    /*
    let profile_payload = json!({
        "repo": did,
        "collection": "app.bsky.actor.profile",
        "rkey": "self",
        "record": {
            "$type": "app.bsky.actor.profile",
            "displayName": "DID Web User",
            "description": "Testing lifecycle"
        }
    });

    let res = client.post(format!("{}/xrpc/com.atproto.repo.putRecord", base_url().await))
        .bearer_auth(_jwt)
        .json(&profile_payload)
        .send()
        .await
        .expect("Failed putRecord");

    if res.status() != StatusCode::OK {
        let body: Value = res.json().await.unwrap();
        println!("putRecord failed: {:?}", body);
        panic!("putRecord returned non-200");
    }
    assert_eq!(res.status(), StatusCode::OK);

    let res = client.get(format!("{}/xrpc/com.atproto.repo.getRecord", base_url().await))
        .query(&[
            ("repo", &handle),
            ("collection", &"app.bsky.actor.profile".to_string()),
            ("rkey", &"self".to_string())
        ])
        .send()
        .await
        .expect("Failed getRecord");

    if res.status() != StatusCode::OK {
        let body: Value = res.json().await.unwrap();
        println!("getRecord failed: {:?}", body);
        panic!("getRecord returned non-200");
    }
    let record_body: Value = res.json().await.expect("Not JSON");
    assert_eq!(record_body["value"]["displayName"], "DID Web User");
    */
}
