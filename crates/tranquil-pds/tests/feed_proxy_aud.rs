mod common;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

fn decode_jwt_claims(jwt: &str) -> Value {
    let payload = jwt
        .split('.')
        .nth(1)
        .expect("malformed jwt: no claims segment");
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .expect("malformed jwt: claims not base64url");
    serde_json::from_slice(&bytes).expect("malformed jwt: claims not json")
}

struct CaptureAuth(Arc<Mutex<Option<String>>>);

impl Respond for CaptureAuth {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let auth = req
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        *self.0.lock().unwrap() = auth;
        ResponseTemplate::new(200).set_body_json(json!({ "feed": [] }))
    }
}

/// getFeed's service-auth token must be audienced to the feed generator, not the AppView.
#[tokio::test]
async fn get_feed_service_auth_is_audienced_to_feed_generator() {
    let client = client();
    let (token, _did) = create_account_and_login(&client).await;

    // One mock server doubles as the AppView: did:web doc, getRecord, and getFeed.
    let appview = MockServer::start().await;
    let appview_uri = appview.uri();
    let host = appview_uri
        .strip_prefix("http://")
        .expect("mock uri should be http");
    // Literal-colon host so did:web resolves over http to the local mock.
    let appview_did = format!("did:web:{host}");

    Mock::given(method("GET"))
        .and(path("/.well-known/did.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": appview_did,
            "service": [{
                "id": "#bsky_appview",
                "type": "BskyAppView",
                "serviceEndpoint": appview_uri,
            }]
        })))
        .mount(&appview)
        .await;

    let feed_did = "did:web:feedgen.example.com";
    let feed_uri = "at://did:plc:feedcreator00000000000000/app.bsky.feed.generator/myfeed";

    // The feed generator record resolves to its service DID.
    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.repo.getRecord"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uri": feed_uri,
            "value": { "$type": "app.bsky.feed.generator", "did": feed_did },
        })))
        .mount(&appview)
        .await;

    // Capture the Authorization header the AppView is handed for getFeed.
    let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.feed.getFeed"))
        .respond_with(CaptureAuth(captured.clone()))
        .mount(&appview)
        .await;

    // Send the params a real client sends, so feed extraction must ignore extras.
    let res = client
        .get(format!("{}/xrpc/app.bsky.feed.getFeed", base_url().await))
        .query(&[("feed", feed_uri), ("limit", "30"), ("cursor", "abc123")])
        .header("authorization", format!("Bearer {}", token))
        .header("atproto-proxy", format!("{}#bsky_appview", appview_did))
        .send()
        .await
        .expect("getFeed proxy request failed");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "getFeed proxy should succeed: {:?}",
        res.text().await
    );

    let auth = captured
        .lock()
        .unwrap()
        .clone()
        .expect("AppView received no Authorization header");
    let jwt = auth
        .strip_prefix("Bearer ")
        .expect("forwarded auth should be a bearer token");
    let claims = decode_jwt_claims(jwt);

    assert_eq!(
        claims["aud"].as_str(),
        Some(feed_did),
        "service-auth token must be audienced to the feed generator, got {:?}",
        claims["aud"]
    );
    assert_eq!(
        claims["lxm"].as_str(),
        Some("app.bsky.feed.getFeedSkeleton"),
        "service-auth token lxm must be getFeedSkeleton, got {:?}",
        claims["lxm"]
    );
}

/// An unresolvable feed generator must be refused, not forwarded with an AppView aud.
#[tokio::test]
async fn get_feed_refuses_when_feed_generator_unresolvable() {
    let client = client();
    let (token, _did) = create_account_and_login(&client).await;

    let appview = MockServer::start().await;
    let appview_uri = appview.uri();
    let host = appview_uri
        .strip_prefix("http://")
        .expect("mock uri should be http");
    let appview_did = format!("did:web:{host}");

    Mock::given(method("GET"))
        .and(path("/.well-known/did.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": appview_did,
            "service": [{
                "id": "#bsky_appview",
                "type": "BskyAppView",
                "serviceEndpoint": appview_uri,
            }]
        })))
        .mount(&appview)
        .await;

    // getRecord fails, so the feed generator DID can't be resolved.
    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.repo.getRecord"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": "RecordNotFound",
        })))
        .mount(&appview)
        .await;

    // getFeed must never be reached with an AppView-audienced token.
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.feed.getFeed"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "feed": [] })))
        .expect(0)
        .mount(&appview)
        .await;

    let feed_uri = "at://did:plc:feedcreator00000000000000/app.bsky.feed.generator/myfeed";
    let res = client
        .get(format!("{}/xrpc/app.bsky.feed.getFeed", base_url().await))
        .query(&[("feed", feed_uri)])
        .header("authorization", format!("Bearer {token}"))
        .header("atproto-proxy", format!("{appview_did}#bsky_appview"))
        .send()
        .await
        .expect("getFeed proxy request failed");

    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "unresolvable feed should be rejected, got {}",
        res.status()
    );
}
