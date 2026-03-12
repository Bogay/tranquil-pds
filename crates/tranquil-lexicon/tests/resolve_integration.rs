#![cfg(feature = "resolve")]

use std::time::Duration;

use serde_json::json;
use tranquil_lexicon::{
    ResolveError, fetch_schema_from_pds, resolve_lexicon_from_did, resolve_pds_endpoint,
};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn mock_did_document(did: &str, pds_endpoint: &str) -> serde_json::Value {
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": pds_endpoint
        }]
    })
}

fn mock_lexicon_schema(nsid: &str) -> serde_json::Value {
    json!({
        "lexicon": 1,
        "id": nsid,
        "defs": {
            "main": {
                "type": "record",
                "key": "tid",
                "record": {
                    "type": "object",
                    "required": ["text", "createdAt"],
                    "properties": {
                        "text": {
                            "type": "string",
                            "maxLength": 1000,
                            "maxGraphemes": 100
                        },
                        "createdAt": {
                            "type": "string",
                            "format": "datetime"
                        }
                    }
                }
            }
        }
    })
}

fn mock_get_record_response(nsid: &str) -> serde_json::Value {
    json!({
        "uri": format!("at://did:plc:test123/com.atproto.lexicon.schema/{}", nsid),
        "cid": "bafyreiabcdef",
        "value": mock_lexicon_schema(nsid)
    })
}

#[tokio::test]
async fn test_resolve_pds_endpoint_from_plc() {
    let plc_server = MockServer::start().await;
    let did = "did:plc:testabcdef123";

    Mock::given(method("GET"))
        .and(path(format!("/{}", did)))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(mock_did_document(did, "https://pds.example.com")),
        )
        .mount(&plc_server)
        .await;

    let endpoint = resolve_pds_endpoint(did, Some(&plc_server.uri()))
        .await
        .unwrap();
    assert_eq!(endpoint, "https://pds.example.com");
}

#[tokio::test]
async fn test_resolve_pds_endpoint_no_pds_service() {
    let plc_server = MockServer::start().await;
    let did = "did:plc:nopds123";

    Mock::given(method("GET"))
        .and(path(format!("/{}", did)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": did,
            "service": [{
                "type": "AtprotoLabeler",
                "serviceEndpoint": "https://labeler.example.com"
            }]
        })))
        .mount(&plc_server)
        .await;

    let result = resolve_pds_endpoint(did, Some(&plc_server.uri())).await;
    assert!(matches!(result, Err(ResolveError::NoPdsEndpoint { .. })));
}

#[tokio::test]
async fn test_resolve_pds_endpoint_plc_not_found() {
    let plc_server = MockServer::start().await;
    let did = "did:plc:missing123";

    Mock::given(method("GET"))
        .and(path(format!("/{}", did)))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(&plc_server)
        .await;

    let result = resolve_pds_endpoint(did, Some(&plc_server.uri())).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_resolve_pds_endpoint_unsupported_did_method() {
    let result = resolve_pds_endpoint("did:key:z6MkTest", None).await;
    assert!(matches!(result, Err(ResolveError::DidResolution { .. })));
}

#[tokio::test]
async fn test_resolve_pds_endpoint_multiple_services_picks_pds() {
    let plc_server = MockServer::start().await;
    let did = "did:plc:multi123";

    Mock::given(method("GET"))
        .and(path(format!("/{}", did)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": did,
            "service": [
                {
                    "type": "AtprotoLabeler",
                    "serviceEndpoint": "https://labeler.example.com"
                },
                {
                    "type": "BskyNotificationService",
                    "serviceEndpoint": "https://notify.example.com"
                },
                {
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": "https://pds.example.com"
                }
            ]
        })))
        .mount(&plc_server)
        .await;

    let endpoint = resolve_pds_endpoint(did, Some(&plc_server.uri()))
        .await
        .unwrap();
    assert_eq!(endpoint, "https://pds.example.com");
}

#[tokio::test]
async fn test_fetch_schema_from_pds_success() {
    let pds_server = MockServer::start().await;
    let did = "did:plc:schemahost123";
    let nsid = "com.example.custom.post";

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.repo.getRecord"))
        .and(query_param("repo", did))
        .and(query_param("collection", "com.atproto.lexicon.schema"))
        .and(query_param("rkey", nsid))
        .respond_with(ResponseTemplate::new(200).set_body_json(mock_get_record_response(nsid)))
        .mount(&pds_server)
        .await;

    let doc = fetch_schema_from_pds(&pds_server.uri(), did, nsid)
        .await
        .unwrap();
    assert_eq!(doc.id, nsid);
    assert_eq!(doc.lexicon, 1);
    assert!(doc.defs.contains_key("main"));
}

#[tokio::test]
async fn test_fetch_schema_missing_value_field() {
    let pds_server = MockServer::start().await;
    let did = "did:plc:test123";
    let nsid = "com.example.missing";

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.repo.getRecord"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uri": "at://did:plc:test123/com.atproto.lexicon.schema/com.example.missing",
            "cid": "bafyreiabcdef"
        })))
        .mount(&pds_server)
        .await;

    let result = fetch_schema_from_pds(&pds_server.uri(), did, nsid).await;
    assert!(matches!(result, Err(ResolveError::SchemaFetch { .. })));
}

#[tokio::test]
async fn test_fetch_schema_invalid_lexicon_json() {
    let pds_server = MockServer::start().await;
    let did = "did:plc:test123";
    let nsid = "com.example.bad";

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.repo.getRecord"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uri": "at://test",
            "cid": "bafyreiabcdef",
            "value": {
                "not_a_lexicon": true
            }
        })))
        .mount(&pds_server)
        .await;

    let result = fetch_schema_from_pds(&pds_server.uri(), did, nsid).await;
    assert!(matches!(result, Err(ResolveError::InvalidSchema(_))));
}

#[tokio::test]
async fn test_full_chain_plc_to_schema() {
    let plc_server = MockServer::start().await;
    let pds_server = MockServer::start().await;
    let did = "did:plc:fullchain123";
    let nsid = "com.example.social.post";

    Mock::given(method("GET"))
        .and(path(format!("/{}", did)))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(mock_did_document(did, &pds_server.uri())),
        )
        .mount(&plc_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.repo.getRecord"))
        .and(query_param("repo", did))
        .and(query_param("collection", "com.atproto.lexicon.schema"))
        .and(query_param("rkey", nsid))
        .respond_with(ResponseTemplate::new(200).set_body_json(mock_get_record_response(nsid)))
        .mount(&pds_server)
        .await;

    let doc = resolve_lexicon_from_did(nsid, did, Some(&plc_server.uri()))
        .await
        .unwrap();
    assert_eq!(doc.id, nsid);
    assert_eq!(doc.lexicon, 1);
}

#[tokio::test]
async fn test_full_chain_schema_id_mismatch_rejected() {
    let plc_server = MockServer::start().await;
    let pds_server = MockServer::start().await;
    let did = "did:plc:mismatch123";
    let nsid = "com.example.requested.type";

    Mock::given(method("GET"))
        .and(path(format!("/{}", did)))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(mock_did_document(did, &pds_server.uri())),
        )
        .mount(&plc_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.repo.getRecord"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(mock_get_record_response("com.example.different.type")),
        )
        .mount(&pds_server)
        .await;

    let result = resolve_lexicon_from_did(nsid, did, Some(&plc_server.uri())).await;
    assert!(matches!(result, Err(ResolveError::InvalidSchema(_))));
}

#[tokio::test]
async fn test_full_chain_bad_lexicon_version_rejected() {
    let plc_server = MockServer::start().await;
    let pds_server = MockServer::start().await;
    let did = "did:plc:badver123";
    let nsid = "com.example.versioned.type";

    Mock::given(method("GET"))
        .and(path(format!("/{}", did)))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(mock_did_document(did, &pds_server.uri())),
        )
        .mount(&plc_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.repo.getRecord"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uri": "at://test",
            "cid": "bafyreiabcdef",
            "value": {
                "lexicon": 2,
                "id": nsid,
                "defs": {}
            }
        })))
        .mount(&pds_server)
        .await;

    let result = resolve_lexicon_from_did(nsid, did, Some(&plc_server.uri())).await;
    assert!(matches!(result, Err(ResolveError::InvalidSchema(_))));
}

#[tokio::test]
async fn test_pds_trailing_slash_handled() {
    let pds_server = MockServer::start().await;
    let did = "did:plc:slash123";
    let nsid = "com.example.slash.test";

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.repo.getRecord"))
        .and(query_param("repo", did))
        .and(query_param("rkey", nsid))
        .respond_with(ResponseTemplate::new(200).set_body_json(mock_get_record_response(nsid)))
        .mount(&pds_server)
        .await;

    let pds_url_with_slash = format!("{}/", pds_server.uri());
    let doc = fetch_schema_from_pds(&pds_url_with_slash, did, nsid)
        .await
        .unwrap();
    assert_eq!(doc.id, nsid);
}

#[tokio::test]
async fn test_fetch_schema_error_status_gives_meaningful_error() {
    let pds_server = MockServer::start().await;
    let did = "did:plc:test123";
    let nsid = "com.example.notfound";

    Mock::given(method("GET"))
        .and(path("/xrpc/com.atproto.repo.getRecord"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "RecordNotFound",
            "message": "record not found"
        })))
        .mount(&pds_server)
        .await;

    let result = fetch_schema_from_pds(&pds_server.uri(), did, nsid).await;
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        !err_msg.contains("missing 'value' field"),
        "a 400 response should report the HTTP status, not a parse error. got: {}",
        err_msg
    );
}

#[tokio::test]
async fn test_plc_server_timeout() {
    let plc_server = MockServer::start().await;
    let did = "did:plc:timeout123";

    Mock::given(method("GET"))
        .and(path(format!("/{}", did)))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
        .mount(&plc_server)
        .await;

    let result = resolve_pds_endpoint(did, Some(&plc_server.uri())).await;
    assert!(result.is_err());
}
