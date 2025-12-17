mod common;
use common::*;
use reqwest::StatusCode;
use serde_json::Value;

#[tokio::test]
async fn test_frontend_client_metadata_returns_valid_json() {
    let client = client();
    let res = client
        .get(format!(
            "{}/oauth/client-metadata.json",
            base_url().await
        ))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Should return valid JSON");
    assert!(body["client_id"].as_str().is_some(), "Should have client_id");
    assert!(body["client_name"].as_str().is_some(), "Should have client_name");
    assert!(body["redirect_uris"].as_array().is_some(), "Should have redirect_uris");
    assert!(body["grant_types"].as_array().is_some(), "Should have grant_types");
    assert!(body["response_types"].as_array().is_some(), "Should have response_types");
    assert!(body["scope"].as_str().is_some(), "Should have scope");
    assert!(body["token_endpoint_auth_method"].as_str().is_some(), "Should have token_endpoint_auth_method");
}

#[tokio::test]
async fn test_frontend_client_metadata_correct_values() {
    let client = client();
    let res = client
        .get(format!(
            "{}/oauth/client-metadata.json",
            base_url().await
        ))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let client_id = body["client_id"].as_str().unwrap();
    assert!(client_id.ends_with("/oauth/client-metadata.json"), "client_id should end with /oauth/client-metadata.json");
    let grant_types = body["grant_types"].as_array().unwrap();
    let grant_strs: Vec<&str> = grant_types.iter().filter_map(|v| v.as_str()).collect();
    assert!(grant_strs.contains(&"authorization_code"), "Should support authorization_code grant");
    assert!(grant_strs.contains(&"refresh_token"), "Should support refresh_token grant");
    let response_types = body["response_types"].as_array().unwrap();
    let response_strs: Vec<&str> = response_types.iter().filter_map(|v| v.as_str()).collect();
    assert!(response_strs.contains(&"code"), "Should support code response type");
    assert_eq!(body["token_endpoint_auth_method"].as_str(), Some("none"), "Should be public client (none auth)");
    assert_eq!(body["application_type"].as_str(), Some("web"), "Should be web application");
    assert_eq!(body["dpop_bound_access_tokens"].as_bool(), Some(false), "Should not require DPoP");
    let scope = body["scope"].as_str().unwrap();
    assert!(scope.contains("atproto"), "Scope should include atproto");
}

#[tokio::test]
async fn test_frontend_client_metadata_redirect_uri_matches_client_uri() {
    let client = client();
    let res = client
        .get(format!(
            "{}/oauth/client-metadata.json",
            base_url().await
        ))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let client_uri = body["client_uri"].as_str().unwrap();
    let redirect_uris = body["redirect_uris"].as_array().unwrap();
    assert!(!redirect_uris.is_empty(), "Should have at least one redirect URI");
    let redirect_uri = redirect_uris[0].as_str().unwrap();
    assert!(redirect_uri.starts_with(client_uri), "Redirect URI should be on same origin as client_uri");
}
