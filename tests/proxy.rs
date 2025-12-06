mod common;

use axum::{
    routing::any,
    Router,
    extract::Request,
    http::StatusCode,
};
use tokio::net::TcpListener;
use reqwest::Client;
use std::sync::Arc;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

async fn spawn_mock_upstream() -> (String, tokio::sync::mpsc::Receiver<(String, String, Option<String>)>) {
    let (tx, rx) = tokio::sync::mpsc::channel(10);
    let tx = Arc::new(tx);

    let app = Router::new().fallback(any(move |req: Request| {
        let tx = tx.clone();
        async move {
            let method = req.method().to_string();
            let uri = req.uri().to_string();
            let auth = req.headers().get("Authorization")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string());

            let _ = tx.send((method, uri, auth)).await;
            (StatusCode::OK, "Mock Response")
        }
    }));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (format!("http://{}", addr), rx)
}

#[tokio::test]
async fn test_proxy_via_header() {
    let app_url = common::base_url().await;
    let (upstream_url, mut rx) = spawn_mock_upstream().await;
    let client = Client::new();

    let res = client.get(format!("{}/xrpc/com.example.test", app_url))
        .header("atproto-proxy", &upstream_url)
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    let (method, uri, auth) = rx.recv().await.expect("Upstream should receive request");
    assert_eq!(method, "GET");
    assert_eq!(uri, "/xrpc/com.example.test");
    assert_eq!(auth, Some("Bearer test-token".to_string()));
}

#[tokio::test]
#[ignore]
async fn test_proxy_via_env_var() {
    let (upstream_url, mut rx) = spawn_mock_upstream().await;

    unsafe { std::env::set_var("APPVIEW_URL", &upstream_url); }

    let app_url = common::base_url().await;
    let client = Client::new();

    let res = client.get(format!("{}/xrpc/com.example.envtest", app_url))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    let (method, uri, _) = rx.recv().await.expect("Upstream should receive request");
    assert_eq!(method, "GET");
    assert_eq!(uri, "/xrpc/com.example.envtest");
}

#[tokio::test]
#[ignore]
async fn test_proxy_missing_config() {
    unsafe { std::env::remove_var("APPVIEW_URL"); }

    let app_url = common::base_url().await;
    let client = Client::new();

    let res = client.get(format!("{}/xrpc/com.example.fail", app_url))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn test_proxy_auth_signing() {
    let app_url = common::base_url().await;
    let (upstream_url, mut rx) = spawn_mock_upstream().await;
    let client = Client::new();

    let (access_jwt, did) = common::create_account_and_login(&client).await;

    let res = client.get(format!("{}/xrpc/com.example.signed", app_url))
        .header("atproto-proxy", &upstream_url)
        .header("Authorization", format!("Bearer {}", access_jwt))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    let (method, uri, auth) = rx.recv().await.expect("Upstream receive");
    assert_eq!(method, "GET");
    assert_eq!(uri, "/xrpc/com.example.signed");

    let received_token = auth.expect("No auth header").replace("Bearer ", "");
    assert_ne!(received_token, access_jwt, "Token should be replaced");

    let parts: Vec<&str> = received_token.split('.').collect();
    assert_eq!(parts.len(), 3);

    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).expect("payload b64");
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).expect("payload json");

    assert_eq!(claims["iss"], did);
    assert_eq!(claims["sub"], did);
    assert_eq!(claims["aud"], upstream_url);
    assert_eq!(claims["lxm"], "com.example.signed");
}
