mod common;
use common::*;
use futures::StreamExt;
use reqwest::StatusCode;
use serde_json::{Value, json};

#[ctor::ctor]
fn enable_on_demand_tls() {
    unsafe {
        std::env::set_var("ENABLE_CADDY_ON_DEMAND_TLS", "true");
        std::env::set_var("PDS_USER_HANDLE_DOMAINS", "handles.pds.test");
    }
}

async fn create_hosted_account() -> String {
    let client = client();
    let short_handle = format!("caddy{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let payload = json!({
        "handle": short_handle,
        "email": format!("{}@oyster.cafe", short_handle),
        "password": "Testpass123!"
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .json(&payload)
        .send()
        .await
        .expect("failed to create account");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res
        .json()
        .await
        .expect("createAccount response wasn't JSON");
    body["handle"]
        .as_str()
        .expect("createAccount didn't return a handle")
        .to_string()
}

async fn ask(client: &reqwest::Client, domain: &str) -> StatusCode {
    client
        .get(format!("{}/.well-known/caddy/ask", base_url().await))
        .query(&[("domain", domain)])
        .send()
        .await
        .expect("failed to query ask endpoint")
        .status()
}

#[tokio::test]
async fn test_caddy_ask_allows_hosted_handle() {
    let client = client();
    let handle = create_hosted_account().await;
    assert_eq!(ask(&client, &handle).await, StatusCode::OK);
    assert_eq!(ask(&client, &handle.to_uppercase()).await, StatusCode::OK);
    assert_eq!(ask(&client, &format!("{handle}.")).await, StatusCode::OK);
}

#[tokio::test]
async fn test_caddy_ask_denies_unhosted_and_invalid_domains() {
    let client = client();
    let unknown = format!("ghost-{}.handles.pds.test", uuid::Uuid::new_v4().simple());
    assert_eq!(ask(&client, &unknown).await, StatusCode::NOT_FOUND);
    assert_eq!(ask(&client, "nel.pet").await, StatusCode::NOT_FOUND);
    assert_eq!(
        ask(&client, "!!not-a-handle").await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(ask(&client, "").await, StatusCode::BAD_REQUEST);
    let res = client
        .get(format!("{}/.well-known/caddy/ask", base_url().await))
        .send()
        .await
        .expect("failed to query ask endpoint");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_caddy_ask_allows_handle_domain_apexes() {
    let client = client();
    base_url().await;
    futures::stream::iter(
        tranquil_config::get()
            .server
            .user_handle_domains
            .iter()
            .flatten(),
    )
    .for_each(|domain| async {
        assert_eq!(ask(&client, domain.as_str()).await, StatusCode::OK);
    })
    .await;
}

#[tokio::test]
async fn test_caddy_ask_allows_the_pds_hostname_beside_handle_domains() {
    let client = client();
    base_url().await;
    let cfg = tranquil_config::get();
    let hostname = cfg.server.hostname_without_port();
    assert!(
        !cfg.server
            .user_handle_domains
            .iter()
            .flatten()
            .any(|d| d == hostname),
        "this test only means something if hostname is outside the handle domains"
    );
    assert_eq!(ask(&client, hostname).await, StatusCode::OK);
}
