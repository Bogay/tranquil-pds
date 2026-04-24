mod common;
use common::*;
use reqwest::StatusCode;
use reqwest::header;
use serde_json::{Value, json};

const HANDLE_DOMAIN: &str = "handles.test";

fn set_handle_domain() {
    unsafe {
        std::env::set_var("PDS_USER_HANDLE_DOMAINS", HANDLE_DOMAIN);
    }
}

async fn base_url_with_domain() -> &'static str {
    set_handle_domain();
    base_url().await
}

#[tokio::test]
async fn describe_server_returns_configured_domain() {
    let client = client();
    let base = base_url_with_domain().await;
    let res = client
        .get(format!("{}/xrpc/com.atproto.server.describeServer", base))
        .send()
        .await
        .expect("describeServer request failed");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    let domains = body["availableUserDomains"]
        .as_array()
        .expect("No availableUserDomains");
    assert!(
        domains.iter().any(|d| d.as_str() == Some(HANDLE_DOMAIN)),
        "availableUserDomains should contain {}, got {:?}",
        HANDLE_DOMAIN,
        domains
    );
}

#[tokio::test]
async fn short_handle_uses_configured_domain() {
    let client = client();
    let base = base_url_with_domain().await;
    let short_handle = format!("hd{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let payload = json!({
        "handle": short_handle,
        "email": format!("{}@example.com", short_handle),
        "password": "Testpass123!"
    });
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base))
        .json(&payload)
        .send()
        .await
        .expect("createAccount request failed");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    let handle = body["handle"].as_str().expect("No handle in response");
    let expected_suffix = format!(".{}", HANDLE_DOMAIN);
    assert!(
        handle.ends_with(&expected_suffix),
        "Handle '{}' should end with '{}' (not PDS hostname)",
        handle,
        expected_suffix
    );
    assert_eq!(
        handle,
        format!("{}.{}", short_handle, HANDLE_DOMAIN),
        "Handle should be short_handle.configured_domain"
    );
}

#[tokio::test]
async fn full_handle_with_configured_domain_accepted() {
    let client = client();
    let base = base_url_with_domain().await;
    let short_handle = format!("hd{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let full_handle = format!("{}.{}", short_handle, HANDLE_DOMAIN);
    let payload = json!({
        "handle": full_handle,
        "email": format!("{}@example.com", short_handle),
        "password": "Testpass123!"
    });
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base))
        .json(&payload)
        .send()
        .await
        .expect("createAccount request failed");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    let handle = body["handle"].as_str().expect("No handle in response");
    assert_eq!(
        handle, full_handle,
        "Handle should match the full handle submitted"
    );
}

#[tokio::test]
async fn handle_with_pds_hostname_treated_as_custom() {
    let client = client();
    let base = base_url_with_domain().await;
    let pds_hostname = pds_hostname();
    let pds_host_no_port = pds_hostname.split(':').next().unwrap_or(&pds_hostname);
    let short_handle = format!("hd{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let handle_with_hostname = format!("{}.{}", short_handle, pds_host_no_port);
    let payload = json!({
        "handle": handle_with_hostname,
        "email": format!("{}@example.com", short_handle),
        "password": "Testpass123!"
    });
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base))
        .json(&payload)
        .send()
        .await
        .expect("createAccount request failed");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    let handle = body["handle"].as_str().expect("No handle in response");
    assert_eq!(
        handle, handle_with_hostname,
        "Handle with non-available domain suffix should be treated as custom handle (passed through)"
    );
}

#[tokio::test]
async fn resolve_handle_works_with_configured_domain() {
    let client = client();
    let base = base_url_with_domain().await;
    let short_handle = format!("hd{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let payload = json!({
        "handle": short_handle,
        "email": format!("{}@example.com", short_handle),
        "password": "Testpass123!"
    });
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base))
        .json(&payload)
        .send()
        .await
        .expect("createAccount request failed");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    let did = body["did"].as_str().expect("No DID").to_string();
    let full_handle = body["handle"].as_str().expect("No handle").to_string();

    let res = client
        .get(format!("{}/xrpc/com.atproto.identity.resolveHandle", base))
        .query(&[("handle", full_handle.as_str())])
        .send()
        .await
        .expect("resolveHandle request failed");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(body["did"], did);
}

#[tokio::test]
async fn admin_update_handle_uses_configured_domain() {
    let client = client();
    let base = base_url_with_domain().await;
    let (admin_jwt, _) = create_admin_account_and_login(&client).await;
    let (_, target_did) = create_account_and_login(&client).await;

    let new_short = format!("hd{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.admin.updateAccountHandle",
            base
        ))
        .bearer_auth(&admin_jwt)
        .json(&json!({
            "did": target_did,
            "handle": new_short,
        }))
        .send()
        .await
        .expect("admin updateAccountHandle request failed");
    assert_eq!(res.status(), StatusCode::OK);

    let res = client
        .get(format!("{}/xrpc/com.atproto.identity.resolveHandle", base))
        .query(&[("handle", format!("{}.{}", new_short, HANDLE_DOMAIN))])
        .send()
        .await
        .expect("resolveHandle request failed");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(
        body["did"], target_did,
        "Admin bare handle update should use configured domain, not PDS hostname"
    );
}

#[tokio::test]
async fn update_handle_bare_uses_configured_domain() {
    let client = client();
    let base = base_url_with_domain().await;
    let short_handle = format!("hd{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let payload = json!({
        "handle": short_handle,
        "email": format!("{}@example.com", short_handle),
        "password": "Testpass123!"
    });
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base))
        .json(&payload)
        .send()
        .await
        .expect("createAccount request failed");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    let did = body["did"].as_str().expect("No DID").to_string();
    let access_jwt = verify_new_account(&client, &did).await;

    let new_short = format!("hd{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let res = client
        .post(format!("{}/xrpc/com.atproto.identity.updateHandle", base))
        .bearer_auth(&access_jwt)
        .header(header::CONTENT_TYPE, "application/json")
        .json(&json!({ "handle": new_short }))
        .send()
        .await
        .expect("updateHandle request failed");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "updateHandle failed: {:?}",
        res.text().await
    );

    let res = client
        .get(format!("{}/xrpc/com.atproto.identity.resolveHandle", base))
        .query(&[("handle", format!("{}.{}", new_short, HANDLE_DOMAIN))])
        .send()
        .await
        .expect("resolveHandle request failed");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    assert_eq!(
        body["did"], did,
        "updateHandle with bare handle should use configured domain, not PDS hostname"
    );
}

#[tokio::test]
async fn did_web_uses_handle_domain_not_hostname() {
    unsafe {
        std::env::set_var("ENABLE_PDS_HOSTED_DID_WEB", "true");
    }
    let client = client();
    let base = base_url_with_domain().await;
    let short_handle = format!("hd{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let payload = json!({
        "handle": short_handle,
        "email": format!("{}@example.com", short_handle),
        "password": "Testpass123!",
        "didType": "web"
    });
    let res = client
        .post(format!("{}/xrpc/com.atproto.server.createAccount", base))
        .json(&payload)
        .send()
        .await
        .expect("createAccount request failed");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.expect("Invalid JSON");
    let did = body["did"].as_str().expect("No DID in response");
    let expected_did = format!("did:web:{}.{}", short_handle, HANDLE_DOMAIN);
    assert_eq!(
        did, expected_did,
        "did:web should use handle domain '{}', not PDS hostname",
        HANDLE_DOMAIN
    );
}
