mod common;
mod helpers;
use common::*;
use helpers::*;
use reqwest::StatusCode;
use serde_json::Value;

#[tokio::test]
async fn test_search_accounts_as_admin() {
    let client = client();
    let (admin_jwt, _) = create_admin_account_and_login(&client).await;
    let (user_did, _) = setup_new_user("search-target").await;
    let mut found = false;
    let mut cursor: Option<String> = None;
    for _ in 0..10 {
        let url = match &cursor {
            Some(c) => format!(
                "{}/xrpc/com.atproto.admin.searchAccounts?limit=100&cursor={}",
                base_url().await,
                c
            ),
            None => format!(
                "{}/xrpc/com.atproto.admin.searchAccounts?limit=100",
                base_url().await
            ),
        };
        let res = client
            .get(&url)
            .bearer_auth(&admin_jwt)
            .send()
            .await
            .expect("Failed to send request");
        assert_eq!(res.status(), StatusCode::OK);
        let body: Value = res.json().await.unwrap();
        let accounts = body["accounts"]
            .as_array()
            .expect("accounts should be array");
        if accounts
            .iter()
            .any(|a| a["did"].as_str() == Some(&user_did))
        {
            found = true;
            break;
        }
        cursor = body["cursor"].as_str().map(|s| s.to_string());
        if cursor.is_none() {
            break;
        }
    }
    assert!(
        found,
        "Should find the created user in results (DID: {})",
        user_did
    );
}

#[tokio::test]
async fn test_search_accounts_with_handle_filter() {
    let client = client();
    let (admin_jwt, _) = create_admin_account_and_login(&client).await;
    let ts = chrono::Utc::now().timestamp_millis();
    let unique_handle = format!("unique-handle-{}.test", ts);
    let create_payload = serde_json::json!({
        "handle": unique_handle,
        "email": format!("unique-{}@searchtest.com", ts),
        "password": "Testpass123!"
    });
    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .json(&create_payload)
        .send()
        .await
        .expect("Failed to create account");
    assert_eq!(create_res.status(), StatusCode::OK);
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.admin.searchAccounts?handle={}",
            base_url().await,
            unique_handle
        ))
        .bearer_auth(&admin_jwt)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let accounts = body["accounts"].as_array().unwrap();
    assert_eq!(
        accounts.len(),
        1,
        "Should find exactly one account with this handle"
    );
    assert_eq!(accounts[0]["handle"].as_str(), Some(unique_handle.as_str()));
}

#[tokio::test]
async fn test_search_accounts_pagination() {
    let client = client();
    let (admin_jwt, _) = create_admin_account_and_login(&client).await;
    for i in 0..3 {
        let _ = setup_new_user(&format!("search-page-{}", i)).await;
    }
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.admin.searchAccounts?limit=2",
            base_url().await
        ))
        .bearer_auth(&admin_jwt)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let accounts = body["accounts"].as_array().unwrap();
    assert_eq!(accounts.len(), 2, "Should return exactly 2 accounts");
    let cursor = body["cursor"].as_str();
    assert!(cursor.is_some(), "Should have cursor for more results");
    let res2 = client
        .get(format!(
            "{}/xrpc/com.atproto.admin.searchAccounts?limit=2&cursor={}",
            base_url().await,
            cursor.unwrap()
        ))
        .bearer_auth(&admin_jwt)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res2.status(), StatusCode::OK);
    let body2: Value = res2.json().await.unwrap();
    let accounts2 = body2["accounts"].as_array().unwrap();
    assert!(
        !accounts2.is_empty(),
        "Should return more accounts after cursor"
    );
    let first_page_dids: Vec<&str> = accounts
        .iter()
        .map(|a| a["did"].as_str().unwrap())
        .collect();
    let second_page_dids: Vec<&str> = accounts2
        .iter()
        .map(|a| a["did"].as_str().unwrap())
        .collect();
    for did in &second_page_dids {
        assert!(
            !first_page_dids.contains(did),
            "Second page should not repeat first page DIDs"
        );
    }
}

#[tokio::test]
async fn test_search_accounts_requires_admin() {
    let client = client();
    let _ = create_account_and_login(&client).await;
    let (_, user_jwt) = setup_new_user("search-nonadmin").await;
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.admin.searchAccounts",
            base_url().await
        ))
        .bearer_auth(&user_jwt)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_search_accounts_requires_auth() {
    let client = client();
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.admin.searchAccounts",
            base_url().await
        ))
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_search_accounts_returns_expected_fields() {
    let client = client();
    let (admin_jwt, _) = create_admin_account_and_login(&client).await;
    let _ = setup_new_user("search-fields").await;
    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.admin.searchAccounts?limit=1",
            base_url().await
        ))
        .bearer_auth(&admin_jwt)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value = res.json().await.unwrap();
    let accounts = body["accounts"].as_array().unwrap();
    assert!(!accounts.is_empty());
    let account = &accounts[0];
    assert!(account["did"].as_str().is_some(), "Should have did");
    assert!(account["handle"].as_str().is_some(), "Should have handle");
    assert!(
        account["indexedAt"].as_str().is_some(),
        "Should have indexedAt"
    );
}
