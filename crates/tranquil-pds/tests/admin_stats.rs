mod common;
use common::{base_url, client, create_admin_account_and_login};
use serde_json::Value;

#[tokio::test]
async fn test_get_server_stats() {
    let client = client();
    let base = base_url().await;
    let (token1, _) = create_admin_account_and_login(&client).await;

    let (_, _) = create_admin_account_and_login(&client).await;

    let resp = client
        .get(format!("{}/xrpc/_admin.getServerStats", base))
        .header("Authorization", format!("Bearer {}", token1))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();

    let user_count = body["userCount"].as_i64().unwrap();
    assert!(user_count >= 2);

    assert!(body["repoCount"].is_number());
    assert!(body["recordCount"].is_number());
    assert!(body["blobStorageBytes"].is_number());
}

#[tokio::test]
async fn test_get_server_stats_no_auth() {
    let client = client();
    let base = base_url().await;
    let resp = client
        .get(format!("{}/xrpc/_admin.getServerStats", base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}
