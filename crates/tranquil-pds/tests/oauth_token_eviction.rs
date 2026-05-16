mod common;
mod helpers;

use chrono::{DateTime, Duration, Utc};
use common::{base_url, client, get_test_db_pool, get_test_repos};
use helpers::verify_new_account;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tranquil_types::Did;

async fn create_account_and_get_did(handle: &str, email: &str, password: &str) -> Did {
    let client = client();
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            base_url().await
        ))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": password,
        }))
        .send()
        .await
        .expect("createAccount request failed");
    assert_eq!(res.status(), StatusCode::OK, "createAccount failed");
    let body: Value = res.json().await.expect("invalid createAccount JSON");
    let did_str = body["did"]
        .as_str()
        .expect("no did in response")
        .to_string();
    let _ = verify_new_account(&client, &did_str).await;
    Did::new(did_str).expect("invalid DID format")
}

async fn insert_token_with_created_at(
    pool: &sqlx::PgPool,
    did: &Did,
    token_id: &str,
    created_at: DateTime<Utc>,
) {
    sqlx::query(
        r#"
        INSERT INTO oauth_token (
            did, token_id, created_at, updated_at, expires_at,
            client_id, client_auth, parameters
        ) VALUES ($1, $2, $3, $3, $4, $5, $6::jsonb, $7::jsonb)
        "#,
    )
    .bind(did.as_str())
    .bind(token_id)
    .bind(created_at)
    .bind(created_at + Duration::hours(1))
    .bind("https://test.example/client")
    .bind(r#"{"method":"none"}"#)
    .bind(
        r#"{"response_type":"code","client_id":"https://test.example/client","redirect_uri":"https://test.example/cb","code_challenge":"x","code_challenge_method":"S256"}"#,
    )
    .execute(pool)
    .await
    .expect("token insert failed");
}

#[tokio::test]
async fn delete_oldest_tokens_evicts_lowest_created_at() {
    let ts = Utc::now().timestamp_millis();
    let handle = format!("tok-evict-{}.test", ts);
    let email = format!("tok-evict-{}@test.com", ts);
    let did = create_account_and_get_did(&handle, &email, "EvictTest123!").await;

    let pool = get_test_db_pool().await;
    let repos = get_test_repos().await;

    let base = Utc::now();
    let token_ids: Vec<String> = (0..5).map(|i| format!("tok-{}-{}", ts, i)).collect();

    for (i, tid) in token_ids.iter().enumerate() {
        let created = base + Duration::seconds(i as i64);
        insert_token_with_created_at(pool, &did, tid, created).await;
    }

    let count_before = repos
        .oauth
        .count_tokens_for_user(&did)
        .await
        .expect("count failed");
    assert_eq!(count_before, 5, "all 5 tokens should be present");

    let deleted = repos
        .oauth
        .delete_oldest_tokens_for_user(&did, 3)
        .await
        .expect("delete failed");
    assert_eq!(deleted, 2, "two oldest tokens should be deleted");

    let remaining = repos
        .oauth
        .list_tokens_for_user(&did)
        .await
        .expect("list failed");
    assert_eq!(remaining.len(), 3, "three newest tokens should remain");

    let remaining_ids: std::collections::HashSet<String> =
        remaining.iter().map(|t| t.token_id.0.clone()).collect();
    let expected_ids: std::collections::HashSet<String> = token_ids[2..].iter().cloned().collect();
    assert_eq!(
        remaining_ids, expected_ids,
        "surviving tokens must be the three newest by created_at"
    );
}

#[tokio::test]
async fn delete_oldest_tokens_no_op_when_under_keep_count() {
    let ts = Utc::now().timestamp_millis();
    let handle = format!("tok-evict-noop-{}.test", ts);
    let email = format!("tok-evict-noop-{}@test.com", ts);
    let did = create_account_and_get_did(&handle, &email, "EvictTest123!").await;

    let pool = get_test_db_pool().await;
    let repos = get_test_repos().await;

    let base = Utc::now();
    for i in 0..2 {
        let tid = format!("noop-tok-{}-{}", ts, i);
        let created = base + Duration::seconds(i);
        insert_token_with_created_at(pool, &did, &tid, created).await;
    }

    let deleted = repos
        .oauth
        .delete_oldest_tokens_for_user(&did, 5)
        .await
        .expect("delete failed");
    assert_eq!(deleted, 0, "nothing to delete when count <= keep");

    let remaining = repos
        .oauth
        .list_tokens_for_user(&did)
        .await
        .expect("list failed");
    assert_eq!(remaining.len(), 2);
}
