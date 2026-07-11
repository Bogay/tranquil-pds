mod common;
mod helpers;

use chrono::{DateTime, Duration, Utc};
use common::{base_url, client, get_test_repos};
use futures::StreamExt;
use helpers::verify_new_account;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tranquil_oauth::{
    AuthorizationRequestParameters, ClientAuth, CodeChallengeMethod, ResponseType, TokenData,
    TokenId,
};
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

fn make_token_data(did: &Did, token_id: &str, created_at: DateTime<Utc>) -> TokenData {
    let client_id = tranquil_types::ClientId::from("https://squid.nel.pet/client".to_string());
    TokenData {
        did: did.clone(),
        token_id: TokenId::from(token_id.to_string()),
        created_at,
        updated_at: created_at,
        expires_at: created_at + Duration::hours(1),
        client_id: client_id.clone(),
        client_auth: ClientAuth::None,
        device_id: None,
        parameters: AuthorizationRequestParameters {
            response_type: ResponseType::Code,
            client_id,
            redirect_uri: "https://squid.nel.pet/cb".to_string(),
            scope: None,
            state: None,
            code_challenge: "x".to_string(),
            code_challenge_method: CodeChallengeMethod::S256,
            response_mode: None,
            login_hint: None,
            dpop_jkt: None,
            prompt: None,
            extra: None,
        },
        details: None,
        code: None,
        current_refresh_token: None,
        scope: None,
        controller_did: None,
    }
}

async fn seed_tokens(repos: &tranquil_db::PostgresRepositories, tokens: &[TokenData]) {
    futures::stream::iter(tokens)
        .for_each(|token| async move {
            repos
                .oauth
                .create_token(token)
                .await
                .expect("token insert failed");
        })
        .await;
}

#[tokio::test]
async fn delete_oldest_tokens_evicts_lowest_created_at() {
    let ts = Utc::now().timestamp_millis();
    let handle = format!("tok-evict-{}.test", ts);
    let email = format!("tok-evict-{}@test.com", ts);
    let did = create_account_and_get_did(&handle, &email, "EvictTest123!").await;

    let repos = get_test_repos().await;

    let base = Utc::now();
    let token_ids: Vec<String> = (0..5).map(|i| format!("tok-{}-{}", ts, i)).collect();
    let tokens: Vec<TokenData> = (0i64..)
        .zip(token_ids.iter())
        .map(|(offset, tid)| make_token_data(&did, tid, base + Duration::seconds(offset)))
        .collect();
    seed_tokens(repos, &tokens).await;

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

    let repos = get_test_repos().await;

    let base = Utc::now();
    let tokens: Vec<TokenData> = (0i64..2)
        .map(|offset| {
            make_token_data(
                &did,
                &format!("noop-tok-{}-{}", ts, offset),
                base + Duration::seconds(offset),
            )
        })
        .collect();
    seed_tokens(repos, &tokens).await;

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
