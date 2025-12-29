mod common;
use common::{base_url, client};
use reqwest::StatusCode;
use serde_json::json;

#[tokio::test]
#[ignore = "rate limiting is disabled in test environment"]
async fn test_login_rate_limiting() {
    let client = client();
    let url = format!("{}/xrpc/com.atproto.server.createSession", base_url().await);
    let payload = json!({
        "identifier": "nonexistent-user-for-rate-limit-test",
        "password": "wrongpassword"
    });
    let mut rate_limited_count = 0;
    let mut auth_failed_count = 0;
    for _ in 0..15 {
        let res = client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .expect("Request failed");
        match res.status() {
            StatusCode::TOO_MANY_REQUESTS => {
                rate_limited_count += 1;
            }
            StatusCode::UNAUTHORIZED => {
                auth_failed_count += 1;
            }
            status => {
                panic!("Unexpected status: {}", status);
            }
        }
    }
    assert!(
        rate_limited_count > 0,
        "Expected at least one rate-limited response after 15 login attempts. Got {} auth failures and {} rate limits.",
        auth_failed_count,
        rate_limited_count
    );
}

#[tokio::test]
#[ignore = "rate limiting is disabled in test environment"]
async fn test_password_reset_rate_limiting() {
    let client = client();
    let url = format!(
        "{}/xrpc/com.atproto.server.requestPasswordReset",
        base_url().await
    );
    let mut rate_limited_count = 0;
    let mut success_count = 0;
    for i in 0..8 {
        let payload = json!({
            "email": format!("ratelimit-test_{}@example.com", i)
        });
        let res = client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .expect("Request failed");
        match res.status() {
            StatusCode::TOO_MANY_REQUESTS => {
                rate_limited_count += 1;
            }
            StatusCode::OK => {
                success_count += 1;
            }
            status => {
                panic!("Unexpected status: {} - {:?}", status, res.text().await);
            }
        }
    }
    assert!(
        rate_limited_count > 0,
        "Expected rate limiting after {} password reset requests. Got {} successes.",
        success_count + rate_limited_count,
        success_count
    );
}

#[tokio::test]
#[ignore = "rate limiting is disabled in test environment"]
async fn test_account_creation_rate_limiting() {
    let client = client();
    let url = format!("{}/xrpc/com.atproto.server.createAccount", base_url().await);
    let mut rate_limited_count = 0;
    let mut other_count = 0;
    for i in 0..15 {
        let unique_id = uuid::Uuid::new_v4();
        let payload = json!({
            "handle": format!("ratelimit-{}_{}", i, unique_id),
            "email": format!("ratelimit-{}_{}@example.com", i, unique_id),
            "password": "Testpass123!"
        });
        let res = client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .expect("Request failed");
        match res.status() {
            StatusCode::TOO_MANY_REQUESTS => {
                rate_limited_count += 1;
            }
            _ => {
                other_count += 1;
            }
        }
    }
    assert!(
        rate_limited_count > 0,
        "Expected rate limiting after account creation attempts. Got {} other responses and {} rate limits.",
        other_count,
        rate_limited_count
    );
}

#[tokio::test]
async fn test_valkey_connection() {
    if std::env::var("VALKEY_URL").is_err() {
        println!("VALKEY_URL not set, skipping Valkey connection test");
        return;
    }
    let valkey_url = std::env::var("VALKEY_URL").unwrap();
    let client = redis::Client::open(valkey_url.as_str()).expect("Failed to create Redis client");
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("Failed to connect to Valkey");
    let pong: String = redis::cmd("PING")
        .query_async(&mut conn)
        .await
        .expect("PING failed");
    assert_eq!(pong, "PONG");
    let _: () = redis::cmd("SET")
        .arg("test_key")
        .arg("test_value")
        .arg("EX")
        .arg(10)
        .query_async(&mut conn)
        .await
        .expect("SET failed");
    let value: String = redis::cmd("GET")
        .arg("test_key")
        .query_async(&mut conn)
        .await
        .expect("GET failed");
    assert_eq!(value, "test_value");
    let _: () = redis::cmd("DEL")
        .arg("test_key")
        .query_async(&mut conn)
        .await
        .expect("DEL failed");
}

#[tokio::test]
async fn test_distributed_rate_limiter_directly() {
    if std::env::var("VALKEY_URL").is_err() {
        println!("VALKEY_URL not set, skipping distributed rate limiter test");
        return;
    }
    use tranquil_pds::cache::{DistributedRateLimiter, RedisRateLimiter};
    let valkey_url = std::env::var("VALKEY_URL").unwrap();
    let client = redis::Client::open(valkey_url.as_str()).expect("Failed to create Redis client");
    let conn = client
        .get_connection_manager()
        .await
        .expect("Failed to get connection manager");
    let rate_limiter = RedisRateLimiter::new(conn);
    let test_key = format!("test_rate_limit_{}", uuid::Uuid::new_v4());
    let limit = 5;
    let window_ms = 60_000;
    for i in 0..limit {
        let allowed = rate_limiter
            .check_rate_limit(&test_key, limit, window_ms)
            .await;
        assert!(
            allowed,
            "Request {} should have been allowed (limit: {})",
            i + 1,
            limit
        );
    }
    let allowed = rate_limiter
        .check_rate_limit(&test_key, limit, window_ms)
        .await;
    assert!(
        !allowed,
        "Request {} should have been rate limited (limit: {})",
        limit + 1,
        limit
    );
    let allowed = rate_limiter
        .check_rate_limit(&test_key, limit, window_ms)
        .await;
    assert!(!allowed, "Subsequent request should also be rate limited");
}
