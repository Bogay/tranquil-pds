mod common;

use reqwest::StatusCode;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tranquil_pds::cache::{Cache, DistributedRateLimiter};

async fn poll_until<F, Fut>(max_ms: u64, interval_ms: u64, check_fn: F)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + Duration::from_millis(max_ms);
    let interval = Duration::from_millis(interval_ms);

    loop {
        if check_fn().await {
            return;
        }
        if tokio::time::Instant::now() + interval > deadline {
            panic!("poll_until timed out after {max_ms}ms");
        }
        tokio::time::sleep(interval).await;
    }
}

fn cache_for(nodes: &[common::ServerInstance], idx: usize) -> Arc<dyn Cache> {
    nodes[idx]
        .cache
        .clone()
        .unwrap_or_else(|| panic!("node {idx} should have a cache"))
}

fn rl_for(nodes: &[common::ServerInstance], idx: usize) -> Arc<dyn DistributedRateLimiter> {
    nodes[idx]
        .distributed_rate_limiter
        .clone()
        .unwrap_or_else(|| panic!("node {idx} should have a rate limiter"))
}

#[tokio::test]
async fn cluster_formation() {
    let nodes = common::cluster().await;
    assert!(nodes.len() >= 3, "expected at least 3 cluster nodes");

    let client = common::client();
    let results: Vec<_> = futures::future::join_all(nodes.iter().map(|node| {
        let client = client.clone();
        let url = node.url.clone();
        async move {
            client
                .get(format!("{url}/xrpc/com.atproto.server.describeServer"))
                .send()
                .await
        }
    }))
    .await;

    results.iter().enumerate().for_each(|(i, result)| {
        let resp = result
            .as_ref()
            .unwrap_or_else(|e| panic!("node {i} unreachable: {e}"));
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "node {i} returned non-200 status"
        );
    });
}

#[tokio::test]
async fn cluster_any_node_access() {
    let nodes = common::cluster().await;
    let client = common::client();

    let handle = format!("u{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let payload = serde_json::json!({
        "handle": handle,
        "email": format!("{handle}@example.com"),
        "password": "Testpass123!"
    });
    let create_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createAccount",
            nodes[0].url
        ))
        .json(&payload)
        .send()
        .await
        .expect("createAccount on node 0 failed");
    assert_eq!(create_res.status(), StatusCode::OK);
    let body: serde_json::Value = create_res.json().await.expect("invalid json");
    let did = body["did"].as_str().expect("no did").to_string();
    let access_jwt = body["accessJwt"]
        .as_str()
        .expect("no accessJwt")
        .to_string();

    let pool = common::get_test_db_pool().await;
    let body_text: String = sqlx::query_scalar!(
        "SELECT body FROM comms_queue WHERE user_id = (SELECT id FROM users WHERE did = $1) AND comms_type = 'email_verification' ORDER BY created_at DESC LIMIT 1",
        &did
    )
    .fetch_one(pool)
    .await
    .expect("verification code not found");

    let lines: Vec<&str> = body_text.lines().collect();
    let verification_code = lines
        .iter()
        .enumerate()
        .find(|(_, line)| line.contains("verification code is:") || line.contains("code is:"))
        .and_then(|(i, _)| lines.get(i + 1).map(|s| s.trim().to_string()))
        .or_else(|| {
            body_text
                .lines()
                .find(|line| line.trim().starts_with("MX"))
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| body_text.clone());

    let confirm_payload = serde_json::json!({
        "did": did,
        "verificationCode": verification_code
    });
    let confirm_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.confirmSignup",
            nodes[0].url
        ))
        .json(&confirm_payload)
        .send()
        .await
        .expect("confirmSignup failed");

    let token = match confirm_res.status() {
        StatusCode::OK => {
            let confirm_body: serde_json::Value = confirm_res
                .json()
                .await
                .expect("invalid json from confirmSignup");
            confirm_body["accessJwt"]
                .as_str()
                .unwrap_or(&access_jwt)
                .to_string()
        }
        _ => access_jwt,
    };

    let describe_res = client
        .get(format!(
            "{}/xrpc/com.atproto.server.getSession",
            nodes[1].url
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("getSession on node 1 failed");
    assert_eq!(
        describe_res.status(),
        StatusCode::OK,
        "session created on node 0 should be valid on node 1 (shared postgres)"
    );
    let session: serde_json::Value = describe_res.json().await.expect("invalid json");
    assert_eq!(session["did"].as_str().unwrap(), did);
}

#[tokio::test]
async fn cache_convergence() {
    let nodes = common::cluster().await;

    let cache_a = nodes[0].cache.as_ref().expect("node 0 should have a cache");
    let cache_b = nodes[1].cache.as_ref().expect("node 1 should have a cache");

    let test_key = format!("ripple-test-{}", uuid::Uuid::new_v4());
    let test_value = "converged-value";

    cache_a
        .set(&test_key, test_value, Duration::from_secs(300))
        .await
        .expect("cache set on node A failed");

    let found_on_a = cache_a.get(&test_key).await;
    assert_eq!(
        found_on_a.as_deref(),
        Some(test_value),
        "value should be immediately readable on the originating node"
    );

    let mut converged = false;
    let mut attempts = 0;
    let max_attempts = 50;
    while attempts < max_attempts {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if let Some(val) = cache_b.get(&test_key).await {
            assert_eq!(val, test_value, "converged value should match");
            converged = true;
            break;
        }
        attempts += 1;
    }

    assert!(
        converged,
        "cache value did not converge to node B within {}ms",
        max_attempts * 200
    );
}

#[tokio::test]
async fn rate_limit_convergence() {
    let nodes = common::cluster().await;

    let rl_a = nodes[0]
        .distributed_rate_limiter
        .as_ref()
        .expect("node 0 should have a rate limiter");
    let rl_b = nodes[1]
        .distributed_rate_limiter
        .as_ref()
        .expect("node 1 should have a rate limiter");

    let test_key = format!("rl-test-{}", uuid::Uuid::new_v4());
    let limit: u32 = 100;
    let window_ms: u64 = 600_000;
    let hits_on_a: u32 = 80;

    let mut count = 0u32;
    while count < hits_on_a {
        let allowed = rl_a.check_rate_limit(&test_key, limit, window_ms).await;
        assert!(
            allowed,
            "request {count} should be allowed (limit is {limit})"
        );
        count += 1;
    }

    let rl_b2 = rl_b.clone();
    let k = test_key.clone();
    poll_until(15_000, 200, move || {
        let rl = rl_b2.clone();
        let k = k.clone();
        async move { rl.peek_rate_limit_count(&k, window_ms).await >= hits_on_a as u64 }
    })
    .await;

    let mut allowed_on_b = 0u32;
    while allowed_on_b < limit {
        if !rl_b.check_rate_limit(&test_key, limit, window_ms).await {
            break;
        }
        allowed_on_b += 1;
    }

    assert!(
        allowed_on_b < limit,
        "node B should have been rate limited after convergence, but {allowed_on_b} requests were allowed (limit={limit})"
    );
    assert!(
        allowed_on_b <= limit - hits_on_a + 10,
        "node B allowed {allowed_on_b} requests but expected at most {} (convergence margin)",
        limit - hits_on_a + 10
    );
}

#[tokio::test]
async fn delete_convergence() {
    let nodes = common::cluster().await;
    let cache_0 = cache_for(nodes, 0);
    let cache_1 = cache_for(nodes, 1);

    let key = format!("del-cluster-{}", uuid::Uuid::new_v4());

    cache_0
        .set(&key, "to-delete", Duration::from_secs(300))
        .await
        .expect("set on node 0 failed");

    let c1 = cache_1.clone();
    let k = key.clone();
    poll_until(10_000, 200, move || {
        let c = c1.clone();
        let k = k.clone();
        async move { c.get(&k).await.is_some() }
    })
    .await;

    cache_0.delete(&key).await.expect("delete on node 0 failed");

    let c1 = cache_1.clone();
    let k = key.clone();
    poll_until(10_000, 200, move || {
        let c = c1.clone();
        let k = k.clone();
        async move { c.get(&k).await.is_none() }
    })
    .await;
}

#[tokio::test]
async fn three_node_transitive_convergence() {
    let nodes = common::cluster().await;
    let cache_0 = cache_for(nodes, 0);
    let cache_2 = cache_for(nodes, 2);

    let key = format!("trans-{}", uuid::Uuid::new_v4());

    cache_0
        .set(&key, "reaches-all", Duration::from_secs(300))
        .await
        .expect("set on node 0 failed");

    let c2 = cache_2.clone();
    let k = key.clone();
    poll_until(15_000, 200, move || {
        let c = c2.clone();
        let k = k.clone();
        async move { c.get(&k).await.as_deref() == Some("reaches-all") }
    })
    .await;
}

#[tokio::test]
async fn cluster_overwrite_conflict_resolution() {
    let nodes = common::cluster().await;
    let cache_0 = cache_for(nodes, 0);
    let cache_1 = cache_for(nodes, 1);
    let cache_2 = cache_for(nodes, 2);

    let key = format!("conflict-{}", uuid::Uuid::new_v4());

    cache_0
        .set(&key, "from-node-0", Duration::from_secs(300))
        .await
        .expect("set on node 0 failed");

    cache_1
        .set(&key, "from-node-1", Duration::from_secs(300))
        .await
        .expect("set on node 1 failed");

    let c0 = cache_0.clone();
    let c1 = cache_1.clone();
    let c2 = cache_2.clone();
    let k = key.clone();
    poll_until(15_000, 200, move || {
        let c0 = c0.clone();
        let c1 = c1.clone();
        let c2 = c2.clone();
        let k = k.clone();
        async move {
            let (v0, v1, v2) = tokio::join!(c0.get(&k), c1.get(&k), c2.get(&k));
            matches!((v0, v1, v2), (Some(a), Some(b), Some(c)) if a == b && b == c)
        }
    })
    .await;

    let v0 = cache_0.get(&key).await.expect("node 0 should have key");
    let v1 = cache_1.get(&key).await.expect("node 1 should have key");
    let v2 = cache_2.get(&key).await.expect("node 2 should have key");

    assert_eq!(v0, v1, "node 0 and 1 must agree");
    assert_eq!(v1, v2, "node 1 and 2 must agree");
}

#[tokio::test]
async fn cluster_bulk_key_convergence() {
    let nodes = common::cluster().await;
    let cache_0 = cache_for(nodes, 0);
    let cache_1 = cache_for(nodes, 1);
    let cache_2 = cache_for(nodes, 2);

    let prefix = format!("bulk-{}", uuid::Uuid::new_v4());

    futures::future::join_all((0..500).map(|i| {
        let cache = cache_0.clone();
        let p = prefix.clone();
        async move {
            cache
                .set(
                    &format!("{p}-{i}"),
                    &format!("v-{i}"),
                    Duration::from_secs(300),
                )
                .await
                .expect("set failed");
        }
    }))
    .await;

    let c1 = cache_1.clone();
    let p = prefix.clone();
    poll_until(60_000, 500, move || {
        let c = c1.clone();
        let p = p.clone();
        async move {
            futures::future::join_all((0..500).map(|i| {
                let c = c.clone();
                let p = p.clone();
                async move { c.get(&format!("{p}-{i}")).await.is_some() }
            }))
            .await
            .into_iter()
            .all(|v| v)
        }
    })
    .await;

    let spot_checks: Vec<Option<String>> =
        futures::future::join_all([0, 99, 250, 499].iter().map(|&i| {
            let c = cache_2.clone();
            let p = prefix.clone();
            async move { c.get(&format!("{p}-{i}")).await }
        }))
        .await;

    spot_checks.iter().enumerate().for_each(|(idx, val)| {
        assert!(
            val.is_some(),
            "node 2 missing spot-check key at index {idx}"
        );
    });
}

#[tokio::test]
async fn cluster_concurrent_multi_node_writes() {
    let nodes = common::cluster().await;
    let cache_0 = cache_for(nodes, 0);
    let cache_1 = cache_for(nodes, 1);
    let cache_2 = cache_for(nodes, 2);

    let prefix = format!("multi-{}", uuid::Uuid::new_v4());

    let write_0 = {
        let cache = cache_0.clone();
        let p = prefix.clone();
        async move {
            futures::future::join_all((0..100).map(|i| {
                let cache = cache.clone();
                let p = p.clone();
                async move {
                    cache
                        .set(
                            &format!("{p}-0-{i}"),
                            &format!("n0-{i}"),
                            Duration::from_secs(300),
                        )
                        .await
                        .expect("set failed");
                }
            }))
            .await;
        }
    };

    let write_1 = {
        let cache = cache_1.clone();
        let p = prefix.clone();
        async move {
            futures::future::join_all((0..100).map(|i| {
                let cache = cache.clone();
                let p = p.clone();
                async move {
                    cache
                        .set(
                            &format!("{p}-1-{i}"),
                            &format!("n1-{i}"),
                            Duration::from_secs(300),
                        )
                        .await
                        .expect("set failed");
                }
            }))
            .await;
        }
    };

    let write_2 = {
        let cache = cache_2.clone();
        let p = prefix.clone();
        async move {
            futures::future::join_all((0..100).map(|i| {
                let cache = cache.clone();
                let p = p.clone();
                async move {
                    cache
                        .set(
                            &format!("{p}-2-{i}"),
                            &format!("n2-{i}"),
                            Duration::from_secs(300),
                        )
                        .await
                        .expect("set failed");
                }
            }))
            .await;
        }
    };

    tokio::join!(write_0, write_1, write_2);

    let caches: Vec<Arc<dyn Cache>> = vec![cache_0.clone(), cache_1.clone(), cache_2.clone()];

    futures::future::join_all(caches.iter().enumerate().map(|(ci, cache)| {
        let cache = cache.clone();
        let p = prefix.clone();
        async move {
            let c = cache.clone();
            let p2 = p.clone();
            poll_until(60_000, 500, move || {
                let c = c.clone();
                let p = p2.clone();
                async move {
                    let checks = futures::future::join_all((0..3u8).flat_map(|node| {
                        let c = c.clone();
                        let p = p.clone();
                        (0..100).map(move |i| {
                            let c = c.clone();
                            let p = p.clone();
                            async move { c.get(&format!("{p}-{node}-{i}")).await.is_some() }
                        })
                    }))
                    .await;
                    checks.into_iter().all(|v| v)
                }
            })
            .await;
            eprintln!("node {ci} has all 300 keys");
        }
    }))
    .await;
}

#[tokio::test]
async fn cluster_rate_limit_multi_node_convergence() {
    let nodes = common::cluster().await;
    let rl_0 = rl_for(nodes, 0);
    let rl_1 = rl_for(nodes, 1);
    let rl_2 = rl_for(nodes, 2);

    let key = format!("rl-multi-{}", uuid::Uuid::new_v4());
    let limit: u32 = 300;
    let window_ms: u64 = 600_000;

    futures::future::join_all((0..50).map(|_| {
        let rl = rl_0.clone();
        let k = key.clone();
        async move {
            assert!(rl.check_rate_limit(&k, limit, window_ms).await);
        }
    }))
    .await;

    futures::future::join_all((0..40).map(|_| {
        let rl = rl_1.clone();
        let k = key.clone();
        async move {
            assert!(rl.check_rate_limit(&k, limit, window_ms).await);
        }
    }))
    .await;

    futures::future::join_all((0..30).map(|_| {
        let rl = rl_2.clone();
        let k = key.clone();
        async move {
            assert!(rl.check_rate_limit(&k, limit, window_ms).await);
        }
    }))
    .await;

    let rl_peek = rl_0.clone();
    let k = key.clone();
    poll_until(15_000, 200, move || {
        let rl = rl_peek.clone();
        let k = k.clone();
        async move { rl.peek_rate_limit_count(&k, window_ms).await >= 120 }
    })
    .await;

    let mut remaining = 0u32;
    loop {
        if !rl_0.check_rate_limit(&key, limit, window_ms).await {
            break;
        }
        remaining += 1;
        if remaining > limit {
            panic!("rate limiter never denied - convergence failed");
        }
    }

    let expected_remaining = limit - 120;
    let margin = 20;
    assert!(
        remaining.abs_diff(expected_remaining) <= margin,
        "expected ~{expected_remaining} remaining hits, got {remaining} (margin={margin})"
    );
}

fn create_account_on_node<'a>(
    client: &'a reqwest::Client,
    node_url: &'a str,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = (String, String)> + Send + 'a>> {
    let url = node_url.to_string();
    Box::pin(async move {
        let handle = format!("u{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
        let payload = json!({
            "handle": handle,
            "email": format!("{handle}@example.com"),
            "password": "Testpass123!"
        });
        let create_res = client
            .post(format!("{url}/xrpc/com.atproto.server.createAccount"))
            .json(&payload)
            .send()
            .await
            .expect("createAccount failed");
        assert_eq!(create_res.status(), StatusCode::OK, "createAccount non-200");
        let body: serde_json::Value = create_res.json().await.expect("invalid json");
        let did = body["did"].as_str().expect("no did").to_string();
        let access_jwt = body["accessJwt"]
            .as_str()
            .expect("no accessJwt")
            .to_string();

        let pool = common::get_test_db_pool().await;
        let body_text: String = sqlx::query_scalar!(
            "SELECT body FROM comms_queue WHERE user_id = (SELECT id FROM users WHERE did = $1) AND comms_type = 'email_verification' ORDER BY created_at DESC LIMIT 1",
            &did
        )
        .fetch_one(pool)
        .await
        .expect("verification code not found");

        let lines: Vec<&str> = body_text.lines().collect();
        let verification_code = lines
            .iter()
            .enumerate()
            .find(|(_, line)| line.contains("verification code is:") || line.contains("code is:"))
            .and_then(|(i, _)| lines.get(i + 1).map(|s| s.trim().to_string()))
            .or_else(|| {
                body_text
                    .lines()
                    .find(|line| line.trim().starts_with("MX"))
                    .map(|s| s.trim().to_string())
            })
            .unwrap_or_else(|| body_text.clone());

        let confirm_res = client
            .post(format!("{url}/xrpc/com.atproto.server.confirmSignup"))
            .json(&json!({ "did": did, "verificationCode": verification_code }))
            .send()
            .await
            .expect("confirmSignup failed");

        let token = match confirm_res.status() {
            StatusCode::OK => {
                let confirm_body: serde_json::Value = confirm_res
                    .json()
                    .await
                    .expect("invalid json from confirmSignup");
                confirm_body["accessJwt"]
                    .as_str()
                    .unwrap_or(&access_jwt)
                    .to_string()
            }
            _ => access_jwt,
        };

        (token, did)
    })
}

#[tokio::test]
async fn cross_node_rate_limit_via_login() {
    let nodes = common::cluster().await;
    let client = common::client();

    let now_ms = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap_or(u64::MAX);
    let login_window_ms: u64 = 60_000;
    let remaining = login_window_ms - (now_ms % login_window_ms);
    if remaining < 35_000 {
        tokio::time::sleep(Duration::from_millis(remaining + 100)).await;
    }

    let uuid_bytes = uuid::Uuid::new_v4();
    let b = uuid_bytes.as_bytes();
    let unique_ip = format!("10.{}.{}.{}", b[0], b[1], b[2]);

    let statuses: Vec<StatusCode> = futures::future::join_all((0..10).map(|_| {
        let client = client.clone();
        let url = nodes[0].url.clone();
        let ip = unique_ip.clone();
        async move {
            client
                .post(format!("{url}/xrpc/com.atproto.server.createSession"))
                .header("X-Forwarded-For", &ip)
                .json(&json!({
                    "identifier": "nonexistent@example.com",
                    "password": "wrongpass"
                }))
                .send()
                .await
                .expect("request failed")
                .status()
        }
    }))
    .await;

    statuses.iter().enumerate().for_each(|(i, status)| {
        assert_ne!(
            *status,
            StatusCode::TOO_MANY_REQUESTS,
            "request {i} should not be rate limited within first 10 attempts"
        );
    });

    let rl_1 = rl_for(nodes, 1);
    let rl_key = format!("login:{unique_ip}");
    let rl_1c = rl_1.clone();
    let k = rl_key.clone();
    poll_until(30_000, 200, move || {
        let rl = rl_1c.clone();
        let k = k.clone();
        async move { rl.peek_rate_limit_count(&k, 60_000).await >= 10 }
    })
    .await;

    let cross_node_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.createSession",
            nodes[1].url
        ))
        .header("X-Forwarded-For", &unique_ip)
        .json(&json!({
            "identifier": "nonexistent@example.com",
            "password": "wrongpass"
        }))
        .send()
        .await
        .expect("cross-node request failed");

    assert_eq!(
        cross_node_res.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "node 1 should rate limit after cross-node convergence of login attempts"
    );
}

#[tokio::test]
async fn cross_node_handle_resolution_from_cache() {
    let nodes = common::cluster().await;
    let client = common::client();
    let cache_0 = cache_for(nodes, 0);

    let fake_handle = format!("cached-{}.test", uuid::Uuid::new_v4().simple());
    let fake_did = format!(
        "did:plc:cached{}",
        &uuid::Uuid::new_v4().simple().to_string()[..16]
    );

    cache_0
        .set(
            &format!("handle:{fake_handle}"),
            &fake_did,
            Duration::from_secs(300),
        )
        .await
        .expect("cache set failed");

    let cache_1 = cache_for(nodes, 1);
    let c1 = cache_1.clone();
    let k = format!("handle:{fake_handle}");
    poll_until(10_000, 200, move || {
        let c = c1.clone();
        let k = k.clone();
        async move { c.get(&k).await.is_some() }
    })
    .await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.identity.resolveHandle?handle={}",
            nodes[1].url, fake_handle
        ))
        .send()
        .await
        .expect("resolveHandle request failed");

    assert_eq!(
        res.status(),
        StatusCode::OK,
        "resolveHandle should succeed from propagated cache"
    );
    let body: serde_json::Value = res.json().await.expect("invalid json");
    assert_eq!(
        body["did"].as_str().unwrap(),
        fake_did,
        "resolved DID should match the cache-propagated value"
    );
}

#[tokio::test]
async fn cross_node_cache_delete_observable_via_http() {
    let nodes = common::cluster().await;
    let client = common::client();
    let cache_0 = cache_for(nodes, 0);
    let cache_1 = cache_for(nodes, 1);

    let fake_handle = format!("deltest-{}.test", uuid::Uuid::new_v4().simple());
    let fake_did = format!(
        "did:plc:del{}",
        &uuid::Uuid::new_v4().simple().to_string()[..16]
    );
    let cache_key = format!("handle:{fake_handle}");

    cache_0
        .set(&cache_key, &fake_did, Duration::from_secs(300))
        .await
        .expect("cache set failed");

    let c1 = cache_1.clone();
    let k = cache_key.clone();
    poll_until(10_000, 200, move || {
        let c = c1.clone();
        let k = k.clone();
        async move { c.get(&k).await.is_some() }
    })
    .await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.identity.resolveHandle?handle={}",
            nodes[1].url, fake_handle
        ))
        .send()
        .await
        .expect("resolveHandle request failed");
    assert_eq!(res.status(), StatusCode::OK, "should resolve before delete");

    cache_0
        .delete(&cache_key)
        .await
        .expect("cache delete failed");

    let c1 = cache_1.clone();
    let k = cache_key.clone();
    poll_until(10_000, 200, move || {
        let c = c1.clone();
        let k = k.clone();
        async move { c.get(&k).await.is_none() }
    })
    .await;

    let res = client
        .get(format!(
            "{}/xrpc/com.atproto.identity.resolveHandle?handle={}",
            nodes[1].url, fake_handle
        ))
        .send()
        .await
        .expect("resolveHandle request failed after delete");
    assert_ne!(
        res.status(),
        StatusCode::OK,
        "resolveHandle should fail after cache delete propagation (handle not in DB)"
    );
}

#[tokio::test]
async fn cross_node_email_update_status() {
    let nodes = common::cluster().await;
    let client = common::client();
    let cache_0 = cache_for(nodes, 0);
    let cache_1 = cache_for(nodes, 1);

    let (token, did) = create_account_on_node(&client, &nodes[0].url).await;

    let new_email = format!("updated-{}@example.com", uuid::Uuid::new_v4().simple());
    let update_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.requestEmailUpdate",
            nodes[0].url
        ))
        .bearer_auth(&token)
        .json(&json!({ "newEmail": new_email }))
        .send()
        .await
        .expect("requestEmailUpdate failed");
    assert_eq!(
        update_res.status(),
        StatusCode::OK,
        "requestEmailUpdate should succeed"
    );
    let update_body: serde_json::Value = update_res.json().await.expect("invalid json");
    assert_eq!(
        update_body["tokenRequired"].as_bool(),
        Some(true),
        "tokenRequired should be true (email is verified after confirmSignup)"
    );

    let cache_key = format!("email_update:{did}");
    let val_on_0 = cache_0.get(&cache_key).await;
    assert!(
        val_on_0.is_some(),
        "email_update entry should exist on node 0 immediately after requestEmailUpdate"
    );

    let c1 = cache_1.clone();
    let k = cache_key.clone();
    poll_until(10_000, 200, move || {
        let c = c1.clone();
        let k = k.clone();
        async move { c.get(&k).await.is_some() }
    })
    .await;

    let status_res = client
        .get(format!(
            "{}/xrpc/_account.checkEmailUpdateStatus",
            nodes[1].url
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("checkEmailUpdateStatus on node 1 failed");
    assert_eq!(
        status_res.status(),
        StatusCode::OK,
        "checkEmailUpdateStatus should succeed on node 1"
    );
    let status_body: serde_json::Value = status_res.json().await.expect("invalid json");
    assert_eq!(
        status_body["pending"].as_bool(),
        Some(true),
        "email update should be pending on node 1 via cache propagation"
    );
    assert_eq!(
        status_body["newEmail"].as_str().unwrap(),
        new_email,
        "new email should match on node 1"
    );
}

#[tokio::test]
async fn cross_node_session_revocation() {
    let nodes = common::cluster().await;
    let client = common::client();

    let (token, _did) = create_account_on_node(&client, &nodes[0].url).await;

    let session_res = client
        .get(format!(
            "{}/xrpc/com.atproto.server.getSession",
            nodes[0].url
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("getSession on node 0 failed");
    assert_eq!(
        session_res.status(),
        StatusCode::OK,
        "session should be valid on node 0"
    );

    let client2 = client.clone();
    let url1 = nodes[1].url.clone();
    let t = token.clone();
    poll_until(15_000, 200, move || {
        let c = client2.clone();
        let u = url1.clone();
        let t = t.clone();
        async move {
            c.get(format!("{u}/xrpc/com.atproto.server.getSession"))
                .bearer_auth(&t)
                .send()
                .await
                .map(|r| r.status() == StatusCode::OK)
                .unwrap_or(false)
        }
    })
    .await;

    let delete_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.deleteSession",
            nodes[0].url
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("deleteSession failed");
    assert_eq!(
        delete_res.status(),
        StatusCode::OK,
        "deleteSession should succeed"
    );

    let client3 = client.clone();
    let url1 = nodes[1].url.clone();
    let t = token.clone();
    poll_until(15_000, 200, move || {
        let c = client3.clone();
        let u = url1.clone();
        let t = t.clone();
        async move {
            c.get(format!("{u}/xrpc/com.atproto.server.getSession"))
                .bearer_auth(&t)
                .send()
                .await
                .map(|r| r.status() != StatusCode::OK)
                .unwrap_or(false)
        }
    })
    .await;
}
