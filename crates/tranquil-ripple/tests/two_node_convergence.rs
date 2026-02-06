use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tranquil_infra::{Cache, DistributedRateLimiter};
use tranquil_ripple::{RippleConfig, RippleEngine};

async fn spawn_pair(
    shutdown: CancellationToken,
) -> (
    (Arc<dyn Cache>, Arc<dyn DistributedRateLimiter>),
    (Arc<dyn Cache>, Arc<dyn DistributedRateLimiter>),
) {
    let config_a = RippleConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        seed_peers: vec![],
        machine_id: 1,
        gossip_interval_ms: 100,
        cache_max_bytes: 64 * 1024 * 1024,
    };
    let (cache_a, rl_a, addr_a) = RippleEngine::start(config_a, shutdown.clone())
        .await
        .expect("node A failed to start");

    let config_b = RippleConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        seed_peers: vec![addr_a],
        machine_id: 2,
        gossip_interval_ms: 100,
        cache_max_bytes: 64 * 1024 * 1024,
    };
    let (cache_b, rl_b, _addr_b) = RippleEngine::start(config_b, shutdown.clone())
        .await
        .expect("node B failed to start");

    tokio::time::sleep(Duration::from_millis(2000)).await;

    ((cache_a, rl_a), (cache_b, rl_b))
}

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

#[tokio::test]
async fn two_node_cache_convergence() {
    tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::DEBUG)
        .with_test_writer()
        .try_init()
        .ok();

    let shutdown = CancellationToken::new();
    let ((cache_a, _rl_a), (cache_b, _rl_b)) = spawn_pair(shutdown.clone()).await;

    cache_a
        .set("test-key", "hello-from-a", Duration::from_secs(300))
        .await
        .expect("set on A failed");

    assert_eq!(
        cache_a.get("test-key").await.as_deref(),
        Some("hello-from-a"),
    );

    let b = cache_b.clone();
    poll_until(10_000, 200, || {
        let b = b.clone();
        async move { b.get("test-key").await.as_deref() == Some("hello-from-a") }
    })
    .await;

    shutdown.cancel();
}

#[tokio::test]
async fn two_node_delete_convergence() {
    tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::DEBUG)
        .with_test_writer()
        .try_init()
        .ok();

    let shutdown = CancellationToken::new();
    let ((cache_a, _), (cache_b, _)) = spawn_pair(shutdown.clone()).await;

    let key = format!("del-{}", uuid::Uuid::new_v4());

    cache_a
        .set(&key, "to-be-deleted", Duration::from_secs(300))
        .await
        .expect("set on A failed");

    let b = cache_b.clone();
    let k = key.clone();
    poll_until(10_000, 200, move || {
        let b = b.clone();
        let k = k.clone();
        async move { b.get(&k).await.is_some() }
    })
    .await;

    cache_a.delete(&key).await.expect("delete on A failed");

    let b = cache_b.clone();
    let k = key.clone();
    poll_until(10_000, 200, move || {
        let b = b.clone();
        let k = k.clone();
        async move { b.get(&k).await.is_none() }
    })
    .await;

    shutdown.cancel();
}

#[tokio::test]
async fn two_node_lww_conflict_resolution() {
    tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::DEBUG)
        .with_test_writer()
        .try_init()
        .ok();

    let shutdown = CancellationToken::new();
    let ((cache_a, _), (cache_b, _)) = spawn_pair(shutdown.clone()).await;

    let key = format!("lww-{}", uuid::Uuid::new_v4());

    cache_a
        .set(&key, "value-from-a", Duration::from_secs(300))
        .await
        .expect("set on A failed");

    cache_b
        .set(&key, "value-from-b", Duration::from_secs(300))
        .await
        .expect("set on B failed");

    let a = cache_a.clone();
    let b = cache_b.clone();
    let k = key.clone();
    poll_until(15_000, 200, move || {
        let a = a.clone();
        let b = b.clone();
        let k = k.clone();
        async move {
            let (va, vb) = tokio::join!(a.get(&k), b.get(&k));
            matches!((va, vb), (Some(a), Some(b)) if a == b)
        }
    })
    .await;

    let val_a = cache_a.get(&key).await.expect("A should have the key");
    let val_b = cache_b.get(&key).await.expect("B should have the key");

    assert_eq!(val_a, val_b, "both nodes must agree on the same value after LWW resolution");

    shutdown.cancel();
}

#[tokio::test]
async fn two_node_binary_data_convergence() {
    tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::DEBUG)
        .with_test_writer()
        .try_init()
        .ok();

    let shutdown = CancellationToken::new();
    let ((cache_a, _), (cache_b, _)) = spawn_pair(shutdown.clone()).await;

    let key = format!("bin-{}", uuid::Uuid::new_v4());
    let payload: Vec<u8> = (0..=255u8).collect();

    cache_a
        .set_bytes(&key, &payload, Duration::from_secs(300))
        .await
        .expect("set_bytes on A failed");

    let b = cache_b.clone();
    let k = key.clone();
    let expected = payload.clone();
    poll_until(10_000, 200, move || {
        let b = b.clone();
        let k = k.clone();
        let expected = expected.clone();
        async move {
            b.get_bytes(&k)
                .await
                .map(|v| v == expected)
                .unwrap_or(false)
        }
    })
    .await;

    shutdown.cancel();
}

#[tokio::test]
async fn two_node_ttl_expiration() {
    tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::DEBUG)
        .with_test_writer()
        .try_init()
        .ok();

    let shutdown = CancellationToken::new();
    let ((cache_a, _), (cache_b, _)) = spawn_pair(shutdown.clone()).await;

    let key = format!("ttl-{}", uuid::Uuid::new_v4());

    cache_a
        .set(&key, "ephemeral", Duration::from_secs(2))
        .await
        .expect("set on A failed");

    let b = cache_b.clone();
    let k = key.clone();
    poll_until(10_000, 200, move || {
        let b = b.clone();
        let k = k.clone();
        async move { b.get(&k).await.is_some() }
    })
    .await;

    tokio::time::sleep(Duration::from_secs(3)).await;

    assert!(cache_a.get(&key).await.is_none(), "A should have expired the key");
    assert!(cache_b.get(&key).await.is_none(), "B should have expired the key");

    shutdown.cancel();
}

#[tokio::test]
async fn two_node_rapid_overwrite_convergence() {
    tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::DEBUG)
        .with_test_writer()
        .try_init()
        .ok();

    let shutdown = CancellationToken::new();
    let ((cache_a, _), (cache_b, _)) = spawn_pair(shutdown.clone()).await;

    let key = format!("rapid-{}", uuid::Uuid::new_v4());

    futures::future::join_all((0..50).map(|i| {
        let cache = cache_a.clone();
        let k = key.clone();
        async move {
            cache
                .set(&k, &format!("value-{i}"), Duration::from_secs(300))
                .await
                .expect("set failed");
        }
    }))
    .await;

    let b = cache_b.clone();
    let k = key.clone();
    poll_until(10_000, 200, move || {
        let b = b.clone();
        let k = k.clone();
        async move { b.get(&k).await.as_deref() == Some("value-49") }
    })
    .await;

    shutdown.cancel();
}

#[tokio::test]
async fn two_node_many_keys_convergence() {
    tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::DEBUG)
        .with_test_writer()
        .try_init()
        .ok();

    let shutdown = CancellationToken::new();
    let ((cache_a, _), (cache_b, _)) = spawn_pair(shutdown.clone()).await;

    let prefix = format!("many-{}", uuid::Uuid::new_v4());

    futures::future::join_all((0..200).map(|i| {
        let cache = cache_a.clone();
        let p = prefix.clone();
        async move {
            cache
                .set(
                    &format!("{p}-{i}"),
                    &format!("val-{i}"),
                    Duration::from_secs(300),
                )
                .await
                .expect("set failed");
        }
    }))
    .await;

    let b = cache_b.clone();
    let p = prefix.clone();
    poll_until(30_000, 500, move || {
        let b = b.clone();
        let p = p.clone();
        async move {
            futures::future::join_all((0..200).map(|i| {
                let b = b.clone();
                let p = p.clone();
                async move { b.get(&format!("{p}-{i}")).await.is_some() }
            }))
            .await
            .into_iter()
            .all(|present| present)
        }
    })
    .await;

    let results: Vec<Option<String>> = futures::future::join_all((0..200).map(|i| {
        let b = cache_b.clone();
        let p = prefix.clone();
        async move { b.get(&format!("{p}-{i}")).await }
    }))
    .await;

    results.into_iter().enumerate().for_each(|(i, val)| {
        assert_eq!(
            val.as_deref(),
            Some(format!("val-{i}").as_str()),
            "key {i} mismatch on B"
        );
    });

    shutdown.cancel();
}

#[tokio::test]
async fn two_node_concurrent_disjoint_writes() {
    tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::DEBUG)
        .with_test_writer()
        .try_init()
        .ok();

    let shutdown = CancellationToken::new();
    let ((cache_a, _), (cache_b, _)) = spawn_pair(shutdown.clone()).await;

    let prefix = format!("disj-{}", uuid::Uuid::new_v4());

    let write_a = {
        let cache = cache_a.clone();
        let p = prefix.clone();
        async move {
            futures::future::join_all((0..100).map(|i| {
                let cache = cache.clone();
                let p = p.clone();
                async move {
                    cache
                        .set(
                            &format!("{p}-a-{i}"),
                            &format!("a-{i}"),
                            Duration::from_secs(300),
                        )
                        .await
                        .expect("set failed");
                }
            }))
            .await;
        }
    };

    let write_b = {
        let cache = cache_b.clone();
        let p = prefix.clone();
        async move {
            futures::future::join_all((0..100).map(|i| {
                let cache = cache.clone();
                let p = p.clone();
                async move {
                    cache
                        .set(
                            &format!("{p}-b-{i}"),
                            &format!("b-{i}"),
                            Duration::from_secs(300),
                        )
                        .await
                        .expect("set failed");
                }
            }))
            .await;
        }
    };

    tokio::join!(write_a, write_b);

    let a = cache_a.clone();
    let b = cache_b.clone();
    let p = prefix.clone();
    poll_until(30_000, 500, move || {
        let a = a.clone();
        let b = b.clone();
        let p = p.clone();
        async move {
            let a_has_b_keys = futures::future::join_all((0..100).map(|i| {
                let a = a.clone();
                let p = p.clone();
                async move { a.get(&format!("{p}-b-{i}")).await.is_some() }
            }))
            .await
            .into_iter()
            .all(|v| v);

            let b_has_a_keys = futures::future::join_all((0..100).map(|i| {
                let b = b.clone();
                let p = p.clone();
                async move { b.get(&format!("{p}-a-{i}")).await.is_some() }
            }))
            .await
            .into_iter()
            .all(|v| v);

            a_has_b_keys && b_has_a_keys
        }
    })
    .await;

    shutdown.cancel();
}

#[tokio::test]
async fn two_node_concurrent_same_key_writes() {
    tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::DEBUG)
        .with_test_writer()
        .try_init()
        .ok();

    let shutdown = CancellationToken::new();
    let ((cache_a, _), (cache_b, _)) = spawn_pair(shutdown.clone()).await;

    let prefix = format!("same-{}", uuid::Uuid::new_v4());

    let write_a = {
        let cache = cache_a.clone();
        let p = prefix.clone();
        async move {
            futures::future::join_all((0..50).map(|i| {
                let cache = cache.clone();
                let p = p.clone();
                async move {
                    cache
                        .set(
                            &format!("{p}-{i}"),
                            &format!("a-{i}"),
                            Duration::from_secs(300),
                        )
                        .await
                        .expect("set failed");
                }
            }))
            .await;
        }
    };

    let write_b = {
        let cache = cache_b.clone();
        let p = prefix.clone();
        async move {
            futures::future::join_all((0..50).map(|i| {
                let cache = cache.clone();
                let p = p.clone();
                async move {
                    cache
                        .set(
                            &format!("{p}-{i}"),
                            &format!("b-{i}"),
                            Duration::from_secs(300),
                        )
                        .await
                        .expect("set failed");
                }
            }))
            .await;
        }
    };

    tokio::join!(write_a, write_b);

    let a = cache_a.clone();
    let b = cache_b.clone();
    let p = prefix.clone();
    poll_until(15_000, 200, move || {
        let a = a.clone();
        let b = b.clone();
        let p = p.clone();
        async move {
            futures::future::join_all((0..50).map(|i| {
                let a = a.clone();
                let b = b.clone();
                let p = p.clone();
                async move {
                    let va = a.get(&format!("{p}-{i}")).await.unwrap_or_default();
                    let vb = b.get(&format!("{p}-{i}")).await.unwrap_or_default();
                    !va.is_empty() && va == vb
                }
            }))
            .await
            .into_iter()
            .all(|v| v)
        }
    })
    .await;

    let results: Vec<(String, String)> = futures::future::join_all((0..50).map(|i| {
        let a = cache_a.clone();
        let b = cache_b.clone();
        let p = prefix.clone();
        async move {
            let va = a.get(&format!("{p}-{i}")).await.unwrap_or_default();
            let vb = b.get(&format!("{p}-{i}")).await.unwrap_or_default();
            (va, vb)
        }
    }))
    .await;

    results.into_iter().enumerate().for_each(|(i, (va, vb))| {
        assert_eq!(va, vb, "key {i}: nodes disagree (A={va}, B={vb})");
    });

    shutdown.cancel();
}

#[tokio::test]
async fn two_node_rate_limit_split_increment() {
    tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::DEBUG)
        .with_test_writer()
        .try_init()
        .ok();

    let shutdown = CancellationToken::new();
    let ((_, rl_a), (_, rl_b)) = spawn_pair(shutdown.clone()).await;

    let key = format!("rl-split-{}", uuid::Uuid::new_v4());
    let limit: u32 = 200;
    let window_ms: u64 = 600_000;

    futures::future::join_all((0..40).map(|_| {
        let rl = rl_a.clone();
        let k = key.clone();
        async move {
            let allowed = rl.check_rate_limit(&k, limit, window_ms).await;
            assert!(allowed, "should be allowed within limit");
        }
    }))
    .await;

    futures::future::join_all((0..30).map(|_| {
        let rl = rl_b.clone();
        let k = key.clone();
        async move {
            let allowed = rl.check_rate_limit(&k, limit, window_ms).await;
            assert!(allowed, "should be allowed within limit");
        }
    }))
    .await;

    let rl_peek = rl_a.clone();
    let k = key.clone();
    poll_until(15_000, 200, move || {
        let rl = rl_peek.clone();
        let k = k.clone();
        async move { rl.peek_rate_limit_count(&k, window_ms).await >= 70 }
    })
    .await;

    let mut remaining = 0u32;
    loop {
        if !rl_a.check_rate_limit(&key, limit, window_ms).await {
            break;
        }
        remaining += 1;
        if remaining > limit {
            panic!("rate limiter never denied - convergence failed");
        }
    }

    let expected_remaining = limit - 70;
    let margin = 15;
    assert!(
        remaining.abs_diff(expected_remaining) <= margin,
        "expected ~{expected_remaining} remaining hits, got {remaining} (margin={margin})"
    );

    shutdown.cancel();
}
