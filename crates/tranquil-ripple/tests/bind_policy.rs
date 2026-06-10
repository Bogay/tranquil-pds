use tokio_util::sync::CancellationToken;
use tranquil_ripple::{RippleConfig, RippleEngine, RippleStartError};

fn config(cluster_key: Option<&str>, allow_insecure: bool) -> RippleConfig {
    RippleConfig {
        bind_addr: "0.0.0.0:0".parse().unwrap(),
        seed_peers: Vec::new(),
        machine_id: 1,
        gossip_interval_ms: 100,
        cache_max_bytes: 64 * 1024 * 1024,
        cluster_key: cluster_key.map(str::to_string),
        allow_insecure,
    }
}

#[tokio::test]
async fn non_loopback_bind_without_key_refuses_to_start() {
    let shutdown = CancellationToken::new();
    let result = RippleEngine::start(config(None, false), shutdown.clone()).await;
    shutdown.cancel();
    match result {
        Err(RippleStartError::Config(msg)) => {
            assert!(
                msg.contains("RIPPLE_CLUSTER_KEY"),
                "unexpected message: {msg}"
            )
        }
        Err(other) => panic!("expected config error, got {other}"),
        Ok(_) => panic!("engine must refuse a keyless non-loopback bind"),
    }
}

#[tokio::test]
async fn non_loopback_bind_with_cluster_key_starts() {
    let shutdown = CancellationToken::new();
    let result =
        RippleEngine::start(config(Some("nautilus-secret"), false), shutdown.clone()).await;
    assert!(
        result.is_ok(),
        "keyed bind must start: {:?}",
        result.err().map(|e| e.to_string())
    );
    shutdown.cancel();
}

#[tokio::test]
async fn non_loopback_bind_with_allow_insecure_starts() {
    let shutdown = CancellationToken::new();
    let result = RippleEngine::start(config(None, true), shutdown.clone()).await;
    assert!(
        result.is_ok(),
        "allow_insecure bind must start: {:?}",
        result.err().map(|e| e.to_string())
    );
    shutdown.cancel();
}

#[tokio::test]
async fn loopback_bind_without_key_starts() {
    let shutdown = CancellationToken::new();
    let mut cfg = config(None, false);
    cfg.bind_addr = "127.0.0.1:0".parse().unwrap();
    let result = RippleEngine::start(cfg, shutdown.clone()).await;
    assert!(
        result.is_ok(),
        "loopback keyless bind must start: {:?}",
        result.err().map(|e| e.to_string())
    );
    shutdown.cancel();
}
