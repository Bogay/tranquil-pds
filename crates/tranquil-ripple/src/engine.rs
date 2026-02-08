use crate::cache::RippleCache;
use crate::config::RippleConfig;
use crate::crdt::ShardedCrdtStore;
use crate::eviction::MemoryBudget;
use crate::gossip::{GossipEngine, PeerId};
use crate::metrics;
use crate::rate_limiter::RippleRateLimiter;
use crate::transport::Transport;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tranquil_infra::{Cache, DistributedRateLimiter};

pub struct RippleEngine;

impl RippleEngine {
    pub async fn start(
        config: RippleConfig,
        shutdown: CancellationToken,
    ) -> Result<(Arc<dyn Cache>, Arc<dyn DistributedRateLimiter>, SocketAddr), RippleStartError> {
        let store = Arc::new(ShardedCrdtStore::new(config.machine_id));

        let (transport, incoming_rx) = Transport::bind(config.bind_addr, config.machine_id, shutdown.clone())
            .await
            .map_err(|e| RippleStartError::Bind(e.to_string()))?;

        let transport = Arc::new(transport);

        let bound_addr = transport.local_addr();
        let generation = u32::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                % u64::from(u32::MAX),
        )
        .unwrap_or(0);
        let local_id = PeerId {
            addr: bound_addr,
            machine_id: config.machine_id,
            generation,
        };

        let gossip = GossipEngine::new(transport, store.clone(), local_id);

        let gossip_handle = gossip.spawn(
            config.seed_peers,
            config.gossip_interval_ms,
            incoming_rx,
            shutdown.clone(),
        );

        let budget = MemoryBudget::new(config.cache_max_bytes);
        let store_for_eviction = store.clone();
        let eviction_shutdown = shutdown.clone();
        let eviction_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            loop {
                tokio::select! {
                    _ = eviction_shutdown.cancelled() => break,
                    _ = interval.tick() => {
                        budget.enforce(&store_for_eviction);
                    }
                }
            }
        });

        let shutdown_for_monitor = shutdown.clone();
        tokio::spawn(async move {
            shutdown_for_monitor.cancelled().await;
            let gossip_result = gossip_handle.await;
            let eviction_result = eviction_handle.await;
            if let Err(e) = gossip_result {
                tracing::error!(error = %e, "gossip task panicked");
            }
            if let Err(e) = eviction_result {
                tracing::error!(error = %e, "eviction task panicked");
            }
        });

        let cache: Arc<dyn Cache> = Arc::new(RippleCache::new(store.clone()));
        let rate_limiter: Arc<dyn DistributedRateLimiter> =
            Arc::new(RippleRateLimiter::new(store));

        metrics::describe_metrics();

        tracing::info!(
            bind = %bound_addr,
            machine_id = config.machine_id,
            max_cache_mb = config.cache_max_bytes / (1024 * 1024),
            "ripple engine started"
        );

        Ok((cache, rate_limiter, bound_addr))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RippleStartError {
    #[error("failed to bind transport: {0}")]
    Bind(String),
    #[error("configuration error: {0}")]
    Config(String),
}
