use crate::crdt::CrdtStore;
use async_trait::async_trait;
use parking_lot::RwLock;
use std::sync::Arc;
use tranquil_infra::DistributedRateLimiter;

pub struct RippleRateLimiter {
    store: Arc<RwLock<CrdtStore>>,
}

impl RippleRateLimiter {
    pub fn new(store: Arc<RwLock<CrdtStore>>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl DistributedRateLimiter for RippleRateLimiter {
    async fn check_rate_limit(&self, key: &str, limit: u32, window_ms: u64) -> bool {
        self.store.write().rate_limit_check(key, limit, window_ms)
    }

    async fn peek_rate_limit_count(&self, key: &str, window_ms: u64) -> u64 {
        self.store.read().rate_limit_peek(key, window_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rate_limiter_trait_allows_within_limit() {
        let store = Arc::new(RwLock::new(CrdtStore::new(1)));
        let rl = RippleRateLimiter::new(store);
        assert!(rl.check_rate_limit("test", 5, 60_000).await);
        assert!(rl.check_rate_limit("test", 5, 60_000).await);
    }

    #[tokio::test]
    async fn rate_limiter_trait_blocks_over_limit() {
        let store = Arc::new(RwLock::new(CrdtStore::new(1)));
        let rl = RippleRateLimiter::new(store);
        assert!(rl.check_rate_limit("k", 3, 60_000).await);
        assert!(rl.check_rate_limit("k", 3, 60_000).await);
        assert!(rl.check_rate_limit("k", 3, 60_000).await);
        assert!(!rl.check_rate_limit("k", 3, 60_000).await);
    }
}
