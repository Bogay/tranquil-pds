pub use tranquil_infra::{Cache, CacheError, DistributedRateLimiter};

use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "valkey")]
mod valkey {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

    #[derive(Clone)]
    pub struct ValkeyCache {
        conn: redis::aio::ConnectionManager,
    }

    impl ValkeyCache {
        pub async fn new(url: &str) -> Result<Self, CacheError> {
            let client =
                redis::Client::open(url).map_err(|e| CacheError::Connection(e.to_string()))?;
            let manager = client
                .get_connection_manager()
                .await
                .map_err(|e| CacheError::Connection(e.to_string()))?;
            Ok(Self { conn: manager })
        }

        pub fn connection(&self) -> redis::aio::ConnectionManager {
            self.conn.clone()
        }
    }

    #[async_trait]
    impl Cache for ValkeyCache {
        async fn get(&self, key: &str) -> Option<String> {
            let mut conn = self.conn.clone();
            redis::cmd("GET")
                .arg(key)
                .query_async::<Option<String>>(&mut conn)
                .await
                .ok()
                .flatten()
        }

        async fn set(&self, key: &str, value: &str, ttl: Duration) -> Result<(), CacheError> {
            let mut conn = self.conn.clone();
            redis::cmd("SET")
                .arg(key)
                .arg(value)
                .arg("PX")
                .arg(i64::try_from(ttl.as_millis()).unwrap_or(i64::MAX))
                .query_async::<()>(&mut conn)
                .await
                .map_err(|e| CacheError::Connection(e.to_string()))
        }

        async fn delete(&self, key: &str) -> Result<(), CacheError> {
            let mut conn = self.conn.clone();
            redis::cmd("DEL")
                .arg(key)
                .query_async::<()>(&mut conn)
                .await
                .map_err(|e| CacheError::Connection(e.to_string()))
        }

        async fn get_bytes(&self, key: &str) -> Option<Vec<u8>> {
            self.get(key).await.and_then(|s| BASE64.decode(&s).ok())
        }

        async fn set_bytes(
            &self,
            key: &str,
            value: &[u8],
            ttl: Duration,
        ) -> Result<(), CacheError> {
            let encoded = BASE64.encode(value);
            self.set(key, &encoded, ttl).await
        }
    }

    #[derive(Clone)]
    pub struct RedisRateLimiter {
        conn: redis::aio::ConnectionManager,
    }

    impl RedisRateLimiter {
        pub fn new(conn: redis::aio::ConnectionManager) -> Self {
            Self { conn }
        }
    }

    #[async_trait]
    impl DistributedRateLimiter for RedisRateLimiter {
        async fn check_rate_limit(&self, key: &str, limit: u32, window_ms: u64) -> bool {
            let mut conn = self.conn.clone();
            let full_key = format!("rl:{}", key);
            let window_secs = i64::try_from(window_ms.div_ceil(1000).max(1)).unwrap_or(i64::MAX);
            let result: Result<i64, _> = redis::Script::new(
                r"local c = redis.call('INCR', KEYS[1])
if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
if redis.call('TTL', KEYS[1]) == -1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return c",
            )
            .key(&full_key)
            .arg(window_secs)
            .invoke_async(&mut conn)
            .await;
            match result {
                Ok(count) => count <= i64::from(limit),
                Err(e) => {
                    tracing::warn!(error = %e, "redis rate limit script failed, allowing request");
                    true
                }
            }
        }

        async fn peek_rate_limit_count(&self, key: &str, _window_ms: u64) -> u64 {
            let mut conn = self.conn.clone();
            let full_key = format!("rl:{}", key);
            redis::cmd("GET")
                .arg(&full_key)
                .query_async::<Option<u64>>(&mut conn)
                .await
                .ok()
                .flatten()
                .unwrap_or(0)
        }
    }
}

#[cfg(feature = "valkey")]
pub use valkey::{RedisRateLimiter, ValkeyCache};

pub struct NoOpCache;

#[async_trait]
impl Cache for NoOpCache {
    async fn get(&self, _key: &str) -> Option<String> {
        None
    }

    async fn set(&self, _key: &str, _value: &str, _ttl: Duration) -> Result<(), CacheError> {
        Ok(())
    }

    async fn delete(&self, _key: &str) -> Result<(), CacheError> {
        Ok(())
    }

    async fn get_bytes(&self, _key: &str) -> Option<Vec<u8>> {
        None
    }

    async fn set_bytes(&self, _key: &str, _value: &[u8], _ttl: Duration) -> Result<(), CacheError> {
        Ok(())
    }

    fn is_available(&self) -> bool {
        false
    }
}

pub struct NoOpRateLimiter;

#[async_trait]
impl DistributedRateLimiter for NoOpRateLimiter {
    async fn check_rate_limit(&self, _key: &str, _limit: u32, _window_ms: u64) -> bool {
        true
    }
}

pub async fn create_cache(
    shutdown: tokio_util::sync::CancellationToken,
) -> (Arc<dyn Cache>, Arc<dyn DistributedRateLimiter>) {
    let cache_cfg = tranquil_config::try_get().map(|c| &c.cache);
    let backend = cache_cfg.map(|c| c.backend.as_str()).unwrap_or("ripple");
    let valkey_url = cache_cfg.and_then(|c| c.valkey_url.as_deref());

    #[cfg(feature = "valkey")]
    if backend == "valkey" {
        if let Some(url) = valkey_url {
            match ValkeyCache::new(url).await {
                Ok(cache) => {
                    tracing::info!("using valkey cache at {url}");
                    let rate_limiter = Arc::new(RedisRateLimiter::new(cache.connection()));
                    return (Arc::new(cache), rate_limiter);
                }
                Err(e) => {
                    tracing::warn!("failed to connect to valkey: {e}. falling back to ripple.");
                }
            }
        } else {
            tracing::warn!("cache.backend is \"valkey\" but VALKEY_URL is not set. using ripple.");
        }
    }

    #[cfg(not(feature = "valkey"))]
    if backend == "valkey" {
        tracing::warn!(
            "cache.backend is \"valkey\" but binary was compiled without valkey feature. using ripple."
        );
    }

    match tranquil_ripple::RippleConfig::from_config() {
        Ok(config) => {
            let peer_count = config.seed_peers.len();
            match tranquil_ripple::RippleEngine::start(config, shutdown).await {
                Ok((cache, rate_limiter, _bound_addr)) => {
                    match peer_count {
                        0 => tracing::info!("ripple cache started (single-node)"),
                        n => tracing::info!("ripple cache started ({n} seed peers)"),
                    }
                    (cache, rate_limiter)
                }
                Err(e) => {
                    tracing::error!("ripple engine failed to start: {e:#}. running without cache.");
                    (Arc::new(NoOpCache), Arc::new(NoOpRateLimiter))
                }
            }
        }
        Err(e) => {
            tracing::error!("ripple config error: {e:#}. running without cache.");
            (Arc::new(NoOpCache), Arc::new(NoOpRateLimiter))
        }
    }
}
