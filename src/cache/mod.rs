use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("Cache connection error: {0}")]
    Connection(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

#[async_trait]
pub trait Cache: Send + Sync {
    async fn get(&self, key: &str) -> Option<String>;
    async fn set(&self, key: &str, value: &str, ttl: Duration) -> Result<(), CacheError>;
    async fn delete(&self, key: &str) -> Result<(), CacheError>;
}

#[derive(Clone)]
pub struct ValkeyCache {
    conn: redis::aio::ConnectionManager,
}

impl ValkeyCache {
    pub async fn new(url: &str) -> Result<Self, CacheError> {
        let client = redis::Client::open(url)
            .map_err(|e| CacheError::Connection(e.to_string()))?;
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
            .arg("EX")
            .arg(ttl.as_secs() as i64)
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
}

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
}

#[async_trait]
pub trait DistributedRateLimiter: Send + Sync {
    async fn check_rate_limit(&self, key: &str, limit: u32, window_ms: u64) -> bool;
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
        let window_secs = ((window_ms + 999) / 1000).max(1) as i64;

        let count: Result<i64, _> = redis::cmd("INCR")
            .arg(&full_key)
            .query_async(&mut conn)
            .await;

        let count = match count {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Redis rate limit INCR failed: {}. Allowing request.", e);
                return true;
            }
        };

        if count == 1 {
            let _: Result<bool, redis::RedisError> = redis::cmd("EXPIRE")
                .arg(&full_key)
                .arg(window_secs)
                .query_async(&mut conn)
                .await;
        }

        count <= limit as i64
    }
}

pub struct NoOpRateLimiter;

#[async_trait]
impl DistributedRateLimiter for NoOpRateLimiter {
    async fn check_rate_limit(&self, _key: &str, _limit: u32, _window_ms: u64) -> bool {
        true
    }
}

pub enum CacheBackend {
    Valkey(ValkeyCache),
    NoOp,
}

impl CacheBackend {
    pub fn rate_limiter(&self) -> Arc<dyn DistributedRateLimiter> {
        match self {
            CacheBackend::Valkey(cache) => {
                Arc::new(RedisRateLimiter::new(cache.connection()))
            }
            CacheBackend::NoOp => Arc::new(NoOpRateLimiter),
        }
    }
}

#[async_trait]
impl Cache for CacheBackend {
    async fn get(&self, key: &str) -> Option<String> {
        match self {
            CacheBackend::Valkey(c) => c.get(key).await,
            CacheBackend::NoOp => None,
        }
    }

    async fn set(&self, key: &str, value: &str, ttl: Duration) -> Result<(), CacheError> {
        match self {
            CacheBackend::Valkey(c) => c.set(key, value, ttl).await,
            CacheBackend::NoOp => Ok(()),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), CacheError> {
        match self {
            CacheBackend::Valkey(c) => c.delete(key).await,
            CacheBackend::NoOp => Ok(()),
        }
    }
}

pub async fn create_cache() -> (Arc<dyn Cache>, Arc<dyn DistributedRateLimiter>) {
    match std::env::var("VALKEY_URL") {
        Ok(url) => match ValkeyCache::new(&url).await {
            Ok(cache) => {
                tracing::info!("Connected to Valkey cache at {}", url);
                let rate_limiter = Arc::new(RedisRateLimiter::new(cache.connection()));
                (Arc::new(cache), rate_limiter)
            }
            Err(e) => {
                tracing::warn!("Failed to connect to Valkey: {}. Running without cache.", e);
                (Arc::new(NoOpCache), Arc::new(NoOpRateLimiter))
            }
        },
        Err(_) => {
            tracing::info!("VALKEY_URL not set. Running without cache.");
            (Arc::new(NoOpCache), Arc::new(NoOpRateLimiter))
        }
    }
}
