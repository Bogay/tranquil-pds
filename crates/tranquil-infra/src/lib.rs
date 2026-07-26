#[cfg(feature = "cache-keys")]
pub mod cache_keys;

#[cfg(feature = "testing")]
mod memory_cache;
#[cfg(feature = "testing")]
pub use memory_cache::MemoryCache;

use async_trait::async_trait;
use bytes::Bytes;
use futures::Stream;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Storage error: {0}")]
    Backend(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Other: {0}")]
    Other(String),
}

pub struct StreamUploadResult {
    pub sha256_hash: [u8; 32],
    pub size: u64,
}

#[async_trait]
pub trait BlobStorage: Send + Sync {
    async fn put(&self, key: &str, data: &[u8]) -> Result<(), StorageError>;
    async fn put_bytes(&self, key: &str, data: Bytes) -> Result<(), StorageError>;
    async fn get(&self, key: &str) -> Result<Vec<u8>, StorageError>;
    async fn get_bytes(&self, key: &str) -> Result<Bytes, StorageError>;
    async fn get_head(&self, key: &str, size: usize) -> Result<Bytes, StorageError>;
    async fn delete(&self, key: &str) -> Result<(), StorageError>;
    async fn put_stream(
        &self,
        key: &str,
        stream: Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>,
    ) -> Result<StreamUploadResult, StorageError>;
    async fn copy(&self, src_key: &str, dst_key: &str) -> Result<(), StorageError>;
}

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
    async fn get_bytes(&self, key: &str) -> Option<Vec<u8>>;
    async fn set_bytes(&self, key: &str, value: &[u8], ttl: Duration) -> Result<(), CacheError>;
    fn is_available(&self) -> bool {
        true
    }
}

pub async fn read_json<T: serde::de::DeserializeOwned>(cache: &dyn Cache, key: &str) -> Option<T> {
    let json = cache.get(key).await?;
    serde_json::from_str(&json).ok()
}

pub async fn write_json<T: serde::Serialize>(
    cache: &dyn Cache,
    key: &str,
    value: &T,
    ttl: Duration,
) {
    if let Ok(json) = serde_json::to_string(value) {
        let _ = cache.set(key, &json, ttl).await;
    }
}

pub async fn cached_json<T, E, Fut>(
    cache: &dyn Cache,
    key: &str,
    ttl: Duration,
    fetch: impl FnOnce() -> Fut,
) -> Result<T, E>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
    Fut: Future<Output = Result<T, E>>,
{
    match read_json(cache, key).await {
        Some(value) => Ok(value),
        None => {
            let value = fetch().await?;
            write_json(cache, key, &value, ttl).await;
            Ok(value)
        }
    }
}

#[async_trait]
pub trait DistributedRateLimiter: Send + Sync {
    async fn check_rate_limit(&self, key: &str, limit: u32, window_ms: u64) -> bool;
    async fn peek_rate_limit_count(&self, _key: &str, _window_ms: u64) -> u64 {
        0
    }
}
