use crate::crdt::ShardedCrdtStore;
use crate::metrics;
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tranquil_infra::{Cache, CacheError};

pub struct RippleCache {
    store: Arc<ShardedCrdtStore>,
}

impl RippleCache {
    pub fn new(store: Arc<ShardedCrdtStore>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl Cache for RippleCache {
    async fn get(&self, key: &str) -> Option<String> {
        let result = self
            .store
            .cache_get(key)
            .and_then(|bytes| String::from_utf8(bytes).ok());
        match result.is_some() {
            true => metrics::record_cache_hit(),
            false => metrics::record_cache_miss(),
        }
        result
    }

    async fn set(&self, key: &str, value: &str, ttl: Duration) -> Result<(), CacheError> {
        let ttl_ms = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX);
        self.store
            .cache_set(key.to_string(), value.as_bytes().to_vec(), ttl_ms);
        metrics::record_cache_write();
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), CacheError> {
        self.store.cache_delete(key);
        metrics::record_cache_delete();
        Ok(())
    }

    async fn get_bytes(&self, key: &str) -> Option<Vec<u8>> {
        let result = self.store.cache_get(key);
        match result.is_some() {
            true => metrics::record_cache_hit(),
            false => metrics::record_cache_miss(),
        }
        result
    }

    async fn set_bytes(&self, key: &str, value: &[u8], ttl: Duration) -> Result<(), CacheError> {
        let ttl_ms = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX);
        self.store
            .cache_set(key.to_string(), value.to_vec(), ttl_ms);
        metrics::record_cache_write();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cache_trait_roundtrip() {
        let store = Arc::new(ShardedCrdtStore::new(1));
        let cache = RippleCache::new(store);
        cache
            .set("test", "value", Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(cache.get("test").await, Some("value".to_string()));
    }

    #[tokio::test]
    async fn cache_trait_bytes() {
        let store = Arc::new(ShardedCrdtStore::new(1));
        let cache = RippleCache::new(store);
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        cache
            .set_bytes("bin", &data, Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(cache.get_bytes("bin").await, Some(data));
    }

    #[tokio::test]
    async fn cache_trait_delete() {
        let store = Arc::new(ShardedCrdtStore::new(1));
        let cache = RippleCache::new(store);
        cache
            .set("del", "x", Duration::from_secs(60))
            .await
            .unwrap();
        cache.delete("del").await.unwrap();
        assert_eq!(cache.get("del").await, None);
    }
}
