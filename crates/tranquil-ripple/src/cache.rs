use crate::crdt::CrdtStore;
use async_trait::async_trait;
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::Duration;
use tranquil_infra::{Cache, CacheError};

pub struct RippleCache {
    store: Arc<RwLock<CrdtStore>>,
}

impl RippleCache {
    pub fn new(store: Arc<RwLock<CrdtStore>>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl Cache for RippleCache {
    async fn get(&self, key: &str) -> Option<String> {
        self.store
            .read()
            .cache_get(key)
            .and_then(|bytes| String::from_utf8(bytes).ok())
    }

    async fn set(&self, key: &str, value: &str, ttl: Duration) -> Result<(), CacheError> {
        self.store
            .write()
            .cache_set(key.to_string(), value.as_bytes().to_vec(), ttl.as_millis() as u64);
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), CacheError> {
        self.store.write().cache_delete(key);
        Ok(())
    }

    async fn get_bytes(&self, key: &str) -> Option<Vec<u8>> {
        self.store.read().cache_get(key)
    }

    async fn set_bytes(&self, key: &str, value: &[u8], ttl: Duration) -> Result<(), CacheError> {
        self.store
            .write()
            .cache_set(key.to_string(), value.to_vec(), ttl.as_millis() as u64);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cache_trait_roundtrip() {
        let store = Arc::new(RwLock::new(CrdtStore::new(1)));
        let cache = RippleCache::new(store);
        cache
            .set("test", "value", Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(cache.get("test").await, Some("value".to_string()));
    }

    #[tokio::test]
    async fn cache_trait_bytes() {
        let store = Arc::new(RwLock::new(CrdtStore::new(1)));
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
        let store = Arc::new(RwLock::new(CrdtStore::new(1)));
        let cache = RippleCache::new(store);
        cache
            .set("del", "x", Duration::from_secs(60))
            .await
            .unwrap();
        cache.delete("del").await.unwrap();
        assert_eq!(cache.get("del").await, None);
    }
}
