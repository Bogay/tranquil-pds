use crate::{Cache, CacheError};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct Entry {
    value: Vec<u8>,
    expires_at: Instant,
}

#[derive(Default)]
pub struct MemoryCache {
    entries: Mutex<HashMap<String, Entry>>,
}

impl MemoryCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn read(&self, key: &str) -> Option<Vec<u8>> {
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        match entries.get(key) {
            Some(entry) if entry.expires_at > now => Some(entry.value.clone()),
            Some(_) => {
                entries.remove(key);
                None
            }
            None => None,
        }
    }

    fn write(&self, key: &str, value: Vec<u8>, ttl: Duration) {
        let entry = Entry {
            value,
            expires_at: Instant::now() + ttl,
        };
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.to_string(), entry);
    }
}

#[async_trait]
impl Cache for MemoryCache {
    async fn get(&self, key: &str) -> Option<String> {
        self.read(key).and_then(|v| String::from_utf8(v).ok())
    }

    async fn set(&self, key: &str, value: &str, ttl: Duration) -> Result<(), CacheError> {
        self.write(key, value.as_bytes().to_vec(), ttl);
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), CacheError> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
        Ok(())
    }

    async fn get_bytes(&self, key: &str) -> Option<Vec<u8>> {
        self.read(key)
    }

    async fn set_bytes(&self, key: &str, value: &[u8], ttl: Duration) -> Result<(), CacheError> {
        self.write(key, value.to_vec(), ttl);
        Ok(())
    }
}
