use async_trait::async_trait;
use bytes::Bytes;
use futures::Stream;
use std::pin::Pin;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("S3 error: {0}")]
    S3(String),
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
}

#[async_trait]
pub trait DistributedRateLimiter: Send + Sync {
    async fn check_rate_limit(&self, key: &str, limit: u32, window_ms: u64) -> bool;
}
