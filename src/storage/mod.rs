use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_s3::Client;
use aws_sdk_s3::primitives::ByteStream;
use bytes::Bytes;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("S3 error: {0}")]
    S3(String),
    #[error("Other: {0}")]
    Other(String),
}

#[async_trait]
pub trait BlobStorage: Send + Sync {
    async fn put(&self, key: &str, data: &[u8]) -> Result<(), StorageError>;
    async fn put_bytes(&self, key: &str, data: Bytes) -> Result<(), StorageError>;
    async fn get(&self, key: &str) -> Result<Vec<u8>, StorageError>;
    async fn get_bytes(&self, key: &str) -> Result<Bytes, StorageError>;
    async fn delete(&self, key: &str) -> Result<(), StorageError>;
}

pub struct S3BlobStorage {
    client: Client,
    bucket: String,
}

impl S3BlobStorage {
    pub async fn new() -> Self {
        let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");

        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(region_provider)
            .load()
            .await;

        let bucket = std::env::var("S3_BUCKET").expect("S3_BUCKET must be set");

        let client = if let Ok(endpoint) = std::env::var("S3_ENDPOINT") {
            let s3_config = aws_sdk_s3::config::Builder::from(&config)
                .endpoint_url(endpoint)
                .force_path_style(true)
                .build();
            Client::from_conf(s3_config)
        } else {
            Client::new(&config)
        };

        Self { client, bucket }
    }
}

#[async_trait]
impl BlobStorage for S3BlobStorage {
    async fn put(&self, key: &str, data: &[u8]) -> Result<(), StorageError> {
        self.put_bytes(key, Bytes::copy_from_slice(data)).await
    }

    async fn put_bytes(&self, key: &str, data: Bytes) -> Result<(), StorageError> {
        let result = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(data))
            .send()
            .await
            .map_err(|e| StorageError::S3(e.to_string()));

        match &result {
            Ok(_) => crate::metrics::record_s3_operation("put", "success"),
            Err(_) => crate::metrics::record_s3_operation("put", "error"),
        }

        result?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        self.get_bytes(key).await.map(|b| b.to_vec())
    }

    async fn get_bytes(&self, key: &str) -> Result<Bytes, StorageError> {
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| {
                crate::metrics::record_s3_operation("get", "error");
                StorageError::S3(e.to_string())
            })?;

        let data = resp
            .body
            .collect()
            .await
            .map_err(|e| {
                crate::metrics::record_s3_operation("get", "error");
                StorageError::S3(e.to_string())
            })?
            .into_bytes();

        crate::metrics::record_s3_operation("get", "success");
        Ok(data)
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let result = self
            .client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| StorageError::S3(e.to_string()));

        match &result {
            Ok(_) => crate::metrics::record_s3_operation("delete", "success"),
            Err(_) => crate::metrics::record_s3_operation("delete", "error"),
        }

        result?;
        Ok(())
    }
}
