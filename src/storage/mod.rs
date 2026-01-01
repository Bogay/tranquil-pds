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
        let bucket = std::env::var("S3_BUCKET").expect("S3_BUCKET must be set");
        let client = create_s3_client().await;
        Self { client, bucket }
    }
}

async fn create_s3_client() -> Client {
    let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");

    let config = aws_config::defaults(BehaviorVersion::latest())
        .region(region_provider)
        .load()
        .await;

    if let Ok(endpoint) = std::env::var("S3_ENDPOINT") {
        let s3_config = aws_sdk_s3::config::Builder::from(&config)
            .endpoint_url(endpoint)
            .force_path_style(true)
            .build();
        Client::from_conf(s3_config)
    } else {
        Client::new(&config)
    }
}

pub struct BackupStorage {
    client: Client,
    bucket: String,
}

impl BackupStorage {
    pub async fn new() -> Option<Self> {
        let backup_enabled = std::env::var("BACKUP_ENABLED")
            .map(|v| v != "false" && v != "0")
            .unwrap_or(true);

        if !backup_enabled {
            return None;
        }

        let bucket = std::env::var("BACKUP_S3_BUCKET").ok()?;
        let client = create_s3_client().await;
        Some(Self { client, bucket })
    }

    pub fn retention_count() -> u32 {
        std::env::var("BACKUP_RETENTION_COUNT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(7)
    }

    pub fn interval_secs() -> u64 {
        std::env::var("BACKUP_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(86400)
    }

    pub async fn put_backup(
        &self,
        did: &str,
        rev: &str,
        data: &[u8],
    ) -> Result<String, StorageError> {
        let key = format!("{}/{}.car", did, rev);
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(ByteStream::from(Bytes::copy_from_slice(data)))
            .send()
            .await
            .map_err(|e| {
                crate::metrics::record_s3_operation("backup_put", "error");
                StorageError::S3(e.to_string())
            })?;

        crate::metrics::record_s3_operation("backup_put", "success");
        Ok(key)
    }

    pub async fn get_backup(&self, storage_key: &str) -> Result<Bytes, StorageError> {
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(storage_key)
            .send()
            .await
            .map_err(|e| {
                crate::metrics::record_s3_operation("backup_get", "error");
                StorageError::S3(e.to_string())
            })?;

        let data = resp
            .body
            .collect()
            .await
            .map_err(|e| {
                crate::metrics::record_s3_operation("backup_get", "error");
                StorageError::S3(e.to_string())
            })?
            .into_bytes();

        crate::metrics::record_s3_operation("backup_get", "success");
        Ok(data)
    }

    pub async fn delete_backup(&self, storage_key: &str) -> Result<(), StorageError> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(storage_key)
            .send()
            .await
            .map_err(|e| {
                crate::metrics::record_s3_operation("backup_delete", "error");
                StorageError::S3(e.to_string())
            })?;

        crate::metrics::record_s3_operation("backup_delete", "success");
        Ok(())
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
