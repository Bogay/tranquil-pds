use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_s3::Client;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::CompletedMultipartUpload;
use aws_sdk_s3::types::CompletedPart;
use bytes::Bytes;
use futures::Stream;
use sha2::{Digest, Sha256};
use std::pin::Pin;
use thiserror::Error;

const MIN_PART_SIZE: usize = 5 * 1024 * 1024;

#[derive(Error, Debug)]
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
    async fn delete(&self, key: &str) -> Result<(), StorageError>;
    async fn put_stream(
        &self,
        key: &str,
        stream: Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>,
    ) -> Result<StreamUploadResult, StorageError>;
    async fn copy(&self, src_key: &str, dst_key: &str) -> Result<(), StorageError>;
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

    async fn put_stream(
        &self,
        key: &str,
        mut stream: Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>,
    ) -> Result<StreamUploadResult, StorageError> {
        use futures::StreamExt;

        let create_resp = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| StorageError::S3(format!("Failed to create multipart upload: {}", e)))?;

        let upload_id = create_resp
            .upload_id()
            .ok_or_else(|| StorageError::S3("No upload ID returned".to_string()))?
            .to_string();

        let mut hasher = Sha256::new();
        let mut total_size: u64 = 0;
        let mut part_number = 1;
        let mut completed_parts: Vec<CompletedPart> = Vec::new();
        let mut buffer = Vec::with_capacity(MIN_PART_SIZE);

        let upload_part = |client: &Client,
                           bucket: &str,
                           key: &str,
                           upload_id: &str,
                           part_num: i32,
                           data: Vec<u8>|
         -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<CompletedPart, StorageError>> + Send>,
        > {
            let client = client.clone();
            let bucket = bucket.to_string();
            let key = key.to_string();
            let upload_id = upload_id.to_string();
            Box::pin(async move {
                let resp = client
                    .upload_part()
                    .bucket(&bucket)
                    .key(&key)
                    .upload_id(&upload_id)
                    .part_number(part_num)
                    .body(ByteStream::from(data))
                    .send()
                    .await
                    .map_err(|e| StorageError::S3(format!("Failed to upload part: {}", e)))?;

                let etag = resp
                    .e_tag()
                    .ok_or_else(|| StorageError::S3("No ETag returned for part".to_string()))?
                    .to_string();

                Ok(CompletedPart::builder()
                    .part_number(part_num)
                    .e_tag(etag)
                    .build())
            })
        };

        loop {
            match stream.next().await {
                Some(Ok(chunk)) => {
                    hasher.update(&chunk);
                    total_size += chunk.len() as u64;
                    buffer.extend_from_slice(&chunk);

                    if buffer.len() >= MIN_PART_SIZE {
                        let part_data =
                            std::mem::replace(&mut buffer, Vec::with_capacity(MIN_PART_SIZE));
                        let part = upload_part(
                            &self.client,
                            &self.bucket,
                            key,
                            &upload_id,
                            part_number,
                            part_data,
                        )
                        .await?;
                        completed_parts.push(part);
                        part_number += 1;
                    }
                }
                Some(Err(e)) => {
                    let _ = self
                        .client
                        .abort_multipart_upload()
                        .bucket(&self.bucket)
                        .key(key)
                        .upload_id(&upload_id)
                        .send()
                        .await;
                    return Err(StorageError::Io(e));
                }
                None => break,
            }
        }

        if !buffer.is_empty() {
            let part = upload_part(
                &self.client,
                &self.bucket,
                key,
                &upload_id,
                part_number,
                buffer,
            )
            .await?;
            completed_parts.push(part);
        }

        if completed_parts.is_empty() {
            let _ = self
                .client
                .abort_multipart_upload()
                .bucket(&self.bucket)
                .key(key)
                .upload_id(&upload_id)
                .send()
                .await;
            return Err(StorageError::Other("Empty upload".to_string()));
        }

        let completed_upload = CompletedMultipartUpload::builder()
            .set_parts(Some(completed_parts))
            .build();

        self.client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(&upload_id)
            .multipart_upload(completed_upload)
            .send()
            .await
            .map_err(|e| StorageError::S3(format!("Failed to complete multipart upload: {}", e)))?;

        crate::metrics::record_s3_operation("put_stream", "success");

        let hash: [u8; 32] = hasher.finalize().into();
        Ok(StreamUploadResult {
            sha256_hash: hash,
            size: total_size,
        })
    }

    async fn copy(&self, src_key: &str, dst_key: &str) -> Result<(), StorageError> {
        let copy_source = format!("{}/{}", self.bucket, src_key);

        self.client
            .copy_object()
            .bucket(&self.bucket)
            .copy_source(&copy_source)
            .key(dst_key)
            .send()
            .await
            .map_err(|e| StorageError::S3(format!("Failed to copy object: {}", e)))?;

        crate::metrics::record_s3_operation("copy", "success");
        Ok(())
    }
}
