pub use tranquil_infra::{
    BackupStorage, BlobStorage, StorageError, StreamUploadResult, backup_interval_secs,
    backup_retention_count,
};

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
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

const MIN_PART_SIZE: usize = 5 * 1024 * 1024;
const EXDEV: i32 = 18;
const CID_SHARD_PREFIX_LEN: usize = 9;

fn split_cid_path(key: &str) -> Option<(&str, &str)> {
    let is_cid = key.get(..3).map_or(false, |p| p.eq_ignore_ascii_case("baf"));
    (key.len() > CID_SHARD_PREFIX_LEN && is_cid)
        .then(|| key.split_at(CID_SHARD_PREFIX_LEN))
}

fn validate_key(key: &str) -> Result<(), StorageError> {
    let dominated_by_traversal = key
        .split('/')
        .filter(|seg| !seg.is_empty())
        .try_fold(0i32, |depth, segment| match segment {
            ".." => {
                let new_depth = depth - 1;
                (new_depth >= 0).then_some(new_depth)
            }
            "." => Some(depth),
            _ => Some(depth + 1),
        })
        .is_none();

    let has_null = key.contains('\0');
    let is_absolute = key.starts_with('/');

    match (dominated_by_traversal, has_null, is_absolute) {
        (true, _, _) => Err(StorageError::Other(format!(
            "Path traversal detected in key: {}",
            key
        ))),
        (_, true, _) => Err(StorageError::Other(format!(
            "Null byte in key: {}",
            key.replace('\0', "\\0")
        ))),
        (_, _, true) => Err(StorageError::Other(format!(
            "Absolute path not allowed: {}",
            key
        ))),
        _ => Ok(()),
    }
}

async fn cleanup_orphaned_tmp_files(tmp_path: &Path) {
    let tmp_path = tmp_path.to_path_buf();
    let cleaned = tokio::task::spawn_blocking(move || {
        std::fs::read_dir(&tmp_path)
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .filter(|e| e.path().is_file())
            .filter_map(|entry| std::fs::remove_file(entry.path()).ok())
            .count()
    })
    .await
    .unwrap_or(0);

    if cleaned > 0 {
        tracing::info!(
            count = cleaned,
            "Cleaned orphaned tmp files from previous run"
        );
    }
}

async fn rename_with_fallback(src: &Path, dst: &Path) -> Result<(), StorageError> {
    match tokio::fs::rename(src, dst).await {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(EXDEV) => {
            tokio::fs::copy(src, dst).await?;
            tokio::fs::File::open(dst).await?.sync_all().await?;
            let _ = tokio::fs::remove_file(src).await;
            Ok(())
        }
        Err(e) => Err(StorageError::Io(e)),
    }
}

async fn ensure_parent_dir(path: &Path) -> Result<(), StorageError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    Ok(())
}

fn map_io_not_found(key: &str) -> impl FnOnce(std::io::Error) -> StorageError + '_ {
    |e| match e.kind() {
        std::io::ErrorKind::NotFound => StorageError::NotFound(key.to_string()),
        _ => StorageError::Io(e),
    }
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

    pub async fn with_bucket(bucket: String) -> Self {
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

    std::env::var("S3_ENDPOINT").ok().map_or_else(
        || Client::new(&config),
        |endpoint| {
            let s3_config = aws_sdk_s3::config::Builder::from(&config)
                .endpoint_url(endpoint)
                .force_path_style(true)
                .build();
            Client::from_conf(s3_config)
        },
    )
}

pub struct S3BackupStorage {
    client: Client,
    bucket: String,
}

impl S3BackupStorage {
    pub async fn new() -> Option<Self> {
        let bucket = std::env::var("BACKUP_S3_BUCKET").ok()?;
        let client = create_s3_client().await;
        Some(Self { client, bucket })
    }
}

#[async_trait]
impl BackupStorage for S3BackupStorage {
    async fn put_backup(&self, did: &str, rev: &str, data: &[u8]) -> Result<String, StorageError> {
        let key = format!("{}/{}.car", did, rev);
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(ByteStream::from(Bytes::copy_from_slice(data)))
            .send()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;

        Ok(key)
    }

    async fn get_backup(&self, storage_key: &str) -> Result<Bytes, StorageError> {
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(storage_key)
            .send()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;

        resp.body
            .collect()
            .await
            .map(|agg| agg.into_bytes())
            .map_err(|e| StorageError::Backend(e.to_string()))
    }

    async fn delete_backup(&self, storage_key: &str) -> Result<(), StorageError> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(storage_key)
            .send()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;

        Ok(())
    }
}

#[async_trait]
impl BlobStorage for S3BlobStorage {
    async fn put(&self, key: &str, data: &[u8]) -> Result<(), StorageError> {
        self.put_bytes(key, Bytes::copy_from_slice(data)).await
    }

    async fn put_bytes(&self, key: &str, data: Bytes) -> Result<(), StorageError> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(data))
            .send()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;

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
            .map_err(|e| StorageError::Backend(e.to_string()))?;

        resp.body
            .collect()
            .await
            .map(|agg| agg.into_bytes())
            .map_err(|e| StorageError::Backend(e.to_string()))
    }

    async fn get_head(&self, key: &str, size: usize) -> Result<Bytes, StorageError> {
        let range = format!("bytes=0-{}", size.saturating_sub(1));
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .range(range)
            .send()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;

        resp.body
            .collect()
            .await
            .map(|agg| agg.into_bytes())
            .map_err(|e| StorageError::Backend(e.to_string()))
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn put_stream(
        &self,
        key: &str,
        stream: Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>,
    ) -> Result<StreamUploadResult, StorageError> {
        use futures::StreamExt;

        let create_resp = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| {
                StorageError::Backend(format!("Failed to create multipart upload: {}", e))
            })?;

        let upload_id = create_resp
            .upload_id()
            .ok_or_else(|| StorageError::Backend("No upload ID returned".to_string()))?
            .to_string();

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
                    .map_err(|e| StorageError::Backend(format!("Failed to upload part: {}", e)))?;

                let etag = resp
                    .e_tag()
                    .ok_or_else(|| StorageError::Backend("No ETag returned for part".to_string()))?
                    .to_string();

                Ok(CompletedPart::builder()
                    .part_number(part_num)
                    .e_tag(etag)
                    .build())
            })
        };

        struct UploadState {
            hasher: Sha256,
            total_size: u64,
            part_number: i32,
            completed_parts: Vec<CompletedPart>,
            buffer: Vec<u8>,
        }

        let initial_state = UploadState {
            hasher: Sha256::new(),
            total_size: 0,
            part_number: 1,
            completed_parts: Vec::new(),
            buffer: Vec::with_capacity(MIN_PART_SIZE),
        };

        let abort_upload = || async {
            let _ = self
                .client
                .abort_multipart_upload()
                .bucket(&self.bucket)
                .key(key)
                .upload_id(&upload_id)
                .send()
                .await;
        };

        let result: Result<UploadState, StorageError> = {
            let mut state = initial_state;

            let chunk_results: Vec<Result<Bytes, std::io::Error>> = stream.collect().await;

            for chunk_result in chunk_results {
                match chunk_result {
                    Ok(chunk) => {
                        state.hasher.update(&chunk);
                        state.total_size += chunk.len() as u64;
                        state.buffer.extend_from_slice(&chunk);

                        if state.buffer.len() >= MIN_PART_SIZE {
                            let part_data = std::mem::replace(
                                &mut state.buffer,
                                Vec::with_capacity(MIN_PART_SIZE),
                            );
                            let part = upload_part(
                                &self.client,
                                &self.bucket,
                                key,
                                &upload_id,
                                state.part_number,
                                part_data,
                            )
                            .await?;
                            state.completed_parts.push(part);
                            state.part_number += 1;
                        }
                    }
                    Err(e) => {
                        abort_upload().await;
                        return Err(StorageError::Io(e));
                    }
                }
            }

            Ok(state)
        };

        let mut state = result?;

        if !state.buffer.is_empty() {
            let part = upload_part(
                &self.client,
                &self.bucket,
                key,
                &upload_id,
                state.part_number,
                std::mem::take(&mut state.buffer),
            )
            .await?;
            state.completed_parts.push(part);
        }

        if state.completed_parts.is_empty() {
            abort_upload().await;
            return Err(StorageError::Other("Empty upload".to_string()));
        }

        let completed_upload = CompletedMultipartUpload::builder()
            .set_parts(Some(state.completed_parts))
            .build();

        self.client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(&upload_id)
            .multipart_upload(completed_upload)
            .send()
            .await
            .map_err(|e| {
                StorageError::Backend(format!("Failed to complete multipart upload: {}", e))
            })?;

        let hash: [u8; 32] = state.hasher.finalize().into();
        Ok(StreamUploadResult {
            sha256_hash: hash,
            size: state.total_size,
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
            .map_err(|e| StorageError::Backend(format!("Failed to copy object: {}", e)))?;

        Ok(())
    }
}

pub struct FilesystemBlobStorage {
    base_path: PathBuf,
    tmp_path: PathBuf,
}

impl FilesystemBlobStorage {
    pub async fn new(base_path: impl Into<PathBuf>) -> Result<Self, StorageError> {
        let base_path = base_path.into();
        let tmp_path = base_path.join(".tmp");
        tokio::fs::create_dir_all(&base_path).await?;
        tokio::fs::create_dir_all(&tmp_path).await?;
        cleanup_orphaned_tmp_files(&tmp_path).await;
        Ok(Self {
            base_path,
            tmp_path,
        })
    }

    pub async fn from_env() -> Result<Self, StorageError> {
        let path = std::env::var("BLOB_STORAGE_PATH")
            .map_err(|_| StorageError::Other("BLOB_STORAGE_PATH not set".into()))?;
        Self::new(path).await
    }

    fn resolve_path(&self, key: &str) -> Result<PathBuf, StorageError> {
        validate_key(key)?;
        Ok(split_cid_path(key).map_or_else(
            || self.base_path.join(key),
            |(dir, file)| self.base_path.join(dir).join(file),
        ))
    }

    async fn atomic_write(&self, path: &Path, data: &[u8]) -> Result<(), StorageError> {
        use tokio::io::AsyncWriteExt;

        let tmp_file_name = uuid::Uuid::new_v4().to_string();
        let tmp_path = self.tmp_path.join(&tmp_file_name);

        let mut file = tokio::fs::File::create(&tmp_path).await?;
        file.write_all(data).await?;
        file.sync_all().await?;
        drop(file);

        rename_with_fallback(&tmp_path, path).await
    }
}

#[async_trait]
impl BlobStorage for FilesystemBlobStorage {
    async fn put(&self, key: &str, data: &[u8]) -> Result<(), StorageError> {
        let path = self.resolve_path(key)?;
        ensure_parent_dir(&path).await?;
        self.atomic_write(&path, data).await
    }

    async fn put_bytes(&self, key: &str, data: Bytes) -> Result<(), StorageError> {
        self.put(key, &data).await
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        let path = self.resolve_path(key)?;
        tokio::fs::read(&path).await.map_err(map_io_not_found(key))
    }

    async fn get_bytes(&self, key: &str) -> Result<Bytes, StorageError> {
        self.get(key).await.map(Bytes::from)
    }

    async fn get_head(&self, key: &str, size: usize) -> Result<Bytes, StorageError> {
        use tokio::io::AsyncReadExt;
        let path = self.resolve_path(key)?;
        let mut file = tokio::fs::File::open(&path)
            .await
            .map_err(map_io_not_found(key))?;
        let mut buffer = vec![0u8; size];
        let n = file.read(&mut buffer).await?;
        buffer.truncate(n);
        Ok(Bytes::from(buffer))
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let path = self.resolve_path(key)?;
        tokio::fs::remove_file(&path).await.or_else(|e| {
            (e.kind() == std::io::ErrorKind::NotFound)
                .then_some(())
                .ok_or(StorageError::Io(e))
        })
    }

    async fn put_stream(
        &self,
        key: &str,
        stream: Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>,
    ) -> Result<StreamUploadResult, StorageError> {
        use futures::TryStreamExt;
        use tokio::io::AsyncWriteExt;

        let tmp_file_name = uuid::Uuid::new_v4().to_string();
        let tmp_path = self.tmp_path.join(&tmp_file_name);
        let final_path = self.resolve_path(key)?;
        ensure_parent_dir(&final_path).await?;

        let file = tokio::fs::File::create(&tmp_path).await?;

        struct StreamState {
            file: tokio::fs::File,
            hasher: Sha256,
            total_size: u64,
        }

        let initial = StreamState {
            file,
            hasher: Sha256::new(),
            total_size: 0,
        };

        let final_state = stream
            .map_err(StorageError::Io)
            .try_fold(initial, |mut state, chunk| async move {
                state.hasher.update(&chunk);
                state.total_size += chunk.len() as u64;
                state.file.write_all(&chunk).await?;
                Ok(state)
            })
            .await?;

        final_state.file.sync_all().await?;
        drop(final_state.file);

        rename_with_fallback(&tmp_path, &final_path).await?;

        let hash: [u8; 32] = final_state.hasher.finalize().into();
        Ok(StreamUploadResult {
            sha256_hash: hash,
            size: final_state.total_size,
        })
    }

    async fn copy(&self, src_key: &str, dst_key: &str) -> Result<(), StorageError> {
        let src_path = self.resolve_path(src_key)?;
        let dst_path = self.resolve_path(dst_key)?;
        ensure_parent_dir(&dst_path).await?;
        tokio::fs::copy(&src_path, &dst_path)
            .await
            .map_err(map_io_not_found(src_key))?;
        tokio::fs::File::open(&dst_path).await?.sync_all().await?;
        Ok(())
    }
}

pub struct FilesystemBackupStorage {
    base_path: PathBuf,
    tmp_path: PathBuf,
}

impl FilesystemBackupStorage {
    pub async fn new(base_path: impl Into<PathBuf>) -> Result<Self, StorageError> {
        let base_path = base_path.into();
        let tmp_path = base_path.join(".tmp");
        tokio::fs::create_dir_all(&base_path).await?;
        tokio::fs::create_dir_all(&tmp_path).await?;
        cleanup_orphaned_tmp_files(&tmp_path).await;
        Ok(Self {
            base_path,
            tmp_path,
        })
    }

    pub async fn from_env() -> Result<Self, StorageError> {
        let path = std::env::var("BACKUP_STORAGE_PATH")
            .map_err(|_| StorageError::Other("BACKUP_STORAGE_PATH not set".into()))?;
        Self::new(path).await
    }

    fn resolve_path(&self, key: &str) -> Result<PathBuf, StorageError> {
        validate_key(key)?;
        Ok(self.base_path.join(key))
    }
}

#[async_trait]
impl BackupStorage for FilesystemBackupStorage {
    async fn put_backup(&self, did: &str, rev: &str, data: &[u8]) -> Result<String, StorageError> {
        use tokio::io::AsyncWriteExt;

        let key = format!("{}/{}.car", did, rev);
        let final_path = self.resolve_path(&key)?;
        ensure_parent_dir(&final_path).await?;

        let tmp_file_name = uuid::Uuid::new_v4().to_string();
        let tmp_path = self.tmp_path.join(&tmp_file_name);

        let mut file = tokio::fs::File::create(&tmp_path).await?;
        file.write_all(data).await?;
        file.sync_all().await?;
        drop(file);

        rename_with_fallback(&tmp_path, &final_path).await?;
        Ok(key)
    }

    async fn get_backup(&self, storage_key: &str) -> Result<Bytes, StorageError> {
        let path = self.resolve_path(storage_key)?;
        tokio::fs::read(&path)
            .await
            .map(Bytes::from)
            .map_err(map_io_not_found(storage_key))
    }

    async fn delete_backup(&self, storage_key: &str) -> Result<(), StorageError> {
        let path = self.resolve_path(storage_key)?;
        tokio::fs::remove_file(&path).await.or_else(|e| {
            (e.kind() == std::io::ErrorKind::NotFound)
                .then_some(())
                .ok_or(StorageError::Io(e))
        })
    }
}

pub async fn create_blob_storage() -> Arc<dyn BlobStorage> {
    let backend = std::env::var("BLOB_STORAGE_BACKEND").unwrap_or_else(|_| "filesystem".into());

    match backend.as_str() {
        "s3" => {
            tracing::info!("Initializing S3 blob storage");
            Arc::new(S3BlobStorage::new().await)
        }
        _ => {
            tracing::info!("Initializing filesystem blob storage");
            FilesystemBlobStorage::from_env()
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "Failed to initialize filesystem blob storage: {}. \
                     Set BLOB_STORAGE_PATH to a valid directory path.",
                        e
                    );
                })
                .pipe(Arc::new)
        }
    }
}

pub async fn create_backup_storage() -> Option<Arc<dyn BackupStorage>> {
    let enabled = std::env::var("BACKUP_ENABLED")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true);

    if !enabled {
        tracing::info!("Backup storage disabled via BACKUP_ENABLED=false");
        return None;
    }

    let backend = std::env::var("BACKUP_STORAGE_BACKEND").unwrap_or_else(|_| "filesystem".into());

    match backend.as_str() {
        "s3" => S3BackupStorage::new().await.map_or_else(
            || {
                tracing::error!(
                    "BACKUP_STORAGE_BACKEND=s3 but BACKUP_S3_BUCKET is not set. \
                     Backups will be disabled."
                );
                None
            },
            |storage| {
                tracing::info!("Initialized S3 backup storage");
                Some(Arc::new(storage) as Arc<dyn BackupStorage>)
            },
        ),
        _ => FilesystemBackupStorage::from_env().await.map_or_else(
            |e| {
                tracing::error!(
                    "Failed to initialize filesystem backup storage: {}. \
                     Set BACKUP_STORAGE_PATH to a valid directory path. \
                     Backups will be disabled.",
                    e
                );
                None
            },
            |storage| {
                tracing::info!("Initialized filesystem backup storage");
                Some(Arc::new(storage) as Arc<dyn BackupStorage>)
            },
        ),
    }
}

trait Pipe: Sized {
    fn pipe<F, R>(self, f: F) -> R
    where
        F: FnOnce(Self) -> R,
    {
        f(self)
    }
}

impl<T> Pipe for T {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_path_from_raw_blob_cid() {
        let cid = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku";
        assert_eq!(
            split_cid_path(cid),
            Some(("bafkreihd", "wdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"))
        );
    }

    #[test]
    fn split_path_from_dag_cbor_cid() {
        let cid = "bafyreigdmqpykrgxyaxtlafqpqhzrb7qy2rh75nldvfd4tucqmqqme5yje";
        assert_eq!(
            split_cid_path(cid),
            Some(("bafyreigd", "mqpykrgxyaxtlafqpqhzrb7qy2rh75nldvfd4tucqmqqme5yje"))
        );
    }

    #[test]
    fn no_split_for_temp_keys() {
        assert_eq!(split_cid_path("temp/abc123"), None);
    }

    #[test]
    fn no_split_for_short_keys() {
        assert_eq!(split_cid_path("bafkreihd"), None);
        assert_eq!(split_cid_path("bafkrei"), None);
        assert_eq!(split_cid_path("baf"), None);
        assert_eq!(split_cid_path("ba"), None);
        assert_eq!(split_cid_path(""), None);
    }

    #[test]
    fn no_split_for_non_cid_keys() {
        assert_eq!(split_cid_path("something/else/entirely"), None);
        assert_eq!(split_cid_path("Qmabcdefghijklmnop"), None);
    }

    #[test]
    fn split_cid_case_insensitive() {
        let upper = "BAFKREIHDWDCEFGH4DQKJV67UZCMW7OJEE6XEDZDETOJUZJEVTENXQUVYKU";
        let mixed = "BaFkReIhDwDcEfGh4DqKjV67UzCmW7OjEe6XeDzDeTojUzJevTeNxQuVyKu";
        assert_eq!(
            split_cid_path(upper),
            Some(("BAFKREIHD", "WDCEFGH4DQKJV67UZCMW7OJEE6XEDZDETOJUZJEVTENXQUVYKU"))
        );
        assert_eq!(
            split_cid_path(mixed),
            Some(("BaFkReIhD", "wDcEfGh4DqKjV67UzCmW7OjEe6XeDzDeTojUzJevTeNxQuVyKu"))
        );
    }

    #[test]
    fn split_at_minimum_length() {
        let cid = "bafkreihdx";
        assert_eq!(split_cid_path(cid), Some(("bafkreihd", "x")));
    }

    #[test]
    fn resolve_path_shards_cid_keys() {
        let base = PathBuf::from("/blobs");
        let cid = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku";

        let expected = PathBuf::from("/blobs/bafkreihd/wdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku");
        let result = split_cid_path(cid).map_or_else(
            || base.join(cid),
            |(dir, file)| base.join(dir).join(file),
        );
        assert_eq!(result, expected);
    }

    #[test]
    fn resolve_path_no_shard_for_temp() {
        let base = PathBuf::from("/blobs");
        let key = "temp/abc123";

        let expected = PathBuf::from("/blobs/temp/abc123");
        let result = split_cid_path(key).map_or_else(
            || base.join(key),
            |(dir, file)| base.join(dir).join(file),
        );
        assert_eq!(result, expected);
    }
}
