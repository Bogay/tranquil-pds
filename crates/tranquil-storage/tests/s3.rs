#![cfg(feature = "s3")]
use bytes::Bytes;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use s3s::auth::SimpleAuth;
use s3s::dto::{
    AbortMultipartUploadInput, AbortMultipartUploadOutput, CreateMultipartUploadInput,
    CreateMultipartUploadOutput,
};
use s3s::service::S3ServiceBuilder;
use s3s::{S3, S3Request, S3Response, S3Result};
use s3s_fs::FileSystem;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tranquil_storage::{BlobStorage, S3BlobStorage};

const BUCKET: &str = "bucket";
const PREFIX: &str = "prefix";

async fn start_s3() -> (TempDir, S3BlobStorage) {
    start_s3_with(|fs| fs).await
}

async fn start_s3_with<T: S3>(wrap: impl FnOnce(FileSystem) -> T) -> (TempDir, S3BlobStorage) {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join(BUCKET)).unwrap();

    let mut builder = S3ServiceBuilder::new(wrap(FileSystem::new(root.path()).unwrap()));
    builder.set_auth(SimpleAuth::from_single("test", "test"));
    let service = builder.build();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());

    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let conn = ConnBuilder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(socket), service.clone())
                .into_owned();
            tokio::spawn(conn);
        }
    });

    unsafe {
        std::env::set_var("AWS_ACCESS_KEY_ID", "test");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
        std::env::set_var("AWS_REGION", "us-east-1");
    }

    let storage = S3BlobStorage::new(BUCKET, Some(&endpoint), PREFIX).await;
    (root, storage)
}

#[tokio::test]
async fn put_get_head_delete() {
    let (root, storage) = start_s3().await;

    storage
        .put_bytes("key", "hello world".into())
        .await
        .unwrap();

    assert_eq!(storage.get_bytes("key").await.unwrap(), "hello world");
    assert_eq!(storage.get_head("key", 5).await.unwrap(), "hello");
    assert!(root.path().join(BUCKET).join(PREFIX).join("key").is_file());

    storage.delete("key").await.unwrap();
    assert!(storage.get_bytes("key").await.is_err());
}

#[tokio::test]
async fn copy() {
    let (_root, storage) = start_s3().await;

    storage.put_bytes("src", "hello".into()).await.unwrap();
    storage.copy("src", "dst").await.unwrap();

    assert_eq!(storage.get_bytes("dst").await.unwrap(), "hello");
}

#[tokio::test]
async fn put_stream() {
    let (_root, storage) = start_s3().await;
    let chunks = ["hello", " ", "world"].map(|c| Ok(Bytes::from(c)));

    let result = storage
        .put_stream("key", Box::pin(futures::stream::iter(chunks)))
        .await
        .unwrap();

    assert_eq!(result.size, 11);
    assert_eq!(result.sha256_hash[..], Sha256::digest("hello world")[..]);
    assert_eq!(storage.get_bytes("key").await.unwrap(), "hello world");
}

#[tokio::test]
async fn put_stream_error_aborts_upload() {
    let (root, storage) = start_s3().await;
    let chunks = [Ok(Bytes::from("hello")), Err(std::io::Error::other("boom"))];

    let result = storage
        .put_stream("key", Box::pin(futures::stream::iter(chunks)))
        .await;

    assert!(result.is_err());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
}

#[tokio::test]
async fn put_stream_empty_aborts_upload() {
    let (root, storage) = start_s3().await;

    let result = storage
        .put_stream("key", Box::pin(futures::stream::empty()))
        .await;

    assert!(result.is_err());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
}

#[tokio::test]
async fn put_stream_multipart() {
    let (_root, storage) = start_s3().await;
    let chunk = Bytes::from(vec![7u8; 1024 * 1024]);
    let chunks = std::iter::repeat_n(chunk, 6).map(Ok);

    let result = storage
        .put_stream("key", Box::pin(futures::stream::iter(chunks)))
        .await
        .unwrap();

    let expected = vec![7u8; 6 * 1024 * 1024];
    assert_eq!(result.size, expected.len() as u64);
    assert_eq!(result.sha256_hash[..], Sha256::digest(&expected)[..]);
    assert_eq!(storage.get_bytes("key").await.unwrap(), expected);
}

struct FailingUploadPart(FileSystem);

#[async_trait::async_trait]
impl S3 for FailingUploadPart {
    async fn create_multipart_upload(
        &self,
        req: S3Request<CreateMultipartUploadInput>,
    ) -> S3Result<S3Response<CreateMultipartUploadOutput>> {
        self.0.create_multipart_upload(req).await
    }

    async fn abort_multipart_upload(
        &self,
        req: S3Request<AbortMultipartUploadInput>,
    ) -> S3Result<S3Response<AbortMultipartUploadOutput>> {
        self.0.abort_multipart_upload(req).await
    }
}

#[tokio::test]
async fn put_stream_part_failure_aborts_upload() {
    let (root, storage) = start_s3_with(FailingUploadPart).await;
    let chunks = [Ok(Bytes::from("hello"))];

    let result = storage
        .put_stream("key", Box::pin(futures::stream::iter(chunks)))
        .await;

    assert!(result.is_err());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
}
