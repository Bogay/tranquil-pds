pub use tranquil_storage::{
    BackupStorage, BlobStorage, FilesystemBackupStorage, FilesystemBlobStorage, StorageError,
    StreamUploadResult, backup_interval_secs, backup_retention_count, create_backup_storage,
    create_blob_storage,
};

#[cfg(feature = "s3-storage")]
pub use tranquil_storage::{S3BackupStorage, S3BlobStorage};
