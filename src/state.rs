use crate::repo::PostgresBlockStore;
use crate::storage::{BlobStorage, S3BlobStorage};
use crate::sync::firehose::SequencedEvent;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub block_store: PostgresBlockStore,
    pub blob_store: Arc<dyn BlobStorage>,
    pub firehose_tx: broadcast::Sender<SequencedEvent>,
}

impl AppState {
    pub async fn new(db: PgPool) -> Self {
        let block_store = PostgresBlockStore::new(db.clone());
        let blob_store = S3BlobStorage::new().await;
        let (firehose_tx, _) = broadcast::channel(1000);
        Self {
            db,
            block_store,
            blob_store: Arc::new(blob_store),
            firehose_tx,
        }
    }
}
