use crate::circuit_breaker::CircuitBreakers;
use crate::config::AuthConfig;
use crate::rate_limit::RateLimiters;
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
    pub rate_limiters: Arc<RateLimiters>,
    pub circuit_breakers: Arc<CircuitBreakers>,
}

impl AppState {
    pub async fn new(db: PgPool) -> Self {
        AuthConfig::init();

        let block_store = PostgresBlockStore::new(db.clone());
        let blob_store = S3BlobStorage::new().await;
        let (firehose_tx, _) = broadcast::channel(1000);
        let rate_limiters = Arc::new(RateLimiters::new());
        let circuit_breakers = Arc::new(CircuitBreakers::new());
        Self {
            db,
            block_store,
            blob_store: Arc::new(blob_store),
            firehose_tx,
            rate_limiters,
            circuit_breakers,
        }
    }

    pub fn with_rate_limiters(mut self, rate_limiters: RateLimiters) -> Self {
        self.rate_limiters = Arc::new(rate_limiters);
        self
    }

    pub fn with_circuit_breakers(mut self, circuit_breakers: CircuitBreakers) -> Self {
        self.circuit_breakers = Arc::new(circuit_breakers);
        self
    }
}
