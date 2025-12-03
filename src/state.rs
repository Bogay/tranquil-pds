use sqlx::PgPool;
use crate::repo::PostgresBlockStore;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub block_store: PostgresBlockStore,
}

impl AppState {
    pub fn new(db: PgPool) -> Self {
        let block_store = PostgresBlockStore::new(db.clone());
        Self { db, block_store }
    }
}
