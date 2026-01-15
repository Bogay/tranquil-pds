use async_trait::async_trait;
use sqlx::PgPool;
use sqlx::postgres::PgListener;
use tranquil_db_traits::{DbError, RepoEventNotifier, RepoEventReceiver};

use super::user::map_sqlx_error;

pub struct PostgresRepoEventNotifier {
    pool: PgPool,
}

impl PostgresRepoEventNotifier {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RepoEventNotifier for PostgresRepoEventNotifier {
    async fn subscribe(&self) -> Result<Box<dyn RepoEventReceiver>, DbError> {
        let mut listener = PgListener::connect_with(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        listener
            .listen("repo_updates")
            .await
            .map_err(map_sqlx_error)?;
        Ok(Box::new(PostgresRepoEventReceiver { listener }))
    }
}

pub struct PostgresRepoEventReceiver {
    listener: PgListener,
}

#[async_trait]
impl RepoEventReceiver for PostgresRepoEventReceiver {
    async fn recv(&mut self) -> Option<i64> {
        match self.listener.recv().await {
            Ok(notification) => notification.payload().parse().ok(),
            Err(_) => None,
        }
    }
}
