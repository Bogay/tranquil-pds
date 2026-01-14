use async_trait::async_trait;
use tranquil_types::{AtUri, Nsid};
use uuid::Uuid;

use crate::DbError;

#[derive(Debug, Clone)]
pub struct Backlink {
    pub uri: AtUri,
    pub path: String,
    pub link_to: String,
}

#[async_trait]
pub trait BacklinkRepository: Send + Sync {
    async fn get_backlink_conflicts(
        &self,
        repo_id: Uuid,
        collection: &Nsid,
        backlinks: &[Backlink],
    ) -> Result<Vec<AtUri>, DbError>;

    async fn add_backlinks(&self, repo_id: Uuid, backlinks: &[Backlink]) -> Result<(), DbError>;

    async fn remove_backlinks_by_uri(&self, uri: &AtUri) -> Result<(), DbError>;

    async fn remove_backlinks_by_repo(&self, repo_id: Uuid) -> Result<(), DbError>;
}
