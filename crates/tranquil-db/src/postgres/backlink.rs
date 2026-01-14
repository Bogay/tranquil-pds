use async_trait::async_trait;
use sqlx::PgPool;
use tranquil_db_traits::{Backlink, BacklinkRepository, DbError};
use tranquil_types::{AtUri, Nsid};
use uuid::Uuid;

use super::user::map_sqlx_error;

pub struct PostgresBacklinkRepository {
    pool: PgPool,
}

impl PostgresBacklinkRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl BacklinkRepository for PostgresBacklinkRepository {
    async fn get_backlink_conflicts(
        &self,
        repo_id: Uuid,
        collection: &Nsid,
        backlinks: &[Backlink],
    ) -> Result<Vec<AtUri>, DbError> {
        if backlinks.is_empty() {
            return Ok(Vec::new());
        }

        let paths: Vec<&str> = backlinks.iter().map(|b| b.path.as_str()).collect();
        let link_tos: Vec<&str> = backlinks.iter().map(|b| b.link_to.as_str()).collect();
        let collection_pattern = format!("%/{}/%", collection.as_str());

        let results = sqlx::query_scalar!(
            r#"
            SELECT DISTINCT uri
            FROM backlinks
            WHERE repo_id = $1
              AND uri LIKE $4
              AND (path, link_to) IN (SELECT unnest($2::text[]), unnest($3::text[]))
            "#,
            repo_id,
            &paths as &[&str],
            &link_tos as &[&str],
            collection_pattern
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(results.into_iter().map(Into::into).collect())
    }

    async fn add_backlinks(&self, repo_id: Uuid, backlinks: &[Backlink]) -> Result<(), DbError> {
        if backlinks.is_empty() {
            return Ok(());
        }

        let uris: Vec<&str> = backlinks.iter().map(|b| b.uri.as_str()).collect();
        let paths: Vec<&str> = backlinks.iter().map(|b| b.path.as_str()).collect();
        let link_tos: Vec<&str> = backlinks.iter().map(|b| b.link_to.as_str()).collect();

        sqlx::query!(
            r#"
            INSERT INTO backlinks (uri, path, link_to, repo_id)
            SELECT unnest($1::text[]), unnest($2::text[]), unnest($3::text[]), $4
            ON CONFLICT (uri, path) DO NOTHING
            "#,
            &uris as &[&str],
            &paths as &[&str],
            &link_tos as &[&str],
            repo_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn remove_backlinks_by_uri(&self, uri: &AtUri) -> Result<(), DbError> {
        sqlx::query!("DELETE FROM backlinks WHERE uri = $1", uri.as_str())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn remove_backlinks_by_repo(&self, repo_id: Uuid) -> Result<(), DbError> {
        sqlx::query!("DELETE FROM backlinks WHERE repo_id = $1", repo_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(())
    }
}
