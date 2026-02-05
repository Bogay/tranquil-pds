use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tranquil_db_traits::{
    AccountStatus, BrokenGenesisCommit, CommitEventData, DbError, EventBlocksCids, FullRecordInfo,
    ImportBlock, ImportRecord, ImportRepoError, RecordInfo, RecordWithTakedown, RepoAccountInfo,
    RepoEventType, RepoInfo, RepoListItem, RepoRepository, RepoWithoutRev, SequenceNumber,
    SequencedEvent, UserNeedingRecordBlobsBackfill, UserWithoutBlocks,
};
use tranquil_types::{AtUri, CidLink, Did, Handle, Nsid, Rkey};
use uuid::Uuid;

use super::user::map_sqlx_error;

struct RecordRow {
    rkey: String,
    record_cid: String,
}

struct SequencedEventRow {
    seq: i64,
    did: String,
    created_at: DateTime<Utc>,
    event_type: RepoEventType,
    commit_cid: Option<String>,
    prev_cid: Option<String>,
    prev_data_cid: Option<String>,
    ops: Option<serde_json::Value>,
    blobs: Option<Vec<String>>,
    blocks_cids: Option<Vec<String>>,
    handle: Option<String>,
    active: Option<bool>,
    status: Option<String>,
    rev: Option<String>,
}

pub struct PostgresRepoRepository {
    pool: PgPool,
}

impl PostgresRepoRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RepoRepository for PostgresRepoRepository {
    async fn create_repo(
        &self,
        user_id: Uuid,
        repo_root_cid: &CidLink,
        repo_rev: &str,
    ) -> Result<(), DbError> {
        sqlx::query!(
            "INSERT INTO repos (user_id, repo_root_cid, repo_rev) VALUES ($1, $2, $3)",
            user_id,
            repo_root_cid.as_str(),
            repo_rev
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn update_repo_root(
        &self,
        user_id: Uuid,
        repo_root_cid: &CidLink,
        repo_rev: &str,
    ) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE repos SET repo_root_cid = $1, repo_rev = $2, updated_at = NOW() WHERE user_id = $3",
            repo_root_cid.as_str(),
            repo_rev,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn update_repo_rev(&self, user_id: Uuid, repo_rev: &str) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE repos SET repo_rev = $1 WHERE user_id = $2",
            repo_rev,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn delete_repo(&self, user_id: Uuid) -> Result<(), DbError> {
        sqlx::query!("DELETE FROM repos WHERE user_id = $1", user_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn get_repo_root_for_update(&self, user_id: Uuid) -> Result<Option<CidLink>, DbError> {
        let result = sqlx::query_scalar!(
            "SELECT repo_root_cid FROM repos WHERE user_id = $1 FOR UPDATE NOWAIT",
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.map(CidLink::from))
    }

    async fn get_repo(&self, user_id: Uuid) -> Result<Option<RepoInfo>, DbError> {
        let row = sqlx::query!(
            "SELECT user_id, repo_root_cid, repo_rev FROM repos WHERE user_id = $1",
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| RepoInfo {
            user_id: r.user_id,
            repo_root_cid: CidLink::from(r.repo_root_cid),
            repo_rev: r.repo_rev,
        }))
    }

    async fn get_repo_root_by_did(&self, did: &Did) -> Result<Option<CidLink>, DbError> {
        let result = sqlx::query_scalar!(
            "SELECT r.repo_root_cid FROM repos r JOIN users u ON r.user_id = u.id WHERE u.did = $1",
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.map(CidLink::from))
    }

    async fn count_repos(&self) -> Result<i64, DbError> {
        let count = sqlx::query_scalar!(r#"SELECT COUNT(*) as "count!" FROM repos"#)
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(count)
    }

    async fn get_repos_without_rev(&self) -> Result<Vec<RepoWithoutRev>, DbError> {
        let rows = sqlx::query!("SELECT user_id, repo_root_cid FROM repos WHERE repo_rev IS NULL")
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(rows
            .into_iter()
            .map(|r| RepoWithoutRev {
                user_id: r.user_id,
                repo_root_cid: CidLink::from(r.repo_root_cid),
            })
            .collect())
    }

    async fn upsert_records(
        &self,
        repo_id: Uuid,
        collections: &[Nsid],
        rkeys: &[Rkey],
        record_cids: &[CidLink],
        repo_rev: &str,
    ) -> Result<(), DbError> {
        let collections_str: Vec<&str> = collections.iter().map(|c| c.as_str()).collect();
        let rkeys_str: Vec<&str> = rkeys.iter().map(|r| r.as_str()).collect();
        let cids_str: Vec<&str> = record_cids.iter().map(|c| c.as_str()).collect();

        sqlx::query!(
            r#"
            INSERT INTO records (repo_id, collection, rkey, record_cid, repo_rev)
            SELECT $1, collection, rkey, record_cid, $5
            FROM UNNEST($2::text[], $3::text[], $4::text[]) AS t(collection, rkey, record_cid)
            ON CONFLICT (repo_id, collection, rkey) DO UPDATE
            SET record_cid = EXCLUDED.record_cid, repo_rev = EXCLUDED.repo_rev, created_at = NOW()
            "#,
            repo_id,
            &collections_str as &[&str],
            &rkeys_str as &[&str],
            &cids_str as &[&str],
            repo_rev
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn delete_records(
        &self,
        repo_id: Uuid,
        collections: &[Nsid],
        rkeys: &[Rkey],
    ) -> Result<(), DbError> {
        let collections_str: Vec<&str> = collections.iter().map(|c| c.as_str()).collect();
        let rkeys_str: Vec<&str> = rkeys.iter().map(|r| r.as_str()).collect();

        sqlx::query!(
            r#"
            DELETE FROM records
            WHERE repo_id = $1
            AND (collection, rkey) IN (SELECT * FROM UNNEST($2::text[], $3::text[]))
            "#,
            repo_id,
            &collections_str as &[&str],
            &rkeys_str as &[&str]
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn delete_all_records(&self, repo_id: Uuid) -> Result<(), DbError> {
        sqlx::query!("DELETE FROM records WHERE repo_id = $1", repo_id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn get_record_cid(
        &self,
        repo_id: Uuid,
        collection: &Nsid,
        rkey: &Rkey,
    ) -> Result<Option<CidLink>, DbError> {
        let result = sqlx::query_scalar!(
            "SELECT record_cid FROM records WHERE repo_id = $1 AND collection = $2 AND rkey = $3",
            repo_id,
            collection.as_str(),
            rkey.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(result.map(CidLink::from))
    }

    async fn list_records(
        &self,
        repo_id: Uuid,
        collection: &Nsid,
        cursor: Option<&Rkey>,
        limit: i64,
        reverse: bool,
        rkey_start: Option<&Rkey>,
        rkey_end: Option<&Rkey>,
    ) -> Result<Vec<RecordInfo>, DbError> {
        let to_record_info = |rows: Vec<RecordRow>| {
            rows.into_iter()
                .map(|r| RecordInfo {
                    rkey: Rkey::from(r.rkey),
                    record_cid: CidLink::from(r.record_cid),
                })
                .collect()
        };

        let collection_str = collection.as_str();

        if let Some(cursor_val) = cursor {
            let cursor_str = cursor_val.as_str();
            return match reverse {
                false => {
                    let rows = sqlx::query_as!(
                        RecordRow,
                        r#"SELECT rkey, record_cid FROM records
                           WHERE repo_id = $1 AND collection = $2 AND rkey < $3
                           ORDER BY rkey DESC LIMIT $4"#,
                        repo_id,
                        collection_str,
                        cursor_str,
                        limit
                    )
                    .fetch_all(&self.pool)
                    .await
                    .map_err(map_sqlx_error)?;
                    Ok(to_record_info(rows))
                }
                true => {
                    let rows = sqlx::query_as!(
                        RecordRow,
                        r#"SELECT rkey, record_cid FROM records
                           WHERE repo_id = $1 AND collection = $2 AND rkey > $3
                           ORDER BY rkey ASC LIMIT $4"#,
                        repo_id,
                        collection_str,
                        cursor_str,
                        limit
                    )
                    .fetch_all(&self.pool)
                    .await
                    .map_err(map_sqlx_error)?;
                    Ok(to_record_info(rows))
                }
            };
        }

        if let (Some(start), Some(end)) = (rkey_start, rkey_end) {
            let start_str = start.as_str();
            let end_str = end.as_str();
            return match reverse {
                false => {
                    let rows = sqlx::query_as!(
                        RecordRow,
                        r#"SELECT rkey, record_cid FROM records
                           WHERE repo_id = $1 AND collection = $2 AND rkey >= $3 AND rkey <= $4
                           ORDER BY rkey DESC LIMIT $5"#,
                        repo_id,
                        collection_str,
                        start_str,
                        end_str,
                        limit
                    )
                    .fetch_all(&self.pool)
                    .await
                    .map_err(map_sqlx_error)?;
                    Ok(to_record_info(rows))
                }
                true => {
                    let rows = sqlx::query_as!(
                        RecordRow,
                        r#"SELECT rkey, record_cid FROM records
                           WHERE repo_id = $1 AND collection = $2 AND rkey >= $3 AND rkey <= $4
                           ORDER BY rkey ASC LIMIT $5"#,
                        repo_id,
                        collection_str,
                        start_str,
                        end_str,
                        limit
                    )
                    .fetch_all(&self.pool)
                    .await
                    .map_err(map_sqlx_error)?;
                    Ok(to_record_info(rows))
                }
            };
        }

        if let Some(start) = rkey_start {
            let start_str = start.as_str();
            return match reverse {
                false => {
                    let rows = sqlx::query_as!(
                        RecordRow,
                        r#"SELECT rkey, record_cid FROM records
                           WHERE repo_id = $1 AND collection = $2 AND rkey >= $3
                           ORDER BY rkey DESC LIMIT $4"#,
                        repo_id,
                        collection_str,
                        start_str,
                        limit
                    )
                    .fetch_all(&self.pool)
                    .await
                    .map_err(map_sqlx_error)?;
                    Ok(to_record_info(rows))
                }
                true => {
                    let rows = sqlx::query_as!(
                        RecordRow,
                        r#"SELECT rkey, record_cid FROM records
                           WHERE repo_id = $1 AND collection = $2 AND rkey >= $3
                           ORDER BY rkey ASC LIMIT $4"#,
                        repo_id,
                        collection_str,
                        start_str,
                        limit
                    )
                    .fetch_all(&self.pool)
                    .await
                    .map_err(map_sqlx_error)?;
                    Ok(to_record_info(rows))
                }
            };
        }

        if let Some(end) = rkey_end {
            let end_str = end.as_str();
            return match reverse {
                false => {
                    let rows = sqlx::query_as!(
                        RecordRow,
                        r#"SELECT rkey, record_cid FROM records
                           WHERE repo_id = $1 AND collection = $2 AND rkey <= $3
                           ORDER BY rkey DESC LIMIT $4"#,
                        repo_id,
                        collection_str,
                        end_str,
                        limit
                    )
                    .fetch_all(&self.pool)
                    .await
                    .map_err(map_sqlx_error)?;
                    Ok(to_record_info(rows))
                }
                true => {
                    let rows = sqlx::query_as!(
                        RecordRow,
                        r#"SELECT rkey, record_cid FROM records
                           WHERE repo_id = $1 AND collection = $2 AND rkey <= $3
                           ORDER BY rkey ASC LIMIT $4"#,
                        repo_id,
                        collection_str,
                        end_str,
                        limit
                    )
                    .fetch_all(&self.pool)
                    .await
                    .map_err(map_sqlx_error)?;
                    Ok(to_record_info(rows))
                }
            };
        }

        match reverse {
            false => {
                let rows = sqlx::query_as!(
                    RecordRow,
                    r#"SELECT rkey, record_cid FROM records
                       WHERE repo_id = $1 AND collection = $2
                       ORDER BY rkey DESC LIMIT $3"#,
                    repo_id,
                    collection_str,
                    limit
                )
                .fetch_all(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
                Ok(to_record_info(rows))
            }
            true => {
                let rows = sqlx::query_as!(
                    RecordRow,
                    r#"SELECT rkey, record_cid FROM records
                       WHERE repo_id = $1 AND collection = $2
                       ORDER BY rkey ASC LIMIT $3"#,
                    repo_id,
                    collection_str,
                    limit
                )
                .fetch_all(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
                Ok(to_record_info(rows))
            }
        }
    }

    async fn get_all_records(&self, repo_id: Uuid) -> Result<Vec<FullRecordInfo>, DbError> {
        let rows = sqlx::query!(
            "SELECT collection, rkey, record_cid FROM records WHERE repo_id = $1",
            repo_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(rows
            .into_iter()
            .map(|r| FullRecordInfo {
                collection: Nsid::from(r.collection),
                rkey: Rkey::from(r.rkey),
                record_cid: CidLink::from(r.record_cid),
            })
            .collect())
    }

    async fn list_collections(&self, repo_id: Uuid) -> Result<Vec<Nsid>, DbError> {
        let rows = sqlx::query_scalar!(
            "SELECT DISTINCT collection FROM records WHERE repo_id = $1",
            repo_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(rows.into_iter().map(Nsid::from).collect())
    }

    async fn count_records(&self, repo_id: Uuid) -> Result<i64, DbError> {
        let count = sqlx::query_scalar!(
            r#"SELECT COUNT(*) as "count!" FROM records WHERE repo_id = $1"#,
            repo_id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(count)
    }

    async fn count_all_records(&self) -> Result<i64, DbError> {
        let count = sqlx::query_scalar!(r#"SELECT COUNT(*) as "count!" FROM records"#)
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(count)
    }

    async fn get_record_by_cid(
        &self,
        cid: &CidLink,
    ) -> Result<Option<RecordWithTakedown>, DbError> {
        let row = sqlx::query!(
            "SELECT id, takedown_ref FROM records WHERE record_cid = $1",
            cid.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| RecordWithTakedown {
            id: r.id,
            takedown_ref: r.takedown_ref,
        }))
    }

    async fn set_record_takedown(
        &self,
        cid: &CidLink,
        takedown_ref: Option<&str>,
    ) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE records SET takedown_ref = $1 WHERE record_cid = $2",
            takedown_ref,
            cid.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn insert_user_blocks(
        &self,
        user_id: Uuid,
        block_cids: &[Vec<u8>],
        repo_rev: &str,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            INSERT INTO user_blocks (user_id, block_cid, repo_rev)
            SELECT $1, block_cid, $3 FROM UNNEST($2::bytea[]) AS t(block_cid)
            ON CONFLICT (user_id, block_cid) DO NOTHING
            "#,
        )
        .bind(user_id)
        .bind(block_cids)
        .bind(repo_rev)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn delete_user_blocks(
        &self,
        user_id: Uuid,
        block_cids: &[Vec<u8>],
    ) -> Result<(), DbError> {
        sqlx::query!(
            "DELETE FROM user_blocks WHERE user_id = $1 AND block_cid = ANY($2)",
            user_id,
            block_cids
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn count_user_blocks(&self, user_id: Uuid) -> Result<i64, DbError> {
        let count = sqlx::query_scalar!(
            r#"SELECT COUNT(*) as "count!" FROM user_blocks WHERE user_id = $1"#,
            user_id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(count)
    }

    async fn get_user_block_cids_since_rev(
        &self,
        user_id: Uuid,
        since_rev: &str,
    ) -> Result<Vec<Vec<u8>>, DbError> {
        let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
            r#"
            SELECT block_cid FROM user_blocks
            WHERE user_id = $1 AND repo_rev > $2
            ORDER BY repo_rev ASC
            "#,
        )
        .bind(user_id)
        .bind(since_rev)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(rows.into_iter().map(|(cid,)| cid).collect())
    }

    async fn insert_commit_event(&self, data: &CommitEventData) -> Result<SequenceNumber, DbError> {
        let seq = sqlx::query_scalar!(
            r#"
            INSERT INTO repo_seq (did, event_type, commit_cid, prev_cid, ops, blobs, blocks_cids, prev_data_cid, rev)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING seq
            "#,
            data.did.as_str(),
            data.event_type.as_str(),
            data.commit_cid.as_ref().map(|c| c.as_str()),
            data.prev_cid.as_ref().map(|c| c.as_str()),
            data.ops,
            data.blobs.as_deref(),
            data.blocks_cids.as_deref(),
            data.prev_data_cid.as_ref().map(|c| c.as_str()),
            data.rev
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(seq.into())
    }

    async fn insert_identity_event(
        &self,
        did: &Did,
        handle: Option<&Handle>,
    ) -> Result<SequenceNumber, DbError> {
        let handle_str = handle.map(|h| h.as_str());
        let seq = sqlx::query_scalar!(
            r#"
            INSERT INTO repo_seq (did, event_type, handle)
            VALUES ($1, 'identity', $2)
            RETURNING seq
            "#,
            did.as_str(),
            handle_str
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        sqlx::query(&format!("NOTIFY repo_updates, '{}'", seq))
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(seq.into())
    }

    async fn insert_account_event(
        &self,
        did: &Did,
        status: AccountStatus,
    ) -> Result<SequenceNumber, DbError> {
        let active = status.is_active();
        let status_str = status.for_firehose();
        let seq = sqlx::query_scalar!(
            r#"
            INSERT INTO repo_seq (did, event_type, active, status)
            VALUES ($1, 'account', $2, $3)
            RETURNING seq
            "#,
            did.as_str(),
            active,
            status_str
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        sqlx::query(&format!("NOTIFY repo_updates, '{}'", seq))
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(seq.into())
    }

    async fn insert_sync_event(
        &self,
        did: &Did,
        commit_cid: &CidLink,
        rev: Option<&str>,
    ) -> Result<SequenceNumber, DbError> {
        let seq = sqlx::query_scalar!(
            r#"
            INSERT INTO repo_seq (did, event_type, commit_cid, rev)
            VALUES ($1, 'sync', $2, $3)
            RETURNING seq
            "#,
            did.as_str(),
            commit_cid.as_str(),
            rev
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        sqlx::query(&format!("NOTIFY repo_updates, '{}'", seq))
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(seq.into())
    }

    async fn insert_genesis_commit_event(
        &self,
        did: &Did,
        commit_cid: &CidLink,
        mst_root_cid: &CidLink,
        rev: &str,
    ) -> Result<SequenceNumber, DbError> {
        let ops = serde_json::json!([]);
        let blobs: Vec<String> = vec![];
        let blocks_cids: Vec<String> = vec![mst_root_cid.to_string(), commit_cid.to_string()];
        let prev_cid: Option<&str> = None;

        let seq = sqlx::query_scalar!(
            r#"
            INSERT INTO repo_seq (did, event_type, commit_cid, prev_cid, ops, blobs, blocks_cids, rev)
            VALUES ($1, 'commit', $2, $3::TEXT, $4, $5, $6, $7)
            RETURNING seq
            "#,
            did.as_str(),
            commit_cid.as_str(),
            prev_cid,
            ops,
            &blobs,
            &blocks_cids,
            rev
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        sqlx::query(&format!("NOTIFY repo_updates, '{}'", seq))
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(seq.into())
    }

    async fn update_seq_blocks_cids(
        &self,
        seq: SequenceNumber,
        blocks_cids: &[String],
    ) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE repo_seq SET blocks_cids = $1 WHERE seq = $2",
            blocks_cids,
            seq.as_i64()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn delete_sequences_except(
        &self,
        did: &Did,
        keep_seq: SequenceNumber,
    ) -> Result<(), DbError> {
        sqlx::query!(
            "DELETE FROM repo_seq WHERE did = $1 AND seq != $2",
            did.as_str(),
            keep_seq.as_i64()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn get_max_seq(&self) -> Result<SequenceNumber, DbError> {
        let seq = sqlx::query_scalar!(r#"SELECT COALESCE(MAX(seq), 0) as "max!" FROM repo_seq"#)
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(seq.into())
    }

    async fn get_min_seq_since(
        &self,
        since: DateTime<Utc>,
    ) -> Result<Option<SequenceNumber>, DbError> {
        let seq = sqlx::query_scalar!(
            "SELECT MIN(seq) FROM repo_seq WHERE created_at >= $1",
            since
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(seq.map(SequenceNumber::from))
    }

    async fn get_account_with_repo(&self, did: &Did) -> Result<Option<RepoAccountInfo>, DbError> {
        let row = sqlx::query!(
            r#"SELECT u.id, u.did, u.deactivated_at, u.takedown_ref, r.repo_root_cid as "repo_root_cid?"
               FROM users u
               LEFT JOIN repos r ON r.user_id = u.id
               WHERE u.did = $1"#,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| RepoAccountInfo {
            user_id: r.id,
            did: Did::from(r.did),
            deactivated_at: r.deactivated_at,
            takedown_ref: r.takedown_ref,
            repo_root_cid: r.repo_root_cid.map(CidLink::from),
        }))
    }

    async fn get_events_since_seq(
        &self,
        since_seq: SequenceNumber,
        limit: Option<i64>,
    ) -> Result<Vec<SequencedEvent>, DbError> {
        let map_row = |r: SequencedEventRow| {
            let status = r
                .status
                .as_deref()
                .and_then(AccountStatus::parse)
                .or_else(|| r.active.filter(|a| *a).map(|_| AccountStatus::Active));
            SequencedEvent {
                seq: r.seq.into(),
                did: Did::from(r.did),
                created_at: r.created_at,
                event_type: r.event_type,
                commit_cid: r.commit_cid.map(CidLink::from),
                prev_cid: r.prev_cid.map(CidLink::from),
                prev_data_cid: r.prev_data_cid.map(CidLink::from),
                ops: r.ops,
                blobs: r.blobs,
                blocks_cids: r.blocks_cids,
                handle: r.handle.map(Handle::from),
                active: r.active,
                status,
                rev: r.rev,
            }
        };
        match limit {
            Some(lim) => {
                let rows = sqlx::query_as!(
                    SequencedEventRow,
                    r#"SELECT seq, did, created_at, event_type as "event_type: RepoEventType", commit_cid, prev_cid, prev_data_cid,
                              ops, blobs, blocks_cids, handle, active, status, rev
                       FROM repo_seq
                       WHERE seq > $1
                       ORDER BY seq ASC
                       LIMIT $2"#,
                    since_seq.as_i64(),
                    lim
                )
                .fetch_all(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
                Ok(rows.into_iter().map(map_row).collect())
            }
            None => {
                let rows = sqlx::query_as!(
                    SequencedEventRow,
                    r#"SELECT seq, did, created_at, event_type as "event_type: RepoEventType", commit_cid, prev_cid, prev_data_cid,
                              ops, blobs, blocks_cids, handle, active, status, rev
                       FROM repo_seq
                       WHERE seq > $1
                       ORDER BY seq ASC"#,
                    since_seq.as_i64()
                )
                .fetch_all(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
                Ok(rows.into_iter().map(map_row).collect())
            }
        }
    }

    async fn get_events_in_seq_range(
        &self,
        start_seq: SequenceNumber,
        end_seq: SequenceNumber,
    ) -> Result<Vec<SequencedEvent>, DbError> {
        let rows = sqlx::query!(
            r#"SELECT seq, did, created_at, event_type as "event_type: RepoEventType", commit_cid, prev_cid, prev_data_cid,
                      ops, blobs, blocks_cids, handle, active, status, rev
               FROM repo_seq
               WHERE seq > $1 AND seq < $2
               ORDER BY seq ASC"#,
            start_seq.as_i64(),
            end_seq.as_i64()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let status = r
                    .status
                    .as_deref()
                    .and_then(AccountStatus::parse)
                    .or_else(|| r.active.filter(|a| *a).map(|_| AccountStatus::Active));
                SequencedEvent {
                    seq: r.seq.into(),
                    did: Did::from(r.did),
                    created_at: r.created_at,
                    event_type: r.event_type,
                    commit_cid: r.commit_cid.map(CidLink::from),
                    prev_cid: r.prev_cid.map(CidLink::from),
                    prev_data_cid: r.prev_data_cid.map(CidLink::from),
                    ops: r.ops,
                    blobs: r.blobs,
                    blocks_cids: r.blocks_cids,
                    handle: r.handle.map(Handle::from),
                    active: r.active,
                    status,
                    rev: r.rev,
                }
            })
            .collect())
    }

    async fn get_event_by_seq(
        &self,
        seq: SequenceNumber,
    ) -> Result<Option<SequencedEvent>, DbError> {
        let row = sqlx::query!(
            r#"SELECT seq, did, created_at, event_type as "event_type: RepoEventType", commit_cid, prev_cid, prev_data_cid,
                      ops, blobs, blocks_cids, handle, active, status, rev
               FROM repo_seq
               WHERE seq = $1"#,
            seq.as_i64()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(row.map(|r| {
            let status = r
                .status
                .as_deref()
                .and_then(AccountStatus::parse)
                .or_else(|| r.active.filter(|a| *a).map(|_| AccountStatus::Active));
            SequencedEvent {
                seq: r.seq.into(),
                did: Did::from(r.did),
                created_at: r.created_at,
                event_type: r.event_type,
                commit_cid: r.commit_cid.map(CidLink::from),
                prev_cid: r.prev_cid.map(CidLink::from),
                prev_data_cid: r.prev_data_cid.map(CidLink::from),
                ops: r.ops,
                blobs: r.blobs,
                blocks_cids: r.blocks_cids,
                handle: r.handle.map(Handle::from),
                active: r.active,
                status,
                rev: r.rev,
            }
        }))
    }

    async fn get_events_since_cursor(
        &self,
        cursor: SequenceNumber,
        limit: i64,
    ) -> Result<Vec<SequencedEvent>, DbError> {
        let rows = sqlx::query!(
            r#"SELECT seq, did, created_at, event_type as "event_type: RepoEventType", commit_cid, prev_cid, prev_data_cid,
                      ops, blobs, blocks_cids, handle, active, status, rev
               FROM repo_seq
               WHERE seq > $1
               ORDER BY seq ASC
               LIMIT $2"#,
            cursor.as_i64(),
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let status = r
                    .status
                    .as_deref()
                    .and_then(AccountStatus::parse)
                    .or_else(|| r.active.filter(|a| *a).map(|_| AccountStatus::Active));
                SequencedEvent {
                    seq: r.seq.into(),
                    did: Did::from(r.did),
                    created_at: r.created_at,
                    event_type: r.event_type,
                    commit_cid: r.commit_cid.map(CidLink::from),
                    prev_cid: r.prev_cid.map(CidLink::from),
                    prev_data_cid: r.prev_data_cid.map(CidLink::from),
                    ops: r.ops,
                    blobs: r.blobs,
                    blocks_cids: r.blocks_cids,
                    handle: r.handle.map(Handle::from),
                    active: r.active,
                    status,
                    rev: r.rev,
                }
            })
            .collect())
    }

    async fn get_events_since_rev(
        &self,
        did: &Did,
        since_rev: &str,
    ) -> Result<Vec<EventBlocksCids>, DbError> {
        let rows = sqlx::query!(
            r#"SELECT blocks_cids, commit_cid
               FROM repo_seq
               WHERE did = $1 AND rev > $2
               ORDER BY seq DESC"#,
            did.as_str(),
            since_rev
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(rows
            .into_iter()
            .map(|r| EventBlocksCids {
                blocks_cids: r.blocks_cids,
                commit_cid: r.commit_cid.map(CidLink::from),
            })
            .collect())
    }

    async fn list_repos_paginated(
        &self,
        cursor_did: Option<&Did>,
        limit: i64,
    ) -> Result<Vec<RepoListItem>, DbError> {
        let cursor_str = cursor_did.map(|d| d.as_str()).unwrap_or("");
        let rows = sqlx::query!(
            r#"SELECT u.did, u.deactivated_at, u.takedown_ref, r.repo_root_cid, r.repo_rev
               FROM repos r
               JOIN users u ON r.user_id = u.id
               WHERE u.did > $1
               ORDER BY u.did ASC
               LIMIT $2"#,
            cursor_str,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(rows
            .into_iter()
            .map(|r| RepoListItem {
                did: Did::from(r.did),
                deactivated_at: r.deactivated_at,
                takedown_ref: r.takedown_ref,
                repo_root_cid: CidLink::from(r.repo_root_cid),
                repo_rev: r.repo_rev,
            })
            .collect())
    }

    async fn get_repo_root_cid_by_user_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<CidLink>, DbError> {
        let cid = sqlx::query_scalar!(
            "SELECT repo_root_cid FROM repos WHERE user_id = $1",
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(cid.map(CidLink::from))
    }

    async fn notify_update(&self, seq: SequenceNumber) -> Result<(), DbError> {
        sqlx::query(&format!("NOTIFY repo_updates, '{}'", seq.as_i64()))
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn import_repo_data(
        &self,
        user_id: Uuid,
        blocks: &[ImportBlock],
        records: &[ImportRecord],
        expected_root_cid: Option<&CidLink>,
    ) -> Result<(), ImportRepoError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ImportRepoError::Database(e.to_string()))?;

        let repo = sqlx::query!(
            "SELECT repo_root_cid FROM repos WHERE user_id = $1 FOR UPDATE NOWAIT",
            user_id
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e
                && db_err.code().as_deref() == Some("55P03")
            {
                return ImportRepoError::ConcurrentModification;
            }
            ImportRepoError::Database(e.to_string())
        })?;

        let repo = match repo {
            Some(r) => r,
            None => return Err(ImportRepoError::RepoNotFound),
        };

        if let Some(expected) = expected_root_cid
            && repo.repo_root_cid.as_str() != expected.as_str()
        {
            return Err(ImportRepoError::ConcurrentModification);
        }

        let block_chunks: Vec<Vec<&ImportBlock>> = blocks
            .iter()
            .collect::<Vec<_>>()
            .chunks(100)
            .map(|c| c.to_vec())
            .collect();

        for chunk in block_chunks {
            for block in chunk {
                sqlx::query!(
                    "INSERT INTO blocks (cid, data) VALUES ($1, $2) ON CONFLICT (cid) DO NOTHING",
                    &block.cid_bytes,
                    &block.data
                )
                .execute(&mut *tx)
                .await
                .map_err(|e| ImportRepoError::Database(e.to_string()))?;
            }
        }

        sqlx::query!("DELETE FROM records WHERE repo_id = $1", user_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| ImportRepoError::Database(e.to_string()))?;

        for record in records {
            sqlx::query!(
                r#"
                INSERT INTO records (repo_id, collection, rkey, record_cid)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (repo_id, collection, rkey) DO UPDATE SET record_cid = $4
                "#,
                user_id,
                record.collection.as_str(),
                record.rkey.as_str(),
                record.record_cid.as_str()
            )
            .execute(&mut *tx)
            .await
            .map_err(|e| ImportRepoError::Database(e.to_string()))?;
        }

        tx.commit()
            .await
            .map_err(|e| ImportRepoError::Database(e.to_string()))?;

        Ok(())
    }

    async fn apply_commit(
        &self,
        input: tranquil_db_traits::ApplyCommitInput,
    ) -> Result<tranquil_db_traits::ApplyCommitResult, tranquil_db_traits::ApplyCommitError> {
        use tranquil_db_traits::ApplyCommitError;

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ApplyCommitError::Database(e.to_string()))?;

        let lock_result: Result<Option<_>, sqlx::Error> = sqlx::query!(
            "SELECT repo_root_cid FROM repos WHERE user_id = $1 FOR UPDATE NOWAIT",
            input.user_id
        )
        .fetch_optional(&mut *tx)
        .await;

        match lock_result {
            Err(e) => {
                if let Some(db_err) = e.as_database_error()
                    && db_err.code().as_deref() == Some("55P03")
                {
                    return Err(ApplyCommitError::ConcurrentModification);
                }
                return Err(ApplyCommitError::Database(format!(
                    "Failed to acquire repo lock: {}",
                    e
                )));
            }
            Ok(Some(row)) => {
                if let Some(expected_root) = &input.expected_root_cid
                    && row.repo_root_cid != expected_root.as_str()
                {
                    return Err(ApplyCommitError::ConcurrentModification);
                }
            }
            Ok(None) => {
                return Err(ApplyCommitError::RepoNotFound);
            }
        }

        let is_account_active: bool =
            sqlx::query_scalar("SELECT deactivated_at IS NULL FROM users WHERE id = $1")
                .bind(input.user_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| ApplyCommitError::Database(e.to_string()))?
                .flatten()
                .unwrap_or(false);

        sqlx::query("UPDATE repos SET repo_root_cid = $1, repo_rev = $2 WHERE user_id = $3")
            .bind(&input.new_root_cid)
            .bind(&input.new_rev)
            .bind(input.user_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| ApplyCommitError::Database(e.to_string()))?;

        if !input.new_block_cids.is_empty() {
            sqlx::query(
                r#"
                INSERT INTO user_blocks (user_id, block_cid, repo_rev)
                SELECT $1, block_cid, $3 FROM UNNEST($2::bytea[]) AS t(block_cid)
                ON CONFLICT (user_id, block_cid) DO NOTHING
                "#,
            )
            .bind(input.user_id)
            .bind(&input.new_block_cids)
            .bind(&input.new_rev)
            .execute(&mut *tx)
            .await
            .map_err(|e| ApplyCommitError::Database(e.to_string()))?;
        }

        if !input.obsolete_block_cids.is_empty() {
            sqlx::query(
                r#"
                DELETE FROM user_blocks
                WHERE user_id = $1
                AND block_cid = ANY($2)
                "#,
            )
            .bind(input.user_id)
            .bind(&input.obsolete_block_cids)
            .execute(&mut *tx)
            .await
            .map_err(|e| ApplyCommitError::Database(e.to_string()))?;
        }

        if !input.record_upserts.is_empty() {
            let collections: Vec<&str> = input
                .record_upserts
                .iter()
                .map(|r| r.collection.as_str())
                .collect();
            let rkeys: Vec<&str> = input
                .record_upserts
                .iter()
                .map(|r| r.rkey.as_str())
                .collect();
            let cids: Vec<&str> = input
                .record_upserts
                .iter()
                .map(|r| r.cid.as_str())
                .collect();

            sqlx::query(
                r#"
                INSERT INTO records (repo_id, collection, rkey, record_cid, repo_rev)
                SELECT $1, t.collection, t.rkey, t.cid, $5
                FROM UNNEST($2::text[], $3::text[], $4::text[]) AS t(collection, rkey, cid)
                ON CONFLICT (repo_id, collection, rkey) DO UPDATE SET record_cid = EXCLUDED.record_cid, repo_rev = EXCLUDED.repo_rev
                "#,
            )
            .bind(input.user_id)
            .bind(&collections)
            .bind(&rkeys)
            .bind(&cids)
            .bind(&input.new_rev)
            .execute(&mut *tx)
            .await
            .map_err(|e| ApplyCommitError::Database(e.to_string()))?;
        }

        if !input.record_deletes.is_empty() {
            let collections: Vec<&str> = input
                .record_deletes
                .iter()
                .map(|r| r.collection.as_str())
                .collect();
            let rkeys: Vec<&str> = input
                .record_deletes
                .iter()
                .map(|r| r.rkey.as_str())
                .collect();

            sqlx::query(
                r#"
                DELETE FROM records
                WHERE repo_id = $1
                AND (collection, rkey) IN (SELECT collection, rkey FROM UNNEST($2::text[], $3::text[]) AS t(collection, rkey))
                "#,
            )
            .bind(input.user_id)
            .bind(&collections)
            .bind(&rkeys)
            .execute(&mut *tx)
            .await
            .map_err(|e| ApplyCommitError::Database(e.to_string()))?;
        }

        let event = &input.commit_event;
        let seq: i64 = sqlx::query_scalar(
            r#"
            INSERT INTO repo_seq (did, event_type, commit_cid, prev_cid, ops, blobs, blocks_cids, prev_data_cid, rev)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING seq
            "#,
        )
        .bind(&event.did)
        .bind(event.event_type.as_str())
        .bind(&event.commit_cid)
        .bind(&event.prev_cid)
        .bind(&event.ops)
        .bind(&event.blobs)
        .bind(&event.blocks_cids)
        .bind(&event.prev_data_cid)
        .bind(&event.rev)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| ApplyCommitError::Database(e.to_string()))?;

        sqlx::query(&format!("NOTIFY repo_updates, '{}'", seq))
            .execute(&mut *tx)
            .await
            .map_err(|e| ApplyCommitError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| ApplyCommitError::Database(e.to_string()))?;

        Ok(tranquil_db_traits::ApplyCommitResult {
            seq,
            is_account_active,
        })
    }

    async fn get_broken_genesis_commits(
        &self,
    ) -> Result<Vec<tranquil_db_traits::BrokenGenesisCommit>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT seq, did, commit_cid
            FROM repo_seq
            WHERE event_type = 'commit'
              AND prev_cid IS NULL
              AND (blocks_cids IS NULL OR array_length(blocks_cids, 1) IS NULL OR array_length(blocks_cids, 1) = 0)
            "#
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(rows
            .into_iter()
            .map(|r| BrokenGenesisCommit {
                seq: r.seq.into(),
                did: Did::from(r.did),
                commit_cid: r.commit_cid.map(CidLink::from),
            })
            .collect())
    }

    async fn get_users_without_blocks(&self) -> Result<Vec<UserWithoutBlocks>, DbError> {
        let rows: Vec<(Uuid, String, Option<String>)> = sqlx::query_as(
            r#"
            SELECT u.id as user_id, r.repo_root_cid, r.repo_rev
            FROM users u
            JOIN repos r ON r.user_id = u.id
            WHERE NOT EXISTS (SELECT 1 FROM user_blocks ub WHERE ub.user_id = u.id)
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(rows
            .into_iter()
            .map(|(user_id, repo_root_cid, repo_rev)| UserWithoutBlocks {
                user_id,
                repo_root_cid: CidLink::from(repo_root_cid),
                repo_rev,
            })
            .collect())
    }

    async fn get_users_needing_record_blobs_backfill(
        &self,
        limit: i64,
    ) -> Result<Vec<tranquil_db_traits::UserNeedingRecordBlobsBackfill>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT DISTINCT u.id as user_id, u.did
            FROM users u
            JOIN records r ON r.repo_id = u.id
            WHERE NOT EXISTS (SELECT 1 FROM record_blobs rb WHERE rb.repo_id = u.id)
            LIMIT $1
            "#,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(rows
            .into_iter()
            .map(|r| UserNeedingRecordBlobsBackfill {
                user_id: r.user_id,
                did: Did::from(r.did),
            })
            .collect())
    }

    async fn insert_record_blobs(
        &self,
        repo_id: Uuid,
        record_uris: &[AtUri],
        blob_cids: &[CidLink],
    ) -> Result<(), DbError> {
        let uris_str: Vec<&str> = record_uris.iter().map(|u| u.as_str()).collect();
        let cids_str: Vec<&str> = blob_cids.iter().map(|c| c.as_str()).collect();

        sqlx::query!(
            r#"
            INSERT INTO record_blobs (repo_id, record_uri, blob_cid)
            SELECT $1, record_uri, blob_cid
            FROM UNNEST($2::text[], $3::text[]) AS t(record_uri, blob_cid)
            ON CONFLICT (repo_id, record_uri, blob_cid) DO NOTHING
            "#,
            repo_id,
            &uris_str as &[&str],
            &cids_str as &[&str]
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(())
    }
}
