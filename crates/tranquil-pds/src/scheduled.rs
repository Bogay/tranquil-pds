use cid::Cid;
use ipld_core::ipld::Ipld;
use jacquard_repo::commit::Commit;
use jacquard_repo::storage::BlockStore;
use sqlx::PgPool;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use crate::repo::PostgresBlockStore;
use crate::storage::{BackupStorage, BlobStorage};
use crate::sync::car::encode_car_header;

async fn update_genesis_blocks_cids(db: &PgPool, blocks_cids: &[String], seq: i64) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE repo_seq SET blocks_cids = $1 WHERE seq = $2",
        blocks_cids,
        seq
    )
    .execute(db)
    .await?;
    Ok(())
}

async fn update_repo_rev(db: &PgPool, rev: &str, user_id: uuid::Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE repos SET repo_rev = $1 WHERE user_id = $2",
        rev,
        user_id
    )
    .execute(db)
    .await?;
    Ok(())
}

async fn insert_user_blocks(db: &PgPool, user_id: uuid::Uuid, block_cids: &[Vec<u8>]) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO user_blocks (user_id, block_cid)
        SELECT $1, block_cid FROM UNNEST($2::bytea[]) AS t(block_cid)
        ON CONFLICT (user_id, block_cid) DO NOTHING
        "#,
        user_id,
        block_cids
    )
    .execute(db)
    .await?;
    Ok(())
}

async fn fetch_user_records(db: &PgPool, user_id: uuid::Uuid) -> Result<Vec<(String, String, String)>, sqlx::Error> {
    let rows = sqlx::query!(
        "SELECT collection, rkey, record_cid FROM records WHERE repo_id = $1",
        user_id
    )
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|r| (r.collection, r.rkey, r.record_cid)).collect())
}

async fn insert_record_blobs(db: &PgPool, user_id: uuid::Uuid, record_uris: &[String], blob_cids: &[String]) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO record_blobs (repo_id, record_uri, blob_cid)
        SELECT $1, record_uri, blob_cid
        FROM UNNEST($2::text[], $3::text[]) AS t(record_uri, blob_cid)
        ON CONFLICT (repo_id, record_uri, blob_cid) DO NOTHING
        "#,
        user_id,
        record_uris,
        blob_cids
    )
    .execute(db)
    .await?;
    Ok(())
}

async fn delete_backup_record(db: &PgPool, id: uuid::Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!("DELETE FROM account_backups WHERE id = $1", id)
        .execute(db)
        .await?;
    Ok(())
}

async fn fetch_old_backups(
    db: &PgPool,
    user_id: uuid::Uuid,
    retention_count: i64,
) -> Result<Vec<(uuid::Uuid, String)>, sqlx::Error> {
    let rows = sqlx::query!(
        r#"
        SELECT id, storage_key
        FROM account_backups
        WHERE user_id = $1
        ORDER BY created_at DESC
        OFFSET $2
        "#,
        user_id,
        retention_count
    )
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|r| (r.id, r.storage_key)).collect())
}

async fn insert_backup_record(
    db: &PgPool,
    user_id: uuid::Uuid,
    storage_key: &str,
    repo_root_cid: &str,
    repo_rev: &str,
    block_count: i32,
    size_bytes: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO account_backups (user_id, storage_key, repo_root_cid, repo_rev, block_count, size_bytes)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        user_id,
        storage_key,
        repo_root_cid,
        repo_rev,
        block_count,
        size_bytes
    )
    .execute(db)
    .await?;
    Ok(())
}

struct GenesisCommitRow {
    seq: i64,
    did: String,
    commit_cid: Option<String>,
}

async fn process_genesis_commit(
    db: &PgPool,
    block_store: &PostgresBlockStore,
    row: GenesisCommitRow,
) -> Result<(String, i64), (i64, &'static str)> {
    let commit_cid_str = row.commit_cid.ok_or((row.seq, "missing commit_cid"))?;
    let commit_cid = Cid::from_str(&commit_cid_str).map_err(|_| (row.seq, "invalid CID"))?;
    let block = block_store
        .get(&commit_cid)
        .await
        .map_err(|_| (row.seq, "failed to fetch block"))?
        .ok_or((row.seq, "block not found"))?;
    let commit = Commit::from_cbor(&block).map_err(|_| (row.seq, "failed to parse commit"))?;
    let blocks_cids = vec![commit.data.to_string(), commit_cid.to_string()];
    update_genesis_blocks_cids(db, &blocks_cids, row.seq)
        .await
        .map_err(|_| (row.seq, "failed to update"))?;
    Ok((row.did, row.seq))
}

pub async fn backfill_genesis_commit_blocks(db: &PgPool, block_store: PostgresBlockStore) {
    let broken_genesis_commits = match sqlx::query!(
        r#"
        SELECT seq, did, commit_cid
        FROM repo_seq
        WHERE event_type = 'commit'
          AND prev_cid IS NULL
          AND (blocks_cids IS NULL OR array_length(blocks_cids, 1) IS NULL OR array_length(blocks_cids, 1) = 0)
        "#
    )
    .fetch_all(db)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("Failed to query repo_seq for genesis commit backfill: {}", e);
            return;
        }
    };

    if broken_genesis_commits.is_empty() {
        debug!("No genesis commits need blocks_cids backfill");
        return;
    }

    info!(
        count = broken_genesis_commits.len(),
        "Backfilling blocks_cids for genesis commits"
    );

    let results = futures::future::join_all(broken_genesis_commits.into_iter().map(|row| {
        process_genesis_commit(
            db,
            &block_store,
            GenesisCommitRow {
                seq: row.seq,
                did: row.did,
                commit_cid: row.commit_cid,
            },
        )
    }))
    .await;

    let (success, failed) = results.iter().fold((0, 0), |(s, f), r| match r {
        Ok((did, seq)) => {
            info!(seq = seq, did = %did, "Fixed genesis commit blocks_cids");
            (s + 1, f)
        }
        Err((seq, reason)) => {
            warn!(seq = seq, reason = reason, "Failed to process genesis commit");
            (s, f + 1)
        }
    });

    info!(
        success,
        failed, "Completed genesis commit blocks_cids backfill"
    );
}

async fn process_repo_rev(
    db: &PgPool,
    block_store: &PostgresBlockStore,
    user_id: uuid::Uuid,
    repo_root_cid: String,
) -> Result<uuid::Uuid, uuid::Uuid> {
    let cid = Cid::from_str(&repo_root_cid).map_err(|_| user_id)?;
    let block = block_store
        .get(&cid)
        .await
        .ok()
        .flatten()
        .ok_or(user_id)?;
    let commit = Commit::from_cbor(&block).map_err(|_| user_id)?;
    let rev = commit.rev().to_string();
    update_repo_rev(db, &rev, user_id)
        .await
        .map_err(|_| user_id)?;
    Ok(user_id)
}

pub async fn backfill_repo_rev(db: &PgPool, block_store: PostgresBlockStore) {
    let repos_missing_rev =
        match sqlx::query!("SELECT user_id, repo_root_cid FROM repos WHERE repo_rev IS NULL")
            .fetch_all(db)
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                error!("Failed to query repos for backfill: {}", e);
                return;
            }
        };

    if repos_missing_rev.is_empty() {
        debug!("No repos need repo_rev backfill");
        return;
    }

    info!(
        count = repos_missing_rev.len(),
        "Backfilling repo_rev for existing repos"
    );

    let results = futures::future::join_all(repos_missing_rev.into_iter().map(|repo| {
        process_repo_rev(db, &block_store, repo.user_id, repo.repo_root_cid)
    }))
    .await;

    let (success, failed) = results
        .iter()
        .fold((0, 0), |(s, f), r| match r {
            Ok(_) => (s + 1, f),
            Err(user_id) => {
                warn!(user_id = %user_id, "Failed to update repo_rev");
                (s, f + 1)
            }
        });

    info!(success, failed, "Completed repo_rev backfill");
}

async fn process_user_blocks(
    db: &PgPool,
    block_store: &PostgresBlockStore,
    user_id: uuid::Uuid,
    repo_root_cid: String,
) -> Result<(uuid::Uuid, usize), uuid::Uuid> {
    let root_cid = Cid::from_str(&repo_root_cid).map_err(|_| user_id)?;
    let block_cids = collect_current_repo_blocks(block_store, &root_cid)
        .await
        .map_err(|_| user_id)?;
    if block_cids.is_empty() {
        return Err(user_id);
    }
    let count = block_cids.len();
    insert_user_blocks(db, user_id, &block_cids)
        .await
        .map_err(|_| user_id)?;
    Ok((user_id, count))
}

pub async fn backfill_user_blocks(db: &PgPool, block_store: PostgresBlockStore) {
    let users_without_blocks = match sqlx::query!(
        r#"
        SELECT u.id as user_id, r.repo_root_cid
        FROM users u
        JOIN repos r ON r.user_id = u.id
        WHERE NOT EXISTS (SELECT 1 FROM user_blocks ub WHERE ub.user_id = u.id)
        "#
    )
    .fetch_all(db)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("Failed to query users for user_blocks backfill: {}", e);
            return;
        }
    };

    if users_without_blocks.is_empty() {
        debug!("No users need user_blocks backfill");
        return;
    }

    info!(
        count = users_without_blocks.len(),
        "Backfilling user_blocks for existing repos"
    );

    let results = futures::future::join_all(users_without_blocks.into_iter().map(|user| {
        process_user_blocks(db, &block_store, user.user_id, user.repo_root_cid)
    }))
    .await;

    let (success, failed) = results.iter().fold((0, 0), |(s, f), r| match r {
        Ok((user_id, count)) => {
            info!(user_id = %user_id, block_count = count, "Backfilled user_blocks");
            (s + 1, f)
        }
        Err(user_id) => {
            warn!(user_id = %user_id, "Failed to backfill user_blocks");
            (s, f + 1)
        }
    });

    info!(success, failed, "Completed user_blocks backfill");
}

pub async fn collect_current_repo_blocks(
    block_store: &PostgresBlockStore,
    head_cid: &Cid,
) -> Result<Vec<Vec<u8>>, String> {
    let mut block_cids: Vec<Vec<u8>> = Vec::new();
    let mut to_visit = vec![*head_cid];
    let mut visited = std::collections::HashSet::new();

    while let Some(cid) = to_visit.pop() {
        if visited.contains(&cid) {
            continue;
        }
        visited.insert(cid);
        block_cids.push(cid.to_bytes());

        let block = match block_store.get(&cid).await {
            Ok(Some(b)) => b,
            Ok(None) => continue,
            Err(e) => return Err(format!("Failed to get block {}: {:?}", cid, e)),
        };

        if let Ok(commit) = Commit::from_cbor(&block) {
            to_visit.push(commit.data);
        } else if let Ok(Ipld::Map(ref obj)) = serde_ipld_dagcbor::from_slice::<Ipld>(&block) {
            if let Some(Ipld::Link(left_cid)) = obj.get("l") {
                to_visit.push(*left_cid);
            }
            if let Some(Ipld::List(entries)) = obj.get("e") {
                to_visit.extend(
                    entries
                        .iter()
                        .filter_map(|entry| match entry {
                            Ipld::Map(entry_obj) => Some(entry_obj),
                            _ => None,
                        })
                        .flat_map(|entry_obj| {
                            [entry_obj.get("t"), entry_obj.get("v")]
                                .into_iter()
                                .flatten()
                                .filter_map(|v| match v {
                                    Ipld::Link(cid) => Some(*cid),
                                    _ => None,
                                })
                        }),
                );
            }
        }
    }

    Ok(block_cids)
}

async fn process_record_blobs(
    db: &PgPool,
    block_store: &PostgresBlockStore,
    user_id: uuid::Uuid,
    did: String,
) -> Result<(uuid::Uuid, String, usize), (uuid::Uuid, &'static str)> {
    let records = fetch_user_records(db, user_id)
        .await
        .map_err(|_| (user_id, "failed to fetch records"))?;

    let mut batch_record_uris: Vec<String> = Vec::new();
    let mut batch_blob_cids: Vec<String> = Vec::new();

    futures::future::join_all(records.into_iter().map(|(collection, rkey, record_cid)| {
        let did = did.clone();
        async move {
            let cid = Cid::from_str(&record_cid).ok()?;
            let block_bytes = block_store.get(&cid).await.ok()??;
            let record_ipld: Ipld = serde_ipld_dagcbor::from_slice(&block_bytes).ok()?;
            let blob_refs = crate::sync::import::find_blob_refs_ipld(&record_ipld, 0);
            Some(
                blob_refs
                    .into_iter()
                    .map(|blob_ref| {
                        let record_uri = format!("at://{}/{}/{}", did, collection, rkey);
                        (record_uri, blob_ref.cid)
                    })
                    .collect::<Vec<_>>(),
            )
        }
    }))
    .await
    .into_iter()
    .flatten()
    .flatten()
    .for_each(|(uri, cid)| {
        batch_record_uris.push(uri);
        batch_blob_cids.push(cid);
    });

    let blob_refs_found = batch_record_uris.len();
    if !batch_record_uris.is_empty() {
        insert_record_blobs(db, user_id, &batch_record_uris, &batch_blob_cids)
            .await
            .map_err(|_| (user_id, "failed to insert"))?;
    }
    Ok((user_id, did, blob_refs_found))
}

pub async fn backfill_record_blobs(db: &PgPool, block_store: PostgresBlockStore) {
    let users_needing_backfill = match sqlx::query!(
        r#"
        SELECT DISTINCT u.id as user_id, u.did
        FROM users u
        JOIN records r ON r.repo_id = u.id
        WHERE NOT EXISTS (SELECT 1 FROM record_blobs rb WHERE rb.repo_id = u.id)
        LIMIT 100
        "#
    )
    .fetch_all(db)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("Failed to query users for record_blobs backfill: {}", e);
            return;
        }
    };

    if users_needing_backfill.is_empty() {
        debug!("No users need record_blobs backfill");
        return;
    }

    info!(
        count = users_needing_backfill.len(),
        "Backfilling record_blobs for existing repos"
    );

    let results = futures::future::join_all(users_needing_backfill.into_iter().map(|user| {
        process_record_blobs(db, &block_store, user.user_id, user.did)
    }))
    .await;

    let (success, failed) = results.iter().fold((0, 0), |(s, f), r| match r {
        Ok((user_id, did, blob_refs)) => {
            if *blob_refs > 0 {
                info!(user_id = %user_id, did = %did, blob_refs = blob_refs, "Backfilled record_blobs");
            }
            (s + 1, f)
        }
        Err((user_id, reason)) => {
            warn!(user_id = %user_id, reason = reason, "Failed to backfill record_blobs");
            (s, f + 1)
        }
    });

    info!(success, failed, "Completed record_blobs backfill");
}

pub async fn start_scheduled_tasks(
    db: PgPool,
    blob_store: Arc<dyn BlobStorage>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let check_interval = Duration::from_secs(
        std::env::var("SCHEDULED_DELETE_CHECK_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3600),
    );

    info!(
        check_interval_secs = check_interval.as_secs(),
        "Starting scheduled tasks service"
    );

    let mut ticker = interval(check_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("Scheduled tasks service shutting down");
                    break;
                }
            }
            _ = ticker.tick() => {
                if let Err(e) = process_scheduled_deletions(&db, blob_store.as_ref()).await {
                    error!("Error processing scheduled deletions: {}", e);
                }
            }
        }
    }
}

async fn process_scheduled_deletions(
    db: &PgPool,
    blob_store: &dyn BlobStorage,
) -> Result<(), String> {
    let accounts_to_delete = sqlx::query!(
        r#"
        SELECT did, handle
        FROM users
        WHERE delete_after IS NOT NULL
          AND delete_after < NOW()
          AND deactivated_at IS NOT NULL
        LIMIT 100
        "#
    )
    .fetch_all(db)
    .await
    .map_err(|e| format!("DB error fetching accounts to delete: {}", e))?;

    if accounts_to_delete.is_empty() {
        debug!("No accounts scheduled for deletion");
        return Ok(());
    }

    info!(
        count = accounts_to_delete.len(),
        "Processing scheduled account deletions"
    );

    futures::future::join_all(accounts_to_delete.into_iter().map(|account| async move {
        let result = delete_account_data(db, blob_store, &account.did, &account.handle).await;
        (account.did, account.handle, result)
    }))
    .await
    .into_iter()
    .for_each(|(did, handle, result)| match result {
        Ok(()) => info!(did = %did, handle = %handle, "Successfully deleted scheduled account"),
        Err(e) => warn!(did = %did, handle = %handle, error = %e, "Failed to delete scheduled account"),
    });

    Ok(())
}

async fn delete_account_data(
    db: &PgPool,
    blob_store: &dyn BlobStorage,
    did: &str,
    _handle: &str,
) -> Result<(), String> {
    let user_id: uuid::Uuid = sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did)
        .fetch_one(db)
        .await
        .map_err(|e| format!("DB error fetching user: {}", e))?;

    let blob_storage_keys: Vec<String> = sqlx::query_scalar!(
        r#"SELECT storage_key as "storage_key!" FROM blobs WHERE created_by_user = $1"#,
        user_id
    )
    .fetch_all(db)
    .await
    .map_err(|e| format!("DB error fetching blob keys: {}", e))?;

    futures::future::join_all(blob_storage_keys.iter().map(|storage_key| async move {
        (storage_key, blob_store.delete(storage_key).await)
    }))
    .await
    .into_iter()
    .filter_map(|(key, result)| result.err().map(|e| (key, e)))
    .for_each(|(key, e)| {
        warn!(storage_key = %key, error = %e, "Failed to delete blob from storage (continuing anyway)");
    });

    let mut tx = db
        .begin()
        .await
        .map_err(|e| format!("Failed to begin transaction: {}", e))?;

    sqlx::query!("DELETE FROM blobs WHERE created_by_user = $1", user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Failed to delete blobs: {}", e))?;

    sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Failed to delete user: {}", e))?;

    let account_seq = sqlx::query_scalar!(
        r#"
        INSERT INTO repo_seq (did, event_type, active, status)
        VALUES ($1, 'account', false, 'deleted')
        RETURNING seq
        "#,
        did
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| format!("Failed to sequence account deletion: {}", e))?;

    sqlx::query!(
        "DELETE FROM repo_seq WHERE did = $1 AND seq != $2",
        did,
        account_seq
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("Failed to cleanup sequences: {}", e))?;

    tx.commit()
        .await
        .map_err(|e| format!("Failed to commit transaction: {}", e))?;

    sqlx::query(&format!("NOTIFY repo_updates, '{}'", account_seq))
        .execute(db)
        .await
        .map_err(|e| format!("Failed to notify: {}", e))?;

    info!(
        did = %did,
        blob_count = blob_storage_keys.len(),
        "Deleted account data including blobs from storage"
    );

    Ok(())
}

pub async fn start_backup_tasks(
    db: PgPool,
    block_store: PostgresBlockStore,
    backup_storage: Arc<BackupStorage>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let backup_interval = Duration::from_secs(BackupStorage::interval_secs());

    info!(
        interval_secs = backup_interval.as_secs(),
        retention_count = BackupStorage::retention_count(),
        "Starting backup service"
    );

    let mut ticker = interval(backup_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("Backup service shutting down");
                    break;
                }
            }
            _ = ticker.tick() => {
                if let Err(e) = process_scheduled_backups(&db, &block_store, &backup_storage).await {
                    error!("Error processing scheduled backups: {}", e);
                }
            }
        }
    }
}

struct BackupResult {
    did: String,
    repo_rev: String,
    size_bytes: i64,
    block_count: i32,
    user_id: uuid::Uuid,
}

enum BackupOutcome {
    Success(BackupResult),
    Skipped(String, &'static str),
    Failed(String, String),
}

async fn process_single_backup(
    db: &PgPool,
    block_store: &PostgresBlockStore,
    backup_storage: &BackupStorage,
    user_id: uuid::Uuid,
    did: String,
    repo_root_cid: String,
    repo_rev: Option<String>,
) -> BackupOutcome {
    let repo_rev = match repo_rev {
        Some(rev) => rev,
        None => return BackupOutcome::Skipped(did, "no repo_rev"),
    };

    let head_cid = match Cid::from_str(&repo_root_cid) {
        Ok(c) => c,
        Err(_) => return BackupOutcome::Skipped(did, "invalid repo_root_cid"),
    };

    let car_bytes = match generate_full_backup(db, block_store, user_id, &head_cid).await {
        Ok(bytes) => bytes,
        Err(e) => return BackupOutcome::Failed(did, format!("CAR generation: {}", e)),
    };

    let block_count = count_car_blocks(&car_bytes);
    let size_bytes = car_bytes.len() as i64;

    let storage_key = match backup_storage.put_backup(&did, &repo_rev, &car_bytes).await {
        Ok(key) => key,
        Err(e) => return BackupOutcome::Failed(did, format!("S3 upload: {}", e)),
    };

    if let Err(e) = insert_backup_record(
        db,
        user_id,
        &storage_key,
        &repo_root_cid,
        &repo_rev,
        block_count,
        size_bytes,
    )
    .await
    {
        if let Err(rollback_err) = backup_storage.delete_backup(&storage_key).await {
            error!(
                did = %did,
                storage_key = %storage_key,
                error = %rollback_err,
                "Failed to rollback orphaned backup from S3"
            );
        }
        return BackupOutcome::Failed(did, format!("DB insert: {}", e));
    }

    BackupOutcome::Success(BackupResult {
        did,
        repo_rev,
        size_bytes,
        block_count,
        user_id,
    })
}

async fn process_scheduled_backups(
    db: &PgPool,
    block_store: &PostgresBlockStore,
    backup_storage: &BackupStorage,
) -> Result<(), String> {
    let backup_interval_secs = BackupStorage::interval_secs() as i64;
    let retention_count = BackupStorage::retention_count();

    let users_needing_backup = sqlx::query!(
        r#"
        SELECT u.id as user_id, u.did, r.repo_root_cid, r.repo_rev
        FROM users u
        JOIN repos r ON r.user_id = u.id
        WHERE u.backup_enabled = true
          AND u.deactivated_at IS NULL
          AND (
            NOT EXISTS (
              SELECT 1 FROM account_backups ab WHERE ab.user_id = u.id
            )
            OR (
              SELECT MAX(ab.created_at) FROM account_backups ab WHERE ab.user_id = u.id
            ) < NOW() - make_interval(secs => $1)
          )
        LIMIT 50
        "#,
        backup_interval_secs as f64
    )
    .fetch_all(db)
    .await
    .map_err(|e| format!("DB error fetching users for backup: {}", e))?;

    if users_needing_backup.is_empty() {
        debug!("No accounts need backup");
        return Ok(());
    }

    info!(
        count = users_needing_backup.len(),
        "Processing scheduled backups"
    );

    let results = futures::future::join_all(users_needing_backup.into_iter().map(|user| {
        process_single_backup(
            db,
            block_store,
            backup_storage,
            user.user_id,
            user.did,
            user.repo_root_cid,
            user.repo_rev,
        )
    }))
    .await;

    futures::future::join_all(results.into_iter().map(|outcome| async move {
        match outcome {
            BackupOutcome::Success(result) => {
                info!(
                    did = %result.did,
                    rev = %result.repo_rev,
                    size_bytes = result.size_bytes,
                    block_count = result.block_count,
                    "Created backup"
                );
                if let Err(e) =
                    cleanup_old_backups(db, backup_storage, result.user_id, retention_count).await
                {
                    warn!(did = %result.did, error = %e, "Failed to cleanup old backups");
                }
            }
            BackupOutcome::Skipped(did, reason) => {
                warn!(did = %did, reason = reason, "Skipped backup");
            }
            BackupOutcome::Failed(did, error) => {
                warn!(did = %did, error = %error, "Failed backup");
            }
        }
    }))
    .await;

    Ok(())
}

pub async fn generate_repo_car(
    block_store: &PostgresBlockStore,
    head_cid: &Cid,
) -> Result<Vec<u8>, String> {
    use jacquard_repo::storage::BlockStore;

    let block_cids_bytes = collect_current_repo_blocks(block_store, head_cid).await?;
    let block_cids: Vec<Cid> = block_cids_bytes
        .iter()
        .filter_map(|b| Cid::try_from(b.as_slice()).ok())
        .collect();

    let car_bytes =
        encode_car_header(head_cid).map_err(|e| format!("Failed to encode CAR header: {}", e))?;

    let blocks = block_store
        .get_many(&block_cids)
        .await
        .map_err(|e| format!("Failed to fetch blocks: {:?}", e))?;

    let car_bytes = block_cids
        .iter()
        .zip(blocks.iter())
        .filter_map(|(cid, block_opt)| block_opt.as_ref().map(|block| (cid, block)))
        .fold(car_bytes, |mut acc, (cid, block)| {
            acc.extend(encode_car_block(cid, block));
            acc
        });

    Ok(car_bytes)
}

fn encode_car_block(cid: &Cid, block: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let cid_bytes = cid.to_bytes();
    let total_len = cid_bytes.len() + block.len();
    let mut writer = Vec::new();
    crate::sync::car::write_varint(&mut writer, total_len as u64)
        .expect("Writing to Vec<u8> should never fail");
    writer
        .write_all(&cid_bytes)
        .expect("Writing to Vec<u8> should never fail");
    writer
        .write_all(block)
        .expect("Writing to Vec<u8> should never fail");
    writer
}

pub async fn generate_repo_car_from_user_blocks(
    db: &PgPool,
    block_store: &PostgresBlockStore,
    user_id: uuid::Uuid,
    _head_cid: &Cid,
) -> Result<Vec<u8>, String> {
    use std::str::FromStr;

    let repo_root_cid_str: String = sqlx::query_scalar!(
        "SELECT repo_root_cid FROM repos WHERE user_id = $1",
        user_id
    )
    .fetch_optional(db)
    .await
    .map_err(|e| format!("Failed to fetch repo: {}", e))?
    .ok_or_else(|| "Repository not found".to_string())?;

    let actual_head_cid =
        Cid::from_str(&repo_root_cid_str).map_err(|e| format!("Invalid repo_root_cid: {}", e))?;

    generate_repo_car(block_store, &actual_head_cid).await
}

pub async fn generate_full_backup(
    db: &PgPool,
    block_store: &PostgresBlockStore,
    user_id: uuid::Uuid,
    head_cid: &Cid,
) -> Result<Vec<u8>, String> {
    generate_repo_car_from_user_blocks(db, block_store, user_id, head_cid).await
}

pub fn count_car_blocks(car_bytes: &[u8]) -> i32 {
    let mut count = 0;
    let mut pos = 0;

    if let Some((header_len, header_varint_len)) = read_varint(&car_bytes[pos..]) {
        pos += header_varint_len + header_len as usize;
    } else {
        return 0;
    }

    while pos < car_bytes.len() {
        if let Some((block_len, varint_len)) = read_varint(&car_bytes[pos..]) {
            pos += varint_len + block_len as usize;
            count += 1;
        } else {
            break;
        }
    }

    count
}

fn read_varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0;
    let mut pos = 0;

    while pos < data.len() && pos < 10 {
        let byte = data[pos];
        value |= ((byte & 0x7f) as u64) << shift;
        pos += 1;
        if byte & 0x80 == 0 {
            return Some((value, pos));
        }
        shift += 7;
    }

    None
}

async fn cleanup_old_backups(
    db: &PgPool,
    backup_storage: &BackupStorage,
    user_id: uuid::Uuid,
    retention_count: u32,
) -> Result<(), String> {
    let old_backups = fetch_old_backups(db, user_id, retention_count as i64)
        .await
        .map_err(|e| format!("DB error fetching old backups: {}", e))?;

    let results = futures::future::join_all(old_backups.into_iter().map(|(id, storage_key)| async move {
        match backup_storage.delete_backup(&storage_key).await {
            Ok(()) => match delete_backup_record(db, id).await {
                Ok(()) => Ok(()),
                Err(e) => Err(format!("DB delete failed for {}: {}", storage_key, e)),
            },
            Err(e) => {
                warn!(
                    storage_key = %storage_key,
                    error = %e,
                    "Failed to delete old backup from storage, skipping DB cleanup to avoid orphan"
                );
                Ok(())
            }
        }
    }))
    .await;

    results
        .into_iter()
        .find_map(|r| r.err())
        .map_or(Ok(()), Err)
}
