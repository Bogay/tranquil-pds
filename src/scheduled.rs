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

    let mut success = 0;
    let mut failed = 0;

    for commit_row in broken_genesis_commits {
        let commit_cid_str = match &commit_row.commit_cid {
            Some(c) => c.clone(),
            None => {
                warn!(seq = commit_row.seq, "Genesis commit missing commit_cid");
                failed += 1;
                continue;
            }
        };

        let commit_cid = match Cid::from_str(&commit_cid_str) {
            Ok(c) => c,
            Err(_) => {
                warn!(seq = commit_row.seq, "Invalid commit CID");
                failed += 1;
                continue;
            }
        };

        let block = match block_store.get(&commit_cid).await {
            Ok(Some(b)) => b,
            Ok(None) => {
                warn!(seq = commit_row.seq, cid = %commit_cid_str, "Commit block not found in store");
                failed += 1;
                continue;
            }
            Err(e) => {
                warn!(seq = commit_row.seq, error = %e, "Failed to fetch commit block");
                failed += 1;
                continue;
            }
        };

        let commit = match Commit::from_cbor(&block) {
            Ok(c) => c,
            Err(e) => {
                warn!(seq = commit_row.seq, error = %e, "Failed to parse commit");
                failed += 1;
                continue;
            }
        };

        let mst_root_cid = commit.data;
        let blocks_cids: Vec<String> = vec![mst_root_cid.to_string(), commit_cid.to_string()];

        if let Err(e) = sqlx::query!(
            "UPDATE repo_seq SET blocks_cids = $1 WHERE seq = $2",
            &blocks_cids,
            commit_row.seq
        )
        .execute(db)
        .await
        {
            warn!(seq = commit_row.seq, error = %e, "Failed to update blocks_cids");
            failed += 1;
        } else {
            info!(seq = commit_row.seq, did = %commit_row.did, "Fixed genesis commit blocks_cids");
            success += 1;
        }
    }

    info!(
        success,
        failed, "Completed genesis commit blocks_cids backfill"
    );
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

    let mut success = 0;
    let mut failed = 0;

    for repo in repos_missing_rev {
        let cid = match Cid::from_str(&repo.repo_root_cid) {
            Ok(c) => c,
            Err(_) => {
                failed += 1;
                continue;
            }
        };

        let block = match block_store.get(&cid).await {
            Ok(Some(b)) => b,
            _ => {
                failed += 1;
                continue;
            }
        };

        let commit = match Commit::from_cbor(&block) {
            Ok(c) => c,
            Err(_) => {
                failed += 1;
                continue;
            }
        };

        let rev = commit.rev().to_string();

        if let Err(e) = sqlx::query!(
            "UPDATE repos SET repo_rev = $1 WHERE user_id = $2",
            rev,
            repo.user_id
        )
        .execute(db)
        .await
        {
            warn!(user_id = %repo.user_id, error = %e, "Failed to update repo_rev");
            failed += 1;
        } else {
            success += 1;
        }
    }

    info!(success, failed, "Completed repo_rev backfill");
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

    let mut success = 0;
    let mut failed = 0;

    for user in users_without_blocks {
        let root_cid = match Cid::from_str(&user.repo_root_cid) {
            Ok(c) => c,
            Err(_) => {
                failed += 1;
                continue;
            }
        };

        match collect_current_repo_blocks(&block_store, &root_cid).await {
            Ok(block_cids) => {
                if block_cids.is_empty() {
                    failed += 1;
                    continue;
                }

                if let Err(e) = sqlx::query!(
                    r#"
                    INSERT INTO user_blocks (user_id, block_cid)
                    SELECT $1, block_cid FROM UNNEST($2::bytea[]) AS t(block_cid)
                    ON CONFLICT (user_id, block_cid) DO NOTHING
                    "#,
                    user.user_id,
                    &block_cids
                )
                .execute(db)
                .await
                {
                    warn!(user_id = %user.user_id, error = %e, "Failed to backfill user_blocks");
                    failed += 1;
                } else {
                    info!(user_id = %user.user_id, block_count = block_cids.len(), "Backfilled user_blocks");
                    success += 1;
                }
            }
            Err(e) => {
                warn!(user_id = %user.user_id, error = %e, "Failed to collect repo blocks for backfill");
                failed += 1;
            }
        }
    }

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

    let mut success = 0;
    let mut failed = 0;

    for user in users_needing_backfill {
        let records = match sqlx::query!(
            "SELECT collection, rkey, record_cid FROM records WHERE repo_id = $1",
            user.user_id
        )
        .fetch_all(db)
        .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(user_id = %user.user_id, error = %e, "Failed to fetch records for backfill");
                failed += 1;
                continue;
            }
        };

        let mut batch_record_uris: Vec<String> = Vec::new();
        let mut batch_blob_cids: Vec<String> = Vec::new();

        for record in records {
            let record_cid = match Cid::from_str(&record.record_cid) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let block_bytes = match block_store.get(&record_cid).await {
                Ok(Some(b)) => b,
                _ => continue,
            };

            let record_ipld: Ipld = match serde_ipld_dagcbor::from_slice(&block_bytes) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let blob_refs = crate::sync::import::find_blob_refs_ipld(&record_ipld, 0);
            for blob_ref in blob_refs {
                let record_uri = format!("at://{}/{}/{}", user.did, record.collection, record.rkey);
                batch_record_uris.push(record_uri);
                batch_blob_cids.push(blob_ref.cid);
            }
        }

        let blob_refs_found = batch_record_uris.len();
        if !batch_record_uris.is_empty() {
            if let Err(e) = sqlx::query!(
                r#"
                INSERT INTO record_blobs (repo_id, record_uri, blob_cid)
                SELECT $1, record_uri, blob_cid
                FROM UNNEST($2::text[], $3::text[]) AS t(record_uri, blob_cid)
                ON CONFLICT (repo_id, record_uri, blob_cid) DO NOTHING
                "#,
                user.user_id,
                &batch_record_uris,
                &batch_blob_cids
            )
            .execute(db)
            .await
            {
                warn!(error = %e, "Failed to batch insert record_blobs during backfill");
            } else {
                info!(
                    user_id = %user.user_id,
                    did = %user.did,
                    blob_refs = blob_refs_found,
                    "Backfilled record_blobs"
                );
            }
        }
        success += 1;
    }

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

    for account in accounts_to_delete {
        if let Err(e) = delete_account_data(db, blob_store, &account.did, &account.handle).await {
            warn!(
                did = %account.did,
                handle = %account.handle,
                error = %e,
                "Failed to delete scheduled account"
            );
        } else {
            info!(
                did = %account.did,
                handle = %account.handle,
                "Successfully deleted scheduled account"
            );
        }
    }

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

    for storage_key in &blob_storage_keys {
        if let Err(e) = blob_store.delete(storage_key).await {
            warn!(
                storage_key = %storage_key,
                error = %e,
                "Failed to delete blob from storage (continuing anyway)"
            );
        }
    }

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

    for user in users_needing_backup {
        let repo_root_cid = user.repo_root_cid.clone();

        let repo_rev = match &user.repo_rev {
            Some(rev) => rev.clone(),
            None => {
                warn!(did = %user.did, "User has no repo_rev, skipping backup");
                continue;
            }
        };

        let head_cid = match Cid::from_str(&repo_root_cid) {
            Ok(c) => c,
            Err(e) => {
                warn!(did = %user.did, error = %e, "Invalid repo_root_cid, skipping backup");
                continue;
            }
        };

        let car_result = generate_full_backup(db, block_store, user.user_id, &head_cid).await;
        let car_bytes = match car_result {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!(did = %user.did, error = %e, "Failed to generate CAR for backup");
                continue;
            }
        };

        let block_count = count_car_blocks(&car_bytes);
        let size_bytes = car_bytes.len() as i64;

        let storage_key = match backup_storage
            .put_backup(&user.did, &repo_rev, &car_bytes)
            .await
        {
            Ok(key) => key,
            Err(e) => {
                warn!(did = %user.did, error = %e, "Failed to upload backup to storage");
                continue;
            }
        };

        if let Err(e) = sqlx::query!(
            r#"
            INSERT INTO account_backups (user_id, storage_key, repo_root_cid, repo_rev, block_count, size_bytes)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            user.user_id,
            storage_key,
            repo_root_cid,
            repo_rev,
            block_count,
            size_bytes
        )
        .execute(db)
        .await
        {
            warn!(did = %user.did, error = %e, "Failed to insert backup record, rolling back S3 upload");
            if let Err(rollback_err) = backup_storage.delete_backup(&storage_key).await {
                error!(
                    did = %user.did,
                    storage_key = %storage_key,
                    error = %rollback_err,
                    "Failed to rollback orphaned backup from S3"
                );
            }
            continue;
        }

        info!(
            did = %user.did,
            rev = %repo_rev,
            size_bytes,
            block_count,
            "Created backup"
        );

        if let Err(e) = cleanup_old_backups(db, backup_storage, user.user_id, retention_count).await
        {
            warn!(did = %user.did, error = %e, "Failed to cleanup old backups");
        }
    }

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
    head_cid: &Cid,
) -> Result<Vec<u8>, String> {
    use jacquard_repo::storage::BlockStore;

    let block_cid_bytes: Vec<Vec<u8>> = sqlx::query_scalar!(
        "SELECT block_cid FROM user_blocks WHERE user_id = $1",
        user_id
    )
    .fetch_all(db)
    .await
    .map_err(|e| format!("Failed to fetch user_blocks: {}", e))?;

    if block_cid_bytes.is_empty() {
        let cids = collect_current_repo_blocks(block_store, head_cid).await?;
        if cids.is_empty() {
            return Err("No blocks found for repo".to_string());
        }
        return generate_repo_car(block_store, head_cid).await;
    }

    let block_cids: Vec<Cid> = block_cid_bytes
        .iter()
        .filter_map(|bytes| Cid::try_from(bytes.as_slice()).ok())
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
    let old_backups = sqlx::query!(
        r#"
        SELECT id, storage_key
        FROM account_backups
        WHERE user_id = $1
        ORDER BY created_at DESC
        OFFSET $2
        "#,
        user_id,
        retention_count as i64
    )
    .fetch_all(db)
    .await
    .map_err(|e| format!("DB error fetching old backups: {}", e))?;

    for backup in old_backups {
        if let Err(e) = backup_storage.delete_backup(&backup.storage_key).await {
            warn!(
                storage_key = %backup.storage_key,
                error = %e,
                "Failed to delete old backup from storage, skipping DB cleanup to avoid orphan"
            );
            continue;
        }

        sqlx::query!("DELETE FROM account_backups WHERE id = $1", backup.id)
            .execute(db)
            .await
            .map_err(|e| format!("Failed to delete old backup record: {}", e))?;
    }

    Ok(())
}
