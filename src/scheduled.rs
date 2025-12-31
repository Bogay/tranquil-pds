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
use crate::storage::BlobStorage;

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

        let mut block_cids: Vec<Vec<u8>> = Vec::new();
        let mut to_visit = vec![root_cid];
        let mut visited = std::collections::HashSet::new();

        while let Some(cid) = to_visit.pop() {
            if visited.contains(&cid) {
                continue;
            }
            visited.insert(cid);
            block_cids.push(cid.to_bytes());

            let block = match block_store.get(&cid).await {
                Ok(Some(b)) => b,
                _ => continue,
            };

            if let Ok(commit) = Commit::from_cbor(&block) {
                to_visit.push(commit.data);
                if let Some(prev) = commit.prev {
                    to_visit.push(prev);
                }
            } else if let Ok(Ipld::Map(ref obj)) = serde_ipld_dagcbor::from_slice::<Ipld>(&block) {
                if let Some(Ipld::Link(left_cid)) = obj.get("l") {
                    to_visit.push(*left_cid);
                }
                if let Some(Ipld::List(entries)) = obj.get("e") {
                    for entry in entries {
                        if let Ipld::Map(entry_obj) = entry {
                            if let Some(Ipld::Link(tree_cid)) = entry_obj.get("t") {
                                to_visit.push(*tree_cid);
                            }
                            if let Some(Ipld::Link(val_cid)) = entry_obj.get("v") {
                                to_visit.push(*val_cid);
                            }
                        }
                    }
                }
            }
        }

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

    info!(success, failed, "Completed user_blocks backfill");
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

        let mut blob_refs_found = 0;
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
                if let Err(e) = sqlx::query!(
                    r#"
                    INSERT INTO record_blobs (repo_id, record_uri, blob_cid)
                    VALUES ($1, $2, $3)
                    ON CONFLICT (repo_id, record_uri, blob_cid) DO NOTHING
                    "#,
                    user.user_id,
                    record_uri,
                    blob_ref.cid
                )
                .execute(db)
                .await
                {
                    warn!(error = %e, "Failed to insert record_blob during backfill");
                } else {
                    blob_refs_found += 1;
                }
            }
        }

        if blob_refs_found > 0 {
            info!(
                user_id = %user.user_id,
                did = %user.did,
                blob_refs = blob_refs_found,
                "Backfilled record_blobs"
            );
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
                if let Err(e) = process_scheduled_deletions(&db, &blob_store).await {
                    error!("Error processing scheduled deletions: {}", e);
                }
            }
        }
    }
}

async fn process_scheduled_deletions(
    db: &PgPool,
    blob_store: &Arc<dyn BlobStorage>,
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
    blob_store: &Arc<dyn BlobStorage>,
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
