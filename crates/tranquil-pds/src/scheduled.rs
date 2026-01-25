use cid::Cid;
use ipld_core::ipld::Ipld;
use jacquard_repo::commit::Commit;
use jacquard_repo::storage::BlockStore;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use tranquil_db_traits::{
    BackupRepository, BlobRepository, BrokenGenesisCommit, RepoRepository, SequenceNumber,
    SsoRepository, UserRepository,
};
use tranquil_types::{AtUri, CidLink, Did};

use crate::repo::PostgresBlockStore;
use crate::storage::{BackupStorage, BlobStorage, backup_interval_secs, backup_retention_count};
use crate::sync::car::encode_car_header;

async fn process_genesis_commit(
    repo_repo: &dyn RepoRepository,
    block_store: &PostgresBlockStore,
    row: BrokenGenesisCommit,
) -> Result<(Did, SequenceNumber), (SequenceNumber, &'static str)> {
    let commit_cid_str = row.commit_cid.ok_or((row.seq, "missing commit_cid"))?;
    let commit_cid = Cid::from_str(&commit_cid_str).map_err(|_| (row.seq, "invalid CID"))?;
    let block = block_store
        .get(&commit_cid)
        .await
        .map_err(|_| (row.seq, "failed to fetch block"))?
        .ok_or((row.seq, "block not found"))?;
    let commit = Commit::from_cbor(&block).map_err(|_| (row.seq, "failed to parse commit"))?;
    let blocks_cids = vec![commit.data.to_string(), commit_cid.to_string()];
    repo_repo
        .update_seq_blocks_cids(row.seq, &blocks_cids)
        .await
        .map_err(|_| (row.seq, "failed to update"))?;
    Ok((row.did, row.seq))
}

pub async fn backfill_genesis_commit_blocks(
    repo_repo: Arc<dyn RepoRepository>,
    block_store: PostgresBlockStore,
) {
    let broken_genesis_commits = match repo_repo.get_broken_genesis_commits().await {
        Ok(rows) => rows,
        Err(e) => {
            error!(
                "Failed to query repo_seq for genesis commit backfill: {:?}",
                e
            );
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
        let repo_repo = repo_repo.clone();
        let block_store = block_store.clone();
        async move { process_genesis_commit(repo_repo.as_ref(), &block_store, row).await }
    }))
    .await;

    let (success, failed) = results.iter().fold((0, 0), |(s, f), r| match r {
        Ok((did, seq)) => {
            info!(seq = seq.as_i64(), did = %did, "Fixed genesis commit blocks_cids");
            (s + 1, f)
        }
        Err((seq, reason)) => {
            warn!(
                seq = seq.as_i64(),
                reason = reason,
                "Failed to process genesis commit"
            );
            (s, f + 1)
        }
    });

    info!(
        success,
        failed, "Completed genesis commit blocks_cids backfill"
    );
}

async fn process_repo_rev(
    repo_repo: &dyn RepoRepository,
    block_store: &PostgresBlockStore,
    user_id: uuid::Uuid,
    repo_root_cid: String,
) -> Result<uuid::Uuid, uuid::Uuid> {
    let cid = Cid::from_str(&repo_root_cid).map_err(|_| user_id)?;
    let block = block_store.get(&cid).await.ok().flatten().ok_or(user_id)?;
    let commit = Commit::from_cbor(&block).map_err(|_| user_id)?;
    let rev = commit.rev().to_string();
    repo_repo
        .update_repo_rev(user_id, &rev)
        .await
        .map_err(|_| user_id)?;
    Ok(user_id)
}

pub async fn backfill_repo_rev(
    repo_repo: Arc<dyn RepoRepository>,
    block_store: PostgresBlockStore,
) {
    let repos_missing_rev = match repo_repo.get_repos_without_rev().await {
        Ok(rows) => rows,
        Err(e) => {
            error!("Failed to query repos for backfill: {:?}", e);
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
        let repo_repo = repo_repo.clone();
        let block_store = block_store.clone();
        async move {
            process_repo_rev(
                repo_repo.as_ref(),
                &block_store,
                repo.user_id,
                repo.repo_root_cid.to_string(),
            )
            .await
        }
    }))
    .await;

    let (success, failed) = results.iter().fold((0, 0), |(s, f), r| match r {
        Ok(_) => (s + 1, f),
        Err(user_id) => {
            warn!(user_id = %user_id, "Failed to update repo_rev");
            (s, f + 1)
        }
    });

    info!(success, failed, "Completed repo_rev backfill");
}

async fn process_user_blocks(
    repo_repo: &dyn RepoRepository,
    block_store: &PostgresBlockStore,
    user_id: uuid::Uuid,
    repo_root_cid: String,
    repo_rev: Option<String>,
) -> Result<(uuid::Uuid, usize), uuid::Uuid> {
    let root_cid = Cid::from_str(&repo_root_cid).map_err(|_| user_id)?;
    let block_cids = collect_current_repo_blocks(block_store, &root_cid)
        .await
        .map_err(|_| user_id)?;
    if block_cids.is_empty() {
        return Err(user_id);
    }
    let count = block_cids.len();
    let rev = repo_rev.unwrap_or_else(|| "0".to_string());
    repo_repo
        .insert_user_blocks(user_id, &block_cids, &rev)
        .await
        .map_err(|_| user_id)?;
    Ok((user_id, count))
}

pub async fn backfill_user_blocks(
    repo_repo: Arc<dyn RepoRepository>,
    block_store: PostgresBlockStore,
) {
    let users_without_blocks = match repo_repo.get_users_without_blocks().await {
        Ok(rows) => rows,
        Err(e) => {
            error!("Failed to query users for user_blocks backfill: {:?}", e);
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
        let repo_repo = repo_repo.clone();
        let block_store = block_store.clone();
        async move {
            process_user_blocks(
                repo_repo.as_ref(),
                &block_store,
                user.user_id,
                user.repo_root_cid.to_string(),
                user.repo_rev,
            )
            .await
        }
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
    repo_repo: &dyn RepoRepository,
    block_store: &PostgresBlockStore,
    user_id: uuid::Uuid,
    did: Did,
) -> Result<(uuid::Uuid, Did, usize), (uuid::Uuid, &'static str)> {
    let records = repo_repo
        .get_all_records(user_id)
        .await
        .map_err(|_| (user_id, "failed to fetch records"))?;

    let mut batch_record_uris: Vec<AtUri> = Vec::new();
    let mut batch_blob_cids: Vec<CidLink> = Vec::new();

    futures::future::join_all(records.into_iter().map(|record| {
        let did = did.clone();
        async move {
            let cid = Cid::from_str(&record.record_cid).ok()?;
            let block_bytes = block_store.get(&cid).await.ok()??;
            let record_ipld: Ipld = serde_ipld_dagcbor::from_slice(&block_bytes).ok()?;
            let blob_refs = crate::sync::import::find_blob_refs_ipld(&record_ipld, 0);
            Some(
                blob_refs
                    .into_iter()
                    .map(|blob_ref| {
                        let record_uri = AtUri::from_parts(
                            did.as_str(),
                            record.collection.as_str(),
                            record.rkey.as_str(),
                        );
                        (record_uri, unsafe { CidLink::new_unchecked(blob_ref.cid) })
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
        repo_repo
            .insert_record_blobs(user_id, &batch_record_uris, &batch_blob_cids)
            .await
            .map_err(|_| (user_id, "failed to insert"))?;
    }
    Ok((user_id, did, blob_refs_found))
}

pub async fn backfill_record_blobs(
    repo_repo: Arc<dyn RepoRepository>,
    block_store: PostgresBlockStore,
) {
    let users_needing_backfill = match repo_repo.get_users_needing_record_blobs_backfill(100).await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("Failed to query users for record_blobs backfill: {:?}", e);
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
        let repo_repo = repo_repo.clone();
        let block_store = block_store.clone();
        async move {
            process_record_blobs(repo_repo.as_ref(), &block_store, user.user_id, user.did).await
        }
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
    user_repo: Arc<dyn UserRepository>,
    blob_repo: Arc<dyn BlobRepository>,
    blob_store: Arc<dyn BlobStorage>,
    sso_repo: Arc<dyn SsoRepository>,
    shutdown: CancellationToken,
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
            _ = shutdown.cancelled() => {
                info!("Scheduled tasks service shutting down");
                break;
            }
            _ = ticker.tick() => {
                if let Err(e) = process_scheduled_deletions(
                    user_repo.as_ref(),
                    blob_repo.as_ref(),
                    blob_store.as_ref(),
                ).await {
                    error!("Error processing scheduled deletions: {}", e);
                }

                match sso_repo.cleanup_expired_sso_auth_states().await {
                    Ok(count) if count > 0 => {
                        info!(count = count, "Cleaned up expired SSO auth states");
                    }
                    Ok(_) => {}
                    Err(e) => {
                        error!("Error cleaning up SSO auth states: {:?}", e);
                    }
                }

                match sso_repo.cleanup_expired_pending_registrations().await {
                    Ok(count) if count > 0 => {
                        info!(count = count, "Cleaned up expired SSO pending registrations");
                    }
                    Ok(_) => {}
                    Err(e) => {
                        error!("Error cleaning up SSO pending registrations: {:?}", e);
                    }
                }

                match user_repo.cleanup_expired_handle_reservations().await {
                    Ok(count) if count > 0 => {
                        info!(count = count, "Cleaned up expired handle reservations");
                    }
                    Ok(_) => {}
                    Err(e) => {
                        error!("Error cleaning up handle reservations: {:?}", e);
                    }
                }
            }
        }
    }
}

async fn process_scheduled_deletions(
    user_repo: &dyn UserRepository,
    blob_repo: &dyn BlobRepository,
    blob_store: &dyn BlobStorage,
) -> Result<(), String> {
    let accounts_to_delete = user_repo
        .get_accounts_scheduled_for_deletion(100)
        .await
        .map_err(|e| format!("DB error fetching accounts to delete: {:?}", e))?;

    if accounts_to_delete.is_empty() {
        debug!("No accounts scheduled for deletion");
        return Ok(());
    }

    info!(
        count = accounts_to_delete.len(),
        "Processing scheduled account deletions"
    );

    futures::future::join_all(accounts_to_delete.into_iter().map(|account| async move {
        let result =
            delete_account_data(user_repo, blob_repo, blob_store, account.id, &account.did).await;
        (account.did, account.handle, result)
    }))
    .await
    .into_iter()
    .for_each(|(did, handle, result)| match result {
        Ok(()) => info!(did = %did, handle = %handle, "Successfully deleted scheduled account"),
        Err(e) => {
            warn!(did = %did, handle = %handle, error = %e, "Failed to delete scheduled account")
        }
    });

    Ok(())
}

async fn delete_account_data(
    user_repo: &dyn UserRepository,
    blob_repo: &dyn BlobRepository,
    blob_store: &dyn BlobStorage,
    user_id: uuid::Uuid,
    did: &Did,
) -> Result<(), String> {
    let blob_storage_keys = blob_repo
        .get_blob_storage_keys_by_user(user_id)
        .await
        .map_err(|e| format!("DB error fetching blob keys: {:?}", e))?;

    futures::future::join_all(blob_storage_keys.iter().map(|storage_key| async move {
        (storage_key, blob_store.delete(storage_key).await)
    }))
    .await
    .into_iter()
    .filter_map(|(key, result)| result.err().map(|e| (key, e)))
    .for_each(|(key, e)| {
        warn!(storage_key = %key, error = %e, "Failed to delete blob from storage (continuing anyway)");
    });

    let _account_seq = user_repo
        .delete_account_with_firehose(user_id, did)
        .await
        .map_err(|e| format!("Failed to delete account: {:?}", e))?;

    info!(
        did = %did,
        blob_count = blob_storage_keys.len(),
        "Deleted account data including blobs from storage"
    );

    Ok(())
}

pub async fn start_backup_tasks(
    repo_repo: Arc<dyn RepoRepository>,
    backup_repo: Arc<dyn BackupRepository>,
    block_store: PostgresBlockStore,
    backup_storage: Arc<dyn BackupStorage>,
    shutdown: CancellationToken,
) {
    let backup_interval = Duration::from_secs(backup_interval_secs());

    info!(
        interval_secs = backup_interval.as_secs(),
        retention_count = backup_retention_count(),
        "Starting backup service"
    );

    let mut ticker = interval(backup_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                info!("Backup service shutting down");
                break;
            }
            _ = ticker.tick() => {
                if let Err(e) = process_scheduled_backups(
                    repo_repo.as_ref(),
                    backup_repo.as_ref(),
                    &block_store,
                    backup_storage.as_ref(),
                ).await {
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

#[allow(clippy::too_many_arguments)]
async fn process_single_backup(
    repo_repo: &dyn RepoRepository,
    backup_repo: &dyn BackupRepository,
    block_store: &PostgresBlockStore,
    backup_storage: &dyn BackupStorage,
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

    let car_bytes = match generate_full_backup(repo_repo, block_store, user_id, &head_cid).await {
        Ok(bytes) => bytes,
        Err(e) => return BackupOutcome::Failed(did, format!("CAR generation: {}", e)),
    };

    let block_count = count_car_blocks(&car_bytes);
    let size_bytes = car_bytes.len() as i64;

    let storage_key = match backup_storage.put_backup(&did, &repo_rev, &car_bytes).await {
        Ok(key) => key,
        Err(e) => return BackupOutcome::Failed(did, format!("S3 upload: {}", e)),
    };

    if let Err(e) = backup_repo
        .insert_backup(
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
        return BackupOutcome::Failed(did, format!("DB insert: {:?}", e));
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
    repo_repo: &dyn RepoRepository,
    backup_repo: &dyn BackupRepository,
    block_store: &PostgresBlockStore,
    backup_storage: &dyn BackupStorage,
) -> Result<(), String> {
    let interval_secs = backup_interval_secs() as i64;
    let retention = backup_retention_count();

    let users_needing_backup = backup_repo
        .get_users_needing_backup(interval_secs, 50)
        .await
        .map_err(|e| format!("DB error fetching users for backup: {:?}", e))?;

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
            repo_repo,
            backup_repo,
            block_store,
            backup_storage,
            user.id,
            user.did.to_string(),
            user.repo_root_cid.to_string(),
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
                    cleanup_old_backups(backup_repo, backup_storage, result.user_id, retention)
                        .await
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
    repo_repo: &dyn tranquil_db_traits::RepoRepository,
    block_store: &PostgresBlockStore,
    user_id: uuid::Uuid,
    _head_cid: &Cid,
) -> Result<Vec<u8>, String> {
    use std::str::FromStr;

    let repo_root_cid_str: String = repo_repo
        .get_repo_root_cid_by_user_id(user_id)
        .await
        .map_err(|e| format!("Failed to fetch repo: {:?}", e))?
        .ok_or_else(|| "Repository not found".to_string())?
        .to_string();

    let actual_head_cid =
        Cid::from_str(&repo_root_cid_str).map_err(|e| format!("Invalid repo_root_cid: {}", e))?;

    generate_repo_car(block_store, &actual_head_cid).await
}

pub async fn generate_full_backup(
    repo_repo: &dyn tranquil_db_traits::RepoRepository,
    block_store: &PostgresBlockStore,
    user_id: uuid::Uuid,
    head_cid: &Cid,
) -> Result<Vec<u8>, String> {
    generate_repo_car_from_user_blocks(repo_repo, block_store, user_id, head_cid).await
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
    backup_repo: &dyn BackupRepository,
    backup_storage: &dyn BackupStorage,
    user_id: uuid::Uuid,
    retention_count: u32,
) -> Result<(), String> {
    let old_backups = backup_repo
        .get_old_backups(user_id, retention_count as i64)
        .await
        .map_err(|e| format!("DB error fetching old backups: {:?}", e))?;

    let results = futures::future::join_all(old_backups.into_iter().map(|backup| async move {
        match backup_storage.delete_backup(&backup.storage_key).await {
            Ok(()) => match backup_repo.delete_backup(backup.id).await {
                Ok(()) => Ok(()),
                Err(e) => Err(format!(
                    "DB delete failed for {}: {:?}",
                    backup.storage_key, e
                )),
            },
            Err(e) => {
                warn!(
                    storage_key = %backup.storage_key,
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
