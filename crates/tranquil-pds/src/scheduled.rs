use anyhow::Context;
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
    BlobRepository, BrokenGenesisCommit, RepoRepository, SequenceNumber, SsoRepository,
    UserRepository,
};
use tranquil_types::{AtUri, CidLink, Did};

use crate::repo::PostgresBlockStore;
use crate::storage::BlobStorage;
use crate::sync::car::encode_car_header;

#[derive(Debug)]
enum GenesisBackfillError {
    MissingCommitCid,
    InvalidCid,
    BlockFetchFailed,
    BlockNotFound,
    CommitParseFailed,
    UpdateFailed,
}

impl std::fmt::Display for GenesisBackfillError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingCommitCid => f.write_str("missing commit_cid"),
            Self::InvalidCid => f.write_str("invalid CID"),
            Self::BlockFetchFailed => f.write_str("failed to fetch block"),
            Self::BlockNotFound => f.write_str("block not found"),
            Self::CommitParseFailed => f.write_str("failed to parse commit"),
            Self::UpdateFailed => f.write_str("failed to update"),
        }
    }
}

async fn process_genesis_commit(
    repo_repo: &dyn RepoRepository,
    block_store: &PostgresBlockStore,
    row: BrokenGenesisCommit,
) -> Result<(Did, SequenceNumber), (SequenceNumber, GenesisBackfillError)> {
    let commit_cid_str = row
        .commit_cid
        .ok_or((row.seq, GenesisBackfillError::MissingCommitCid))?;
    let commit_cid =
        Cid::from_str(&commit_cid_str).map_err(|_| (row.seq, GenesisBackfillError::InvalidCid))?;
    let block = block_store
        .get(&commit_cid)
        .await
        .map_err(|_| (row.seq, GenesisBackfillError::BlockFetchFailed))?
        .ok_or((row.seq, GenesisBackfillError::BlockNotFound))?;
    let commit = Commit::from_cbor(&block)
        .map_err(|_| (row.seq, GenesisBackfillError::CommitParseFailed))?;
    let blocks_cids = vec![commit.data.to_string(), commit_cid.to_string()];
    repo_repo
        .update_seq_blocks_cids(row.seq, &blocks_cids)
        .await
        .map_err(|_| (row.seq, GenesisBackfillError::UpdateFailed))?;
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
                reason = %reason,
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
    let block = match block_store.get(&cid).await {
        Ok(Some(b)) => b,
        Ok(None) => {
            tracing::warn!(user_id = %user_id, cid = %cid, "block not found for repo rev backfill");
            return Err(user_id);
        }
        Err(e) => {
            tracing::warn!(user_id = %user_id, cid = %cid, error = %e, "block store error during repo rev backfill");
            return Err(user_id);
        }
    };
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
) -> anyhow::Result<Vec<Vec<u8>>> {
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
            Err(e) => anyhow::bail!("Failed to get block {}: {:?}", cid, e),
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
                    .filter_map(|blob_ref| {
                        let record_uri = AtUri::from_parts(
                            did.as_str(),
                            record.collection.as_str(),
                            record.rkey.as_str(),
                        );
                        match CidLink::new(&blob_ref.cid) {
                            Ok(cid_link) => Some((record_uri, cid_link)),
                            Err(_) => {
                                tracing::warn!(cid = %blob_ref.cid, "skipping unparseable blob CID in record blob backfill");
                                None
                            }
                        }
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
    let check_interval =
        Duration::from_secs(tranquil_config::get().scheduled.delete_check_interval_secs);

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
) -> anyhow::Result<()> {
    let accounts_to_delete = user_repo
        .get_accounts_scheduled_for_deletion(100)
        .await
        .context("DB error fetching accounts to delete")?;

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
) -> anyhow::Result<()> {
    let blob_storage_keys = blob_repo
        .get_blob_storage_keys_by_user(user_id)
        .await
        .context("DB error fetching blob keys")?;

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
        .context("Failed to delete account")?;

    info!(
        did = %did,
        blob_count = blob_storage_keys.len(),
        "Deleted account data including blobs from storage"
    );

    Ok(())
}

pub async fn generate_repo_car(
    block_store: &PostgresBlockStore,
    head_cid: &Cid,
) -> anyhow::Result<Vec<u8>> {
    use jacquard_repo::storage::BlockStore;

    let block_cids_bytes = collect_current_repo_blocks(block_store, head_cid).await?;
    let block_cids: Vec<Cid> = block_cids_bytes
        .iter()
        .filter_map(|b| match Cid::try_from(b.as_slice()) {
            Ok(cid) => Some(cid),
            Err(e) => {
                tracing::warn!(error = %e, "skipping unparseable CID in CAR generation");
                None
            }
        })
        .collect();

    let car_bytes = encode_car_header(head_cid).context("Failed to encode CAR header")?;

    let blocks = block_store
        .get_many(&block_cids)
        .await
        .context("Failed to fetch blocks")?;

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
    crate::sync::car::write_varint(&mut writer, u64::try_from(total_len).expect("len fits u64"))
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
) -> anyhow::Result<Vec<u8>> {
    use std::str::FromStr;

    let repo_root_cid_str: String = repo_repo
        .get_repo_root_cid_by_user_id(user_id)
        .await
        .context("Failed to fetch repo")?
        .ok_or_else(|| anyhow::anyhow!("Repository not found"))?
        .to_string();

    let actual_head_cid = Cid::from_str(&repo_root_cid_str).context("Invalid repo_root_cid")?;

    generate_repo_car(block_store, &actual_head_cid).await
}
