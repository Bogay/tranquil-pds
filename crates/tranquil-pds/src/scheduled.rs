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
use tranquil_db_traits::{BlobRepository, RepoRepository, SsoRepository, UserRepository};
use tranquil_store::blockstore::CidBytes;
use tranquil_store::bloom::BloomFilter;
use tranquil_types::{AtUri, CidLink, Did};

use crate::repo::AnyBlockStore;
use crate::storage::BlobStorage;
use crate::sync::car::encode_car_header;

async fn process_repo_rev(
    repo_repo: &dyn RepoRepository,
    block_store: &AnyBlockStore,
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

pub async fn backfill_repo_rev(repo_repo: Arc<dyn RepoRepository>, block_store: AnyBlockStore) {
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
    block_store: &AnyBlockStore,
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

pub async fn backfill_user_blocks(repo_repo: Arc<dyn RepoRepository>, block_store: AnyBlockStore) {
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
    block_store: &AnyBlockStore,
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
    block_store: &AnyBlockStore,
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

pub async fn backfill_record_blobs(repo_repo: Arc<dyn RepoRepository>, block_store: AnyBlockStore) {
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

#[allow(clippy::too_many_arguments)]
pub async fn start_scheduled_tasks(
    user_repo: Arc<dyn UserRepository>,
    blob_repo: Arc<dyn BlobRepository>,
    blob_store: Arc<dyn BlobStorage>,
    sso_repo: Arc<dyn SsoRepository>,
    repo_repo: Arc<dyn RepoRepository>,
    block_store: AnyBlockStore,
    eventlog_segments_dir: Option<std::path::PathBuf>,
    shutdown: CancellationToken,
) {
    let cfg = tranquil_config::get();
    let check_interval = Duration::from_secs(cfg.scheduled.delete_check_interval_secs);
    let compaction_enabled = cfg.scheduled.compaction_interval_secs > 0;
    let reachability_enabled = cfg.scheduled.reachability_walk_interval_secs > 0;
    let archival_enabled_secs = cfg.scheduled.archival_interval_secs > 0;
    let event_retention_enabled = cfg.scheduled.event_retention_interval_secs > 0;
    let compaction_interval = Duration::from_secs(cfg.scheduled.compaction_interval_secs.max(60));
    let reachability_interval =
        Duration::from_secs(cfg.scheduled.reachability_walk_interval_secs.max(60));
    let archival_interval = Duration::from_secs(cfg.scheduled.archival_interval_secs.max(60));
    let event_retention_interval =
        Duration::from_secs(cfg.scheduled.event_retention_interval_secs.max(60));
    let event_retention_max_age = Duration::from_secs(cfg.scheduled.event_retention_max_age_secs);

    let archiver: Option<Arc<tranquil_store::archival::ContinuousArchiver>> =
        match (&eventlog_segments_dir, &cfg.scheduled.archival_dest_dir) {
            (Some(segments_dir), Some(dest_dir)) if archival_enabled_secs => {
                let sidecar_path = segments_dir
                    .parent()
                    .unwrap_or(segments_dir)
                    .join("archival.state");
                match tranquil_store::archival::LocalArchivalDestination::new(
                    std::path::PathBuf::from(dest_dir),
                ) {
                    Ok(dest) => {
                        info!(
                            dest_dir = dest_dir,
                            interval_secs = archival_interval.as_secs(),
                            "continuous archival enabled"
                        );
                        Some(Arc::new(tranquil_store::archival::ContinuousArchiver::new(
                            segments_dir.clone(),
                            sidecar_path,
                            Box::new(dest),
                        )))
                    }
                    Err(e) => {
                        error!(
                            dest_dir = dest_dir,
                            error = %e,
                            "failed to initialize archival destination, archival disabled"
                        );
                        None
                    }
                }
            }
            _ => None,
        };

    info!(
        check_interval_secs = check_interval.as_secs(),
        compaction_enabled,
        compaction_interval_secs = cfg.scheduled.compaction_interval_secs,
        reachability_enabled,
        reachability_interval_secs = cfg.scheduled.reachability_walk_interval_secs,
        archival_enabled = archiver.is_some(),
        event_retention_enabled,
        event_retention_interval_secs = cfg.scheduled.event_retention_interval_secs,
        event_retention_max_age_secs = cfg.scheduled.event_retention_max_age_secs,
        "Starting scheduled tasks service"
    );

    let mut ticker = interval(check_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut compaction_ticker = interval(compaction_interval);
    compaction_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut reachability_ticker = interval(reachability_interval);
    reachability_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut archival_ticker = interval(archival_interval);
    archival_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut event_retention_ticker = match event_retention_enabled {
        true => {
            let mut t = interval(event_retention_interval);
            t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            Some(t)
        }
        false => None,
    };

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
            _ = compaction_ticker.tick(), if compaction_enabled => {
                if let Some(store) = block_store.as_tranquil_store() {
                    let store = store.clone();
                    let threshold = cfg.scheduled.compaction_liveness_threshold;
                    let grace_ms = cfg.scheduled.compaction_grace_period_ms;
                    if let Err(e) = tokio::task::spawn_blocking(move || {
                        run_compaction_pass(&store, threshold, grace_ms)
                    }).await.unwrap_or_else(|e| Err(anyhow::anyhow!("compaction task panicked: {e}"))) {
                        error!("Compaction error: {e}");
                    }
                }
            }
            _ = reachability_ticker.tick(), if reachability_enabled => {
                if let Some(store) = block_store.as_tranquil_store() {
                    let store = store.clone();
                    let repo_repo = repo_repo.clone();
                    match tokio::task::spawn_blocking(move || {
                        run_reachability_walk(&store, repo_repo.as_ref())
                    }).await {
                        Ok(Ok(result)) => {
                            info!(
                                repos_walked = result.repos_walked,
                                blocks_visited = result.blocks_visited,
                                live_refcounted = result.live_refcounted,
                                leaked_blocks = result.leaked_blocks,
                                repaired_blocks = result.repaired_blocks,
                                bloom_heap_mb = result.bloom_heap_bytes / (1024 * 1024),
                                "reachability walk complete"
                            );
                        }
                        Ok(Err(e)) => error!("Reachability walk error: {e}"),
                        Err(e) => error!("Reachability walk panicked: {e}"),
                    }
                }
            }
            _ = archival_ticker.tick(), if archival_enabled_secs => {
                if let Some(ref archiver) = archiver {
                    let archiver = Arc::clone(archiver);
                    match tokio::task::spawn_blocking(move || {
                        archiver.run_pass()
                    }).await {
                        Ok(Ok(result)) if result.segments_archived > 0 => {
                            info!(
                                segments_archived = result.segments_archived,
                                bytes_archived = result.bytes_archived,
                                "archival pass complete"
                            );
                        }
                        Ok(Ok(_)) => {}
                        Ok(Err(e)) => error!("Archival pass error: {e}"),
                        Err(e) => error!("Archival task panicked: {e}"),
                    }
                }
            }
            _ = async {
                match event_retention_ticker.as_mut() {
                    Some(t) => { t.tick().await; }
                    None => std::future::pending::<()>().await,
                }
            }, if event_retention_enabled => {
                let cutoff = chrono::Utc::now()
                    - chrono::Duration::from_std(event_retention_max_age)
                        .expect("event_retention_max_age fits chrono::Duration: validated at config load");
                match repo_repo.prune_events_older_than(cutoff).await {
                    Ok(count) if count.is_zero() => {
                        debug!("event retention: nothing past cutoff");
                    }
                    Ok(count) => {
                        info!(deleted = count.count(), unit = count.unit(), "event retention prune complete");
                    }
                    Err(e) => error!(error = %e, "event retention error"),
                }
            }
        }
    }
}

fn run_compaction_pass(
    store: &tranquil_store::blockstore::TranquilBlockStore,
    liveness_threshold: f64,
    grace_period_ms: u64,
) -> anyhow::Result<()> {
    match store.cleanup_gc_meta() {
        Ok(0) => {}
        Ok(n) => info!(count = n, "cleaned up stale gc_meta entries"),
        Err(e) => warn!(error = %e, "gc_meta cleanup failed, continuing"),
    }

    let liveness_map = store
        .compaction_liveness(grace_period_ms)
        .context("failed to compute liveness")?;

    let candidate = liveness_map
        .iter()
        .filter(|(_, info)| info.total_blocks > 0 && info.ratio() < liveness_threshold)
        .min_by(|(_, a), (_, b)| {
            a.ratio()
                .partial_cmp(&b.ratio())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

    match candidate {
        None => {
            debug!("Compaction: no files below liveness threshold");
            Ok(())
        }
        Some((&file_id, info)) => {
            info!(
                file_id = %file_id,
                liveness = format!("{:.1}%", info.ratio() * 100.0),
                live_blocks = info.live_blocks,
                total_blocks = info.total_blocks,
                "compacting data file"
            );
            match store.compact_file(file_id, grace_period_ms) {
                Ok(result) => {
                    info!(
                        file_id = %result.file_id,
                        reclaimed_bytes = result.reclaimed_bytes,
                        live_blocks = result.live_blocks,
                        dead_blocks = result.dead_blocks,
                        "compaction complete"
                    );
                    Ok(())
                }
                Err(tranquil_store::blockstore::CompactionError::ActiveFileCannotBeCompacted) => {
                    debug!(file_id = %file_id, "skipped active file");
                    Ok(())
                }
                Err(e) => Err(anyhow::anyhow!("compaction failed: {e}")),
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
    block_store: &AnyBlockStore,
    head_cid: &Cid,
) -> anyhow::Result<Vec<u8>> {
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
    block_store: &AnyBlockStore,
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

pub struct ReachabilityResult {
    pub repos_walked: u64,
    pub blocks_visited: u64,
    pub live_refcounted: u64,
    pub leaked_blocks: u64,
    pub repaired_blocks: u64,
    pub bloom_heap_bytes: usize,
}

const REPO_PAGE_SIZE: i64 = 500;
const BLOOM_FALSE_POSITIVE_RATE: f64 = 0.01;

fn cid_to_bytes(cid: &Cid) -> anyhow::Result<CidBytes> {
    cid.to_bytes()
        .try_into()
        .map_err(|_| anyhow::anyhow!("CID byte length mismatch for {cid}"))
}

fn walk_repo_dag_sync(
    store: &tranquil_store::blockstore::TranquilBlockStore,
    head_cid: &Cid,
    reachable: &mut std::collections::HashSet<CidBytes>,
) -> anyhow::Result<()> {
    let mut to_visit = vec![cid_to_bytes(head_cid)?];

    while let Some(cid_bytes) = to_visit.pop() {
        if !reachable.insert(cid_bytes) {
            continue;
        }

        let block = match store.get_block_sync(&cid_bytes)? {
            Some(b) => b,
            None => {
                tracing::warn!(
                    ?cid_bytes,
                    "referenced block missing during reachability walk"
                );
                continue;
            }
        };

        if let Ok(commit) = Commit::from_cbor(&block) {
            to_visit.push(cid_to_bytes(&commit.data)?);
            if let Some(prev) = &commit.prev {
                to_visit.push(cid_to_bytes(prev)?);
            }
        } else if let Ok(Ipld::Map(ref obj)) = serde_ipld_dagcbor::from_slice::<Ipld>(&block) {
            if let Some(Ipld::Link(left_cid)) = obj.get("l")
                && let Ok(bytes) = <CidBytes>::try_from(left_cid.to_bytes().as_slice())
            {
                to_visit.push(bytes);
            }
            if let Some(Ipld::List(entries)) = obj.get("e") {
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
                                Ipld::Link(link_cid) => {
                                    <CidBytes>::try_from(link_cid.to_bytes().as_slice()).ok()
                                }
                                _ => None,
                            })
                    })
                    .for_each(|bytes| to_visit.push(bytes));
            }
        }
    }

    Ok(())
}

fn paginate_repos(
    rt: &tokio::runtime::Handle,
    repo_repo: &dyn RepoRepository,
    mut each_page: impl FnMut(&[tranquil_db_traits::RepoListItem]) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut cursor_did: Option<Did> = None;

    std::iter::from_fn(|| {
        let page = rt
            .block_on(repo_repo.list_repos_paginated(cursor_did.as_ref(), REPO_PAGE_SIZE))
            .context("failed to list repos");
        match &page {
            Ok(p) => {
                cursor_did = p.last().map(|r| r.did.clone());
                cursor_did.as_ref().map(|_| page)
            }
            Err(_) => Some(page),
        }
    })
    .try_for_each(|page| each_page(&page?))
}

pub fn run_reachability_walk(
    store: &tranquil_store::blockstore::TranquilBlockStore,
    repo_repo: &dyn RepoRepository,
) -> anyhow::Result<ReachabilityResult> {
    let rt = tokio::runtime::Handle::current();

    let approx_blocks = store.approximate_block_count();

    const MAX_PREALLOC: usize = 64_000_000;
    let mut visited = std::collections::HashSet::with_capacity(
        usize::try_from(approx_blocks)
            .unwrap_or(0)
            .min(MAX_PREALLOC),
    );

    info!(approx_blocks, "reachability walk starting");

    let mut repos_walked: u64 = 0;
    let mut seen_heads: std::collections::HashMap<Did, CidLink> = std::collections::HashMap::new();

    paginate_repos(&rt, repo_repo, |page| {
        page.iter().try_for_each(|repo| -> anyhow::Result<()> {
            let cid =
                Cid::from_str(repo.repo_root_cid.as_str()).context("invalid repo_root_cid")?;
            seen_heads.insert(repo.did.clone(), repo.repo_root_cid.clone());
            walk_repo_dag_sync(store, &cid, &mut visited)?;
            repos_walked = repos_walked.saturating_add(1);
            if repos_walked.is_multiple_of(1000) {
                info!(
                    repos_walked,
                    blocks_so_far = visited.len(),
                    "reachability walk progress"
                );
            }
            Ok(())
        })
    })?;

    let blocks_visited = u64::try_from(visited.len()).unwrap_or(u64::MAX);

    let mut reachable =
        BloomFilter::with_capacity_and_fpr(blocks_visited.max(1024), BLOOM_FALSE_POSITIVE_RATE);
    visited.iter().for_each(|cid| reachable.insert(cid));
    drop(visited);

    let mut stale_repos: u64 = 0;
    paginate_repos(&rt, repo_repo, |page| {
        let stale: Vec<_> = page
            .iter()
            .filter(|repo| seen_heads.get(&repo.did) != Some(&repo.repo_root_cid))
            .collect();
        stale.iter().try_for_each(|repo| -> anyhow::Result<()> {
            let cid =
                Cid::from_str(repo.repo_root_cid.as_str()).context("invalid repo_root_cid")?;
            let mut extra = std::collections::HashSet::new();
            walk_repo_dag_sync(store, &cid, &mut extra)?;
            extra.iter().for_each(|c| reachable.insert(c));
            seen_heads.insert(repo.did.clone(), repo.repo_root_cid.clone());
            stale_repos = stale_repos.saturating_add(1);
            Ok(())
        })
    })?;

    info!(
        repos_walked,
        blocks_visited,
        stale_repos,
        bloom_heap_mb = reachable.heap_bytes() / (1024 * 1024),
        "DAG traversal complete, quiescing blockstore for leak scan"
    );

    let (_snapshot, quiesce_guard) = store
        .quiesce()
        .map_err(|e| anyhow::anyhow!("failed to quiesce blockstore: {e}"))?;

    let mut quiesced_stale: u64 = 0;
    paginate_repos(&rt, repo_repo, |page| {
        page.iter()
            .filter(|repo| seen_heads.get(&repo.did) != Some(&repo.repo_root_cid))
            .try_for_each(|repo| -> anyhow::Result<()> {
                let cid =
                    Cid::from_str(repo.repo_root_cid.as_str()).context("invalid repo_root_cid")?;
                let mut extra = std::collections::HashSet::new();
                walk_repo_dag_sync(store, &cid, &mut extra)?;
                extra.iter().for_each(|c| reachable.insert(c));
                quiesced_stale = quiesced_stale.saturating_add(1);
                Ok(())
            })
    })?;

    if quiesced_stale > 0 {
        info!(
            quiesced_stale,
            "caught additional stale repos during quiesced re-walk"
        );
    }

    let (leaked, live_refcounted) = store
        .find_leaked_refcounts(|cid| reachable.contains(cid))
        .map_err(|e| anyhow::anyhow!("failed to scan index: {e}"))?;
    let leaked_blocks = u64::try_from(leaked.len()).unwrap_or(u64::MAX);
    let bloom_heap_bytes = reachable.heap_bytes();
    drop(reachable);

    quiesce_guard.resume();

    let repaired_blocks = match leaked.is_empty() {
        true => 0,
        false => {
            warn!(
                leaked_blocks,
                "reachability walk found leaked refcounts, repairing"
            );
            store
                .repair_leaked_refcounts(&leaked)
                .map_err(|e| anyhow::anyhow!("failed to repair leaked refcounts: {e}"))?
        }
    };

    Ok(ReachabilityResult {
        repos_walked,
        blocks_visited,
        live_refcounted,
        leaked_blocks,
        repaired_blocks,
        bloom_heap_bytes,
    })
}
