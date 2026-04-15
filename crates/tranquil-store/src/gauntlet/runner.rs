use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use cid::Cid;
use jacquard_repo::mst::Mst;
use jacquard_repo::storage::BlockStore;

use super::invariants::{InvariantCtx, InvariantSet, InvariantViolation, invariants_for};
use super::op::{Op, OpStream, Seed, ValueSeed};
use super::oracle::{CidFormatError, Oracle, hex_short, try_cid_to_fixed};
use super::workload::{Lcg, OpCount, SizeDistribution, ValueBytes, WorkloadModel};
use crate::blockstore::{
    BlockStoreConfig, CidBytes, CompactionError, GroupCommitConfig, TranquilBlockStore,
};

#[derive(Debug, Clone, Copy)]
pub enum IoBackend {
    Real,
    Simulated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpInterval(pub usize);

#[derive(Debug, Clone, Copy)]
pub enum RestartPolicy {
    Never,
    EveryNOps(OpInterval),
    PoissonByOps(OpInterval),
}

#[derive(Debug, Clone, Copy)]
pub struct WallMs(pub u64);

#[derive(Debug, Clone, Copy)]
pub struct RunLimits {
    pub max_wall_ms: Option<WallMs>,
}

#[derive(Debug, Clone, Copy)]
pub struct MaxFileSize(pub u64);

#[derive(Debug, Clone, Copy)]
pub struct ShardCount(pub u8);

#[derive(Debug, Clone)]
pub struct StoreConfig {
    pub max_file_size: MaxFileSize,
    pub group_commit: GroupCommitConfig,
    pub shard_count: ShardCount,
}

#[derive(Debug, Clone)]
pub struct GauntletConfig {
    pub seed: Seed,
    pub io: IoBackend,
    pub workload: WorkloadModel,
    pub op_count: OpCount,
    pub invariants: InvariantSet,
    pub limits: RunLimits,
    pub restart_policy: RestartPolicy,
    pub store: StoreConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpsExecuted(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RestartCount(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpIndex(pub usize);

#[derive(Debug)]
pub struct GauntletReport {
    pub seed: Seed,
    pub ops_executed: OpsExecuted,
    pub restarts: RestartCount,
    pub violations: Vec<InvariantViolation>,
}

impl GauntletReport {
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }
}

#[derive(Debug, thiserror::Error)]
enum OpError {
    #[error("put record: {0}")]
    PutRecord(String),
    #[error("mst add: {0}")]
    MstAdd(String),
    #[error("mst delete: {0}")]
    MstDelete(String),
    #[error("mst persist: {0}")]
    MstPersist(String),
    #[error("mst diff: {0}")]
    MstDiff(String),
    #[error("apply commit: {0}")]
    ApplyCommit(String),
    #[error("compact_file: {0}")]
    CompactFile(String),
    #[error("join: {0}")]
    Join(String),
    #[error("cid format: {0}")]
    CidFormat(#[from] CidFormatError),
}

pub struct Gauntlet {
    config: GauntletConfig,
}

#[derive(Debug, thiserror::Error)]
pub enum GauntletBuildError {
    #[error("IoBackend::Simulated not wired yet")]
    UnsupportedIoBackend,
}

impl Gauntlet {
    pub fn new(config: GauntletConfig) -> Result<Self, GauntletBuildError> {
        match config.io {
            IoBackend::Real => Ok(Self { config }),
            IoBackend::Simulated => Err(GauntletBuildError::UnsupportedIoBackend),
        }
    }

    pub async fn run(self) -> GauntletReport {
        let deadline = self
            .config
            .limits
            .max_wall_ms
            .map(|WallMs(ms)| Duration::from_millis(ms));

        let seed = self.config.seed;
        let ops_counter = Arc::new(AtomicUsize::new(0));
        let restarts_counter = Arc::new(AtomicUsize::new(0));
        let fut = run_real_inner(self.config, ops_counter.clone(), restarts_counter.clone());
        match deadline {
            Some(d) => match tokio::time::timeout(d, fut).await {
                Ok(r) => r,
                Err(_) => GauntletReport {
                    seed,
                    ops_executed: OpsExecuted(ops_counter.load(Ordering::Relaxed)),
                    restarts: RestartCount(restarts_counter.load(Ordering::Relaxed)),
                    violations: vec![InvariantViolation {
                        invariant: "WallClockBudget",
                        detail: format!("exceeded max_wall_ms of {} ms", d.as_millis()),
                    }],
                },
            },
            None => fut.await,
        }
    }
}

async fn run_real_inner(
    config: GauntletConfig,
    ops_counter: Arc<AtomicUsize>,
    restarts_counter: Arc<AtomicUsize>,
) -> GauntletReport {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let op_stream: OpStream = config.workload.generate(config.seed, config.op_count);

    let mut oracle = Oracle::new();
    let mut violations: Vec<InvariantViolation> = Vec::new();

    let mut store = Arc::new(
        TranquilBlockStore::open(blockstore_config(dir.path(), &config.store)).expect("open store"),
    );
    let mut root: Option<Cid> = None;
    let mut restart_rng = Lcg::new(Seed(config.seed.0 ^ 0xA5A5_A5A5_A5A5_A5A5));
    let mut halt_ops = false;

    let mid_run_set = config
        .invariants
        .without(InvariantSet::RESTART_IDEMPOTENT)
        .without(InvariantSet::ACKED_WRITE_PERSISTENCE);
    let post_reopen_set = config.invariants.without(InvariantSet::RESTART_IDEMPOTENT);

    for (idx, op) in op_stream.iter().enumerate() {
        if halt_ops {
            break;
        }
        match apply_op(&store, &mut root, &mut oracle, op, &config.workload).await {
            Ok(()) => {}
            Err(e) => {
                violations.push(InvariantViolation {
                    invariant: "OpExecution",
                    detail: format!("op {idx}: {e}"),
                });
                halt_ops = true;
                continue;
            }
        }
        ops_counter.store(idx + 1, Ordering::Relaxed);

        if should_restart(config.restart_policy, OpIndex(idx), &mut restart_rng) {
            drop(store);
            store = Arc::new(
                TranquilBlockStore::open(blockstore_config(dir.path(), &config.store))
                    .expect("reopen store"),
            );
            let n = restarts_counter.fetch_add(1, Ordering::Relaxed) + 1;

            if let Err(e) = refresh_oracle_graph(&store, &mut oracle, root).await {
                violations.push(InvariantViolation {
                    invariant: "OpExecution",
                    detail: format!("refresh after restart {n}: {e}"),
                });
                halt_ops = true;
                continue;
            }
            let before = violations.len();
            violations.extend(run_invariants(&store, &oracle, root, mid_run_set).await);
            if violations.len() > before {
                halt_ops = true;
            }
        }
    }

    if !halt_ops {
        match refresh_oracle_graph(&store, &mut oracle, root).await {
            Ok(()) => {
                let before = violations.len();
                violations.extend(run_invariants(&store, &oracle, root, mid_run_set).await);
                if violations.len() > before {
                    halt_ops = true;
                }
            }
            Err(e) => {
                violations.push(InvariantViolation {
                    invariant: "OpExecution",
                    detail: format!("refresh at end: {e}"),
                });
                halt_ops = true;
            }
        }
    }

    if config.invariants.contains(InvariantSet::RESTART_IDEMPOTENT) && !halt_ops {
        let pre_snapshot = snapshot_block_index(&store);
        drop(store);
        let reopened = Arc::new(
            TranquilBlockStore::open(blockstore_config(dir.path(), &config.store))
                .expect("reopen for RestartIdempotent"),
        );
        let post_snapshot = snapshot_block_index(&reopened);
        if let Some(detail) = diff_snapshots(&pre_snapshot, &post_snapshot) {
            violations.push(InvariantViolation {
                invariant: "RestartIdempotent",
                detail,
            });
        } else {
            violations.extend(run_invariants(&reopened, &oracle, root, post_reopen_set).await);
        }
    }

    GauntletReport {
        seed: config.seed,
        ops_executed: OpsExecuted(ops_counter.load(Ordering::Relaxed)),
        restarts: RestartCount(restarts_counter.load(Ordering::Relaxed)),
        violations,
    }
}

async fn run_invariants(
    store: &Arc<TranquilBlockStore>,
    oracle: &Oracle,
    root: Option<Cid>,
    set: InvariantSet,
) -> Vec<InvariantViolation> {
    let ctx = InvariantCtx {
        store,
        oracle,
        root,
    };
    let mut out = Vec::new();
    for inv in invariants_for(set) {
        if let Err(v) = inv.check(&ctx).await {
            out.push(v);
        }
    }
    out
}

fn snapshot_block_index(store: &TranquilBlockStore) -> Vec<(CidBytes, u32)> {
    let mut v: Vec<(CidBytes, u32)> = store
        .block_index()
        .live_entries_snapshot()
        .into_iter()
        .map(|(c, r)| (c, r.raw()))
        .collect();
    v.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    v
}

const SNAPSHOT_DIFF_ITEMS: usize = 16;

fn diff_snapshots(pre: &[(CidBytes, u32)], post: &[(CidBytes, u32)]) -> Option<String> {
    if pre == post {
        return None;
    }
    let pre_map: std::collections::HashMap<CidBytes, u32> = pre.iter().copied().collect();
    let post_map: std::collections::HashMap<CidBytes, u32> = post.iter().copied().collect();

    let only_pre: Vec<String> = pre_map
        .iter()
        .filter(|(c, _)| !post_map.contains_key(*c))
        .map(|(c, r)| format!("lost {} refcount {}", hex_short(c), r))
        .collect();
    let only_post: Vec<String> = post_map
        .iter()
        .filter(|(c, _)| !pre_map.contains_key(*c))
        .map(|(c, r)| format!("gained {} refcount {}", hex_short(c), r))
        .collect();
    let changed: Vec<String> = pre_map
        .iter()
        .filter_map(|(c, pre_r)| match post_map.get(c) {
            Some(post_r) if post_r != pre_r => {
                Some(format!("{} refcount {} -> {}", hex_short(c), pre_r, post_r))
            }
            _ => None,
        })
        .collect();

    let total = only_pre.len() + only_post.len() + changed.len();
    let mut items: Vec<String> = only_pre
        .into_iter()
        .chain(only_post)
        .chain(changed)
        .take(SNAPSHOT_DIFF_ITEMS)
        .collect();
    if total > items.len() {
        items.push(format!("+{} more", total - items.len()));
    }
    Some(format!(
        "block index changed across clean reopen: pre={} entries, post={} entries; {}",
        pre.len(),
        post.len(),
        items.join("; "),
    ))
}

async fn refresh_oracle_graph(
    store: &Arc<TranquilBlockStore>,
    oracle: &mut Oracle,
    root: Option<Cid>,
) -> Result<(), String> {
    match root {
        None => {
            oracle.clear_mst_state();
            Ok(())
        }
        Some(r) => {
            let settled = Mst::load(store.clone(), r, None);
            let cids = settled
                .collect_node_cids()
                .await
                .map_err(|e| format!("collect_node_cids: {e}"))?;
            let fixed: Vec<CidBytes> = cids
                .iter()
                .map(try_cid_to_fixed)
                .collect::<Result<_, _>>()
                .map_err(|e| format!("mst node cid: {e}"))?;
            oracle.set_root(r);
            oracle.set_mst_node_cids(fixed);
            Ok(())
        }
    }
}

fn should_restart(policy: RestartPolicy, idx: OpIndex, rng: &mut Lcg) -> bool {
    match policy {
        RestartPolicy::Never => false,
        RestartPolicy::EveryNOps(OpInterval(n)) => n > 0 && (idx.0 + 1).is_multiple_of(n),
        RestartPolicy::PoissonByOps(OpInterval(n)) => {
            if n == 0 {
                false
            } else {
                rng.next_u64().is_multiple_of(n as u64)
            }
        }
    }
}

fn blockstore_config(dir: &std::path::Path, s: &StoreConfig) -> BlockStoreConfig {
    BlockStoreConfig {
        data_dir: dir.join("data"),
        index_dir: dir.join("index"),
        max_file_size: s.max_file_size.0,
        group_commit: s.group_commit.clone(),
        shard_count: s.shard_count.0,
    }
}

fn make_record_bytes(value_seed: ValueSeed, dist: SizeDistribution) -> Vec<u8> {
    let raw = value_seed.0;
    let target_len: usize = match dist {
        SizeDistribution::Fixed(ValueBytes(n)) => n as usize,
        SizeDistribution::Uniform(range) => {
            let ValueBytes(lo) = range.min();
            let ValueBytes(hi) = range.max();
            let span = u64::from(hi.saturating_sub(lo)).max(1);
            (lo as usize) + (u64::from(raw) % span) as usize
        }
    };
    let target_len = target_len.max(8);
    let seed_bytes = raw.to_le_bytes();
    (0..target_len)
        .map(|i| seed_bytes[i % 4] ^ (i as u8).wrapping_mul(31))
        .collect()
}

async fn apply_op(
    store: &Arc<TranquilBlockStore>,
    root: &mut Option<Cid>,
    oracle: &mut Oracle,
    op: &Op,
    workload: &WorkloadModel,
) -> Result<(), OpError> {
    match op {
        Op::AddRecord {
            collection,
            rkey,
            value_seed,
        } => {
            let record_bytes = make_record_bytes(*value_seed, workload.size_distribution);
            let record_cid = store
                .put(&record_bytes)
                .await
                .map_err(|e| OpError::PutRecord(e.to_string()))?;
            let record_cid_bytes = try_cid_to_fixed(&record_cid)?;

            let outcome =
                add_record_inner(store, *root, collection, rkey, record_cid, record_cid_bytes)
                    .await;
            match outcome {
                Ok((new_root, applied)) => {
                    *root = Some(new_root);
                    if applied {
                        oracle.add(collection.clone(), rkey.clone(), record_cid_bytes);
                    }
                    Ok(())
                }
                Err(e) => {
                    if let Err(cleanup_err) =
                        decrement_obsolete(store, vec![record_cid_bytes]).await
                    {
                        tracing::warn!(
                            op_error = %e,
                            cleanup_error = %cleanup_err,
                            "AddRecord cleanup decrement failed; refcount may leak",
                        );
                    }
                    Err(e)
                }
            }
        }
        Op::DeleteRecord { collection, rkey } => {
            let Some(old_root) = *root else { return Ok(()) };
            if oracle.delete(collection, rkey).is_none() {
                return Ok(());
            }
            let key = format!("{}/{}", collection.0, rkey.0);
            let loaded = Mst::load(store.clone(), old_root, None);
            let updated = loaded
                .delete(&key)
                .await
                .map_err(|e| OpError::MstDelete(e.to_string()))?;
            let new_root = updated
                .persist()
                .await
                .map_err(|e| OpError::MstPersist(e.to_string()))?;
            apply_mst_diff(store, old_root, new_root).await?;
            *root = Some(new_root);
            Ok(())
        }
        Op::Compact => {
            let s = store.clone();
            tokio::task::spawn_blocking(move || compact_by_liveness(&s))
                .await
                .map_err(|e| OpError::Join(e.to_string()))?
        }
        Op::Checkpoint => {
            let s = store.clone();
            tokio::task::spawn_blocking(move || {
                s.apply_commit_blocking(vec![], vec![])
                    .map_err(|e| e.to_string())
            })
            .await
            .map_err(|e| OpError::Join(e.to_string()))?
            .map_err(OpError::ApplyCommit)
        }
    }
}

async fn add_record_inner(
    store: &Arc<TranquilBlockStore>,
    root: Option<Cid>,
    collection: &super::op::CollectionName,
    rkey: &super::op::RecordKey,
    record_cid: Cid,
    record_cid_bytes: CidBytes,
) -> Result<(Cid, bool), OpError> {
    let key = format!("{}/{}", collection.0, rkey.0);
    let loaded = match root {
        None => Mst::new(store.clone()),
        Some(r) => Mst::load(store.clone(), r, None),
    };
    let updated = loaded
        .add(&key, record_cid)
        .await
        .map_err(|e| OpError::MstAdd(e.to_string()))?;
    let new_root = updated
        .persist()
        .await
        .map_err(|e| OpError::MstPersist(e.to_string()))?;

    match root {
        Some(old_root) if old_root == new_root => {
            decrement_obsolete(store, vec![record_cid_bytes]).await?;
            Ok((new_root, false))
        }
        Some(old_root) => {
            apply_mst_diff(store, old_root, new_root).await?;
            Ok((new_root, true))
        }
        None => Ok((new_root, true)),
    }
}

async fn decrement_obsolete(
    store: &Arc<TranquilBlockStore>,
    obsolete: Vec<CidBytes>,
) -> Result<(), OpError> {
    let s = store.clone();
    tokio::task::spawn_blocking(move || {
        s.apply_commit_blocking(vec![], obsolete)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| OpError::Join(e.to_string()))?
    .map_err(OpError::ApplyCommit)
}

async fn apply_mst_diff(
    store: &Arc<TranquilBlockStore>,
    old_root: Cid,
    new_root: Cid,
) -> Result<(), OpError> {
    let old_m = Mst::load(store.clone(), old_root, None);
    let new_m = Mst::load(store.clone(), new_root, None);
    let diff = old_m
        .diff(&new_m)
        .await
        .map_err(|e| OpError::MstDiff(e.to_string()))?;
    let obsolete: Vec<CidBytes> = diff
        .removed_mst_blocks
        .into_iter()
        .chain(diff.removed_cids.into_iter())
        .map(|c| try_cid_to_fixed(&c))
        .collect::<Result<_, _>>()?;
    let s = store.clone();
    tokio::task::spawn_blocking(move || {
        s.apply_commit_blocking(vec![], obsolete)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| OpError::Join(e.to_string()))?
    .map_err(OpError::ApplyCommit)
}

const COMPACT_LIVENESS_CEILING: f64 = 0.99;

fn compact_by_liveness(store: &TranquilBlockStore) -> Result<(), OpError> {
    let liveness = store
        .compaction_liveness(0)
        .map_err(|e| OpError::CompactFile(format!("compaction_liveness: {e}")))?;
    let targets: Vec<_> = liveness
        .iter()
        .filter(|(_, info)| info.total_blocks > 0 && info.ratio() < COMPACT_LIVENESS_CEILING)
        .map(|(&fid, _)| fid)
        .collect();
    targets
        .into_iter()
        .try_for_each(|fid| match store.compact_file(fid, 0) {
            Ok(_) => Ok(()),
            Err(CompactionError::ActiveFileCannotBeCompacted) => Ok(()),
            Err(e) => Err(OpError::CompactFile(format!("{fid}: {e}"))),
        })
}
