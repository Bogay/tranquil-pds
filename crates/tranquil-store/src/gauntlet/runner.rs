use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use cid::Cid;
use jacquard_repo::mst::Mst;
use jacquard_repo::storage::BlockStore;

use super::invariants::{InvariantSet, InvariantViolation, invariants_for};
use super::op::{Op, OpStream, Seed, ValueSeed};
use super::oracle::{Oracle, cid_to_fixed};
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

#[derive(Debug, Clone, Copy)]
pub struct CompactInterval(pub u32);

#[derive(Debug, Clone)]
pub struct StoreConfig {
    pub max_file_size: MaxFileSize,
    pub group_commit: GroupCommitConfig,
    pub shard_count: ShardCount,
    pub compact_every: CompactInterval,
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
                        detail: format!("exceeded max_wall_ms ({} ms)", d.as_millis()),
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
                ops_counter.store(idx + 1, Ordering::Relaxed);
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
            violations.extend(check_all(&store, &oracle, config.invariants));
            if !violations.is_empty() {
                halt_ops = true;
            }
        }
    }

    match refresh_oracle_graph(&store, &mut oracle, root).await {
        Ok(()) => violations.extend(check_all(&store, &oracle, config.invariants)),
        Err(e) => violations.push(InvariantViolation {
            invariant: "OpExecution",
            detail: format!("refresh at end: {e}"),
        }),
    }

    GauntletReport {
        seed: config.seed,
        ops_executed: OpsExecuted(ops_counter.load(Ordering::Relaxed)),
        restarts: RestartCount(restarts_counter.load(Ordering::Relaxed)),
        violations,
    }
}

fn check_all(
    store: &TranquilBlockStore,
    oracle: &Oracle,
    set: InvariantSet,
) -> Vec<InvariantViolation> {
    invariants_for(set)
        .into_iter()
        .filter_map(|inv| inv.check(store, oracle).err())
        .collect()
}

async fn refresh_oracle_graph(
    store: &Arc<TranquilBlockStore>,
    oracle: &mut Oracle,
    root: Option<Cid>,
) -> Result<(), String> {
    match root {
        None => {
            oracle.set_node_cids(Vec::new());
            Ok(())
        }
        Some(r) => {
            let settled = Mst::load(store.clone(), r, None);
            let cids = settled
                .collect_node_cids()
                .await
                .map_err(|e| format!("collect_node_cids: {e}"))?;
            oracle.set_root(r);
            oracle.set_node_cids(cids);
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
            let rng_state = u64::from(raw);
            (lo as usize) + (rng_state % span) as usize
        }
    };
    serde_ipld_dagcbor::to_vec(&serde_json::json!({
        "$type": "app.bsky.feed.post",
        "text": format!("record-{raw}"),
        "createdAt": "2026-01-01T00:00:00Z",
        "pad": "x".repeat(target_len.saturating_sub(64)),
    }))
    .expect("encode record")
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
            let key = format!("{}/{}", collection.0, rkey.0);
            let loaded = match *root {
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

            if let Some(old_root) = *root {
                apply_mst_diff(store, old_root, new_root).await?;
            }

            *root = Some(new_root);
            oracle.add(collection.clone(), rkey.clone(), cid_to_fixed(&record_cid));
            Ok(())
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
        .map(|c| cid_to_fixed(&c))
        .collect();
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
    let liveness = match store.compaction_liveness(0) {
        Ok(l) => l,
        Err(_) => return Ok(()),
    };
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
