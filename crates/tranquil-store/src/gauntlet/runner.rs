use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use cid::Cid;
use jacquard_repo::mst::Mst;

use super::invariants::{
    EventLogSnapshot, InvariantCtx, InvariantSet, InvariantViolation, SnapshotEvent, invariants_for,
};
use super::op::{DidSeed, EventKind, Op, OpStream, PayloadSeed, RetentionSecs, Seed, ValueSeed};
use super::oracle::{CidFormatError, EventExpectation, Oracle, hex_short, try_cid_to_fixed};
use super::workload::{Lcg, OpCount, SizeDistribution, ValueBytes, WorkloadModel};
use crate::blockstore::{
    BlockStoreConfig, CidBytes, CompactionError, GroupCommitConfig, TranquilBlockStore,
    hash_to_cid, hash_to_cid_bytes,
};
use crate::eventlog::{
    DEFAULT_INDEX_INTERVAL, DidHash, EventLogWriter, EventTypeTag, MAX_EVENT_PAYLOAD, SegmentId,
    SegmentManager, SegmentReader, TimestampMicros, ValidEvent,
};
use crate::io::{RealIO, StorageIO};
use crate::sim::{FaultConfig, SimulatedIO};

#[derive(Debug, Clone, Copy)]
pub enum IoBackend {
    Real,
    Simulated { fault: FaultConfig },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpInterval(pub usize);

#[derive(Debug, Clone, Copy)]
pub enum RestartPolicy {
    Never,
    EveryNOps(OpInterval),
    PoissonByOps(OpInterval),
    CrashAtSyscall(OpInterval),
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
pub struct MaxSegmentSize(pub u64);

#[derive(Debug, Clone, Copy)]
pub struct ShardCount(pub u8);

#[derive(Debug, Clone)]
pub struct StoreConfig {
    pub max_file_size: MaxFileSize,
    pub group_commit: GroupCommitConfig,
    pub shard_count: ShardCount,
}

#[derive(Debug, Clone, Copy)]
pub struct EventLogConfig {
    pub max_segment_size: MaxSegmentSize,
}

#[derive(Debug, Clone, Copy)]
pub struct WriterConcurrency(pub usize);

impl Default for WriterConcurrency {
    fn default() -> Self {
        Self(1)
    }
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
    pub eventlog: Option<EventLogConfig>,
    pub writer_concurrency: WriterConcurrency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpsExecuted(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpErrorCount(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RestartCount(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpIndex(pub usize);

#[derive(Debug, Clone)]
pub struct GauntletReport {
    pub seed: Seed,
    pub ops_executed: OpsExecuted,
    pub op_errors: OpErrorCount,
    pub restarts: RestartCount,
    pub violations: Vec<InvariantViolation>,
    pub ops: OpStream,
}

impl GauntletReport {
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }

    pub fn violation_invariants(&self) -> std::collections::BTreeSet<&'static str> {
        self.violations.iter().map(|v| v.invariant).collect()
    }
}

#[derive(Debug, thiserror::Error)]
enum OpError {
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
    #[error("eventlog append: {0}")]
    EventLogAppend(String),
    #[error("eventlog sync: {0}")]
    EventLogSync(String),
    #[error("eventlog retention: {0}")]
    EventLogRetention(String),
}

pub struct EventLogState<S: StorageIO + Send + Sync + 'static> {
    pub writer: EventLogWriter<S>,
    pub manager: Arc<SegmentManager<S>>,
    pub segments_dir: PathBuf,
    pub max_segment_size: u64,
}

pub struct Harness<S: StorageIO + Send + Sync + 'static> {
    pub store: Arc<TranquilBlockStore<S>>,
    pub eventlog: Option<EventLogState<S>>,
}

pub struct WriteState<S: StorageIO + Send + Sync + 'static> {
    pub root: Option<Cid>,
    pub oracle: Oracle,
    pub eventlog: Option<EventLogState<S>>,
}

pub struct SharedState<S: StorageIO + Send + Sync + 'static> {
    pub store: Arc<TranquilBlockStore<S>>,
    pub write: tokio::sync::Mutex<WriteState<S>>,
}

pub struct Gauntlet {
    config: GauntletConfig,
}

#[derive(Debug, thiserror::Error)]
pub enum GauntletBuildError {}

impl Gauntlet {
    pub fn new(config: GauntletConfig) -> Result<Self, GauntletBuildError> {
        Ok(Self { config })
    }

    pub fn generate_ops(&self) -> OpStream {
        self.config
            .workload
            .generate(self.config.seed, self.config.op_count)
    }

    pub async fn run(self) -> GauntletReport {
        let ops = self.generate_ops();
        self.run_with_ops(ops).await
    }

    pub async fn run_with_ops(self, ops: OpStream) -> GauntletReport {
        let deadline = self
            .config
            .limits
            .max_wall_ms
            .map(|WallMs(ms)| Duration::from_millis(ms));

        let seed = self.config.seed;
        let ops_for_report = ops.clone();
        let ops_counter = Arc::new(AtomicUsize::new(0));
        let op_errors_counter = Arc::new(AtomicUsize::new(0));
        let restarts_counter = Arc::new(AtomicUsize::new(0));
        let fut: std::pin::Pin<Box<dyn std::future::Future<Output = GauntletReport> + Send>> =
            match self.config.io {
                IoBackend::Real => Box::pin(run_inner_real(
                    self.config,
                    ops,
                    ops_counter.clone(),
                    op_errors_counter.clone(),
                    restarts_counter.clone(),
                )),
                IoBackend::Simulated { fault } => Box::pin(run_inner_simulated(
                    self.config,
                    fault,
                    ops,
                    ops_counter.clone(),
                    op_errors_counter.clone(),
                    restarts_counter.clone(),
                )),
            };
        let mut report = match deadline {
            Some(d) => match tokio::time::timeout(d, fut).await {
                Ok(r) => r,
                Err(_) => GauntletReport {
                    seed,
                    ops_executed: OpsExecuted(ops_counter.load(Ordering::Relaxed)),
                    op_errors: OpErrorCount(op_errors_counter.load(Ordering::Relaxed)),
                    restarts: RestartCount(restarts_counter.load(Ordering::Relaxed)),
                    violations: vec![InvariantViolation {
                        invariant: "WallClockBudget",
                        detail: format!("exceeded max_wall_ms of {} ms", d.as_millis()),
                    }],
                    ops: OpStream::empty(),
                },
            },
            None => fut.await,
        };
        report.ops = ops_for_report;
        report
    }
}

fn segments_subdir(root: &Path) -> PathBuf {
    root.join("segments")
}

async fn run_inner_real(
    config: GauntletConfig,
    ops: OpStream,
    ops_counter: Arc<AtomicUsize>,
    op_errors_counter: Arc<AtomicUsize>,
    restarts_counter: Arc<AtomicUsize>,
) -> GauntletReport {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let cfg = blockstore_config(dir.path(), &config.store);
    let eventlog_cfg = config.eventlog;
    let segments_dir = segments_subdir(dir.path());
    let open = {
        let segments_dir = segments_dir.clone();
        move || -> Result<Harness<RealIO>, String> {
            let store = TranquilBlockStore::open(cfg.clone())
                .map(Arc::new)
                .map_err(|e| e.to_string())?;
            let eventlog = match eventlog_cfg {
                None => None,
                Some(elc) => Some(
                    open_eventlog(RealIO::new(), segments_dir.clone(), elc.max_segment_size.0)
                        .map_err(|e| format!("eventlog: {e}"))?,
                ),
            };
            Ok(Harness { store, eventlog })
        }
    };
    if config.writer_concurrency.0 > 1 {
        run_inner_generic_concurrent::<RealIO, _, _>(
            config,
            ops,
            ops_counter,
            op_errors_counter,
            restarts_counter,
            open,
            || {},
            false,
        )
        .await
    } else {
        run_inner_generic::<RealIO, _, _>(
            config,
            ops,
            ops_counter,
            op_errors_counter,
            restarts_counter,
            open,
            || {},
            false,
        )
        .await
    }
}

async fn run_inner_simulated(
    config: GauntletConfig,
    fault: FaultConfig,
    ops: OpStream,
    ops_counter: Arc<AtomicUsize>,
    op_errors_counter: Arc<AtomicUsize>,
    restarts_counter: Arc<AtomicUsize>,
) -> GauntletReport {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let cfg = blockstore_config(dir.path(), &config.store);
    let tolerate_errors = fault.injects_errors();
    let eventlog_cfg = config.eventlog;
    let segments_dir = segments_subdir(dir.path());
    let sim: Arc<SimulatedIO> = Arc::new(SimulatedIO::new(config.seed.0, fault));
    let sim_for_open = Arc::clone(&sim);
    let open = {
        let segments_dir = segments_dir.clone();
        move || -> Result<Harness<Arc<SimulatedIO>>, String> {
            let factory_sim = Arc::clone(&sim_for_open);
            let make_io = move || Arc::clone(&factory_sim);
            let store = TranquilBlockStore::<Arc<SimulatedIO>>::open_with_io(cfg.clone(), make_io)
                .map(Arc::new)
                .map_err(|e| e.to_string())?;
            let eventlog = match eventlog_cfg {
                None => None,
                Some(elc) => Some(
                    open_eventlog(
                        Arc::clone(&sim_for_open),
                        segments_dir.clone(),
                        elc.max_segment_size.0,
                    )
                    .map_err(|e| format!("eventlog: {e}"))?,
                ),
            };
            Ok(Harness { store, eventlog })
        }
    };
    let sim_for_crash = Arc::clone(&sim);
    let crash = move || sim_for_crash.crash();
    if config.writer_concurrency.0 > 1 {
        run_inner_generic_concurrent::<Arc<SimulatedIO>, _, _>(
            config,
            ops,
            ops_counter,
            op_errors_counter,
            restarts_counter,
            open,
            crash,
            tolerate_errors,
        )
        .await
    } else {
        run_inner_generic::<Arc<SimulatedIO>, _, _>(
            config,
            ops,
            ops_counter,
            op_errors_counter,
            restarts_counter,
            open,
            crash,
            tolerate_errors,
        )
        .await
    }
}

fn open_eventlog<S: StorageIO + Send + Sync + 'static>(
    io: S,
    segments_dir: PathBuf,
    max_segment_size: u64,
) -> std::io::Result<EventLogState<S>> {
    let manager = Arc::new(SegmentManager::new(
        io,
        segments_dir.clone(),
        max_segment_size,
    )?);
    let writer = EventLogWriter::open(
        Arc::clone(&manager),
        DEFAULT_INDEX_INTERVAL,
        MAX_EVENT_PAYLOAD,
    )?;
    Ok(EventLogState {
        writer,
        manager,
        segments_dir,
        max_segment_size,
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_inner_generic<S, Open, Crash>(
    config: GauntletConfig,
    op_stream: OpStream,
    ops_counter: Arc<AtomicUsize>,
    op_errors_counter: Arc<AtomicUsize>,
    restarts_counter: Arc<AtomicUsize>,
    mut open: Open,
    mut crash: Crash,
    tolerate_op_errors: bool,
) -> GauntletReport
where
    S: StorageIO + Send + Sync + 'static,
    Open: FnMut() -> Result<Harness<S>, String>,
    Crash: FnMut(),
{
    let mut oracle = Oracle::new();
    let mut violations: Vec<InvariantViolation> = Vec::new();

    let mut harness: Option<Harness<S>> = match open() {
        Ok(h) => Some(h),
        Err(e) => {
            return GauntletReport {
                seed: config.seed,
                ops_executed: OpsExecuted(0),
                op_errors: OpErrorCount(op_errors_counter.load(Ordering::Relaxed)),
                restarts: RestartCount(0),
                violations: vec![InvariantViolation {
                    invariant: "OpenStore",
                    detail: format!("initial open: {e}"),
                }],
                ops: OpStream::empty(),
            };
        }
    };
    let mut root: Option<Cid> = None;
    let mut restart_rng = Lcg::new(Seed(config.seed.0 ^ 0xA5A5_A5A5_A5A5_A5A5));
    let mut sample_rng = Lcg::new(Seed(config.seed.0 ^ 0x5A5A_5A5A_5A5A_5A5A));
    let mut halt_ops = false;

    let post_reopen_set = config.invariants.without(InvariantSet::RESTART_IDEMPOTENT);

    for (idx, op) in op_stream.iter().enumerate() {
        if halt_ops {
            break;
        }
        let live = harness
            .as_mut()
            .expect("harness invariant: present when halt_ops is false");
        let root_before = root;
        match apply_op(live, &mut root, &mut oracle, op, &config.workload).await {
            Ok(()) => {}
            Err(e) => {
                if tolerate_op_errors {
                    op_errors_counter.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                violations.push(InvariantViolation {
                    invariant: "OpExecution",
                    detail: format!("op {idx}: {e}"),
                });
                halt_ops = true;
                continue;
            }
        }
        let _ = root_before;
        ops_counter.store(idx + 1, Ordering::Relaxed);

        let action = should_restart(config.restart_policy, OpIndex(idx), &mut restart_rng);
        let crashing = matches!(action, RestartAction::Crash);
        if matches!(action, RestartAction::None) {
            continue;
        }
        if crashing {
            crash();
            oracle.record_crash();
        }
        shutdown_harness(&mut harness);
        match reopen_with_recovery(&mut open, &mut crash, tolerate_op_errors) {
            Ok(reopened) => {
                harness = Some(reopened);
                let n = restarts_counter.fetch_add(1, Ordering::Relaxed) + 1;
                let live = harness.as_ref().expect("just reopened");
                let before = violations.len();
                violations.extend(
                    run_quick_check(
                        &live.store,
                        &oracle,
                        root,
                        &mut sample_rng,
                        QUICK_SAMPLE_SIZE,
                        n,
                    )
                    .await,
                );
                if violations.len() > before {
                    halt_ops = true;
                }
            }
            Err(detail) => {
                violations.push(InvariantViolation {
                    invariant: "ReopenFailed",
                    detail: format!("reopen after op {idx}: {detail}"),
                });
                halt_ops = true;
                break;
            }
        }
    }

    if !halt_ops && tolerate_op_errors && harness.is_some() {
        crash();
        oracle.record_crash();
        shutdown_harness(&mut harness);
        match reopen_with_recovery(&mut open, &mut crash, tolerate_op_errors) {
            Ok(reopened) => harness = Some(reopened),
            Err(detail) => {
                violations.push(InvariantViolation {
                    invariant: "ReopenFailed",
                    detail: format!("reopen after post-run crash: {detail}"),
                });
                halt_ops = true;
            }
        }
    }

    let end_of_run_set = config.invariants.without(InvariantSet::RESTART_IDEMPOTENT);
    if !halt_ops && let Some(live) = harness.as_ref() {
        match refresh_oracle_graph(&live.store, &mut oracle, root).await {
            Ok(()) => {
                let before = violations.len();
                let snapshot = eventlog_snapshot(live.eventlog.as_ref());
                violations.extend(
                    run_invariants(&live.store, &oracle, root, snapshot, end_of_run_set).await,
                );
                if violations.len() > before {
                    halt_ops = true;
                }
            }
            Err(e) => {
                violations.push(InvariantViolation {
                    invariant: "MstRootDurability",
                    detail: format!("refresh after final reopen: {e}"),
                });
                halt_ops = true;
            }
        }
    }

    if config.invariants.contains(InvariantSet::RESTART_IDEMPOTENT)
        && !halt_ops
        && let Some(live) = harness.as_ref()
    {
        let pre_snapshot = snapshot_block_index(&live.store);
        shutdown_harness(&mut harness);
        match reopen_with_recovery(&mut open, &mut crash, tolerate_op_errors) {
            Ok(reopened) => {
                let post_snapshot = snapshot_block_index(&reopened.store);
                if let Some(detail) = diff_snapshots(&pre_snapshot, &post_snapshot) {
                    violations.push(InvariantViolation {
                        invariant: "RestartIdempotent",
                        detail,
                    });
                } else {
                    let snapshot = eventlog_snapshot(reopened.eventlog.as_ref());
                    violations.extend(
                        run_invariants(&reopened.store, &oracle, root, snapshot, post_reopen_set)
                            .await,
                    );
                }
            }
            Err(detail) => {
                violations.push(InvariantViolation {
                    invariant: "ReopenFailed",
                    detail: format!("reopen for idempotency check: {detail}"),
                });
            }
        }
    }

    GauntletReport {
        seed: config.seed,
        ops_executed: OpsExecuted(ops_counter.load(Ordering::Relaxed)),
        op_errors: OpErrorCount(op_errors_counter.load(Ordering::Relaxed)),
        restarts: RestartCount(restarts_counter.load(Ordering::Relaxed)),
        violations,
        ops: OpStream::empty(),
    }
}

fn eventlog_snapshot<S: StorageIO + Send + Sync + 'static>(
    state: Option<&EventLogState<S>>,
) -> Option<EventLogSnapshot> {
    let s = state?;
    let segments = s.manager.list_segments().unwrap_or_default();
    let mut events: Vec<SnapshotEvent> = Vec::new();
    let mut segment_last_ts: Vec<(SegmentId, u64)> = Vec::new();
    segments.iter().for_each(|&id| {
        let per_segment: Vec<ValidEvent> = match s.manager.open_for_read(id) {
            Ok(handle) => match SegmentReader::open(s.manager.io(), handle.fd(), MAX_EVENT_PAYLOAD) {
                Ok(reader) => reader.valid_prefix().unwrap_or_default(),
                Err(_) => Vec::new(),
            },
            Err(_) => Vec::new(),
        };
        if let Some(last) = per_segment.last() {
            segment_last_ts.push((id, last.timestamp.raw()));
        }
        per_segment.into_iter().for_each(|e| {
            events.push(SnapshotEvent {
                seq: e.seq,
                timestamp_us: e.timestamp.raw(),
                event_type_raw: e.event_type.raw(),
                did_hash: e.did_hash.raw(),
            });
        });
    });
    Some(EventLogSnapshot {
        segments_dir: s.segments_dir.clone(),
        max_segment_size: s.max_segment_size,
        synced_seq: s.writer.synced_seq(),
        segments,
        events,
        segment_last_ts,
    })
}

fn shutdown_harness<S: StorageIO + Send + Sync + 'static>(harness: &mut Option<Harness<S>>) {
    if let Some(h) = harness.as_mut()
        && let Some(el) = h.eventlog.as_mut()
    {
        let _ = el.writer.shutdown();
        el.manager.shutdown();
    }
    let _ = harness.take();
}

const MAX_REOPEN_ATTEMPTS: usize = 5;

fn reopen_with_recovery<S, Open, Crash>(
    open: &mut Open,
    crash: &mut Crash,
    tolerate: bool,
) -> Result<Harness<S>, String>
where
    S: StorageIO + Send + Sync + 'static,
    Open: FnMut() -> Result<Harness<S>, String>,
    Crash: FnMut(),
{
    let mut errors: Vec<String> = Vec::new();
    (0..MAX_REOPEN_ATTEMPTS)
        .find_map(|attempt| match open() {
            Ok(h) => Some(Ok(h)),
            Err(e) => {
                errors.push(format!("attempt {attempt}: {e}"));
                if !tolerate {
                    return Some(Err(errors.join(" | ")));
                }
                crash();
                None
            }
        })
        .unwrap_or_else(|| Err(errors.join(" | ")))
}

const QUICK_SAMPLE_SIZE: usize = 32;

fn sample_distinct(rng: &mut Lcg, n: usize, k: usize) -> Vec<usize> {
    assert!(k <= n, "sample_distinct: k {k} > n {n}");
    let mut selected: std::collections::HashSet<usize> =
        std::collections::HashSet::with_capacity(k);
    ((n - k)..n)
        .map(|i| {
            let t = (rng.next_u64() as usize) % (i + 1);
            let pick = if selected.contains(&t) { i } else { t };
            selected.insert(pick);
            pick
        })
        .collect()
}

async fn run_quick_check<S: StorageIO + Send + Sync + 'static>(
    store: &Arc<TranquilBlockStore<S>>,
    oracle: &Oracle,
    root: Option<Cid>,
    rng: &mut Lcg,
    sample_size: usize,
    restart_seq: usize,
) -> Vec<InvariantViolation> {
    let Some(r) = root else {
        return if oracle.live_count() == 0 {
            Vec::new()
        } else {
            vec![InvariantViolation {
                invariant: "QuickHealth",
                detail: format!(
                    "restart {restart_seq}: oracle has {} live records but reopened store has no root",
                    oracle.live_count()
                ),
            }]
        };
    };

    let mst = Mst::load(store.clone(), r, None);
    let live: Vec<(super::op::CollectionName, super::op::RecordKey, CidBytes)> = oracle
        .live_records()
        .map(|(c, k, v)| (c.clone(), k.clone(), *v))
        .collect();
    let total = live.len();
    let picks: Vec<usize> = if total <= sample_size {
        (0..total).collect()
    } else {
        sample_distinct(rng, total, sample_size)
    };

    let mut violations: Vec<String> = Vec::new();
    for idx in picks {
        let (coll, rkey, expected) = &live[idx];
        let key = format!("{}/{}", coll.0, rkey.0);
        match mst.get(&key).await {
            Ok(Some(cid)) => match try_cid_to_fixed(&cid) {
                Ok(actual) if actual == *expected => {}
                Ok(actual) => violations.push(format!(
                    "{key}: MST cid {} != oracle cid {}",
                    hex_short(&actual),
                    hex_short(expected)
                )),
                Err(e) => violations.push(format!("{key}: cid format: {e}")),
            },
            Ok(None) => violations.push(format!("{key}: missing after reopen")),
            Err(e) => violations.push(format!("{key}: mst.get error: {e}")),
        }
    }

    if violations.is_empty() {
        Vec::new()
    } else {
        vec![InvariantViolation {
            invariant: "QuickHealth",
            detail: format!(
                "restart {restart_seq}, sampled {}/{}: {}",
                violations.len(),
                sample_size.min(total),
                violations.join("; ")
            ),
        }]
    }
}

async fn run_invariants<S: StorageIO + Send + Sync + 'static>(
    store: &Arc<TranquilBlockStore<S>>,
    oracle: &Oracle,
    root: Option<Cid>,
    eventlog: Option<EventLogSnapshot>,
    set: InvariantSet,
) -> Vec<InvariantViolation> {
    let ctx = InvariantCtx::<S> {
        store,
        oracle,
        root,
        eventlog: eventlog.as_ref(),
    };
    let mut out = Vec::new();
    for inv in invariants_for::<S>(set) {
        if let Err(v) = inv.check(&ctx).await {
            out.push(v);
        }
    }
    out
}

fn snapshot_block_index<S: StorageIO + Send + Sync + 'static>(
    store: &TranquilBlockStore<S>,
) -> Vec<(CidBytes, u32)> {
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
    let pre_map: std::collections::BTreeMap<CidBytes, u32> = pre.iter().copied().collect();
    let post_map: std::collections::BTreeMap<CidBytes, u32> = post.iter().copied().collect();

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
        "block index changed across clean reopen: {} -> {} entries; {}",
        pre.len(),
        post.len(),
        items.join("; "),
    ))
}

async fn refresh_oracle_graph<S: StorageIO + Send + Sync + 'static>(
    store: &Arc<TranquilBlockStore<S>>,
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

enum RestartAction {
    None,
    Clean,
    Crash,
}

fn should_restart(policy: RestartPolicy, idx: OpIndex, rng: &mut Lcg) -> RestartAction {
    match policy {
        RestartPolicy::Never => RestartAction::None,
        RestartPolicy::EveryNOps(OpInterval(n)) => {
            if n > 0 && (idx.0 + 1).is_multiple_of(n) {
                RestartAction::Clean
            } else {
                RestartAction::None
            }
        }
        RestartPolicy::PoissonByOps(OpInterval(n)) => {
            if n > 0 && rng.next_u64().is_multiple_of(n as u64) {
                RestartAction::Clean
            } else {
                RestartAction::None
            }
        }
        RestartPolicy::CrashAtSyscall(OpInterval(n)) => {
            if n > 0 && rng.next_u64().is_multiple_of(n as u64) {
                RestartAction::Crash
            } else {
                RestartAction::None
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
        SizeDistribution::HeavyTail(range) => {
            let ValueBytes(lo) = range.min();
            let ValueBytes(hi) = range.max();
            let lo64 = u64::from(lo);
            let hi64 = u64::from(hi);
            let span = hi64.saturating_sub(lo64).max(1);
            let roll = u64::from(raw) % 1024;
            let extra = match roll {
                0..=820 => span / 64,
                821..=1000 => span / 8,
                1001..=1015 => span / 2,
                _ => span,
            };
            (lo64 + (extra.min(span))) as usize
        }
    };
    let target_len = target_len.max(8);
    let seed_bytes = raw.to_le_bytes();
    (0..target_len)
        .map(|i| seed_bytes[i % 4] ^ (i as u8).wrapping_mul(31))
        .collect()
}

fn event_payload_bytes(payload_seed: PayloadSeed) -> Vec<u8> {
    let raw = payload_seed.0;
    let len: usize = 48 + ((raw as usize) % 256);
    let seed_bytes = raw.to_le_bytes();
    (0..len)
        .map(|i| seed_bytes[i % 4] ^ (i as u8).wrapping_mul(17))
        .collect()
}

fn event_kind_to_tag(kind: EventKind) -> EventTypeTag {
    match kind {
        EventKind::Commit => EventTypeTag::COMMIT,
        EventKind::Identity => EventTypeTag::IDENTITY,
        EventKind::Account => EventTypeTag::ACCOUNT,
        EventKind::Sync => EventTypeTag::SYNC,
    }
}

fn did_hash_for_seed(seed: DidSeed) -> DidHash {
    DidHash::from_did(&format!("did:plc:gauntlet{:08x}", seed.0))
}

async fn apply_op<S: StorageIO + Send + Sync + 'static>(
    harness: &mut Harness<S>,
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
            let record_cid = hash_to_cid(&record_bytes);
            let record_cid_bytes = try_cid_to_fixed(&record_cid)?;

            let (new_root, applied) = add_record_atomic(
                &harness.store,
                *root,
                collection,
                rkey,
                record_cid,
                record_cid_bytes,
                record_bytes,
            )
            .await?;
            *root = Some(new_root);
            if applied {
                oracle.add(collection.clone(), rkey.clone(), record_cid_bytes);
            }
            Ok(())
        }
        Op::DeleteRecord { collection, rkey } => {
            let Some(old_root) = *root else { return Ok(()) };
            if !oracle.contains_record(collection, rkey) {
                return Ok(());
            }
            let new_root =
                delete_record_atomic(&harness.store, old_root, collection, rkey).await?;
            oracle.delete(collection, rkey);
            *root = Some(new_root);
            Ok(())
        }
        Op::Compact => {
            let s = harness.store.clone();
            tokio::task::spawn_blocking(move || compact_by_liveness(&s))
                .await
                .map_err(|e| OpError::Join(e.to_string()))?
        }
        Op::Checkpoint => {
            let s = harness.store.clone();
            tokio::task::spawn_blocking(move || {
                s.apply_commit_blocking(vec![], vec![])
                    .map_err(|e| e.to_string())
            })
            .await
            .map_err(|e| OpError::Join(e.to_string()))?
            .map_err(OpError::ApplyCommit)
        }
        Op::AppendEvent {
            did_seed,
            event_kind,
            payload_seed,
        } => {
            let Some(el) = harness.eventlog.as_mut() else {
                return Ok(());
            };
            let did_hash = did_hash_for_seed(*did_seed);
            let tag = event_kind_to_tag(*event_kind);
            let payload = event_payload_bytes(*payload_seed);
            let ts_before = TimestampMicros::now().raw();
            match el.writer.append(did_hash, tag, payload) {
                Ok(seq) => {
                    oracle.record_event_append(EventExpectation {
                        seq,
                        timestamp_us: ts_before,
                        kind: *event_kind,
                        did_hash: did_hash.raw(),
                    });
                    let _ = el.writer.rotate_if_needed();
                    Ok(())
                }
                Err(e) => Err(OpError::EventLogAppend(e.to_string())),
            }
        }
        Op::SyncEventLog => {
            let Some(el) = harness.eventlog.as_mut() else {
                return Ok(());
            };
            match el.writer.sync() {
                Ok(result) => {
                    let _ = el.manager.io().sync_dir(el.segments_dir.as_path());
                    let _ = el.writer.rotate_if_needed();
                    oracle.record_event_sync(result.synced_through);
                    Ok(())
                }
                Err(e) => Err(OpError::EventLogSync(e.to_string())),
            }
        }
        Op::RunRetention { max_age_secs } => {
            let Some(el) = harness.eventlog.as_mut() else {
                return Ok(());
            };
            run_retention(el, oracle, *max_age_secs).map_err(OpError::EventLogRetention)
        }
        Op::ReadRecord { collection, rkey } => {
            let Some(r) = *root else { return Ok(()) };
            let key = format!("{}/{}", collection.0, rkey.0);
            let mst = Mst::load(harness.store.clone(), r, None);
            let _ = mst.get(&key).await;
            Ok(())
        }
        Op::ReadBlock { value_seed } => {
            let record_bytes = make_record_bytes(*value_seed, workload.size_distribution);
            let record_cid = hash_to_cid_bytes(&record_bytes);
            let _ = harness.store.get_block_sync(&record_cid);
            Ok(())
        }
    }
}

fn run_retention<S: StorageIO + Send + Sync + 'static>(
    el: &mut EventLogState<S>,
    oracle: &mut Oracle,
    max_age: RetentionSecs,
) -> Result<(), String> {
    let sync_result = el.writer.sync().map_err(|e| e.to_string())?;
    let _ = el.writer.rotate_if_needed();
    oracle.record_event_sync(sync_result.synced_through);
    let active_id = sync_result.segment_id;
    let now_us = TimestampMicros::now().raw();
    let max_age_us = u64::from(max_age.0).saturating_mul(1_000_000);
    let cutoff_us = now_us.saturating_sub(max_age_us);
    let segments = el.manager.list_segments().map_err(|e| e.to_string())?;
    segments
        .iter()
        .take_while(|&&id| id != active_id)
        .try_for_each(|&id| -> Result<(), String> {
            let last_ts = segment_last_timestamp(&el.manager, id).map_err(|e| e.to_string())?;
            match last_ts {
                Some(ts) if ts < cutoff_us => {
                    el.manager.delete_segment(id).map_err(|e| e.to_string())
                }
                _ => Ok(()),
            }
        })?;
    oracle.record_retention(cutoff_us);
    Ok(())
}

fn segment_last_timestamp<S: StorageIO + Send + Sync + 'static>(
    manager: &SegmentManager<S>,
    id: SegmentId,
) -> std::io::Result<Option<u64>> {
    let handle = manager.open_for_read(id)?;
    let reader = SegmentReader::open(manager.io(), handle.fd(), MAX_EVENT_PAYLOAD)?;
    let events = reader.valid_prefix()?;
    Ok(events.last().map(|e: &ValidEvent| e.timestamp.raw()))
}

async fn add_record_atomic<S: StorageIO + Send + Sync + 'static>(
    store: &Arc<TranquilBlockStore<S>>,
    root: Option<Cid>,
    collection: &super::op::CollectionName,
    rkey: &super::op::RecordKey,
    record_cid: Cid,
    record_cid_bytes: CidBytes,
    record_bytes: Vec<u8>,
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
    let diff = loaded
        .diff(&updated)
        .await
        .map_err(|e| OpError::MstDiff(e.to_string()))?;
    let new_root = updated
        .get_pointer()
        .await
        .map_err(|e| OpError::MstPersist(e.to_string()))?;

    if matches!(root, Some(r) if r == new_root) {
        return Ok((new_root, false));
    }

    let blocks = diff_blocks_plus_record(diff.new_mst_blocks, record_cid_bytes, record_bytes)?;
    let obsolete = diff_obsolete(diff.removed_mst_blocks, diff.removed_cids)?;
    commit_atomic(store, blocks, obsolete).await?;
    Ok((new_root, true))
}

async fn delete_record_atomic<S: StorageIO + Send + Sync + 'static>(
    store: &Arc<TranquilBlockStore<S>>,
    old_root: Cid,
    collection: &super::op::CollectionName,
    rkey: &super::op::RecordKey,
) -> Result<Cid, OpError> {
    let key = format!("{}/{}", collection.0, rkey.0);
    let loaded = Mst::load(store.clone(), old_root, None);
    let updated = loaded
        .delete(&key)
        .await
        .map_err(|e| OpError::MstDelete(e.to_string()))?;
    let diff = loaded
        .diff(&updated)
        .await
        .map_err(|e| OpError::MstDiff(e.to_string()))?;
    let new_root = updated
        .get_pointer()
        .await
        .map_err(|e| OpError::MstPersist(e.to_string()))?;
    let blocks: Vec<(CidBytes, Vec<u8>)> = diff
        .new_mst_blocks
        .into_iter()
        .map(|(c, b)| Ok::<_, OpError>((try_cid_to_fixed(&c)?, b.to_vec())))
        .collect::<Result<_, _>>()?;
    let obsolete = diff_obsolete(diff.removed_mst_blocks, diff.removed_cids)?;
    commit_atomic(store, blocks, obsolete).await?;
    Ok(new_root)
}

fn diff_blocks_plus_record(
    new_mst_blocks: std::collections::BTreeMap<Cid, bytes::Bytes>,
    record_cid_bytes: CidBytes,
    record_bytes: Vec<u8>,
) -> Result<Vec<(CidBytes, Vec<u8>)>, OpError> {
    let mut blocks: Vec<(CidBytes, Vec<u8>)> = Vec::with_capacity(new_mst_blocks.len() + 1);
    blocks.push((record_cid_bytes, record_bytes));
    new_mst_blocks.into_iter().try_for_each(|(c, b)| {
        let cb = try_cid_to_fixed(&c)?;
        blocks.push((cb, b.to_vec()));
        Ok::<_, OpError>(())
    })?;
    Ok(blocks)
}

fn diff_obsolete(
    removed_mst_blocks: Vec<Cid>,
    removed_cids: Vec<Cid>,
) -> Result<Vec<CidBytes>, OpError> {
    removed_mst_blocks
        .into_iter()
        .chain(removed_cids.into_iter())
        .map(|c| try_cid_to_fixed(&c))
        .collect::<Result<_, _>>()
        .map_err(OpError::from)
}

async fn commit_atomic<S: StorageIO + Send + Sync + 'static>(
    store: &Arc<TranquilBlockStore<S>>,
    blocks: Vec<(CidBytes, Vec<u8>)>,
    obsolete: Vec<CidBytes>,
) -> Result<(), OpError> {
    let s = store.clone();
    tokio::task::spawn_blocking(move || {
        s.apply_commit_blocking(blocks, obsolete)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| OpError::Join(e.to_string()))?
    .map_err(OpError::ApplyCommit)
}

const COMPACT_LIVENESS_CEILING: f64 = 0.99;

fn compact_by_liveness<S: StorageIO + Send + Sync + 'static>(
    store: &TranquilBlockStore<S>,
) -> Result<(), OpError> {
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
            Err(CompactionError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(OpError::CompactFile(format!("{fid}: {e}"))),
        })
}

async fn apply_op_concurrent<S: StorageIO + Send + Sync + 'static>(
    shared: &Arc<SharedState<S>>,
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
            let record_cid = hash_to_cid(&record_bytes);
            let record_cid_bytes = try_cid_to_fixed(&record_cid)?;

            let mut state = shared.write.lock().await;
            let (new_root, applied) = add_record_atomic(
                &shared.store,
                state.root,
                collection,
                rkey,
                record_cid,
                record_cid_bytes,
                record_bytes,
            )
            .await?;
            state.root = Some(new_root);
            if applied {
                state
                    .oracle
                    .add(collection.clone(), rkey.clone(), record_cid_bytes);
            }
            Ok(())
        }
        Op::DeleteRecord { collection, rkey } => {
            let mut state = shared.write.lock().await;
            let Some(old_root) = state.root else {
                return Ok(());
            };
            if !state.oracle.contains_record(collection, rkey) {
                return Ok(());
            }
            let new_root =
                delete_record_atomic(&shared.store, old_root, collection, rkey).await?;
            state.oracle.delete(collection, rkey);
            state.root = Some(new_root);
            Ok(())
        }
        Op::Compact => {
            let _guard = shared.write.lock().await;
            let s = shared.store.clone();
            tokio::task::spawn_blocking(move || compact_by_liveness(&s))
                .await
                .map_err(|e| OpError::Join(e.to_string()))?
        }
        Op::Checkpoint => {
            let s = shared.store.clone();
            tokio::task::spawn_blocking(move || {
                s.apply_commit_blocking(vec![], vec![])
                    .map_err(|e| e.to_string())
            })
            .await
            .map_err(|e| OpError::Join(e.to_string()))?
            .map_err(OpError::ApplyCommit)
        }
        Op::AppendEvent {
            did_seed,
            event_kind,
            payload_seed,
        } => {
            let did_hash = did_hash_for_seed(*did_seed);
            let tag = event_kind_to_tag(*event_kind);
            let payload = event_payload_bytes(*payload_seed);
            let ts_before = TimestampMicros::now().raw();
            let mut state = shared.write.lock().await;
            let Some(el) = state.eventlog.as_mut() else {
                return Ok(());
            };
            match el.writer.append(did_hash, tag, payload) {
                Ok(seq) => {
                    let _ = el.writer.rotate_if_needed();
                    state.oracle.record_event_append(EventExpectation {
                        seq,
                        timestamp_us: ts_before,
                        kind: *event_kind,
                        did_hash: did_hash.raw(),
                    });
                    Ok(())
                }
                Err(e) => Err(OpError::EventLogAppend(e.to_string())),
            }
        }
        Op::SyncEventLog => {
            let mut state = shared.write.lock().await;
            let Some(el) = state.eventlog.as_mut() else {
                return Ok(());
            };
            match el.writer.sync() {
                Ok(result) => {
                    let _ = el.manager.io().sync_dir(el.segments_dir.as_path());
                    let _ = el.writer.rotate_if_needed();
                    state.oracle.record_event_sync(result.synced_through);
                    Ok(())
                }
                Err(e) => Err(OpError::EventLogSync(e.to_string())),
            }
        }
        Op::RunRetention { max_age_secs } => {
            let mut state_guard = shared.write.lock().await;
            let state = &mut *state_guard;
            let WriteState {
                oracle, eventlog, ..
            } = state;
            let Some(el) = eventlog.as_mut() else {
                return Ok(());
            };
            run_retention(el, oracle, *max_age_secs).map_err(OpError::EventLogRetention)
        }
        Op::ReadRecord { collection, rkey } => {
            let r = { shared.write.lock().await.root };
            let Some(r) = r else {
                return Ok(());
            };
            let key = format!("{}/{}", collection.0, rkey.0);
            let mst = Mst::load(shared.store.clone(), r, None);
            let _ = mst.get(&key).await;
            Ok(())
        }
        Op::ReadBlock { value_seed } => {
            let record_bytes = make_record_bytes(*value_seed, workload.size_distribution);
            let record_cid = hash_to_cid_bytes(&record_bytes);
            let _ = shared.store.get_block_sync(&record_cid);
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn writer_task<S: StorageIO + Send + Sync + 'static>(
    shared: Arc<SharedState<S>>,
    ops: Arc<Vec<Op>>,
    index: Arc<AtomicUsize>,
    end: usize,
    workload: Arc<WorkloadModel>,
    ops_counter: Arc<AtomicUsize>,
    op_errors_counter: Arc<AtomicUsize>,
    tolerate_op_errors: bool,
) -> Option<InvariantViolation> {
    loop {
        let idx = index.fetch_add(1, Ordering::Relaxed);
        if idx >= end {
            return None;
        }
        let op = &ops[idx];
        match apply_op_concurrent(&shared, op, &workload).await {
            Ok(()) => {
                ops_counter.fetch_max(idx + 1, Ordering::Relaxed);
            }
            Err(e) => {
                if tolerate_op_errors {
                    op_errors_counter.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                return Some(InvariantViolation {
                    invariant: "OpExecution",
                    detail: format!("op {idx}: {e}"),
                });
            }
        }
    }
}

fn compute_chunks(
    policy: RestartPolicy,
    total_ops: usize,
    restart_rng: &mut Lcg,
) -> Vec<(Range<usize>, RestartAction)> {
    let points: Vec<(usize, RestartAction)> = (0..total_ops)
        .filter_map(|i| match should_restart(policy, OpIndex(i), restart_rng) {
            RestartAction::None => None,
            a => Some((i + 1, a)),
        })
        .collect();
    let mut chunks = Vec::new();
    let mut start = 0;
    for (end, action) in points {
        chunks.push((start..end, action));
        start = end;
    }
    if start < total_ops {
        chunks.push((start..total_ops, RestartAction::None));
    }
    chunks
}

#[allow(clippy::too_many_arguments)]
async fn run_inner_generic_concurrent<S, Open, Crash>(
    config: GauntletConfig,
    op_stream: OpStream,
    ops_counter: Arc<AtomicUsize>,
    op_errors_counter: Arc<AtomicUsize>,
    restarts_counter: Arc<AtomicUsize>,
    mut open: Open,
    mut crash: Crash,
    tolerate_op_errors: bool,
) -> GauntletReport
where
    S: StorageIO + Send + Sync + 'static,
    Open: FnMut() -> Result<Harness<S>, String>,
    Crash: FnMut(),
{
    let ops: Vec<Op> = op_stream.into_vec();
    let total_ops = ops.len();
    let ops_arc = Arc::new(ops);
    let workload_arc = Arc::new(config.workload.clone());

    let mut violations: Vec<InvariantViolation> = Vec::new();
    let mut restart_rng = Lcg::new(Seed(config.seed.0 ^ 0xA5A5_A5A5_A5A5_A5A5));
    let mut sample_rng = Lcg::new(Seed(config.seed.0 ^ 0x5A5A_5A5A_5A5A_5A5A));
    let chunks = compute_chunks(config.restart_policy, total_ops, &mut restart_rng);

    let mut harness: Option<Harness<S>> = match open() {
        Ok(h) => Some(h),
        Err(e) => {
            return GauntletReport {
                seed: config.seed,
                ops_executed: OpsExecuted(0),
                op_errors: OpErrorCount(op_errors_counter.load(Ordering::Relaxed)),
                restarts: RestartCount(0),
                violations: vec![InvariantViolation {
                    invariant: "OpenStore",
                    detail: format!("initial open: {e}"),
                }],
                ops: OpStream::empty(),
            };
        }
    };
    let mut root: Option<Cid> = None;
    let mut oracle = Oracle::new();
    let mut halt_ops = false;

    let writer_n = config.writer_concurrency.0.max(1);

    for (chunk_i, (chunk_range, action)) in chunks.iter().enumerate() {
        if halt_ops {
            break;
        }
        let current = harness.take().expect("harness present before chunk");
        let taken_oracle = std::mem::take(&mut oracle);
        let shared = Arc::new(SharedState {
            store: Arc::clone(&current.store),
            write: tokio::sync::Mutex::new(WriteState {
                root,
                oracle: taken_oracle,
                eventlog: current.eventlog,
            }),
        });

        let index = Arc::new(AtomicUsize::new(chunk_range.start));
        let end = chunk_range.end;
        let mut handles: Vec<tokio::task::JoinHandle<Option<InvariantViolation>>> = Vec::new();
        for _ in 0..writer_n {
            handles.push(tokio::spawn(writer_task(
                Arc::clone(&shared),
                Arc::clone(&ops_arc),
                Arc::clone(&index),
                end,
                Arc::clone(&workload_arc),
                Arc::clone(&ops_counter),
                Arc::clone(&op_errors_counter),
                tolerate_op_errors,
            )));
        }
        for h in handles.drain(..) {
            match h.await {
                Ok(None) => {}
                Ok(Some(v)) => {
                    violations.push(v);
                    halt_ops = true;
                }
                Err(join) => {
                    violations.push(InvariantViolation {
                        invariant: "TaskJoin",
                        detail: join.to_string(),
                    });
                    halt_ops = true;
                }
            }
        }

        let shared = match Arc::try_unwrap(shared) {
            Ok(s) => s,
            Err(still_held) => {
                violations.push(InvariantViolation {
                    invariant: "ConcurrencyInvariant",
                    detail: format!(
                        "SharedState still held by {} refs after task join",
                        Arc::strong_count(&still_held)
                    ),
                });
                halt_ops = true;
                break;
            }
        };
        let store = shared.store;
        let write_state = shared.write.into_inner();
        root = write_state.root;
        oracle = write_state.oracle;
        let eventlog = write_state.eventlog;
        harness = Some(Harness { store, eventlog });

        if halt_ops {
            break;
        }

        match action {
            RestartAction::None => {}
            RestartAction::Clean | RestartAction::Crash => {
                if matches!(action, RestartAction::Crash) {
                    crash();
                    oracle.record_crash();
                }
                shutdown_harness(&mut harness);
                match reopen_with_recovery(&mut open, &mut crash, tolerate_op_errors) {
                    Ok(reopened) => {
                        harness = Some(reopened);
                        let n = restarts_counter.fetch_add(1, Ordering::Relaxed) + 1;
                        let live = harness.as_ref().expect("just reopened");
                        let before = violations.len();
                        violations.extend(
                            run_quick_check(
                                &live.store,
                                &oracle,
                                root,
                                &mut sample_rng,
                                QUICK_SAMPLE_SIZE,
                                n,
                            )
                            .await,
                        );
                        if violations.len() > before {
                            halt_ops = true;
                        }
                    }
                    Err(detail) => {
                        violations.push(InvariantViolation {
                            invariant: "ReopenFailed",
                            detail: format!("reopen after chunk {chunk_i}: {detail}"),
                        });
                        halt_ops = true;
                    }
                }
            }
        }
    }

    if !halt_ops && tolerate_op_errors && harness.is_some() {
        crash();
        oracle.record_crash();
        shutdown_harness(&mut harness);
        match reopen_with_recovery(&mut open, &mut crash, tolerate_op_errors) {
            Ok(reopened) => harness = Some(reopened),
            Err(detail) => {
                violations.push(InvariantViolation {
                    invariant: "ReopenFailed",
                    detail: format!("reopen after post-run crash: {detail}"),
                });
                halt_ops = true;
            }
        }
    }

    let end_of_run_set = config.invariants.without(InvariantSet::RESTART_IDEMPOTENT);
    if !halt_ops && let Some(live) = harness.as_ref() {
        match refresh_oracle_graph(&live.store, &mut oracle, root).await {
            Ok(()) => {
                let before = violations.len();
                let snapshot = eventlog_snapshot(live.eventlog.as_ref());
                violations.extend(
                    run_invariants(&live.store, &oracle, root, snapshot, end_of_run_set).await,
                );
                if violations.len() > before {
                    halt_ops = true;
                }
            }
            Err(e) => {
                violations.push(InvariantViolation {
                    invariant: "MstRootDurability",
                    detail: format!("refresh after final reopen: {e}"),
                });
                halt_ops = true;
            }
        }
    }

    let post_reopen_set = config.invariants.without(InvariantSet::RESTART_IDEMPOTENT);
    if config.invariants.contains(InvariantSet::RESTART_IDEMPOTENT)
        && !halt_ops
        && let Some(live) = harness.as_ref()
    {
        let pre_snapshot = snapshot_block_index(&live.store);
        shutdown_harness(&mut harness);
        match reopen_with_recovery(&mut open, &mut crash, tolerate_op_errors) {
            Ok(reopened) => {
                let post_snapshot = snapshot_block_index(&reopened.store);
                if let Some(detail) = diff_snapshots(&pre_snapshot, &post_snapshot) {
                    violations.push(InvariantViolation {
                        invariant: "RestartIdempotent",
                        detail,
                    });
                } else {
                    let snapshot = eventlog_snapshot(reopened.eventlog.as_ref());
                    violations.extend(
                        run_invariants(&reopened.store, &oracle, root, snapshot, post_reopen_set)
                            .await,
                    );
                }
            }
            Err(detail) => {
                violations.push(InvariantViolation {
                    invariant: "ReopenFailed",
                    detail: format!("reopen for idempotency check: {detail}"),
                });
            }
        }
    }

    GauntletReport {
        seed: config.seed,
        ops_executed: OpsExecuted(ops_counter.load(Ordering::Relaxed)),
        op_errors: OpErrorCount(op_errors_counter.load(Ordering::Relaxed)),
        restarts: RestartCount(restarts_counter.load(Ordering::Relaxed)),
        violations,
        ops: OpStream::empty(),
    }
}
