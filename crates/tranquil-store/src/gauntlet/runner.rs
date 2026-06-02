use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use cid::Cid;
use jacquard_repo::mst::Mst;

use super::flaky::{FlakyConfig, FlakyMount};
use super::invariants::{
    EventLogSnapshot, InvariantCtx, InvariantSet, InvariantViolation, SnapshotEvent, invariants_for,
};
use super::op::{DidSeed, EventKind, Op, OpStream, PayloadSeed, RetentionSecs, Seed, ValueSeed};
use super::oracle::{CidFormatError, EventExpectation, Oracle, hex_short, try_cid_to_fixed};
use super::workload::{Lcg, OpCount, SizeDistribution, ValueBytes, WorkloadModel};
use crate::blockstore::{
    BlockStoreConfig, CidBytes, CompactionError, DataFileId, GroupCommitConfig, TranquilBlockStore,
    hash_to_cid, hash_to_cid_bytes,
};
use crate::clock::{Clock, SimClock, SystemClock};
use crate::eventlog::{
    DEFAULT_INDEX_INTERVAL, DidHash, EventLogWriter, EventTypeTag, MAX_EVENT_PAYLOAD, SegmentId,
    SegmentManager, SegmentReader, ValidEvent, parse_segment_id,
};
use crate::io::{RealIO, StorageIO};
use crate::sim::{FaultConfig, PristineGuard, SimulatedIO};

#[derive(Debug, Clone, Copy)]
pub enum IoBackend {
    Real,
    RealWithFlaky { flaky: FlakyConfig },
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
    pub tolerate_op_errors: bool,
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
pub(super) enum OpError {
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
    #[error("read validation: {0}")]
    ReadValidation(String),
}

impl OpError {
    pub(super) fn is_hard_violation(&self) -> bool {
        matches!(self, OpError::ReadValidation(_))
    }
}

pub struct EventLogState<S: StorageIO + Send + Sync + 'static> {
    pub writer: EventLogWriter<S>,
    pub manager: Arc<SegmentManager<S>>,
    pub segments_dir: PathBuf,
    pub max_segment_size: u64,
}

pub struct Harness<S: StorageIO + Send + Sync + 'static, C: Clock> {
    pub store: Arc<TranquilBlockStore<S, C>>,
    pub eventlog: Option<EventLogState<S>>,
}

pub struct WriteState<S: StorageIO + Send + Sync + 'static> {
    pub root: Option<Cid>,
    pub oracle: Oracle,
    pub eventlog: Option<EventLogState<S>>,
}

pub struct SharedState<S: StorageIO + Send + Sync + 'static, C: Clock> {
    pub store: Arc<TranquilBlockStore<S, C>>,
    pub write: tokio::sync::Mutex<WriteState<S>>,
}

pub struct Gauntlet {
    config: GauntletConfig,
    scratch_root: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum GauntletBuildError {}

impl Gauntlet {
    pub fn new(config: GauntletConfig) -> Result<Self, GauntletBuildError> {
        Ok(Self {
            config,
            scratch_root: None,
        })
    }

    pub fn with_scratch_root(mut self, root: PathBuf) -> Self {
        self.scratch_root = Some(root);
        self
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
        let scratch_root = self.scratch_root;
        let fut: std::pin::Pin<Box<dyn std::future::Future<Output = GauntletReport> + Send>> =
            match self.config.io {
                IoBackend::Real => Box::pin(run_inner_real(
                    self.config,
                    ops,
                    ops_counter.clone(),
                    op_errors_counter.clone(),
                    restarts_counter.clone(),
                    scratch_root,
                )),
                IoBackend::RealWithFlaky { flaky } => Box::pin(run_inner_real_with_flaky(
                    self.config,
                    flaky,
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

pub(super) fn segments_subdir(root: &Path) -> PathBuf {
    root.join("segments")
}

async fn run_inner_real(
    config: GauntletConfig,
    ops: OpStream,
    ops_counter: Arc<AtomicUsize>,
    op_errors_counter: Arc<AtomicUsize>,
    restarts_counter: Arc<AtomicUsize>,
    scratch_root: Option<PathBuf>,
) -> GauntletReport {
    let dir = match scratch_root.as_deref() {
        Some(parent) => tempfile::TempDir::new_in(parent).expect("tempdir in scratch root"),
        None => tempfile::TempDir::new().expect("tempdir"),
    };
    let root = dir.path().to_path_buf();
    let tolerate = config.tolerate_op_errors;
    let report = run_inner_real_on_root(
        config,
        root,
        ops,
        ops_counter,
        op_errors_counter,
        restarts_counter,
        tolerate,
        Duration::ZERO,
    )
    .await;
    drop(dir);
    report
}

async fn run_inner_real_with_flaky(
    config: GauntletConfig,
    flaky_cfg: FlakyConfig,
    ops: OpStream,
    ops_counter: Arc<AtomicUsize>,
    op_errors_counter: Arc<AtomicUsize>,
    restarts_counter: Arc<AtomicUsize>,
) -> GauntletReport {
    let mount = match FlakyMount::try_new(&flaky_cfg) {
        Ok(m) => m,
        Err(e) => {
            let invariant = if e.is_env_absent() {
                "FlakyEnvironment"
            } else {
                "FlakyOperational"
            };
            return GauntletReport {
                seed: config.seed,
                ops_executed: OpsExecuted(0),
                op_errors: OpErrorCount(0),
                restarts: RestartCount(0),
                violations: vec![InvariantViolation {
                    invariant,
                    detail: format!("flaky mount: {e}"),
                }],
                ops: OpStream::empty(),
            };
        }
    };
    let root = mount.path().join("store");
    if let Err(e) = std::fs::create_dir_all(&root) {
        return GauntletReport {
            seed: config.seed,
            ops_executed: OpsExecuted(0),
            op_errors: OpErrorCount(0),
            restarts: RestartCount(0),
            violations: vec![InvariantViolation {
                invariant: "FlakyOperational",
                detail: format!("create_dir_all {}: {e}", root.display()),
            }],
            ops: OpStream::empty(),
        };
    }
    let down_ms = u64::from(flaky_cfg.down_interval.0.get())
        .saturating_mul(1_000)
        .saturating_add(500);
    let report = run_inner_real_on_root(
        config,
        root,
        ops,
        ops_counter,
        op_errors_counter,
        restarts_counter,
        true,
        Duration::from_millis(down_ms),
    )
    .await;
    drop(mount);
    report
}

#[allow(clippy::too_many_arguments)]
async fn run_inner_real_on_root(
    config: GauntletConfig,
    root: PathBuf,
    ops: OpStream,
    ops_counter: Arc<AtomicUsize>,
    op_errors_counter: Arc<AtomicUsize>,
    restarts_counter: Arc<AtomicUsize>,
    tolerate_op_errors: bool,
    reopen_backoff: Duration,
) -> GauntletReport {
    let cfg = blockstore_config(&root, &config.store);
    let eventlog_cfg = config.eventlog;
    let segments_dir = segments_subdir(&root);
    let open = {
        let segments_dir = segments_dir.clone();
        move |_attempt: usize| -> Result<Harness<RealIO, SystemClock>, String> {
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
        run_inner_generic_concurrent::<RealIO, SystemClock, _, _, _>(
            config,
            ops,
            ops_counter,
            op_errors_counter,
            restarts_counter,
            open,
            Vec::new,
            tolerate_op_errors,
            reopen_backoff,
            SystemClock,
            |_| {},
        )
        .await
    } else {
        run_inner_generic::<RealIO, SystemClock, _, _, _>(
            config,
            ops,
            ops_counter,
            op_errors_counter,
            restarts_counter,
            open,
            Vec::new,
            tolerate_op_errors,
            reopen_backoff,
            SystemClock,
            |_| {},
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
    let mut cfg = blockstore_config(dir.path(), &config.store);
    cfg.group_commit.synchronous = config.writer_concurrency.0 == 1;
    let tolerate_errors = fault.injects_errors() || config.tolerate_op_errors;
    let eventlog_cfg = config.eventlog;
    let segments_dir = segments_subdir(dir.path());
    let sim: Arc<SimulatedIO> = Arc::new(SimulatedIO::new(config.seed.0, fault));
    let clock = sim.clock();
    let sim_for_open = Arc::clone(&sim);
    let clock_for_open = clock.clone();
    let open = {
        let segments_dir = segments_dir.clone();
        move |attempt: usize| -> Result<Harness<Arc<SimulatedIO>, SimClock>, String> {
            let _pristine = PristineGuard::new(Arc::clone(&sim_for_open), attempt > 0);
            let factory_sim = Arc::clone(&sim_for_open);
            let make_io = move || Arc::clone(&factory_sim);
            let store = TranquilBlockStore::<Arc<SimulatedIO>, SimClock>::open_with_io(
                cfg.clone(),
                make_io,
                clock_for_open.clone(),
            )
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
    let sim_for_quiesce = Arc::clone(&sim);
    let quiesce = move |on: bool| sim_for_quiesce.set_pristine_mode(on);
    if config.writer_concurrency.0 > 1 {
        run_inner_generic_concurrent::<Arc<SimulatedIO>, SimClock, _, _, _>(
            config,
            ops,
            ops_counter,
            op_errors_counter,
            restarts_counter,
            open,
            crash,
            tolerate_errors,
            Duration::ZERO,
            clock,
            quiesce,
        )
        .await
    } else {
        run_inner_generic::<Arc<SimulatedIO>, SimClock, _, _, _>(
            config,
            ops,
            ops_counter,
            op_errors_counter,
            restarts_counter,
            open,
            crash,
            tolerate_errors,
            Duration::ZERO,
            clock,
            quiesce,
        )
        .await
    }
}

pub(super) fn open_eventlog<S: StorageIO + Send + Sync + 'static>(
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
async fn run_inner_generic<S, C, Open, Crash, Quiesce>(
    config: GauntletConfig,
    op_stream: OpStream,
    ops_counter: Arc<AtomicUsize>,
    op_errors_counter: Arc<AtomicUsize>,
    restarts_counter: Arc<AtomicUsize>,
    mut open: Open,
    mut crash: Crash,
    tolerate_op_errors: bool,
    reopen_backoff: Duration,
    clock: C,
    quiesce_faults: Quiesce,
) -> GauntletReport
where
    S: StorageIO + Send + Sync + 'static,
    C: Clock,
    Open: FnMut(usize) -> Result<Harness<S, C>, String>,
    Crash: FnMut() -> Vec<PathBuf>,
    Quiesce: Fn(bool),
{
    let mut oracle = Oracle::new();
    let mut violations: Vec<InvariantViolation> = Vec::new();

    let mut harness: Option<Harness<S, C>> =
        match reopen_with_recovery(&mut open, &mut crash, tolerate_op_errors, reopen_backoff).await
        {
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
        match apply_op(live, &mut root, &mut oracle, op, &config.workload, &clock).await {
            Ok(()) => {}
            Err(e) if e.is_hard_violation() => {
                violations.push(InvariantViolation {
                    invariant: "ReadValidation",
                    detail: format!("op {idx}: {e}"),
                });
                halt_ops = true;
                continue;
            }
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
            let removed = crash();
            record_crash_losses(&removed, harness.as_ref(), &mut oracle);
        }
        shutdown_harness(&mut harness);
        match reopen_with_recovery(&mut open, &mut crash, tolerate_op_errors, reopen_backoff).await
        {
            Ok(reopened) => {
                harness = Some(reopened);
                let n = restarts_counter.fetch_add(1, Ordering::Relaxed) + 1;
                let live = harness.as_ref().expect("just reopened");
                let before = violations.len();
                quiesce_faults(true);
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
                quiesce_faults(false);
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

    quiesce_faults(true);
    if !halt_ops && tolerate_op_errors && harness.is_some() {
        let removed = crash();
        record_crash_losses(&removed, harness.as_ref(), &mut oracle);
        shutdown_harness(&mut harness);
        match reopen_with_recovery(&mut open, &mut crash, tolerate_op_errors, reopen_backoff).await
        {
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
    if !halt_ops
        && config.invariants.contains(InvariantSet::MST_REPAIRABLE)
        && let Some(live) = harness.as_ref()
        && let Some(v) = attempt_structural_repair(&live.store, &oracle, root).await
    {
        violations.push(v);
        halt_ops = true;
    }
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
        match reopen_with_recovery(&mut open, &mut crash, tolerate_op_errors, reopen_backoff).await
        {
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

pub(super) fn eventlog_snapshot<S: StorageIO + Send + Sync + 'static>(
    state: Option<&EventLogState<S>>,
) -> Option<EventLogSnapshot> {
    let s = state?;
    let segments = s.manager.list_segments().unwrap_or_default();
    let mut events: Vec<SnapshotEvent> = Vec::new();
    let mut segment_last_ts: Vec<(SegmentId, u64)> = Vec::new();
    segments.iter().for_each(|&id| {
        let per_segment: Vec<ValidEvent> = match s.manager.open_for_read(id) {
            Ok(handle) => match SegmentReader::open(s.manager.io(), handle.fd(), MAX_EVENT_PAYLOAD)
            {
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

fn shutdown_harness<S: StorageIO + Send + Sync + 'static, C: Clock>(
    harness: &mut Option<Harness<S, C>>,
) {
    if let Some(h) = harness.as_mut()
        && let Some(el) = h.eventlog.as_mut()
    {
        let _ = el.writer.shutdown();
        el.manager.shutdown();
    }
    let _ = harness.take();
}

fn record_crash_losses<S: StorageIO + Send + Sync + 'static, C: Clock>(
    removed: &[PathBuf],
    harness: Option<&Harness<S, C>>,
    oracle: &mut Oracle,
) {
    mark_block_crash_losses(removed, harness, oracle);
    mark_event_crash_losses(removed, oracle);
    oracle.record_crash();
}

fn mark_block_crash_losses<S: StorageIO + Send + Sync + 'static, C: Clock>(
    removed: &[PathBuf],
    harness: Option<&Harness<S, C>>,
    oracle: &mut Oracle,
) {
    let Some(h) = harness else { return };
    let data_dir = h.store.data_dir();
    let lost: Vec<CidBytes> = removed
        .iter()
        .filter(|p| p.parent() == Some(data_dir))
        .filter_map(|p| p.file_stem()?.to_str()?.parse::<u32>().ok())
        .map(DataFileId::new)
        .flat_map(|fid| h.store.block_index().cids_in_file(fid))
        .collect();
    if !lost.is_empty() {
        oracle.mark_blocks_lost(lost);
    }
}

fn mark_event_crash_losses(removed: &[PathBuf], oracle: &mut Oracle) {
    let lost: std::collections::HashSet<SegmentId> =
        removed.iter().filter_map(|p| parse_segment_id(p)).collect();
    oracle.forget_events_in_segments(&lost);
}

const MAX_REOPEN_ATTEMPTS: usize = 5;

async fn reopen_with_recovery<S, C, Open, Crash>(
    open: &mut Open,
    crash: &mut Crash,
    tolerate: bool,
    backoff: Duration,
) -> Result<Harness<S, C>, String>
where
    S: StorageIO + Send + Sync + 'static,
    C: Clock,
    Open: FnMut(usize) -> Result<Harness<S, C>, String>,
    Crash: FnMut() -> Vec<PathBuf>,
{
    let mut errors: Vec<String> = Vec::new();
    for attempt in 0..MAX_REOPEN_ATTEMPTS {
        if attempt > 0 && !backoff.is_zero() {
            tokio::time::sleep(backoff).await;
        }
        match open(attempt) {
            Ok(h) => return Ok(h),
            Err(e) => {
                errors.push(format!("attempt {attempt}: {e}"));
                if !tolerate {
                    return Err(errors.join(" | "));
                }
                crash();
            }
        }
    }
    Err(errors.join(" | "))
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

async fn run_quick_check<S: StorageIO + Send + Sync + 'static, C: Clock>(
    store: &Arc<TranquilBlockStore<S, C>>,
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

    let store_c = store.clone();
    let lost_clone = oracle.lost_blocks().clone();
    let live_clone = live.clone();
    let picks_c = picks.clone();
    let violations: Vec<String> = tokio::task::spawn_blocking(move || {
        picks_c
            .iter()
            .filter_map(|&idx| {
                let (coll, rkey, expected) = &live_clone[idx];
                let key = format!("{}/{}", coll.0, rkey.0);
                match super::chaos_walker::mst_get_tolerant(&store_c, r, &key, &lost_clone) {
                    Ok(super::chaos_walker::LookupResult::Found(cid)) => {
                        match try_cid_to_fixed(&cid) {
                            Ok(actual) if actual == *expected => None,
                            Ok(actual) => Some(format!(
                                "{key}: MST cid {} != oracle cid {}",
                                hex_short(&actual),
                                hex_short(expected)
                            )),
                            Err(e) => Some(format!("{key}: cid format: {e}")),
                        }
                    }
                    Ok(super::chaos_walker::LookupResult::NotFound) => {
                        Some(format!("{key}: missing after reopen"))
                    }
                    Ok(super::chaos_walker::LookupResult::LostPath) => None,
                    Err(e) => Some(format!("{key}: mst.get error: {e}")),
                }
            })
            .collect()
    })
    .await
    .unwrap_or_else(|e| vec![format!("quick_check join: {e}")]);

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

pub(super) async fn run_invariants<S: StorageIO + Send + Sync + 'static, C: Clock>(
    store: &Arc<TranquilBlockStore<S, C>>,
    oracle: &Oracle,
    root: Option<Cid>,
    eventlog: Option<EventLogSnapshot>,
    set: InvariantSet,
) -> Vec<InvariantViolation> {
    let ctx = InvariantCtx::<S, C> {
        store,
        oracle,
        root,
        eventlog: eventlog.as_ref(),
    };
    let mut out = Vec::new();
    for inv in invariants_for::<S, C>(set) {
        if let Err(v) = inv.check(&ctx).await {
            out.push(v);
        }
    }
    out
}

fn snapshot_block_index<S: StorageIO + Send + Sync + 'static, C: Clock>(
    store: &TranquilBlockStore<S, C>,
) -> Vec<(CidBytes, u32)> {
    let mut v: Vec<(CidBytes, u32)> = store
        .block_index()
        .live_entries_snapshot()
        .into_iter()
        .map(|(c, r)| (c, r.raw()))
        .collect();
    v.sort_unstable_by_key(|a| a.0);
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

pub(super) async fn refresh_oracle_graph<S: StorageIO + Send + Sync + 'static, C: Clock>(
    store: &Arc<TranquilBlockStore<S, C>>,
    oracle: &mut Oracle,
    root: Option<Cid>,
) -> Result<(), String> {
    match root {
        None => {
            oracle.clear_mst_state();
            Ok(())
        }
        Some(r) => {
            let store_c = store.clone();
            let lost_clone = oracle.lost_blocks().clone();
            let fixed = tokio::task::spawn_blocking(move || {
                super::chaos_walker::walk_mst_node_cids_tolerant(&store_c, r, &lost_clone)
            })
            .await
            .map_err(|e| format!("refresh join: {e}"))??;
            oracle.set_root(r);
            oracle.set_mst_node_cids(fixed);
            Ok(())
        }
    }
}

async fn attempt_structural_repair<S: StorageIO + Send + Sync + 'static, C: Clock>(
    store: &Arc<TranquilBlockStore<S, C>>,
    oracle: &Oracle,
    root: Option<Cid>,
) -> Option<InvariantViolation> {
    let r = root?;
    let entries: Vec<(String, Cid)> = oracle
        .live_records()
        .filter_map(|(c, rk, v)| {
            Cid::try_from(&v[..])
                .ok()
                .map(|cid| (format!("{}/{}", c.0, rk.0), cid))
        })
        .collect();
    match crate::blockstore::rebuild_and_repair_mst(store, &entries, r).await {
        Ok(outcome) => {
            tracing::info!(
                nodes_repaired = outcome.nodes_repaired,
                nodes_total = outcome.nodes_total,
                "structural repair complete"
            );
            None
        }
        Err(e) => Some(InvariantViolation {
            invariant: "MstRepairFailed",
            detail: e.to_string(),
        }),
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

pub(super) fn blockstore_config(dir: &std::path::Path, s: &StoreConfig) -> BlockStoreConfig {
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

fn validate_block_self_consistent<S: StorageIO + Send + Sync + 'static, C: Clock>(
    store: &Arc<TranquilBlockStore<S, C>>,
    requested: CidBytes,
) -> Result<(), OpError> {
    match store.get_block_sync(&requested) {
        Ok(Some(bytes)) => {
            let actual = hash_to_cid_bytes(&bytes);
            if actual == requested {
                Ok(())
            } else {
                Err(OpError::ReadValidation(format!(
                    "block served under cid {} hashes to {}: store returned content not matching its address",
                    hex_short(&requested),
                    hex_short(&actual),
                )))
            }
        }
        Ok(None) => Ok(()),
        Err(_) => Ok(()),
    }
}

fn mst_list_violation(
    expected: &std::collections::HashMap<String, CidBytes>,
    actual: &std::collections::HashMap<String, CidBytes>,
) -> Option<String> {
    if expected == actual {
        return None;
    }
    let missing: Vec<String> = expected
        .iter()
        .filter(|(k, v)| actual.get(*k) != Some(v))
        .map(|(k, _)| k.clone())
        .take(8)
        .collect();
    let extra: Vec<String> = actual
        .iter()
        .filter(|(k, v)| expected.get(*k) != Some(v))
        .map(|(k, _)| k.clone())
        .take(8)
        .collect();
    Some(format!(
        "MST list walk mismatch: oracle has {} live records, walk found {}; missing-or-wrong {missing:?}; extra-or-wrong {extra:?}",
        expected.len(),
        actual.len(),
    ))
}

async fn validate_read_record<S: StorageIO + Send + Sync + 'static, C: Clock>(
    store: &Arc<TranquilBlockStore<S, C>>,
    root: Cid,
    key: &str,
    expected: Option<CidBytes>,
    has_lost_blocks: bool,
) -> Result<(), OpError> {
    let mst = Mst::load(store.clone(), root, None);
    let Ok(Some(value_cid)) = mst.get(key).await else {
        return Ok(());
    };
    let actual = try_cid_to_fixed(&value_cid)?;
    match expected {
        Some(x) if !has_lost_blocks && actual != x => {
            return Err(OpError::ReadValidation(format!(
                "{key}: MST returned cid {} but oracle holds {}",
                hex_short(&actual),
                hex_short(&x),
            )));
        }
        None if !has_lost_blocks => {
            return Err(OpError::ReadValidation(format!(
                "{key}: MST holds a record with cid {} but the oracle has no live record at this key",
                hex_short(&actual),
            )));
        }
        _ => {}
    }
    validate_block_self_consistent(store, actual)
}

pub(super) async fn apply_op<S: StorageIO + Send + Sync + 'static, C: Clock>(
    harness: &mut Harness<S, C>,
    root: &mut Option<Cid>,
    oracle: &mut Oracle,
    op: &Op,
    workload: &WorkloadModel,
    clock: &C,
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
            let new_root = delete_record_atomic(&harness.store, old_root, collection, rkey).await?;
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
            let ts_before = clock.unix_micros().raw();
            match el.writer.append_with_clock(did_hash, tag, payload, clock) {
                Ok(seq) => {
                    let segment = el.writer.active_segment_id();
                    oracle.record_event_append(EventExpectation {
                        seq,
                        timestamp_us: ts_before,
                        kind: *event_kind,
                        did_hash: did_hash.raw(),
                        segment,
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
            run_retention(el, oracle, *max_age_secs, clock).map_err(OpError::EventLogRetention)
        }
        Op::AdvanceTime { by } => {
            clock.advance(Duration::from_nanos(by.0));
            Ok(())
        }
        Op::ReadRecord { collection, rkey } => {
            let Some(r) = *root else { return Ok(()) };
            let key = format!("{}/{}", collection.0, rkey.0);
            let expected = oracle.expected_record_cid(collection, rkey);
            validate_read_record(&harness.store, r, &key, expected, oracle.has_lost_blocks()).await
        }
        Op::ReadBlock { value_seed } => {
            let record_bytes = make_record_bytes(*value_seed, workload.size_distribution);
            let record_cid = hash_to_cid_bytes(&record_bytes);
            validate_block_self_consistent(&harness.store, record_cid)
        }
        Op::MstList => {
            let Some(r) = *root else {
                return Ok(());
            };
            let store = harness.store.clone();
            let lost = oracle.lost_blocks().clone();
            let walked = tokio::task::spawn_blocking(move || {
                super::chaos_walker::walk_mst_entries_tolerant(&store, r, &lost)
            })
            .await
            .map_err(|e| OpError::Join(e.to_string()))?;
            if oracle.has_lost_blocks() {
                return Ok(());
            }
            let entries = match walked {
                Ok(Some(entries)) => entries,
                Ok(None) | Err(_) => return Ok(()),
            };
            let actual: std::collections::HashMap<String, CidBytes> = entries.into_iter().collect();
            let expected: std::collections::HashMap<String, CidBytes> = oracle
                .live_records()
                .map(|(c, rk, v)| (format!("{}/{}", c.0, rk.0), *v))
                .collect();
            match mst_list_violation(&expected, &actual) {
                None => Ok(()),
                Some(detail) => Err(OpError::ReadValidation(detail)),
            }
        }
        Op::ExternalDeleteDataFile { choice } => {
            let s = harness.store.clone();
            let pick = choice.0;
            let lost_cids =
                tokio::task::spawn_blocking(move || externally_delete_data_file(&s, pick))
                    .await
                    .map_err(|e| OpError::Join(e.to_string()))??;
            if !lost_cids.is_empty() {
                oracle.mark_blocks_lost(lost_cids);
            }
            Ok(())
        }
    }
}

fn externally_delete_data_file<S: StorageIO + Send + Sync + 'static, C: Clock>(
    store: &std::sync::Arc<TranquilBlockStore<S, C>>,
    pick: u32,
) -> Result<Vec<CidBytes>, OpError> {
    let active = store.block_index().read_write_cursor().map(|c| c.file_id);
    let mut candidates = match store.list_data_files() {
        Ok(files) => files,
        Err(_) => return Ok(Vec::new()),
    };
    candidates.retain(|fid| active.is_some_and(|a| *fid < a));
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let idx = (pick as usize) % candidates.len();
    let victim = candidates[idx];
    let cids = store.block_index().cids_in_file(victim);
    match std::fs::remove_file(store.data_file_path(victim)) {
        Ok(()) => Ok(cids),
        Err(_) => Ok(Vec::new()),
    }
}

fn run_retention<S: StorageIO + Send + Sync + 'static, C: Clock>(
    el: &mut EventLogState<S>,
    oracle: &mut Oracle,
    max_age: RetentionSecs,
    clock: &C,
) -> Result<(), String> {
    let sync_result = el.writer.sync().map_err(|e| e.to_string())?;
    el.manager
        .io()
        .sync_dir(el.segments_dir.as_path())
        .map_err(|e| e.to_string())?;
    oracle.record_event_sync(sync_result.synced_through);
    let now_us = clock.unix_micros().raw();
    let max_age_us = u64::from(max_age.0).saturating_mul(1_000_000);
    let cutoff_us = now_us.saturating_sub(max_age_us);
    let segments = el.manager.list_segments().map_err(|e| e.to_string())?;
    let active_id = segments.last().copied();
    segments
        .iter()
        .filter(|&&id| Some(id) != active_id)
        .try_for_each(|&id| -> Result<(), String> {
            let last_ts = segment_last_timestamp(&el.manager, id).map_err(|e| e.to_string())?;
            match last_ts {
                Some(ts) if ts < cutoff_us => {
                    el.manager.delete_segment(id).map_err(|e| e.to_string())
                }
                _ => Ok(()),
            }
        })?;
    oracle.record_retention(cutoff_us, active_id);
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

async fn add_record_atomic<S: StorageIO + Send + Sync + 'static, C: Clock>(
    store: &Arc<TranquilBlockStore<S, C>>,
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

async fn delete_record_atomic<S: StorageIO + Send + Sync + 'static, C: Clock>(
    store: &Arc<TranquilBlockStore<S, C>>,
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
        .chain(removed_cids)
        .map(|c| try_cid_to_fixed(&c))
        .collect::<Result<_, _>>()
        .map_err(OpError::from)
}

async fn commit_atomic<S: StorageIO + Send + Sync + 'static, C: Clock>(
    store: &Arc<TranquilBlockStore<S, C>>,
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

fn compact_by_liveness<S: StorageIO + Send + Sync + 'static, C: Clock>(
    store: &TranquilBlockStore<S, C>,
) -> Result<(), OpError> {
    let liveness = store
        .compaction_liveness(0)
        .map_err(|e| OpError::CompactFile(format!("compaction_liveness: {e}")))?;
    let mut targets: Vec<_> = liveness
        .iter()
        .filter(|(_, info)| info.total_blocks > 0 && info.ratio() < COMPACT_LIVENESS_CEILING)
        .map(|(&fid, _)| fid)
        .collect();
    targets.sort_unstable();
    targets
        .into_iter()
        .try_for_each(|fid| match store.compact_file(fid, 0) {
            Ok(_) => Ok(()),
            Err(CompactionError::ActiveFileCannotBeCompacted) => Ok(()),
            Err(CompactionError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(OpError::CompactFile(format!("{fid}: {e}"))),
        })
}

async fn apply_op_concurrent<S: StorageIO + Send + Sync + 'static, C: Clock>(
    shared: &Arc<SharedState<S, C>>,
    op: &Op,
    workload: &WorkloadModel,
    clock: &C,
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
            let new_root = delete_record_atomic(&shared.store, old_root, collection, rkey).await?;
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
            let ts_before = clock.unix_micros().raw();
            let mut state = shared.write.lock().await;
            let Some(el) = state.eventlog.as_mut() else {
                return Ok(());
            };
            match el.writer.append_with_clock(did_hash, tag, payload, clock) {
                Ok(seq) => {
                    let segment = el.writer.active_segment_id();
                    let _ = el.writer.rotate_if_needed();
                    state.oracle.record_event_append(EventExpectation {
                        seq,
                        timestamp_us: ts_before,
                        kind: *event_kind,
                        did_hash: did_hash.raw(),
                        segment,
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
            run_retention(el, oracle, *max_age_secs, clock).map_err(OpError::EventLogRetention)
        }
        Op::AdvanceTime { by } => {
            clock.advance(Duration::from_nanos(by.0));
            Ok(())
        }
        Op::ReadRecord { collection, rkey } => {
            let r = { shared.write.lock().await.root };
            let Some(r) = r else {
                return Ok(());
            };
            let key = format!("{}/{}", collection.0, rkey.0);
            validate_read_record(&shared.store, r, &key, None, true).await
        }
        Op::ReadBlock { value_seed } => {
            let record_bytes = make_record_bytes(*value_seed, workload.size_distribution);
            let record_cid = hash_to_cid_bytes(&record_bytes);
            validate_block_self_consistent(&shared.store, record_cid)
        }
        Op::MstList => {
            let r = { shared.write.lock().await.root };
            let Some(r) = r else {
                return Ok(());
            };
            let store = shared.store.clone();
            let _ = tokio::task::spawn_blocking(move || {
                super::chaos_walker::walk_mst_entries_tolerant(
                    &store,
                    r,
                    &std::collections::HashSet::new(),
                )
            })
            .await
            .map_err(|e| OpError::Join(e.to_string()))?;
            Ok(())
        }
        Op::ExternalDeleteDataFile { choice } => {
            let mut guard = shared.write.lock().await;
            let s = shared.store.clone();
            let pick = choice.0;
            let lost_cids =
                tokio::task::spawn_blocking(move || externally_delete_data_file(&s, pick))
                    .await
                    .map_err(|e| OpError::Join(e.to_string()))??;
            if !lost_cids.is_empty() {
                guard.oracle.mark_blocks_lost(lost_cids);
            }
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn writer_task<S: StorageIO + Send + Sync + 'static, C: Clock>(
    shared: Arc<SharedState<S, C>>,
    ops: Arc<Vec<Op>>,
    index: Arc<AtomicUsize>,
    end: usize,
    workload: Arc<WorkloadModel>,
    ops_counter: Arc<AtomicUsize>,
    op_errors_counter: Arc<AtomicUsize>,
    tolerate_op_errors: bool,
    clock: C,
) -> Option<InvariantViolation> {
    loop {
        let idx = index.fetch_add(1, Ordering::Relaxed);
        if idx >= end {
            return None;
        }
        let op = &ops[idx];
        match apply_op_concurrent(&shared, op, &workload, &clock).await {
            Ok(()) => {
                ops_counter.fetch_max(idx + 1, Ordering::Relaxed);
            }
            Err(e) if e.is_hard_violation() => {
                return Some(InvariantViolation {
                    invariant: "ReadValidation",
                    detail: format!("op {idx}: {e}"),
                });
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
async fn run_inner_generic_concurrent<S, C, Open, Crash, Quiesce>(
    config: GauntletConfig,
    op_stream: OpStream,
    ops_counter: Arc<AtomicUsize>,
    op_errors_counter: Arc<AtomicUsize>,
    restarts_counter: Arc<AtomicUsize>,
    mut open: Open,
    mut crash: Crash,
    tolerate_op_errors: bool,
    reopen_backoff: Duration,
    clock: C,
    quiesce_faults: Quiesce,
) -> GauntletReport
where
    S: StorageIO + Send + Sync + 'static,
    C: Clock,
    Open: FnMut(usize) -> Result<Harness<S, C>, String>,
    Crash: FnMut() -> Vec<PathBuf>,
    Quiesce: Fn(bool),
{
    let ops: Vec<Op> = op_stream.into_vec();
    let total_ops = ops.len();
    let ops_arc = Arc::new(ops);
    let workload_arc = Arc::new(config.workload.clone());

    let mut violations: Vec<InvariantViolation> = Vec::new();
    let mut restart_rng = Lcg::new(Seed(config.seed.0 ^ 0xA5A5_A5A5_A5A5_A5A5));
    let mut sample_rng = Lcg::new(Seed(config.seed.0 ^ 0x5A5A_5A5A_5A5A_5A5A));
    let chunks = compute_chunks(config.restart_policy, total_ops, &mut restart_rng);

    let mut harness: Option<Harness<S, C>> =
        match reopen_with_recovery(&mut open, &mut crash, tolerate_op_errors, reopen_backoff).await
        {
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
                clock.clone(),
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
                    let removed = crash();
                    record_crash_losses(&removed, harness.as_ref(), &mut oracle);
                }
                shutdown_harness(&mut harness);
                match reopen_with_recovery(
                    &mut open,
                    &mut crash,
                    tolerate_op_errors,
                    reopen_backoff,
                )
                .await
                {
                    Ok(reopened) => {
                        harness = Some(reopened);
                        let n = restarts_counter.fetch_add(1, Ordering::Relaxed) + 1;
                        let live = harness.as_ref().expect("just reopened");
                        let before = violations.len();
                        quiesce_faults(true);
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
                        quiesce_faults(false);
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

    quiesce_faults(true);
    if !halt_ops && tolerate_op_errors && harness.is_some() {
        let removed = crash();
        record_crash_losses(&removed, harness.as_ref(), &mut oracle);
        shutdown_harness(&mut harness);
        match reopen_with_recovery(&mut open, &mut crash, tolerate_op_errors, reopen_backoff).await
        {
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
    if !halt_ops
        && config.invariants.contains(InvariantSet::MST_REPAIRABLE)
        && let Some(live) = harness.as_ref()
        && let Some(v) = attempt_structural_repair(&live.store, &oracle, root).await
    {
        violations.push(v);
        halt_ops = true;
    }
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
        match reopen_with_recovery(&mut open, &mut crash, tolerate_op_errors, reopen_backoff).await
        {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config() -> GauntletConfig {
        GauntletConfig {
            seed: Seed(0),
            io: IoBackend::Real,
            workload: WorkloadModel::default(),
            op_count: OpCount(0),
            invariants: InvariantSet::EMPTY,
            limits: RunLimits {
                max_wall_ms: Some(WallMs(30_000)),
            },
            restart_policy: RestartPolicy::Never,
            store: StoreConfig {
                max_file_size: MaxFileSize(8 * 1024),
                group_commit: GroupCommitConfig::default(),
                shard_count: ShardCount(1),
            },
            eventlog: None,
            writer_concurrency: WriterConcurrency(1),
            tolerate_op_errors: false,
        }
    }

    fn flaky_open(
        attempts: Arc<AtomicUsize>,
        sim: Arc<SimulatedIO>,
        store_cfg: BlockStoreConfig,
        clock: SimClock,
    ) -> impl FnMut(usize) -> Result<Harness<Arc<SimulatedIO>, SimClock>, String> + Send + 'static
    {
        move |_attempt: usize| -> Result<Harness<Arc<SimulatedIO>, SimClock>, String> {
            let n = attempts.fetch_add(1, Ordering::Relaxed);
            if n == 0 {
                return Err("simulated EIO on initial open".to_string());
            }
            let factory_sim = Arc::clone(&sim);
            let make_io = move || Arc::clone(&factory_sim);
            TranquilBlockStore::<Arc<SimulatedIO>, SimClock>::open_with_io(
                store_cfg.clone(),
                make_io,
                clock.clone(),
            )
            .map(|s| Harness {
                store: Arc::new(s),
                eventlog: None,
            })
            .map_err(|e| e.to_string())
        }
    }

    #[tokio::test]
    async fn run_inner_generic_retries_initial_open_on_transient_io_error() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let cfg = minimal_config();
        let store_cfg = blockstore_config(dir.path(), &cfg.store);
        let sim: Arc<SimulatedIO> = Arc::new(SimulatedIO::pristine(0));
        let clock = sim.clock();
        let attempts = Arc::new(AtomicUsize::new(0));

        let report = run_inner_generic::<Arc<SimulatedIO>, SimClock, _, _, _>(
            cfg,
            OpStream::empty(),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
            flaky_open(
                Arc::clone(&attempts),
                Arc::clone(&sim),
                store_cfg,
                clock.clone(),
            ),
            Vec::new,
            true,
            Duration::ZERO,
            clock,
            |_| {},
        )
        .await;

        let opens: Vec<&InvariantViolation> = report
            .violations
            .iter()
            .filter(|v| v.invariant == "OpenStore")
            .collect();
        assert!(
            opens.is_empty(),
            "expected initial open to retry, got OpenStore violations: {opens:?}"
        );
        let total = attempts.load(Ordering::Relaxed);
        assert!(
            total >= 2,
            "expected at least one retry after first failure, attempts={total}"
        );
    }

    #[tokio::test]
    async fn run_inner_generic_concurrent_retries_initial_open_on_transient_io_error() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut cfg = minimal_config();
        cfg.writer_concurrency = WriterConcurrency(2);
        let store_cfg = blockstore_config(dir.path(), &cfg.store);
        let sim: Arc<SimulatedIO> = Arc::new(SimulatedIO::pristine(0));
        let clock = sim.clock();
        let attempts = Arc::new(AtomicUsize::new(0));

        let report = run_inner_generic_concurrent::<Arc<SimulatedIO>, SimClock, _, _, _>(
            cfg,
            OpStream::empty(),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
            flaky_open(
                Arc::clone(&attempts),
                Arc::clone(&sim),
                store_cfg,
                clock.clone(),
            ),
            Vec::new,
            true,
            Duration::ZERO,
            clock,
            |_| {},
        )
        .await;

        let opens: Vec<&InvariantViolation> = report
            .violations
            .iter()
            .filter(|v| v.invariant == "OpenStore")
            .collect();
        assert!(
            opens.is_empty(),
            "expected initial open to retry, got OpenStore violations: {opens:?}"
        );
        let total = attempts.load(Ordering::Relaxed);
        assert!(
            total >= 2,
            "expected at least one retry after first failure, attempts={total}"
        );
    }

    #[tokio::test]
    async fn dst_retention_advances_logical_hours_in_real_milliseconds() {
        use crate::gauntlet::op::AdvanceNanos;
        use futures::stream::StreamExt;
        use std::time::Instant;

        const NANOS_PER_HOUR: u64 = 3600 * 1_000_000_000;

        let dir = tempfile::TempDir::new().expect("tempdir");
        let store_cfg = blockstore_config(dir.path(), &minimal_config().store);
        let sim: Arc<SimulatedIO> = Arc::new(SimulatedIO::pristine(0xDADA));
        let clock = sim.clock();

        let store = {
            let s = Arc::clone(&sim);
            TranquilBlockStore::<Arc<SimulatedIO>, SimClock>::open_with_io(
                store_cfg,
                move || Arc::clone(&s),
                clock.clone(),
            )
            .map(Arc::new)
            .expect("open store")
        };
        let eventlog = open_eventlog(Arc::clone(&sim), segments_subdir(dir.path()), 200)
            .expect("open eventlog");
        let harness = Harness {
            store,
            eventlog: Some(eventlog),
        };

        let workload = WorkloadModel::default();
        let appends: Vec<Op> = (0..80u32)
            .map(|i| Op::AppendEvent {
                did_seed: DidSeed(i),
                event_kind: EventKind::Commit,
                payload_seed: PayloadSeed(i),
            })
            .collect();

        let start = Instant::now();
        let (mut harness, mut root, mut oracle) = futures::stream::iter(appends)
            .fold(
                (harness, None::<Cid>, Oracle::new()),
                |(mut h, mut r, mut o), op| {
                    let clk = clock.clone();
                    let wl = workload.clone();
                    async move {
                        apply_op(&mut h, &mut r, &mut o, &op, &wl, &clk)
                            .await
                            .expect("append op");
                        (h, r, o)
                    }
                },
            )
            .await;

        apply_op(
            &mut harness,
            &mut root,
            &mut oracle,
            &Op::SyncEventLog,
            &workload,
            &clock,
        )
        .await
        .expect("sync");
        let segments_before = harness
            .eventlog
            .as_ref()
            .unwrap()
            .manager
            .list_segments()
            .expect("list before");

        apply_op(
            &mut harness,
            &mut root,
            &mut oracle,
            &Op::AdvanceTime {
                by: AdvanceNanos(2 * NANOS_PER_HOUR),
            },
            &workload,
            &clock,
        )
        .await
        .expect("advance");
        apply_op(
            &mut harness,
            &mut root,
            &mut oracle,
            &Op::RunRetention {
                max_age_secs: RetentionSecs(3600),
            },
            &workload,
            &clock,
        )
        .await
        .expect("retention");
        let elapsed = start.elapsed();

        let segments_after = harness
            .eventlog
            .as_ref()
            .unwrap()
            .manager
            .list_segments()
            .expect("list after");

        assert!(
            segments_before.len() > 1,
            "expected appends to seal old segments, got {} segment(s)",
            segments_before.len()
        );
        assert!(
            segments_after.len() < segments_before.len(),
            "retention after advancing 2 logical hours must delete sealed segments older than the 1h cutoff: before={} after={}",
            segments_before.len(),
            segments_after.len()
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "advancing 2 logical hours took {elapsed:?} of wall time"
        );
    }
}
