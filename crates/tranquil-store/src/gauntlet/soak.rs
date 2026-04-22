use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cid::Cid;
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::invariants::{InvariantSet, InvariantViolation};
use super::leak::{LeakGateConfig, LeakViolation, evaluate as evaluate_leak_gate};
use super::metrics::{MetricsSample, sample_harness};
use super::op::{OpStream, Seed};
use super::oracle::Oracle;
use super::runner::{
    EventLogState, GauntletConfig, Harness, IoBackend, apply_op, blockstore_config,
    eventlog_snapshot, open_eventlog, refresh_oracle_graph, run_invariants, segments_subdir,
};
use super::workload::OpCount;
use crate::blockstore::TranquilBlockStore;
use crate::io::{RealIO, StorageIO};

const OP_ERROR_LOG_THROTTLE: u64 = 1024;

pub const DEFAULT_CHUNK_OPS: usize = 5_000;
pub const DEFAULT_SAMPLE_INTERVAL_MS: u64 = 60_000;

#[derive(Debug, Clone)]
pub struct SoakConfig {
    pub gauntlet: GauntletConfig,
    pub total_duration: Duration,
    pub sample_interval: Duration,
    pub chunk_ops: usize,
    pub leak_gate: LeakGateConfig,
}

impl SoakConfig {
    pub fn new(gauntlet: GauntletConfig, total_duration: Duration) -> Self {
        Self {
            gauntlet,
            total_duration,
            sample_interval: Duration::from_millis(DEFAULT_SAMPLE_INTERVAL_MS),
            chunk_ops: DEFAULT_CHUNK_OPS,
            leak_gate: LeakGateConfig::standard(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SoakError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("soak requires IoBackend::Real; scenario configured Simulated")]
    SimulatedBackendRejected,
    #[error("open block store: {0}")]
    StoreOpen(String),
    #[error("open event log: {0}")]
    EventLogOpen(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoakReport {
    pub seed: Seed,
    pub ops_executed: u64,
    pub op_errors: u64,
    pub chunks: u64,
    pub samples: Vec<MetricsSample>,
    pub invariant_violations: Vec<InvariantViolationRecord>,
    pub leak_violations: Vec<LeakViolation>,
    pub total_wall_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantViolationRecord {
    pub invariant: String,
    pub detail: String,
}

impl SoakReport {
    pub fn is_clean(&self) -> bool {
        self.invariant_violations.is_empty() && self.leak_violations.is_empty()
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SoakEvent {
    #[serde(rename = "sample")]
    Sample {
        seed: u64,
        chunk: u64,
        ops_executed: u64,
        sample: MetricsSample,
    },
    #[serde(rename = "invariant_violation")]
    Invariant {
        seed: u64,
        invariant: String,
        detail: String,
    },
    #[serde(rename = "summary")]
    Summary {
        seed: u64,
        total_wall_ms: u64,
        ops_executed: u64,
        op_errors: u64,
        chunks: u64,
        clean: bool,
        invariant_violations: usize,
        leak_violations: Vec<LeakViolation>,
    },
}

pub async fn run_soak<W: Write + Send>(
    cfg: SoakConfig,
    mut emitter: W,
) -> Result<SoakReport, SoakError> {
    if !matches!(cfg.gauntlet.io, IoBackend::Real) {
        return Err(SoakError::SimulatedBackendRejected);
    }
    let dir = tempfile::TempDir::new()?;
    let store_cfg = blockstore_config(dir.path(), &cfg.gauntlet.store);
    let segments_dir: PathBuf = segments_subdir(dir.path());
    let store = TranquilBlockStore::open(store_cfg)
        .map(Arc::new)
        .map_err(|e| SoakError::StoreOpen(e.to_string()))?;
    let eventlog: Option<EventLogState<RealIO>> = match cfg.gauntlet.eventlog {
        None => None,
        Some(ec) => Some(
            open_eventlog(RealIO::new(), segments_dir, ec.max_segment_size.0)
                .map_err(|e| SoakError::EventLogOpen(e.to_string()))?,
        ),
    };
    let mut harness = Harness { store, eventlog };
    let outcome = drive_soak(&mut harness, &cfg, &mut emitter).await;
    shutdown_harness(&mut harness);
    outcome
}

fn shutdown_harness<S: StorageIO + Send + Sync + 'static>(harness: &mut Harness<S>) {
    if let Some(el) = harness.eventlog.as_mut() {
        if let Err(e) = el.writer.shutdown() {
            warn!(error = %e, "soak: event log writer shutdown failed");
        }
        el.manager.shutdown();
    }
}

async fn drive_soak<S, W>(
    harness: &mut Harness<S>,
    cfg: &SoakConfig,
    emitter: &mut W,
) -> Result<SoakReport, SoakError>
where
    S: StorageIO + Send + Sync + 'static,
    W: Write + Send,
{
    let mut oracle = Oracle::new();
    let mut root: Option<Cid> = None;

    let start = Instant::now();
    let mut samples: Vec<MetricsSample> = Vec::new();
    let mut invariant_records: Vec<InvariantViolationRecord> = Vec::new();
    let mut ops_executed: u64 = 0;
    let mut op_errors: u64 = 0;
    let mut chunks: u64 = 0;
    let mut last_sample = start;
    let mut next_error_log_at: u64 = 1;

    let initial = sample_harness(harness, Duration::ZERO);
    emit_event(
        emitter,
        &SoakEvent::Sample {
            seed: cfg.gauntlet.seed.0,
            chunk: 0,
            ops_executed: 0,
            sample: initial,
        },
    )?;
    samples.push(initial);

    while start.elapsed() < cfg.total_duration {
        let chunk_seed = Seed(
            cfg.gauntlet
                .seed
                .0
                .wrapping_add(chunks.wrapping_mul(0x9E37_79B9_7F4A_7C15)),
        );
        let stream: OpStream = cfg
            .gauntlet
            .workload
            .generate(chunk_seed, OpCount(cfg.chunk_ops));
        for op in stream.iter() {
            if start.elapsed() >= cfg.total_duration {
                break;
            }
            match apply_op(harness, &mut root, &mut oracle, op, &cfg.gauntlet.workload).await {
                Ok(()) => {
                    ops_executed = ops_executed.saturating_add(1);
                }
                Err(e) => {
                    op_errors = op_errors.saturating_add(1);
                    if op_errors >= next_error_log_at {
                        warn!(
                            op_errors,
                            ops_executed,
                            elapsed_ms = u64::try_from(start.elapsed().as_millis())
                                .unwrap_or(u64::MAX),
                            error = %e,
                            "soak: op error milestone"
                        );
                        next_error_log_at = next_error_log_at
                            .saturating_mul(2)
                            .max(OP_ERROR_LOG_THROTTLE);
                    }
                }
            }
            if last_sample.elapsed() >= cfg.sample_interval {
                let elapsed = start.elapsed();
                let s = sample_harness(harness, elapsed);
                emit_event(
                    emitter,
                    &SoakEvent::Sample {
                        seed: cfg.gauntlet.seed.0,
                        chunk: chunks,
                        ops_executed,
                        sample: s,
                    },
                )?;
                samples.push(s);
                last_sample = Instant::now();
            }
        }
        chunks = chunks.saturating_add(1);
        tokio::task::yield_now().await;
    }

    let final_elapsed = start.elapsed();
    let final_sample = sample_harness(harness, final_elapsed);
    emit_event(
        emitter,
        &SoakEvent::Sample {
            seed: cfg.gauntlet.seed.0,
            chunk: chunks,
            ops_executed,
            sample: final_sample,
        },
    )?;
    samples.push(final_sample);

    let invariants = match refresh_oracle_graph(&harness.store, &mut oracle, root).await {
        Ok(()) => {
            let snapshot = eventlog_snapshot(harness.eventlog.as_ref());
            let set = cfg
                .gauntlet
                .invariants
                .without(InvariantSet::RESTART_IDEMPOTENT);
            run_invariants(&harness.store, &oracle, root, snapshot, set).await
        }
        Err(e) => vec![InvariantViolation {
            invariant: "MstRootDurability",
            detail: format!("refresh: {e}"),
        }],
    };
    for v in invariants.iter() {
        let rec = InvariantViolationRecord {
            invariant: v.invariant.to_string(),
            detail: v.detail.clone(),
        };
        emit_event(
            emitter,
            &SoakEvent::Invariant {
                seed: cfg.gauntlet.seed.0,
                invariant: rec.invariant.clone(),
                detail: rec.detail.clone(),
            },
        )?;
        invariant_records.push(rec);
    }

    let leak_violations = evaluate_leak_gate(&samples, cfg.leak_gate);
    let total_wall_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let clean = invariant_records.is_empty() && leak_violations.is_empty();
    emit_event(
        emitter,
        &SoakEvent::Summary {
            seed: cfg.gauntlet.seed.0,
            total_wall_ms,
            ops_executed,
            op_errors,
            chunks,
            clean,
            invariant_violations: invariant_records.len(),
            leak_violations: leak_violations.clone(),
        },
    )?;

    Ok(SoakReport {
        seed: cfg.gauntlet.seed,
        ops_executed,
        op_errors,
        chunks,
        samples,
        invariant_violations: invariant_records,
        leak_violations,
        total_wall_ms,
    })
}

fn emit_event<W: Write>(emitter: &mut W, event: &SoakEvent) -> io::Result<()> {
    let line = serde_json::to_string(event).map_err(io::Error::other)?;
    writeln!(emitter, "{line}")?;
    emitter.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn send_sync<T: Send + Sync>() {}

    #[test]
    fn soak_error_is_send_sync() {
        send_sync::<SoakError>();
    }
}
