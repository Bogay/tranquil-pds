use std::collections::BTreeSet;

use super::op::OpStream;
use super::runner::{Gauntlet, GauntletConfig, GauntletReport};

pub const DEFAULT_MAX_SHRINK_ITERATIONS: usize = 256;

#[derive(Debug)]
pub struct ShrinkOutcome {
    pub ops: OpStream,
    pub report: GauntletReport,
    pub iterations: usize,
}

pub async fn shrink_failure(
    config: GauntletConfig,
    initial_ops: OpStream,
    initial_report: GauntletReport,
    max_iterations: usize,
) -> ShrinkOutcome {
    let target: BTreeSet<&'static str> = initial_report.violation_invariants();
    if target.is_empty() {
        return ShrinkOutcome {
            ops: initial_ops,
            report: initial_report,
            iterations: 0,
        };
    }

    let mut current_ops = initial_ops;
    let mut current_report = initial_report;
    let mut iterations = 0usize;

    while iterations < max_iterations {
        match try_one_shrink_round(&config, &current_ops, &target, max_iterations - iterations)
            .await
        {
            ShrinkRound::Progress {
                ops,
                report,
                runs_used,
            } => {
                current_ops = ops;
                current_report = report;
                iterations += runs_used;
            }
            ShrinkRound::Exhausted { runs_used } => {
                iterations += runs_used;
                break;
            }
        }
    }

    ShrinkOutcome {
        ops: current_ops,
        report: current_report,
        iterations,
    }
}

enum ShrinkRound {
    Progress {
        ops: OpStream,
        report: GauntletReport,
        runs_used: usize,
    },
    Exhausted {
        runs_used: usize,
    },
}

async fn try_one_shrink_round(
    config: &GauntletConfig,
    current_ops: &OpStream,
    target: &BTreeSet<&'static str>,
    budget: usize,
) -> ShrinkRound {
    let mut runs_used = 0usize;
    for candidate in current_ops.shrink_candidates() {
        if candidate.is_empty() || candidate.len() >= current_ops.len() {
            continue;
        }
        if runs_used >= budget {
            return ShrinkRound::Exhausted { runs_used };
        }
        runs_used += 1;
        let gauntlet = match Gauntlet::new(config.clone()) {
            Ok(g) => g,
            Err(_) => continue,
        };
        let report = gauntlet.run_with_ops(candidate.clone()).await;
        let got: BTreeSet<&'static str> = report.violation_invariants();
        if !got.is_disjoint(target) {
            return ShrinkRound::Progress {
                ops: candidate,
                report,
                runs_used,
            };
        }
    }
    ShrinkRound::Exhausted { runs_used }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockstore::GroupCommitConfig;
    use crate::gauntlet::invariants::{InvariantSet, InvariantViolation};
    use crate::gauntlet::op::{CollectionName, Op, OpStream, RecordKey, Seed, ValueSeed};
    use crate::gauntlet::runner::{
        GauntletConfig, IoBackend, MaxFileSize, OpErrorCount, OpsExecuted, RestartCount,
        RestartPolicy, RunLimits, ShardCount, StoreConfig, WriterConcurrency,
    };
    use crate::gauntlet::workload::{
        DidSpaceSize, KeySpaceSize, OpCount, OpWeights, RetentionMaxSecs, SizeDistribution,
        ValueBytes, WorkloadModel,
    };
    use crate::sim::FaultConfig;

    fn dummy_config() -> GauntletConfig {
        GauntletConfig {
            seed: Seed(1),
            io: IoBackend::Simulated {
                fault: FaultConfig::none(),
            },
            workload: WorkloadModel {
                weights: OpWeights::default(),
                size_distribution: SizeDistribution::Fixed(ValueBytes(16)),
                collections: vec![CollectionName("c".into())],
                key_space: KeySpaceSize(4),
                did_space: DidSpaceSize(1),
                retention_max_secs: RetentionMaxSecs(60),
            },
            op_count: OpCount(4),
            invariants: InvariantSet::EMPTY,
            limits: RunLimits { max_wall_ms: None },
            restart_policy: RestartPolicy::Never,
            store: StoreConfig {
                max_file_size: MaxFileSize(4096),
                group_commit: GroupCommitConfig::default(),
                shard_count: ShardCount(1),
            },
            eventlog: None,
            writer_concurrency: WriterConcurrency(1),
        }
    }

    fn fake_report(seed: u64, names: &[&'static str]) -> GauntletReport {
        GauntletReport {
            seed: Seed(seed),
            ops_executed: OpsExecuted(0),
            op_errors: OpErrorCount(0),
            restarts: RestartCount(0),
            violations: names
                .iter()
                .copied()
                .map(|n| InvariantViolation {
                    invariant: n,
                    detail: "x".to_string(),
                })
                .collect(),
            ops: OpStream::empty(),
        }
    }

    fn sample_stream() -> OpStream {
        OpStream::from_vec(vec![
            Op::AddRecord {
                collection: CollectionName("c".into()),
                rkey: RecordKey("a".into()),
                value_seed: ValueSeed(1),
            },
            Op::Compact,
        ])
    }

    #[test]
    fn clean_report_returns_input_unchanged() {
        let cfg = dummy_config();
        let ops = sample_stream();
        let clean = fake_report(1, &[]);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let before_len = ops.len();
        let out = rt.block_on(shrink_failure(cfg, ops, clean, 8));
        assert_eq!(out.iterations, 0);
        assert_eq!(out.ops.len(), before_len);
    }
}
