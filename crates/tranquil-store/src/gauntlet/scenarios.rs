use super::invariants::InvariantSet;
use super::op::{CollectionName, Seed};
use super::runner::{
    EventLogConfig, GauntletConfig, IoBackend, MaxFileSize, MaxSegmentSize, OpInterval,
    RestartPolicy, RunLimits, ShardCount, StoreConfig, WallMs, WriterConcurrency,
};
use super::workload::{
    ByteRange, DidSpaceSize, KeySpaceSize, OpCount, OpWeights, RetentionMaxSecs, SizeDistribution,
    ValueBytes, WorkloadModel,
};
use crate::blockstore::GroupCommitConfig;
use crate::sim::FaultConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    SmokePR,
    MstChurn,
    MstRestartChurn,
    FullStackRestart,
    CatastrophicChurn,
    HugeValues,
    TinyBatches,
    GiantBatches,
    ManyFiles,
    ModerateFaults,
    AggressiveFaults,
    TornPages,
    Fsyncgate,
    FirehoseFanout,
    ContendedReaders,
    ContendedWriters,
}

impl Scenario {
    pub const fn name(self) -> &'static str {
        match self {
            Self::SmokePR => "SmokePR",
            Self::MstChurn => "MstChurn",
            Self::MstRestartChurn => "MstRestartChurn",
            Self::FullStackRestart => "FullStackRestart",
            Self::CatastrophicChurn => "CatastrophicChurn",
            Self::HugeValues => "HugeValues",
            Self::TinyBatches => "TinyBatches",
            Self::GiantBatches => "GiantBatches",
            Self::ManyFiles => "ManyFiles",
            Self::ModerateFaults => "ModerateFaults",
            Self::AggressiveFaults => "AggressiveFaults",
            Self::TornPages => "TornPages",
            Self::Fsyncgate => "Fsyncgate",
            Self::FirehoseFanout => "FirehoseFanout",
            Self::ContendedReaders => "ContendedReaders",
            Self::ContendedWriters => "ContendedWriters",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|s| s.name() == name)
    }

    pub const ALL: &'static [Scenario] = &[
        Self::SmokePR,
        Self::MstChurn,
        Self::MstRestartChurn,
        Self::FullStackRestart,
        Self::CatastrophicChurn,
        Self::HugeValues,
        Self::TinyBatches,
        Self::GiantBatches,
        Self::ManyFiles,
        Self::ModerateFaults,
        Self::AggressiveFaults,
        Self::TornPages,
        Self::Fsyncgate,
        Self::FirehoseFanout,
        Self::ContendedReaders,
        Self::ContendedWriters,
    ];
}

impl std::fmt::Display for Scenario {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unknown scenario: {0}")]
pub struct UnknownScenario(pub String);

impl std::str::FromStr for Scenario {
    type Err = UnknownScenario;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_name(s).ok_or_else(|| UnknownScenario(s.to_string()))
    }
}

pub fn config_for(scenario: Scenario, seed: Seed) -> GauntletConfig {
    match scenario {
        Scenario::SmokePR => smoke_pr(seed),
        Scenario::MstChurn => mst_churn(seed),
        Scenario::MstRestartChurn => mst_restart_churn(seed),
        Scenario::FullStackRestart => full_stack_restart(seed),
        Scenario::CatastrophicChurn => catastrophic_churn(seed),
        Scenario::HugeValues => huge_values(seed),
        Scenario::TinyBatches => tiny_batches(seed),
        Scenario::GiantBatches => giant_batches(seed),
        Scenario::ManyFiles => many_files(seed),
        Scenario::ModerateFaults => moderate_faults(seed),
        Scenario::AggressiveFaults => aggressive_faults(seed),
        Scenario::TornPages => torn_pages(seed),
        Scenario::Fsyncgate => fsyncgate(seed),
        Scenario::FirehoseFanout => firehose_fanout(seed),
        Scenario::ContendedReaders => contended_readers(seed),
        Scenario::ContendedWriters => contended_writers(seed),
    }
}

fn default_collections() -> Vec<CollectionName> {
    vec![
        CollectionName("app.bsky.feed.post".to_string()),
        CollectionName("app.bsky.feed.like".to_string()),
    ]
}

fn block_weights(add: u32, delete: u32, compact: u32, checkpoint: u32) -> OpWeights {
    OpWeights {
        add,
        delete,
        compact,
        checkpoint,
        ..OpWeights::default()
    }
}

fn block_workload(
    weights: OpWeights,
    size_distribution: SizeDistribution,
    key_space: KeySpaceSize,
) -> WorkloadModel {
    WorkloadModel {
        weights,
        size_distribution,
        collections: default_collections(),
        key_space,
        did_space: DidSpaceSize(32),
        retention_max_secs: RetentionMaxSecs(3600),
    }
}

fn tiny_store() -> StoreConfig {
    StoreConfig {
        max_file_size: MaxFileSize(4096),
        group_commit: GroupCommitConfig {
            checkpoint_interval_ms: 100,
            checkpoint_write_threshold: 10,
            ..GroupCommitConfig::default()
        },
        shard_count: ShardCount(1),
    }
}

fn smoke_pr(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::Real,
        workload: block_workload(
            block_weights(80, 0, 10, 10),
            SizeDistribution::Fixed(ValueBytes(64)),
            KeySpaceSize(200),
        ),
        op_count: OpCount(10_000),
        invariants: InvariantSet::REFCOUNT_CONSERVATION
            | InvariantSet::REACHABILITY
            | InvariantSet::ACKED_WRITE_PERSISTENCE
            | InvariantSet::READ_AFTER_WRITE
            | InvariantSet::RESTART_IDEMPOTENT,
        limits: RunLimits {
            max_wall_ms: Some(WallMs(60_000)),
        },
        restart_policy: RestartPolicy::EveryNOps(OpInterval(2_000)),
        store: tiny_store(),
        eventlog: None,
        writer_concurrency: WriterConcurrency(1),
    }
}

fn mst_churn(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::Real,
        workload: block_workload(
            block_weights(85, 0, 10, 5),
            SizeDistribution::Fixed(ValueBytes(64)),
            KeySpaceSize(2_000),
        ),
        op_count: OpCount(100_000),
        invariants: InvariantSet::REFCOUNT_CONSERVATION
            | InvariantSet::REACHABILITY
            | InvariantSet::ACKED_WRITE_PERSISTENCE
            | InvariantSet::READ_AFTER_WRITE
            | InvariantSet::RESTART_IDEMPOTENT,
        limits: RunLimits {
            max_wall_ms: Some(WallMs(600_000)),
        },
        restart_policy: RestartPolicy::Never,
        store: tiny_store(),
        eventlog: None,
        writer_concurrency: WriterConcurrency(1),
    }
}

fn mst_restart_churn(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::Real,
        workload: block_workload(
            block_weights(85, 0, 10, 5),
            SizeDistribution::Fixed(ValueBytes(64)),
            KeySpaceSize(2_000),
        ),
        op_count: OpCount(100_000),
        invariants: InvariantSet::REFCOUNT_CONSERVATION
            | InvariantSet::REACHABILITY
            | InvariantSet::ACKED_WRITE_PERSISTENCE
            | InvariantSet::READ_AFTER_WRITE
            | InvariantSet::RESTART_IDEMPOTENT,
        limits: RunLimits {
            max_wall_ms: Some(WallMs(600_000)),
        },
        restart_policy: RestartPolicy::PoissonByOps(OpInterval(5_000)),
        store: tiny_store(),
        eventlog: None,
        writer_concurrency: WriterConcurrency(1),
    }
}

fn full_stack_restart(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::Real,
        workload: block_workload(
            block_weights(80, 0, 15, 5),
            SizeDistribution::Fixed(ValueBytes(80)),
            KeySpaceSize(500),
        ),
        op_count: OpCount(5_000),
        invariants: InvariantSet::REFCOUNT_CONSERVATION
            | InvariantSet::REACHABILITY
            | InvariantSet::ACKED_WRITE_PERSISTENCE
            | InvariantSet::READ_AFTER_WRITE
            | InvariantSet::RESTART_IDEMPOTENT,
        limits: RunLimits {
            max_wall_ms: Some(WallMs(120_000)),
        },
        restart_policy: RestartPolicy::EveryNOps(OpInterval(500)),
        store: StoreConfig {
            max_file_size: MaxFileSize(4096),
            group_commit: GroupCommitConfig::default(),
            shard_count: ShardCount(1),
        },
        eventlog: None,
        writer_concurrency: WriterConcurrency(1),
    }
}

fn phase2_invariants() -> InvariantSet {
    InvariantSet::REFCOUNT_CONSERVATION
        | InvariantSet::REACHABILITY
        | InvariantSet::ACKED_WRITE_PERSISTENCE
        | InvariantSet::READ_AFTER_WRITE
        | InvariantSet::RESTART_IDEMPOTENT
        | InvariantSet::COMPACTION_IDEMPOTENT
        | InvariantSet::BYTE_BUDGET
        | InvariantSet::MANIFEST_EQUALS_REALITY
        | InvariantSet::CHECKSUM_COVERAGE
}

fn catastrophic_churn(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::Real,
        workload: block_workload(
            block_weights(94, 0, 5, 1),
            SizeDistribution::Fixed(ValueBytes(64)),
            KeySpaceSize(200),
        ),
        op_count: OpCount(1_000_000),
        invariants: phase2_invariants(),
        limits: RunLimits {
            max_wall_ms: Some(WallMs(30 * 60_000)),
        },
        restart_policy: RestartPolicy::PoissonByOps(OpInterval(50_000)),
        store: tiny_store(),
        eventlog: None,
        writer_concurrency: WriterConcurrency(1),
    }
}

fn huge_values(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::Real,
        workload: block_workload(
            block_weights(85, 5, 8, 2),
            SizeDistribution::HeavyTail(
                ByteRange::new(ValueBytes(256), ValueBytes(16 * 1024 * 1024))
                    .expect("huge_values ByteRange"),
            ),
            KeySpaceSize(64),
        ),
        op_count: OpCount(2_000),
        invariants: InvariantSet::REFCOUNT_CONSERVATION
            | InvariantSet::REACHABILITY
            | InvariantSet::ACKED_WRITE_PERSISTENCE
            | InvariantSet::READ_AFTER_WRITE
            | InvariantSet::RESTART_IDEMPOTENT,
        limits: RunLimits {
            max_wall_ms: Some(WallMs(10 * 60_000)),
        },
        restart_policy: RestartPolicy::EveryNOps(OpInterval(500)),
        store: StoreConfig {
            max_file_size: MaxFileSize(32 * 1024 * 1024),
            group_commit: GroupCommitConfig::default(),
            shard_count: ShardCount(1),
        },
        eventlog: None,
        writer_concurrency: WriterConcurrency(1),
    }
}

fn tiny_batches(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::Real,
        workload: block_workload(
            block_weights(85, 0, 5, 10),
            SizeDistribution::Fixed(ValueBytes(64)),
            KeySpaceSize(500),
        ),
        op_count: OpCount(10_000),
        invariants: phase2_invariants(),
        limits: RunLimits {
            max_wall_ms: Some(WallMs(120_000)),
        },
        restart_policy: RestartPolicy::EveryNOps(OpInterval(2_000)),
        store: StoreConfig {
            max_file_size: MaxFileSize(4096),
            group_commit: GroupCommitConfig {
                max_batch_size: 1,
                checkpoint_interval_ms: 100,
                checkpoint_write_threshold: 1,
                ..GroupCommitConfig::default()
            },
            shard_count: ShardCount(1),
        },
        eventlog: None,
        writer_concurrency: WriterConcurrency(1),
    }
}

fn giant_batches(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::Real,
        workload: block_workload(
            block_weights(95, 0, 3, 2),
            SizeDistribution::Fixed(ValueBytes(64)),
            KeySpaceSize(5_000),
        ),
        op_count: OpCount(50_000),
        invariants: phase2_invariants(),
        limits: RunLimits {
            max_wall_ms: Some(WallMs(10 * 60_000)),
        },
        restart_policy: RestartPolicy::EveryNOps(OpInterval(10_000)),
        store: StoreConfig {
            max_file_size: MaxFileSize(16 * 1024 * 1024),
            group_commit: GroupCommitConfig {
                max_batch_size: 100_000,
                checkpoint_interval_ms: 5_000,
                checkpoint_write_threshold: 100_000,
                ..GroupCommitConfig::default()
            },
            shard_count: ShardCount(1),
        },
        eventlog: None,
        writer_concurrency: WriterConcurrency(1),
    }
}

fn many_files(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::Real,
        workload: block_workload(
            block_weights(80, 10, 5, 5),
            SizeDistribution::Fixed(ValueBytes(128)),
            KeySpaceSize(2_000),
        ),
        op_count: OpCount(200_000),
        invariants: phase2_invariants(),
        limits: RunLimits {
            max_wall_ms: Some(WallMs(20 * 60_000)),
        },
        restart_policy: RestartPolicy::PoissonByOps(OpInterval(5_000)),
        store: StoreConfig {
            max_file_size: MaxFileSize(256),
            group_commit: GroupCommitConfig::default(),
            shard_count: ShardCount(1),
        },
        eventlog: None,
        writer_concurrency: WriterConcurrency(1),
    }
}

fn sim_invariants() -> InvariantSet {
    InvariantSet::REFCOUNT_CONSERVATION
        | InvariantSet::REACHABILITY
        | InvariantSet::ACKED_WRITE_PERSISTENCE
        | InvariantSet::READ_AFTER_WRITE
        | InvariantSet::RESTART_IDEMPOTENT
        | InvariantSet::NO_ORPHAN_FILES
        | InvariantSet::BYTE_BUDGET
        | InvariantSet::CHECKSUM_COVERAGE
}

fn sim_microbench_workload() -> WorkloadModel {
    block_workload(
        block_weights(80, 10, 5, 5),
        SizeDistribution::Fixed(ValueBytes(128)),
        KeySpaceSize(500),
    )
}

fn sim_store() -> StoreConfig {
    StoreConfig {
        max_file_size: MaxFileSize(16 * 1024),
        group_commit: GroupCommitConfig::default(),
        shard_count: ShardCount(1),
    }
}

fn moderate_faults(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::Simulated {
            fault: FaultConfig::moderate(),
        },
        workload: sim_microbench_workload(),
        op_count: OpCount(50_000),
        invariants: sim_invariants(),
        limits: RunLimits {
            max_wall_ms: Some(WallMs(10 * 60_000)),
        },
        restart_policy: RestartPolicy::CrashAtSyscall(OpInterval(2_000)),
        store: sim_store(),
        eventlog: None,
        writer_concurrency: WriterConcurrency(1),
    }
}

fn aggressive_faults(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::Simulated {
            fault: FaultConfig::aggressive(),
        },
        workload: sim_microbench_workload(),
        op_count: OpCount(50_000),
        invariants: sim_invariants(),
        limits: RunLimits {
            max_wall_ms: Some(WallMs(10 * 60_000)),
        },
        restart_policy: RestartPolicy::CrashAtSyscall(OpInterval(2_000)),
        store: sim_store(),
        eventlog: None,
        writer_concurrency: WriterConcurrency(1),
    }
}

fn torn_pages(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::Simulated {
            fault: FaultConfig::torn_pages_only(),
        },
        workload: sim_microbench_workload(),
        op_count: OpCount(20_000),
        invariants: sim_invariants(),
        limits: RunLimits {
            max_wall_ms: Some(WallMs(5 * 60_000)),
        },
        restart_policy: RestartPolicy::CrashAtSyscall(OpInterval(1_000)),
        store: sim_store(),
        eventlog: None,
        writer_concurrency: WriterConcurrency(1),
    }
}

fn fsyncgate(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::Simulated {
            fault: FaultConfig::fsyncgate_only(),
        },
        workload: sim_microbench_workload(),
        op_count: OpCount(10_000),
        invariants: sim_invariants(),
        limits: RunLimits {
            max_wall_ms: Some(WallMs(5 * 60_000)),
        },
        restart_policy: RestartPolicy::CrashAtSyscall(OpInterval(500)),
        store: sim_store(),
        eventlog: None,
        writer_concurrency: WriterConcurrency(1),
    }
}

fn firehose_fanout(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::Simulated {
            fault: FaultConfig::moderate(),
        },
        workload: WorkloadModel {
            weights: OpWeights {
                add: 20,
                compact: 2,
                checkpoint: 3,
                append_event: 60,
                sync_event_log: 10,
                run_retention: 5,
                ..OpWeights::default()
            },
            size_distribution: SizeDistribution::Fixed(ValueBytes(128)),
            collections: default_collections(),
            key_space: KeySpaceSize(500),
            did_space: DidSpaceSize(64),
            retention_max_secs: RetentionMaxSecs(60),
        },
        op_count: OpCount(20_000),
        invariants: sim_invariants()
            | InvariantSet::MONOTONIC_SEQ
            | InvariantSet::FSYNC_ORDERING
            | InvariantSet::TOMBSTONE_BOUND,
        limits: RunLimits {
            max_wall_ms: Some(WallMs(10 * 60_000)),
        },
        restart_policy: RestartPolicy::CrashAtSyscall(OpInterval(2_000)),
        store: sim_store(),
        eventlog: Some(EventLogConfig {
            max_segment_size: MaxSegmentSize(64 * 1024),
        }),
        writer_concurrency: WriterConcurrency(1),
    }
}

fn contended_readers(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::Simulated {
            fault: FaultConfig::moderate(),
        },
        workload: WorkloadModel {
            weights: OpWeights {
                add: 15,
                delete: 1,
                compact: 2,
                checkpoint: 2,
                read_record: 60,
                read_block: 20,
                ..OpWeights::default()
            },
            size_distribution: SizeDistribution::Fixed(ValueBytes(128)),
            collections: default_collections(),
            key_space: KeySpaceSize(400),
            did_space: DidSpaceSize(32),
            retention_max_secs: RetentionMaxSecs(3600),
        },
        op_count: OpCount(20_000),
        invariants: sim_invariants(),
        limits: RunLimits {
            max_wall_ms: Some(WallMs(10 * 60_000)),
        },
        restart_policy: RestartPolicy::CrashAtSyscall(OpInterval(2_000)),
        store: sim_store(),
        eventlog: None,
        writer_concurrency: WriterConcurrency(64),
    }
}

fn contended_writers(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::Simulated {
            fault: FaultConfig::moderate(),
        },
        workload: WorkloadModel {
            weights: OpWeights {
                add: 85,
                delete: 5,
                compact: 3,
                checkpoint: 2,
                read_record: 4,
                read_block: 1,
                ..OpWeights::default()
            },
            size_distribution: SizeDistribution::Fixed(ValueBytes(128)),
            collections: default_collections(),
            key_space: KeySpaceSize(1_000),
            did_space: DidSpaceSize(32),
            retention_max_secs: RetentionMaxSecs(3600),
        },
        op_count: OpCount(20_000),
        invariants: sim_invariants(),
        limits: RunLimits {
            max_wall_ms: Some(WallMs(10 * 60_000)),
        },
        restart_policy: RestartPolicy::CrashAtSyscall(OpInterval(2_000)),
        store: sim_store(),
        eventlog: None,
        writer_concurrency: WriterConcurrency(32),
    }
}
