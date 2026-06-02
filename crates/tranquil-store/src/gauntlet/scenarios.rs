use super::flaky::FlakyConfig;
use super::invariants::InvariantSet;
use super::op::{CollectionName, Seed};
use super::runner::{
    EventLogConfig, GauntletConfig, IoBackend, MaxFileSize, MaxSegmentSize, OpInterval,
    RestartPolicy, RunLimits, ShardCount, StoreConfig, WallMs, WriterConcurrency,
};
use super::workload::{
    AdvanceMaxSecs, ByteRange, DidSpaceSize, KeySpaceSize, OpCount, OpWeights, RetentionMaxSecs,
    SizeDistribution, ValueBytes, WorkloadModel,
};
use crate::blockstore::{GroupCommitConfig, MAX_BLOCK_SIZE};
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
    MisdirectedWrites,
    Fsyncgate,
    FirehoseFanout,
    ContendedReaders,
    ContendedWriters,
    FlakyDevice,
    ExternalCorruption,
    RetentionTimeTravel,
    EventlogTimeTravelChaos,
    BlockChurnRecoverable,
    ReadCorruption,
    InlineCommit,
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
            Self::MisdirectedWrites => "MisdirectedWrites",
            Self::Fsyncgate => "Fsyncgate",
            Self::FirehoseFanout => "FirehoseFanout",
            Self::ContendedReaders => "ContendedReaders",
            Self::ContendedWriters => "ContendedWriters",
            Self::FlakyDevice => "FlakyDevice",
            Self::ExternalCorruption => "ExternalCorruption",
            Self::RetentionTimeTravel => "RetentionTimeTravel",
            Self::EventlogTimeTravelChaos => "EventlogTimeTravelChaos",
            Self::BlockChurnRecoverable => "BlockChurnRecoverable",
            Self::ReadCorruption => "ReadCorruption",
            Self::InlineCommit => "InlineCommit",
        }
    }

    pub const fn cli_name(self) -> &'static str {
        match self {
            Self::SmokePR => "smoke-pr",
            Self::MstChurn => "mst-churn",
            Self::MstRestartChurn => "mst-restart-churn",
            Self::FullStackRestart => "full-stack-restart",
            Self::CatastrophicChurn => "catastrophic-churn",
            Self::HugeValues => "huge-values",
            Self::TinyBatches => "tiny-batches",
            Self::GiantBatches => "giant-batches",
            Self::ManyFiles => "many-files",
            Self::ModerateFaults => "moderate-faults",
            Self::AggressiveFaults => "aggressive-faults",
            Self::TornPages => "torn-pages",
            Self::MisdirectedWrites => "misdirected-writes",
            Self::Fsyncgate => "fsyncgate",
            Self::FirehoseFanout => "firehose-fanout",
            Self::ContendedReaders => "contended-readers",
            Self::ContendedWriters => "contended-writers",
            Self::FlakyDevice => "flaky-device",
            Self::ExternalCorruption => "external-corruption",
            Self::RetentionTimeTravel => "retention-time-travel",
            Self::EventlogTimeTravelChaos => "eventlog-time-travel-chaos",
            Self::BlockChurnRecoverable => "block-churn-recoverable",
            Self::ReadCorruption => "read-corruption",
            Self::InlineCommit => "inline-commit",
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::SmokePR => "60s canary, 10k ops, core invariants. Default PR gate.",
            Self::MstChurn => "100k churn, no restart. Refcount + reachability focus.",
            Self::MstRestartChurn => "100k churn with Poisson restart bursts every ~5k ops.",
            Self::FullStackRestart => "5k ops, deterministic restart every 500 ops.",
            Self::CatastrophicChurn => {
                "1M ops, phase-2 invariants, Poisson restart. 30 min budget."
            }
            Self::HugeValues => "Heavy-tail values up to 16 MiB. 32 MiB file cap.",
            Self::TinyBatches => "Group-commit batch size 1, tight checkpoints, 4 KiB files.",
            Self::GiantBatches => "Group-commit batch size 100k, 16 MiB files.",
            Self::ManyFiles => "256-byte file cap, many segments, delete-heavy.",
            Self::ModerateFaults => {
                "Simulated IO with moderate fault config. CrashAtSyscall restarts."
            }
            Self::AggressiveFaults => {
                "Simulated IO with aggressive fault config. CrashAtSyscall restarts."
            }
            Self::TornPages => "Torn-page faults only, 20k ops.",
            Self::MisdirectedWrites => "Misdirected-write faults only, 20k ops.",
            Self::Fsyncgate => "Fsync-drop faults only, 10k ops.",
            Self::FirehoseFanout => {
                "Eventlog-heavy workload with FSYNC_ORDERING / MONOTONIC_SEQ / TOMBSTONE_BOUND invariants."
            }
            Self::ContendedReaders => "60% reads, 64 writer tasks, simulated moderate faults.",
            Self::ContendedWriters => {
                "Add/delete heavy, 32 writer tasks, simulated moderate faults."
            }
            Self::FlakyDevice => {
                "Real IO on ext4 atop dm-flakey. Requires root with dm-flakey available, skips otherwise."
            }
            Self::ExternalCorruption => {
                "Rare external data-file deletion mid-workload. Validates phantom-purge self-heal under chaos."
            }
            Self::RetentionTimeTravel => {
                "Eventlog retention under logical time travel: random multi-day AdvanceTime jumps interleaved with append/sync/retention. TOMBSTONE_BOUND across fake weeks."
            }
            Self::EventlogTimeTravelChaos => {
                "Eventlog crash-recovery under logical time travel with recoverable faults. Expect 100% clean: any violation is a recovery bug, not the single-copy detection limit."
            }
            Self::BlockChurnRecoverable => {
                "Block-only churn under recoverable faults with crashes. Deterministic vehicle for refcount/reachability recovery bugs without the single-copy corruption-detection noise."
            }
            Self::ReadCorruption => {
                "Read-heavy workload under misdirected-read and bit-flip faults. Validates ReadRecord/ReadBlock results against the oracle at op time: the store must never serve content that does not match the requested address."
            }
            Self::InlineCommit => {
                "Synchronous inline group-commit on the real backend with persisted-block verification and frequent restarts. Drives the GroupCommitConfig synchronous + verify_persisted_blocks path that production single-writer commits use."
            }
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|s| s.name() == name)
    }

    pub fn from_cli_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|s| s.cli_name() == name)
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
        Self::MisdirectedWrites,
        Self::Fsyncgate,
        Self::FirehoseFanout,
        Self::ContendedReaders,
        Self::ContendedWriters,
        Self::FlakyDevice,
        Self::ExternalCorruption,
        Self::RetentionTimeTravel,
        Self::EventlogTimeTravelChaos,
        Self::BlockChurnRecoverable,
        Self::ReadCorruption,
        Self::InlineCommit,
    ];
}

impl serde::Serialize for Scenario {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.cli_name())
    }
}

impl<'de> serde::Deserialize<'de> for Scenario {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        Self::from_cli_name(&s).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "unknown scenario {s:?}; expected one of {}",
                Self::ALL
                    .iter()
                    .map(|s| s.cli_name())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })
    }
}

#[cfg(feature = "gauntlet-cli")]
impl clap::ValueEnum for Scenario {
    fn value_variants<'a>() -> &'a [Self] {
        Self::ALL
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(clap::builder::PossibleValue::new(self.cli_name()).help(self.description()))
    }
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
        Scenario::MisdirectedWrites => misdirected_writes(seed),
        Scenario::Fsyncgate => fsyncgate(seed),
        Scenario::FirehoseFanout => firehose_fanout(seed),
        Scenario::ContendedReaders => contended_readers(seed),
        Scenario::ContendedWriters => contended_writers(seed),
        Scenario::FlakyDevice => flaky_device(seed),
        Scenario::ExternalCorruption => external_corruption(seed),
        Scenario::RetentionTimeTravel => retention_time_travel(seed),
        Scenario::EventlogTimeTravelChaos => eventlog_time_travel_chaos(seed),
        Scenario::BlockChurnRecoverable => block_churn_recoverable(seed),
        Scenario::ReadCorruption => read_corruption(seed),
        Scenario::InlineCommit => inline_commit(seed),
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
        advance_max_secs: AdvanceMaxSecs(7200),
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
        tolerate_op_errors: false,
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
        tolerate_op_errors: false,
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
        tolerate_op_errors: false,
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
        tolerate_op_errors: false,
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
        | InvariantSet::INDEX_BACKED_BY_DISK
        | InvariantSet::HINT_BACKED_BY_DATA
        | InvariantSet::INDEX_BLOCKS_READABLE
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
        tolerate_op_errors: false,
    }
}

fn huge_values(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::Real,
        workload: block_workload(
            block_weights(85, 5, 8, 2),
            SizeDistribution::HeavyTail(
                ByteRange::new(ValueBytes(256), ValueBytes(MAX_BLOCK_SIZE))
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
        tolerate_op_errors: false,
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
        tolerate_op_errors: false,
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
        tolerate_op_errors: false,
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
        tolerate_op_errors: false,
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
        | InvariantSet::INDEX_BACKED_BY_DISK
        | InvariantSet::HINT_BACKED_BY_DATA
        | InvariantSet::INDEX_BLOCKS_READABLE
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
        group_commit: GroupCommitConfig {
            verify_persisted_blocks: true,
            ..GroupCommitConfig::default()
        },
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
        tolerate_op_errors: false,
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
        tolerate_op_errors: false,
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
        tolerate_op_errors: false,
    }
}

fn misdirected_writes(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::Simulated {
            fault: FaultConfig::misdirected_only(),
        },
        workload: sim_microbench_workload(),
        op_count: OpCount(20_000),
        invariants: InvariantSet::MST_REPAIRABLE,
        limits: RunLimits {
            max_wall_ms: Some(WallMs(5 * 60_000)),
        },
        restart_policy: RestartPolicy::Never,
        store: sim_store(),
        eventlog: None,
        writer_concurrency: WriterConcurrency(1),
        tolerate_op_errors: false,
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
        tolerate_op_errors: false,
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
            advance_max_secs: AdvanceMaxSecs(7200),
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
        tolerate_op_errors: false,
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
            advance_max_secs: AdvanceMaxSecs(7200),
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
        tolerate_op_errors: false,
    }
}

fn flaky_device(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::RealWithFlaky {
            flaky: FlakyConfig::default_stress(),
        },
        workload: block_workload(
            block_weights(80, 5, 10, 5),
            SizeDistribution::Fixed(ValueBytes(128)),
            KeySpaceSize(500),
        ),
        op_count: OpCount(20_000),
        invariants: InvariantSet::REFCOUNT_CONSERVATION
            | InvariantSet::REACHABILITY
            | InvariantSet::ACKED_WRITE_PERSISTENCE
            | InvariantSet::READ_AFTER_WRITE
            | InvariantSet::RESTART_IDEMPOTENT
            | InvariantSet::NO_ORPHAN_FILES
            | InvariantSet::MANIFEST_EQUALS_REALITY
            | InvariantSet::BYTE_BUDGET
            | InvariantSet::CHECKSUM_COVERAGE,
        limits: RunLimits {
            max_wall_ms: Some(WallMs(30 * 60_000)),
        },
        restart_policy: RestartPolicy::EveryNOps(OpInterval(1_000)),
        store: tiny_store(),
        eventlog: None,
        writer_concurrency: WriterConcurrency(1),
        tolerate_op_errors: false,
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
            advance_max_secs: AdvanceMaxSecs(7200),
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
        tolerate_op_errors: false,
    }
}

fn external_corruption(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::Real,
        workload: block_workload(
            OpWeights {
                add: 50,
                delete: 30,
                compact: 18,
                checkpoint: 1,
                external_delete_data_file: 1,
                ..OpWeights::default()
            },
            SizeDistribution::Fixed(ValueBytes(128)),
            KeySpaceSize(200),
        ),
        op_count: OpCount(2_000),
        invariants: InvariantSet::NO_ORPHAN_FILES | InvariantSet::BYTE_BUDGET,
        limits: RunLimits {
            max_wall_ms: Some(WallMs(60_000)),
        },
        restart_policy: RestartPolicy::EveryNOps(OpInterval(1_000)),
        store: tiny_store(),
        eventlog: None,
        writer_concurrency: WriterConcurrency(1),
        tolerate_op_errors: true,
    }
}

fn retention_time_travel(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::Simulated {
            fault: FaultConfig::none(),
        },
        workload: WorkloadModel {
            weights: OpWeights {
                add: 20,
                compact: 3,
                checkpoint: 2,
                append_event: 30,
                sync_event_log: 15,
                run_retention: 10,
                advance_time: 20,
                ..OpWeights::default()
            },
            size_distribution: SizeDistribution::Fixed(ValueBytes(96)),
            collections: default_collections(),
            key_space: KeySpaceSize(400),
            did_space: DidSpaceSize(64),
            retention_max_secs: RetentionMaxSecs(1_209_600),
            advance_max_secs: AdvanceMaxSecs(1_209_600),
        },
        op_count: OpCount(1_200),
        invariants: sim_invariants() | InvariantSet::MONOTONIC_SEQ | InvariantSet::TOMBSTONE_BOUND,
        limits: RunLimits {
            max_wall_ms: Some(WallMs(5 * 60_000)),
        },
        restart_policy: RestartPolicy::EveryNOps(OpInterval(400)),
        store: sim_store(),
        eventlog: Some(EventLogConfig {
            max_segment_size: MaxSegmentSize(8 * 1024),
        }),
        writer_concurrency: WriterConcurrency(1),
        tolerate_op_errors: false,
    }
}

fn eventlog_time_travel_chaos(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::Simulated {
            fault: FaultConfig::recoverable(),
        },
        workload: WorkloadModel {
            weights: OpWeights {
                add: 15,
                compact: 2,
                checkpoint: 3,
                append_event: 35,
                sync_event_log: 15,
                run_retention: 10,
                advance_time: 20,
                ..OpWeights::default()
            },
            size_distribution: SizeDistribution::Fixed(ValueBytes(96)),
            collections: default_collections(),
            key_space: KeySpaceSize(400),
            did_space: DidSpaceSize(64),
            retention_max_secs: RetentionMaxSecs(604_800),
            advance_max_secs: AdvanceMaxSecs(259_200),
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
            max_segment_size: MaxSegmentSize(16 * 1024),
        }),
        writer_concurrency: WriterConcurrency(1),
        tolerate_op_errors: false,
    }
}

fn block_churn_recoverable(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::Simulated {
            fault: FaultConfig::recoverable(),
        },
        workload: WorkloadModel {
            weights: OpWeights {
                add: 70,
                delete: 10,
                compact: 5,
                checkpoint: 5,
                mst_list: 10,
                ..OpWeights::default()
            },
            size_distribution: SizeDistribution::Fixed(ValueBytes(128)),
            collections: default_collections(),
            key_space: KeySpaceSize(500),
            did_space: DidSpaceSize(32),
            retention_max_secs: RetentionMaxSecs(3600),
            advance_max_secs: AdvanceMaxSecs(7200),
        },
        op_count: OpCount(20_000),
        invariants: sim_invariants(),
        limits: RunLimits {
            max_wall_ms: Some(WallMs(10 * 60_000)),
        },
        restart_policy: RestartPolicy::CrashAtSyscall(OpInterval(2_000)),
        store: sim_store(),
        eventlog: None,
        writer_concurrency: WriterConcurrency(1),
        tolerate_op_errors: false,
    }
}

fn read_corruption(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::Simulated {
            fault: FaultConfig::read_faults(),
        },
        workload: WorkloadModel {
            weights: OpWeights {
                add: 35,
                delete: 3,
                compact: 2,
                read_record: 40,
                read_block: 12,
                mst_list: 8,
                ..OpWeights::default()
            },
            size_distribution: SizeDistribution::Fixed(ValueBytes(128)),
            collections: default_collections(),
            key_space: KeySpaceSize(300),
            did_space: DidSpaceSize(32),
            retention_max_secs: RetentionMaxSecs(3600),
            advance_max_secs: AdvanceMaxSecs(7200),
        },
        op_count: OpCount(20_000),
        invariants: sim_invariants(),
        limits: RunLimits {
            max_wall_ms: Some(WallMs(10 * 60_000)),
        },
        restart_policy: RestartPolicy::Never,
        store: sim_store(),
        eventlog: None,
        writer_concurrency: WriterConcurrency(1),
        tolerate_op_errors: false,
    }
}

fn inline_commit(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::Real,
        workload: block_workload(
            block_weights(80, 10, 5, 5),
            SizeDistribution::Fixed(ValueBytes(96)),
            KeySpaceSize(300),
        ),
        op_count: OpCount(10_000),
        invariants: phase2_invariants(),
        limits: RunLimits {
            max_wall_ms: Some(WallMs(120_000)),
        },
        restart_policy: RestartPolicy::EveryNOps(OpInterval(1_000)),
        store: StoreConfig {
            max_file_size: MaxFileSize(8 * 1024),
            group_commit: GroupCommitConfig {
                synchronous: true,
                verify_persisted_blocks: true,
                checkpoint_interval_ms: 100,
                checkpoint_write_threshold: 16,
                ..GroupCommitConfig::default()
            },
            shard_count: ShardCount(1),
        },
        eventlog: None,
        writer_concurrency: WriterConcurrency(1),
        tolerate_op_errors: false,
    }
}
