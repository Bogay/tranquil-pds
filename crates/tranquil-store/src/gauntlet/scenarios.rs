use super::invariants::InvariantSet;
use super::op::{CollectionName, Seed};
use super::runner::{
    CompactInterval, GauntletConfig, IoBackend, MaxFileSize, OpInterval, RestartPolicy, RunLimits,
    ShardCount, StoreConfig, WallMs,
};
use super::workload::{
    KeySpaceSize, OpCount, OpWeights, SizeDistribution, ValueBytes, WorkloadModel,
};
use crate::blockstore::GroupCommitConfig;

#[derive(Debug, Clone, Copy)]
pub enum Scenario {
    SmokePR,
    MstChurn,
    MstRestartChurn,
}

pub fn config_for(scenario: Scenario, seed: Seed) -> GauntletConfig {
    match scenario {
        Scenario::SmokePR => smoke_pr(seed),
        Scenario::MstChurn => mst_churn(seed),
        Scenario::MstRestartChurn => mst_restart_churn(seed),
    }
}

fn default_collections() -> Vec<CollectionName> {
    vec![
        CollectionName("app.bsky.feed.post".to_string()),
        CollectionName("app.bsky.feed.like".to_string()),
    ]
}

fn tiny_store() -> StoreConfig {
    StoreConfig {
        max_file_size: MaxFileSize(300),
        group_commit: GroupCommitConfig {
            checkpoint_interval_ms: 100,
            checkpoint_write_threshold: 10,
            ..GroupCommitConfig::default()
        },
        shard_count: ShardCount(1),
        compact_every: CompactInterval(5),
    }
}

fn smoke_pr(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::Real,
        workload: WorkloadModel {
            weights: OpWeights {
                add: 80,
                delete: 0,
                compact: 10,
                checkpoint: 10,
            },
            size_distribution: SizeDistribution::Fixed(ValueBytes(64)),
            collections: default_collections(),
            key_space: KeySpaceSize(200),
        },
        op_count: OpCount(10_000),
        invariants: InvariantSet::REFCOUNT_CONSERVATION | InvariantSet::REACHABILITY,
        limits: RunLimits {
            max_wall_ms: Some(WallMs(60_000)),
        },
        restart_policy: RestartPolicy::EveryNOps(OpInterval(2_000)),
        store: tiny_store(),
    }
}

fn mst_churn(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::Real,
        workload: WorkloadModel {
            weights: OpWeights {
                add: 85,
                delete: 0,
                compact: 10,
                checkpoint: 5,
            },
            size_distribution: SizeDistribution::Fixed(ValueBytes(64)),
            collections: default_collections(),
            key_space: KeySpaceSize(2_000),
        },
        op_count: OpCount(100_000),
        invariants: InvariantSet::REFCOUNT_CONSERVATION | InvariantSet::REACHABILITY,
        limits: RunLimits {
            max_wall_ms: Some(WallMs(600_000)),
        },
        restart_policy: RestartPolicy::Never,
        store: tiny_store(),
    }
}

fn mst_restart_churn(seed: Seed) -> GauntletConfig {
    GauntletConfig {
        seed,
        io: IoBackend::Real,
        workload: WorkloadModel {
            weights: OpWeights {
                add: 85,
                delete: 0,
                compact: 10,
                checkpoint: 5,
            },
            size_distribution: SizeDistribution::Fixed(ValueBytes(64)),
            collections: default_collections(),
            key_space: KeySpaceSize(2_000),
        },
        op_count: OpCount(100_000),
        invariants: InvariantSet::REFCOUNT_CONSERVATION | InvariantSet::REACHABILITY,
        limits: RunLimits {
            max_wall_ms: Some(WallMs(600_000)),
        },
        restart_policy: RestartPolicy::PoissonByOps(OpInterval(5_000)),
        store: tiny_store(),
    }
}
