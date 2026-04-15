use tranquil_store::blockstore::GroupCommitConfig;
use tranquil_store::gauntlet::{
    CollectionName, Gauntlet, GauntletConfig, InvariantSet, IoBackend, KeySpaceSize, MaxFileSize,
    OpCount, OpInterval, OpWeights, RestartPolicy, RunLimits, Scenario, Seed, ShardCount,
    SizeDistribution, StoreConfig, ValueBytes, WallMs, WorkloadModel, config_for, farm,
};

#[test]
#[ignore = "long running, 30 seeds of 10k ops each"]
fn smoke_pr_30_seeds() {
    let reports = farm::run_many(
        |seed| config_for(Scenario::SmokePR, seed),
        (0..30).map(Seed),
    );
    let failures: Vec<String> = reports
        .iter()
        .filter(|r| !r.is_clean())
        .map(|r| {
            format!(
                "seed {}: {} violations\n  {}",
                r.seed.0,
                r.violations.len(),
                r.violations
                    .iter()
                    .map(|v| format!("{}: {}", v.invariant, v.detail))
                    .collect::<Vec<_>>()
                    .join("\n  ")
            )
        })
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n---\n"));
}

fn fast_sanity_config(seed: Seed) -> GauntletConfig {
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
            collections: vec![CollectionName("app.bsky.feed.post".to_string())],
            key_space: KeySpaceSize(100),
        },
        op_count: OpCount(200),
        invariants: InvariantSet::REFCOUNT_CONSERVATION
            | InvariantSet::REACHABILITY
            | InvariantSet::ACKED_WRITE_PERSISTENCE
            | InvariantSet::READ_AFTER_WRITE
            | InvariantSet::RESTART_IDEMPOTENT,
        limits: RunLimits {
            max_wall_ms: Some(WallMs(30_000)),
        },
        restart_policy: RestartPolicy::EveryNOps(OpInterval(80)),
        store: StoreConfig {
            max_file_size: MaxFileSize(512),
            group_commit: GroupCommitConfig {
                checkpoint_interval_ms: 50,
                checkpoint_write_threshold: 8,
                ..GroupCommitConfig::default()
            },
            shard_count: ShardCount(1),
        },
    }
}

#[tokio::test]
async fn gauntlet_fast_sanity() {
    let report = Gauntlet::new(fast_sanity_config(Seed(7)))
        .expect("build gauntlet")
        .run()
        .await;
    assert!(
        report.is_clean(),
        "violations: {:?}",
        report
            .violations
            .iter()
            .map(|v| format!("{}: {}", v.invariant, v.detail))
            .collect::<Vec<_>>()
    );
    assert!(
        report.restarts.0 >= 2,
        "expected at least 2 restarts, got {}",
        report.restarts.0
    );
    assert_eq!(report.ops_executed.0, 200);
}

#[tokio::test]
async fn full_stack_restart_port() {
    let cfg = config_for(Scenario::FullStackRestart, Seed(1));
    let report = Gauntlet::new(cfg).expect("build gauntlet").run().await;
    assert!(
        report.is_clean(),
        "violations: {:?}",
        report
            .violations
            .iter()
            .map(|v| format!("{}: {}", v.invariant, v.detail))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        report.restarts.0, 10,
        "FullStackRestart with EveryNOps(500) over 5000 ops must restart exactly 10 times",
    );
}

#[tokio::test]
#[ignore = "long running, 100k ops with around 20 restarts"]
async fn mst_restart_churn_single_seed() {
    let cfg = config_for(Scenario::MstRestartChurn, Seed(42));
    let report = Gauntlet::new(cfg).expect("build gauntlet").run().await;
    assert!(
        report.is_clean(),
        "violations: {:?}",
        report
            .violations
            .iter()
            .map(|v| format!("{}: {}", v.invariant, v.detail))
            .collect::<Vec<_>>()
    );
    assert!(
        report.restarts.0 >= 1,
        "PoissonByOps(5000) over 100k ops should fire at least 1 restart, got {}",
        report.restarts.0
    );
}
