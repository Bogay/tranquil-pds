use tranquil_store::FaultConfig;
use tranquil_store::blockstore::GroupCommitConfig;
use tranquil_store::gauntlet::{
    CollectionName, ConfigOverrides, DidSpaceSize, Gauntlet, GauntletConfig, GauntletReport,
    InvariantSet, IoBackend, KeySpaceSize, MaxFileSize, OpCount, OpInterval, OpWeights,
    RegressionRecord, RestartPolicy, RetentionMaxSecs, RunLimits, Scenario, Seed, ShardCount,
    SizeDistribution, StoreConfig, StoreOverrides, ValueBytes, WallMs, WorkloadModel,
    WriterConcurrency, config_for, farm,
};

#[track_caller]
fn assert_clean(report: &GauntletReport) {
    let violations: Vec<String> = report
        .violations
        .iter()
        .map(|v| format!("{}: {}", v.invariant, v.detail))
        .collect();
    assert!(report.is_clean(), "violations: {violations:?}");
}

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
                compact: 10,
                checkpoint: 10,
                ..OpWeights::default()
            },
            size_distribution: SizeDistribution::Fixed(ValueBytes(64)),
            collections: vec![CollectionName("app.bsky.feed.post".to_string())],
            key_space: KeySpaceSize(100),
            did_space: DidSpaceSize(32),
            retention_max_secs: RetentionMaxSecs(3600),
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
        eventlog: None,
        writer_concurrency: WriterConcurrency(1),
    }
}

#[tokio::test]
async fn gauntlet_fast_sanity() {
    let report = Gauntlet::new(fast_sanity_config(Seed(7)))
        .expect("build gauntlet")
        .run()
        .await;
    assert_clean(&report);
    assert!(report.restarts.0 >= 2);
    assert_eq!(report.ops_executed.0, 200);
}

#[tokio::test]
async fn full_stack_restart_port() {
    let cfg = config_for(Scenario::FullStackRestart, Seed(1));
    let report = Gauntlet::new(cfg).expect("build gauntlet").run().await;
    assert_clean(&report);
    assert_eq!(
        report.restarts.0, 10,
        "FullStackRestart with EveryNOps(500) over 5000 ops must restart exactly 10 times",
    );
}

#[tokio::test]
async fn compaction_idempotent_sanity() {
    let cfg = GauntletConfig {
        seed: Seed(3),
        io: IoBackend::Real,
        workload: WorkloadModel {
            weights: OpWeights {
                add: 70,
                delete: 10,
                compact: 15,
                checkpoint: 5,
                ..OpWeights::default()
            },
            size_distribution: SizeDistribution::Fixed(ValueBytes(64)),
            collections: vec![CollectionName("app.bsky.feed.post".to_string())],
            key_space: KeySpaceSize(50),
            did_space: DidSpaceSize(32),
            retention_max_secs: RetentionMaxSecs(3600),
        },
        op_count: OpCount(300),
        invariants: InvariantSet::REFCOUNT_CONSERVATION
            | InvariantSet::REACHABILITY
            | InvariantSet::READ_AFTER_WRITE
            | InvariantSet::COMPACTION_IDEMPOTENT,
        limits: RunLimits {
            max_wall_ms: Some(WallMs(30_000)),
        },
        restart_policy: RestartPolicy::Never,
        store: StoreConfig {
            max_file_size: MaxFileSize(4096),
            group_commit: GroupCommitConfig::default(),
            shard_count: ShardCount(1),
        },
        eventlog: None,
        writer_concurrency: WriterConcurrency(1),
    };
    let report = Gauntlet::new(cfg).expect("build gauntlet").run().await;
    assert_clean(&report);
}

#[tokio::test]
async fn no_orphan_files_sanity() {
    let cfg = GauntletConfig {
        seed: Seed(11),
        io: IoBackend::Real,
        workload: WorkloadModel {
            weights: OpWeights {
                add: 90,
                checkpoint: 10,
                ..OpWeights::default()
            },
            size_distribution: SizeDistribution::Fixed(ValueBytes(128)),
            collections: vec![CollectionName("app.bsky.feed.post".to_string())],
            key_space: KeySpaceSize(80),
            did_space: DidSpaceSize(32),
            retention_max_secs: RetentionMaxSecs(3600),
        },
        op_count: OpCount(200),
        invariants: InvariantSet::REFCOUNT_CONSERVATION
            | InvariantSet::REACHABILITY
            | InvariantSet::READ_AFTER_WRITE
            | InvariantSet::COMPACTION_IDEMPOTENT
            | InvariantSet::NO_ORPHAN_FILES,
        limits: RunLimits {
            max_wall_ms: Some(WallMs(30_000)),
        },
        restart_policy: RestartPolicy::Never,
        store: StoreConfig {
            max_file_size: MaxFileSize(64 * 1024),
            group_commit: GroupCommitConfig::default(),
            shard_count: ShardCount(1),
        },
        eventlog: None,
        writer_concurrency: WriterConcurrency(1),
    };
    let report = Gauntlet::new(cfg).expect("build gauntlet").run().await;
    assert_clean(&report);
}

#[tokio::test]
async fn simulated_pristine_roundtrip() {
    let cfg = GauntletConfig {
        seed: Seed(21),
        io: IoBackend::Simulated {
            fault: FaultConfig::none(),
        },
        workload: WorkloadModel {
            weights: OpWeights {
                add: 80,
                delete: 10,
                compact: 5,
                checkpoint: 5,
                ..OpWeights::default()
            },
            size_distribution: SizeDistribution::Fixed(ValueBytes(96)),
            collections: vec![CollectionName("app.bsky.feed.post".to_string())],
            key_space: KeySpaceSize(80),
            did_space: DidSpaceSize(32),
            retention_max_secs: RetentionMaxSecs(3600),
        },
        op_count: OpCount(300),
        invariants: InvariantSet::REFCOUNT_CONSERVATION
            | InvariantSet::REACHABILITY
            | InvariantSet::ACKED_WRITE_PERSISTENCE
            | InvariantSet::READ_AFTER_WRITE
            | InvariantSet::RESTART_IDEMPOTENT
            | InvariantSet::CHECKSUM_COVERAGE,
        limits: RunLimits {
            max_wall_ms: Some(WallMs(60_000)),
        },
        restart_policy: RestartPolicy::EveryNOps(OpInterval(100)),
        store: StoreConfig {
            max_file_size: MaxFileSize(8 * 1024),
            group_commit: GroupCommitConfig::default(),
            shard_count: ShardCount(1),
        },
        eventlog: None,
        writer_concurrency: WriterConcurrency(1),
    };
    let report = Gauntlet::new(cfg).expect("build gauntlet").run().await;
    assert_clean(&report);
    assert_eq!(report.ops_executed.0, 300);
    assert!(report.restarts.0 >= 2);
}

#[tokio::test]
async fn firehose_fanout_pristine_smoke() {
    use tranquil_store::gauntlet::{EventLogConfig, MaxSegmentSize};

    let cfg = GauntletConfig {
        seed: Seed(1),
        io: IoBackend::Simulated {
            fault: FaultConfig::none(),
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
            collections: vec![CollectionName("app.bsky.feed.post".to_string())],
            key_space: KeySpaceSize(100),
            did_space: DidSpaceSize(32),
            retention_max_secs: RetentionMaxSecs(60),
        },
        op_count: OpCount(2_000),
        invariants: InvariantSet::REFCOUNT_CONSERVATION
            | InvariantSet::REACHABILITY
            | InvariantSet::ACKED_WRITE_PERSISTENCE
            | InvariantSet::READ_AFTER_WRITE
            | InvariantSet::RESTART_IDEMPOTENT
            | InvariantSet::MONOTONIC_SEQ
            | InvariantSet::FSYNC_ORDERING
            | InvariantSet::TOMBSTONE_BOUND,
        limits: RunLimits {
            max_wall_ms: Some(WallMs(60_000)),
        },
        restart_policy: RestartPolicy::EveryNOps(OpInterval(500)),
        store: StoreConfig {
            max_file_size: MaxFileSize(16 * 1024),
            group_commit: GroupCommitConfig::default(),
            shard_count: ShardCount(1),
        },
        eventlog: Some(EventLogConfig {
            max_segment_size: MaxSegmentSize(32 * 1024),
        }),
        writer_concurrency: WriterConcurrency(1),
    };
    let report = Gauntlet::new(cfg).expect("build gauntlet").run().await;
    assert_clean(&report);
    assert_eq!(report.ops_executed.0, 2_000);
    assert!(report.restarts.0 >= 2);
}

#[tokio::test]
async fn contended_readers_pristine_smoke() {
    let cfg = GauntletConfig {
        seed: Seed(1),
        io: IoBackend::Simulated {
            fault: FaultConfig::none(),
        },
        workload: WorkloadModel {
            weights: OpWeights {
                add: 20,
                compact: 2,
                checkpoint: 3,
                read_record: 60,
                read_block: 15,
                ..OpWeights::default()
            },
            size_distribution: SizeDistribution::Fixed(ValueBytes(128)),
            collections: vec![CollectionName("app.bsky.feed.post".to_string())],
            key_space: KeySpaceSize(200),
            did_space: DidSpaceSize(32),
            retention_max_secs: RetentionMaxSecs(3600),
        },
        op_count: OpCount(1_000),
        invariants: InvariantSet::REFCOUNT_CONSERVATION
            | InvariantSet::REACHABILITY
            | InvariantSet::ACKED_WRITE_PERSISTENCE
            | InvariantSet::READ_AFTER_WRITE
            | InvariantSet::RESTART_IDEMPOTENT,
        limits: RunLimits {
            max_wall_ms: Some(WallMs(60_000)),
        },
        restart_policy: RestartPolicy::EveryNOps(OpInterval(250)),
        store: StoreConfig {
            max_file_size: MaxFileSize(16 * 1024),
            group_commit: GroupCommitConfig::default(),
            shard_count: ShardCount(1),
        },
        eventlog: None,
        writer_concurrency: WriterConcurrency(16),
    };
    let report = Gauntlet::new(cfg).expect("build gauntlet").run().await;
    assert_clean(&report);
    assert_eq!(report.ops_executed.0, 1_000);
    assert!(report.restarts.0 >= 2);
}

#[tokio::test]
async fn contended_writers_pristine_smoke() {
    let cfg = GauntletConfig {
        seed: Seed(2),
        io: IoBackend::Simulated {
            fault: FaultConfig::none(),
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
            collections: vec![CollectionName("app.bsky.feed.post".to_string())],
            key_space: KeySpaceSize(500),
            did_space: DidSpaceSize(32),
            retention_max_secs: RetentionMaxSecs(3600),
        },
        op_count: OpCount(1_000),
        invariants: InvariantSet::REFCOUNT_CONSERVATION
            | InvariantSet::REACHABILITY
            | InvariantSet::ACKED_WRITE_PERSISTENCE
            | InvariantSet::READ_AFTER_WRITE
            | InvariantSet::RESTART_IDEMPOTENT,
        limits: RunLimits {
            max_wall_ms: Some(WallMs(60_000)),
        },
        restart_policy: RestartPolicy::EveryNOps(OpInterval(250)),
        store: StoreConfig {
            max_file_size: MaxFileSize(16 * 1024),
            group_commit: GroupCommitConfig::default(),
            shard_count: ShardCount(1),
        },
        eventlog: None,
        writer_concurrency: WriterConcurrency(8),
    };
    let report = Gauntlet::new(cfg).expect("build gauntlet").run().await;
    assert_clean(&report);
    assert_eq!(report.ops_executed.0, 1_000);
    assert!(report.restarts.0 >= 2);
}

#[tokio::test]
async fn report_carries_generated_ops_when_clean() {
    let cfg = fast_sanity_config(Seed(5));
    let expected_len = cfg.op_count.0;
    let report = Gauntlet::new(cfg).expect("build gauntlet").run().await;
    assert_clean(&report);
    assert_eq!(
        report.ops.len(),
        expected_len,
        "clean report missing op stream"
    );
}

#[tokio::test]
async fn regression_round_trip_replays_injected_ops() {
    let overrides = ConfigOverrides {
        op_count: Some(25),
        store: StoreOverrides {
            max_file_size: Some(8192),
            ..StoreOverrides::default()
        },
        ..ConfigOverrides::default()
    };
    let mut cfg = config_for(Scenario::SmokePR, Seed(99));
    overrides.apply_to(&mut cfg);

    let original_report = Gauntlet::new(cfg.clone())
        .expect("build gauntlet")
        .run()
        .await;
    let captured_ops = original_report.ops.clone();
    assert_eq!(
        captured_ops.len(),
        25,
        "captured op stream must match op_count override"
    );

    let dir = tempfile::TempDir::new().unwrap();
    let record = RegressionRecord::from_report(
        Scenario::SmokePR,
        overrides.clone(),
        &original_report,
        captured_ops.len(),
        captured_ops.clone(),
    );
    let written = record.write_to(dir.path()).expect("write regression");
    let loaded = RegressionRecord::load(&written).expect("load regression");
    assert_eq!(loaded.overrides, overrides);
    assert_eq!(loaded.ops.len(), captured_ops.len());

    let rebuilt = loaded.build_config().expect("rebuild config");
    assert_eq!(rebuilt.op_count.0, 25);
    assert_eq!(rebuilt.store.max_file_size.0, 8192);

    let replay = Gauntlet::new(rebuilt)
        .expect("build gauntlet")
        .run_with_ops(loaded.op_stream())
        .await;
    assert_eq!(
        replay.violations.len(),
        original_report.violations.len(),
        "replay from regression must produce same violation count",
    );
    let original_inv: Vec<&'static str> = original_report
        .violations
        .iter()
        .map(|v| v.invariant)
        .collect();
    let replay_inv: Vec<&'static str> = replay.violations.iter().map(|v| v.invariant).collect();
    assert_eq!(original_inv, replay_inv);
    assert_eq!(replay.ops.len(), captured_ops.len());
}

#[tokio::test]
#[ignore = "long running, 100k ops with around 20 restarts"]
async fn mst_restart_churn_single_seed() {
    let cfg = config_for(Scenario::MstRestartChurn, Seed(42));
    let report = Gauntlet::new(cfg).expect("build gauntlet").run().await;
    assert_clean(&report);
    assert!(report.restarts.0 >= 1);
}
