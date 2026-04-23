#![no_main]

use std::sync::OnceLock;

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use tokio::runtime::Runtime;
use tranquil_store::blockstore::GroupCommitConfig;
use tranquil_store::gauntlet::{
    CollectionName, DidSpaceSize, Gauntlet, GauntletConfig, InvariantSet, IoBackend, KeySpaceSize,
    MaxFileSize, Op, OpCount, OpInterval, OpStream, OpWeights, RecordKey, RestartPolicy,
    RetentionMaxSecs, RunLimits, Seed, ShardCount, SizeDistribution, StoreConfig, ValueBytes,
    ValueSeed, WallMs, WorkloadModel, WriterConcurrency,
};

#[derive(Arbitrary, Debug)]
enum FuzzOp {
    Add { rkey: u8, value: u16 },
    Delete { rkey: u8 },
    Compact,
    Checkpoint,
    Read { rkey: u8 },
    ReadBlock { value: u16 },
}

const COLLECTION: &str = "app.bsky.feed.post";
const MAX_OPS: usize = 128;

fn to_op(fuzz_op: FuzzOp) -> Op {
    match fuzz_op {
        FuzzOp::Add { rkey, value } => Op::AddRecord {
            collection: CollectionName(COLLECTION.to_string()),
            rkey: RecordKey(format!("k{rkey:03}")),
            value_seed: ValueSeed(u32::from(value)),
        },
        FuzzOp::Delete { rkey } => Op::DeleteRecord {
            collection: CollectionName(COLLECTION.to_string()),
            rkey: RecordKey(format!("k{rkey:03}")),
        },
        FuzzOp::Compact => Op::Compact,
        FuzzOp::Checkpoint => Op::Checkpoint,
        FuzzOp::Read { rkey } => Op::ReadRecord {
            collection: CollectionName(COLLECTION.to_string()),
            rkey: RecordKey(format!("k{rkey:03}")),
        },
        FuzzOp::ReadBlock { value } => Op::ReadBlock {
            value_seed: ValueSeed(u32::from(value)),
        },
    }
}

fn tiny_config() -> GauntletConfig {
    GauntletConfig {
        seed: Seed(0),
        io: IoBackend::Real,
        workload: WorkloadModel {
            weights: OpWeights::default(),
            size_distribution: SizeDistribution::Fixed(ValueBytes(64)),
            collections: vec![CollectionName(COLLECTION.to_string())],
            key_space: KeySpaceSize(256),
            did_space: DidSpaceSize(8),
            retention_max_secs: RetentionMaxSecs(3600),
        },
        op_count: OpCount(0),
        invariants: InvariantSet::REFCOUNT_CONSERVATION
            | InvariantSet::REACHABILITY
            | InvariantSet::READ_AFTER_WRITE,
        limits: RunLimits {
            max_wall_ms: Some(WallMs(2_000)),
        },
        restart_policy: RestartPolicy::EveryNOps(OpInterval(32)),
        store: StoreConfig {
            max_file_size: MaxFileSize(4096),
            group_commit: GroupCommitConfig::default(),
            shard_count: ShardCount(1),
        },
        eventlog: None,
        writer_concurrency: WriterConcurrency(1),
    }
}

fn shared_runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("build tokio runtime")
    })
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let mut u = Unstructured::new(data);
    let ops: Vec<FuzzOp> = match Vec::<FuzzOp>::arbitrary(&mut u) {
        Ok(ops) => ops.into_iter().take(MAX_OPS).collect(),
        Err(_) => return,
    };
    if ops.is_empty() {
        return;
    }
    let stream = OpStream::from_vec(ops.into_iter().map(to_op).collect());

    let cfg = tiny_config();
    let gauntlet = Gauntlet::new(cfg).expect("build gauntlet");
    let _ = shared_runtime().block_on(gauntlet.run_with_ops(stream));
});
