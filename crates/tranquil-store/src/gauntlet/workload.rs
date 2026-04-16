use super::op::{
    CollectionName, DidSeed, EventKind, Op, OpStream, PayloadSeed, RecordKey, RetentionSecs, Seed,
    ValueSeed,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ValueBytes(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeySpaceSize(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpCount(pub usize);

#[derive(Debug, Clone, Copy, Default)]
pub struct OpWeights {
    pub add: u32,
    pub delete: u32,
    pub compact: u32,
    pub checkpoint: u32,
    pub append_event: u32,
    pub sync_event_log: u32,
    pub run_retention: u32,
    pub read_record: u32,
    pub read_block: u32,
}

impl OpWeights {
    pub const fn total(&self) -> u32 {
        self.add
            + self.delete
            + self.compact
            + self.checkpoint
            + self.append_event
            + self.sync_event_log
            + self.run_retention
            + self.read_record
            + self.read_block
    }

    pub const fn touches_eventlog(&self) -> bool {
        self.append_event > 0 || self.sync_event_log > 0 || self.run_retention > 0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ByteRange {
    min: ValueBytes,
    max: ValueBytes,
}

impl ByteRange {
    pub fn new(min: ValueBytes, max: ValueBytes) -> Result<Self, String> {
        if max.0 < min.0 {
            Err(format!("ByteRange: max {} < min {}", max.0, min.0))
        } else {
            Ok(Self { min, max })
        }
    }

    pub fn min(&self) -> ValueBytes {
        self.min
    }

    pub fn max(&self) -> ValueBytes {
        self.max
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SizeDistribution {
    Fixed(ValueBytes),
    Uniform(ByteRange),
    HeavyTail(ByteRange),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DidSpaceSize(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RetentionMaxSecs(pub u32);

#[derive(Debug, Clone)]
pub struct WorkloadModel {
    pub weights: OpWeights,
    pub size_distribution: SizeDistribution,
    pub collections: Vec<CollectionName>,
    pub key_space: KeySpaceSize,
    pub did_space: DidSpaceSize,
    pub retention_max_secs: RetentionMaxSecs,
}

impl Default for WorkloadModel {
    fn default() -> Self {
        Self {
            weights: OpWeights {
                add: 80,
                delete: 10,
                compact: 5,
                checkpoint: 5,
                append_event: 0,
                sync_event_log: 0,
                run_retention: 0,
                read_record: 0,
                read_block: 0,
            },
            size_distribution: SizeDistribution::Fixed(ValueBytes(64)),
            collections: vec![CollectionName("app.bsky.feed.post".to_string())],
            key_space: KeySpaceSize(200),
            did_space: DidSpaceSize(32),
            retention_max_secs: RetentionMaxSecs(3600),
        }
    }
}

impl WorkloadModel {
    pub fn generate(&self, seed: Seed, op_count: OpCount) -> OpStream {
        let mut rng = Lcg::new(seed);
        let total = self.weights.total();
        assert!(total > 0, "workload weights must sum to > 0");
        assert!(
            !self.collections.is_empty(),
            "workload needs at least 1 collection"
        );

        let ops: Vec<Op> = (0..op_count.0)
            .map(|_| {
                let bucket = rng.next_u32() % total;
                let coll = self.collections[rng.next_usize() % self.collections.len()].clone();
                let rkey = RecordKey(format!("{:06}", rng.next_u32() % self.key_space.0.max(1)));

                let w = &self.weights;
                let t1 = w.add;
                let t2 = t1 + w.delete;
                let t3 = t2 + w.compact;
                let t4 = t3 + w.checkpoint;
                let t5 = t4 + w.append_event;
                let t6 = t5 + w.sync_event_log;
                let t7 = t6 + w.run_retention;
                let t8 = t7 + w.read_record;

                match bucket {
                    b if b < t1 => Op::AddRecord {
                        collection: coll,
                        rkey,
                        value_seed: ValueSeed(rng.next_u32()),
                    },
                    b if b < t2 => Op::DeleteRecord {
                        collection: coll,
                        rkey,
                    },
                    b if b < t3 => Op::Compact,
                    b if b < t4 => Op::Checkpoint,
                    b if b < t5 => Op::AppendEvent {
                        did_seed: DidSeed(rng.next_u32() % self.did_space.0.max(1)),
                        event_kind: event_kind_for(rng.next_u32()),
                        payload_seed: PayloadSeed(rng.next_u32()),
                    },
                    b if b < t6 => Op::SyncEventLog,
                    b if b < t7 => Op::RunRetention {
                        max_age_secs: RetentionSecs(
                            rng.next_u32() % self.retention_max_secs.0.max(1),
                        ),
                    },
                    b if b < t8 => Op::ReadRecord {
                        collection: coll,
                        rkey,
                    },
                    _ => Op::ReadBlock {
                        value_seed: ValueSeed(rng.next_u32()),
                    },
                }
            })
            .collect();
        OpStream::from_vec(ops)
    }
}

fn event_kind_for(n: u32) -> EventKind {
    match n & 0b11 {
        0 => EventKind::Commit,
        1 => EventKind::Identity,
        2 => EventKind::Account,
        _ => EventKind::Sync,
    }
}

pub struct Lcg {
    state: u64,
}

impl Lcg {
    pub fn new(seed: Seed) -> Self {
        Self {
            state: seed
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407),
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.state
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 16) as u32
    }

    pub fn next_usize(&mut self) -> usize {
        self.next_u32() as usize
    }
}
