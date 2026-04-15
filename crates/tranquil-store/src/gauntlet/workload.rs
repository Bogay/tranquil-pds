use super::op::{CollectionName, Op, OpStream, RecordKey, Seed, ValueSeed};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ValueBytes(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeySpaceSize(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpCount(pub usize);

#[derive(Debug, Clone, Copy)]
pub struct OpWeights {
    pub add: u32,
    pub delete: u32,
    pub compact: u32,
    pub checkpoint: u32,
}

impl OpWeights {
    pub const fn total(&self) -> u32 {
        self.add + self.delete + self.compact + self.checkpoint
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
}

#[derive(Debug, Clone)]
pub struct WorkloadModel {
    pub weights: OpWeights,
    pub size_distribution: SizeDistribution,
    pub collections: Vec<CollectionName>,
    pub key_space: KeySpaceSize,
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

                let (a, d, c) = (
                    self.weights.add,
                    self.weights.add + self.weights.delete,
                    self.weights.add + self.weights.delete + self.weights.compact,
                );
                match bucket {
                    b if b < a => Op::AddRecord {
                        collection: coll,
                        rkey,
                        value_seed: ValueSeed(rng.next_u32()),
                    },
                    b if b < d => Op::DeleteRecord {
                        collection: coll,
                        rkey,
                    },
                    b if b < c => Op::Compact,
                    _ => Op::Checkpoint,
                }
            })
            .collect();
        OpStream::from_vec(ops)
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
