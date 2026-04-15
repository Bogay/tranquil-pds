#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Seed(pub u64);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CollectionName(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecordKey(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ValueSeed(pub u32);

#[derive(Debug, Clone)]
pub enum Op {
    AddRecord {
        collection: CollectionName,
        rkey: RecordKey,
        value_seed: ValueSeed,
    },
    DeleteRecord {
        collection: CollectionName,
        rkey: RecordKey,
    },
    Compact,
    Checkpoint,
}

#[derive(Debug, Clone)]
pub struct OpStream {
    ops: Vec<Op>,
}

impl OpStream {
    pub fn from_vec(ops: Vec<Op>) -> Self {
        Self { ops }
    }

    pub fn into_vec(self) -> Vec<Op> {
        self.ops
    }

    pub fn iter(&self) -> impl Iterator<Item = &Op> {
        self.ops.iter()
    }

    pub fn len(&self) -> usize {
        self.ops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    pub fn shrink(&self) -> Option<OpStream> {
        (self.ops.len() >= 2).then(|| {
            let half = self.ops.len() / 2;
            OpStream::from_vec(self.ops[..half].to_vec())
        })
    }
}
