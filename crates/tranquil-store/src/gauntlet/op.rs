use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Seed(pub u64);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CollectionName(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RecordKey(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValueSeed(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DidSeed(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PayloadSeed(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RetentionSecs(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventKind {
    Commit,
    Identity,
    Account,
    Sync,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    AppendEvent {
        did_seed: DidSeed,
        event_kind: EventKind,
        payload_seed: PayloadSeed,
    },
    SyncEventLog,
    RunRetention {
        max_age_secs: RetentionSecs,
    },
    ReadRecord {
        collection: CollectionName,
        rkey: RecordKey,
    },
    ReadBlock {
        value_seed: ValueSeed,
    },
}

impl Op {
    pub const fn is_read_only(&self) -> bool {
        matches!(self, Op::ReadRecord { .. } | Op::ReadBlock { .. })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OpStream {
    ops: Vec<Op>,
}

impl OpStream {
    pub fn from_vec(ops: Vec<Op>) -> Self {
        Self { ops }
    }

    pub fn empty() -> Self {
        Self { ops: Vec::new() }
    }

    pub fn as_slice(&self) -> &[Op] {
        &self.ops
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

    pub fn shrink_candidates(&self) -> impl Iterator<Item = OpStream> + '_ {
        let len = self.ops.len();
        let chunk_sizes: Vec<usize> = std::iter::successors((len >= 2).then_some(len / 2), |&s| {
            (s >= 2).then_some(s / 2)
        })
        .collect();

        let chunk_candidates = chunk_sizes.into_iter().flat_map(move |chunk_size| {
            let count = len.div_ceil(chunk_size);
            (0..count).map(move |i| {
                let start = i * chunk_size;
                let end = (start + chunk_size).min(len);
                let mut reduced = Vec::with_capacity(len - (end - start));
                reduced.extend_from_slice(&self.ops[..start]);
                reduced.extend_from_slice(&self.ops[end..]);
                OpStream::from_vec(reduced)
            })
        });

        let single_candidates = (0..len).map(move |i| {
            let mut reduced = self.ops.clone();
            reduced.remove(i);
            OpStream::from_vec(reduced)
        });

        chunk_candidates.chain(single_candidates)
    }

    pub fn shrink_to_fixpoint(mut self, mut fails: impl FnMut(&OpStream) -> bool) -> OpStream {
        loop {
            let next = self.shrink_candidates().find(|c| !c.is_empty() && fails(c));
            match next {
                Some(smaller) => self = smaller,
                None => return self,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(n: usize) -> OpStream {
        OpStream::from_vec(
            (0..n)
                .map(|i| Op::AddRecord {
                    collection: CollectionName("c".into()),
                    rkey: RecordKey(format!("{i:04}")),
                    value_seed: ValueSeed(i as u32),
                })
                .collect(),
        )
    }

    fn contains_index(s: &OpStream, target: u32) -> bool {
        s.iter()
            .any(|op| matches!(op, Op::AddRecord { value_seed, .. } if value_seed.0 == target))
    }

    #[test]
    fn shrink_candidates_nonempty_for_len_ge_2() {
        let s = stream(8);
        let count = s.shrink_candidates().count();
        assert!(count > 0);
    }

    #[test]
    fn shrink_candidates_empty_for_len_0() {
        let s = OpStream::from_vec(Vec::new());
        assert_eq!(s.shrink_candidates().count(), 0);
    }

    #[test]
    fn shrink_candidates_includes_every_single_removal() {
        let s = stream(5);
        let singles: Vec<_> = s.shrink_candidates().filter(|c| c.len() == 4).collect();
        assert!(
            singles.len() >= 5,
            "expected at least 5 size-4 candidates, got {}",
            singles.len()
        );
    }

    #[test]
    fn shrink_to_fixpoint_converges_to_culprit() {
        let s = stream(64);
        let shrunk = s.shrink_to_fixpoint(|c| contains_index(c, 17));
        assert!(contains_index(&shrunk, 17));
        assert!(
            shrunk.len() < 4,
            "expected shrink to close on culprit, got {} ops",
            shrunk.len()
        );
    }
}
