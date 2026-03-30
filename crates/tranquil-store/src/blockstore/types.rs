use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use super::data_file::CID_SIZE;

pub type CidBytes = [u8; CID_SIZE];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct CommitEpoch(u64);

impl CommitEpoch {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn zero() -> Self {
        Self(0)
    }

    pub fn raw(self) -> u64 {
        self.0
    }

    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

#[derive(Debug, Clone)]
pub struct EpochCounter(Arc<AtomicU64>);

impl Default for EpochCounter {
    fn default() -> Self {
        Self(Arc::new(AtomicU64::new(0)))
    }
}

impl EpochCounter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_raw(value: u64) -> Self {
        Self(Arc::new(AtomicU64::new(value)))
    }

    pub fn current(&self) -> CommitEpoch {
        CommitEpoch(self.0.load(Ordering::Acquire))
    }

    pub fn advance(&self) -> CommitEpoch {
        let prev = self
            .0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                Some(v.saturating_add(1))
            })
            .unwrap_or(u64::MAX);
        CommitEpoch(prev.saturating_add(1))
    }
}

pub struct CollectionResult {
    pub candidates: HashMap<DataFileId, Vec<CidBytes>>,
    pub total_bytes: u64,
}

pub struct CompactionResult {
    pub file_id: DataFileId,
    pub old_size: u64,
    pub new_size: u64,
    pub live_blocks: u64,
    pub dead_blocks: u64,
    pub reclaimed_bytes: u64,
}

pub struct LivenessInfo {
    pub live_bytes: u64,
    pub total_bytes: u64,
    pub live_blocks: u64,
    pub total_blocks: u64,
}

impl LivenessInfo {
    pub fn ratio(&self) -> f64 {
        match self.total_bytes {
            0 => 1.0,
            total => self.live_bytes as f64 / total as f64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct DataFileId(u32);

impl DataFileId {
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    pub fn raw(self) -> u32 {
        self.0
    }

    pub fn next(self) -> Self {
        Self(self.0.checked_add(1).expect("DataFileId overflow"))
    }
}

impl std::fmt::Display for DataFileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:06}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct BlockOffset(u64);

impl BlockOffset {
    pub const fn new(offset: u64) -> Self {
        Self(offset)
    }

    pub fn raw(self) -> u64 {
        self.0
    }

    pub fn advance(self, delta: u64) -> Self {
        Self(self.0.checked_add(delta).expect("BlockOffset overflow"))
    }
}

pub const MAX_BLOCK_SIZE: u32 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct BlockLength(u32);

impl BlockLength {
    pub fn new(length: u32) -> Self {
        assert!(
            length <= MAX_BLOCK_SIZE,
            "BlockLength {length} exceeds MAX_BLOCK_SIZE {MAX_BLOCK_SIZE}"
        );
        Self(length)
    }

    pub const fn from_raw(length: u32) -> Self {
        Self(length)
    }

    pub fn raw(self) -> u32 {
        self.0
    }

    pub fn as_u64(self) -> u64 {
        u64::from(self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct RefCount(u32);

impl RefCount {
    pub const fn new(count: u32) -> Self {
        Self(count)
    }

    pub fn raw(self) -> u32 {
        self.0
    }

    pub const fn one() -> Self {
        Self(1)
    }

    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    pub fn increment(self) -> Self {
        Self(self.0.checked_add(1).expect("RefCount overflow"))
    }

    pub fn saturating_increment(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    pub fn decrement(self) -> Self {
        Self(self.0.saturating_sub(1))
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockLocation {
    pub file_id: DataFileId,
    pub offset: BlockOffset,
    pub length: BlockLength,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IndexEntry {
    pub location: BlockLocation,
    pub refcount: RefCount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WriteCursor {
    pub file_id: DataFileId,
    pub offset: BlockOffset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct HintOffset(u64);

impl HintOffset {
    pub fn new(offset: u64) -> Self {
        Self(offset)
    }

    pub fn raw(self) -> u64 {
        self.0
    }

    pub fn advance(self, delta: u64) -> Self {
        Self(self.0.checked_add(delta).expect("HintOffset overflow"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct WallClockMs(u64);

impl WallClockMs {
    pub const fn new(ms: u64) -> Self {
        Self(ms)
    }

    pub fn now() -> Self {
        let millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        Self(u64::try_from(millis).unwrap_or(u64::MAX))
    }

    pub fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ShardId(u8);

impl ShardId {
    pub const fn new(id: u8) -> Self {
        Self(id)
    }

    pub fn raw(self) -> u8 {
        self.0
    }

    pub fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl std::fmt::Display for ShardId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "shard_{}", self.0)
    }
}

pub struct BlockstoreSnapshot {
    pub shard_cursors: Vec<WriteCursor>,
    pub epoch: CommitEpoch,
    pub data_files: Vec<DataFileId>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_epoch_advances() {
        let e = CommitEpoch::zero();
        assert_eq!(e.raw(), 0);
        assert_eq!(e.next().raw(), 1);
    }

    #[test]
    fn commit_epoch_saturates() {
        let e = CommitEpoch::new(u64::MAX);
        assert_eq!(e.next().raw(), u64::MAX);
    }

    #[test]
    fn epoch_counter_advance_returns_new_value() {
        let counter = EpochCounter::new();
        assert_eq!(counter.current().raw(), 0);
        let epoch1 = counter.advance();
        assert_eq!(epoch1.raw(), 1);
        assert_eq!(counter.current().raw(), 1);
        let epoch2 = counter.advance();
        assert_eq!(epoch2.raw(), 2);
    }

    #[test]
    fn index_entry_postcard_round_trip() {
        let entry = IndexEntry {
            location: BlockLocation {
                file_id: DataFileId::new(42),
                offset: BlockOffset::new(1024),
                length: BlockLength::new(256),
            },
            refcount: RefCount::one(),
        };

        let bytes = postcard::to_allocvec(&entry).unwrap();
        let decoded: IndexEntry = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(entry, decoded);
    }

    #[test]
    fn write_cursor_postcard_round_trip() {
        let cursor = WriteCursor {
            file_id: DataFileId::new(7),
            offset: BlockOffset::new(65536),
        };

        let bytes = postcard::to_allocvec(&cursor).unwrap();
        let decoded: WriteCursor = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(cursor, decoded);
    }

    #[test]
    fn data_file_id_display_zero_padded() {
        assert_eq!(DataFileId::new(0).to_string(), "000000");
        assert_eq!(DataFileId::new(42).to_string(), "000042");
        assert_eq!(DataFileId::new(999999).to_string(), "999999");
    }

    #[test]
    fn data_file_id_next_increments() {
        assert_eq!(DataFileId::new(0).next(), DataFileId::new(1));
        assert_eq!(DataFileId::new(99).next(), DataFileId::new(100));
    }

    #[test]
    #[should_panic(expected = "DataFileId overflow")]
    fn data_file_id_overflow_panics() {
        DataFileId::new(u32::MAX).next();
    }

    #[test]
    fn block_offset_advance() {
        let offset = BlockOffset::new(100);
        assert_eq!(offset.advance(50), BlockOffset::new(150));
    }

    #[test]
    fn refcount_lifecycle() {
        let rc = RefCount::one();
        assert!(!rc.is_zero());
        assert_eq!(rc.raw(), 1);

        let rc2 = rc.increment();
        assert_eq!(rc2.raw(), 2);

        let rc3 = rc2.decrement().decrement();
        assert!(rc3.is_zero());
    }

    #[test]
    fn refcount_underflow_saturates_at_zero() {
        assert!(RefCount::new(0).decrement().is_zero());
    }
}
