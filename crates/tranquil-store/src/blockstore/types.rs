use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DataFileId(u32);

impl DataFileId {
    pub fn new(id: u32) -> Self {
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
pub struct BlockOffset(u64);

impl BlockOffset {
    pub fn new(offset: u64) -> Self {
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
pub struct BlockLength(u32);

impl BlockLength {
    pub fn new(length: u32) -> Self {
        assert!(
            length <= MAX_BLOCK_SIZE,
            "BlockLength {length} exceeds MAX_BLOCK_SIZE {MAX_BLOCK_SIZE}"
        );
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
pub struct RefCount(u32);

impl RefCount {
    pub fn new(count: u32) -> Self {
        Self(count)
    }

    pub fn raw(self) -> u32 {
        self.0
    }

    pub fn one() -> Self {
        Self(1)
    }

    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    pub fn increment(self) -> Self {
        Self(self.0.checked_add(1).expect("RefCount overflow"))
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

#[cfg(test)]
mod tests {
    use super::*;

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
