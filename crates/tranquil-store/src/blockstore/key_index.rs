use std::collections::HashMap;
use std::path::Path;

use fjall::{
    Database, Keyspace, KeyspaceCreateOptions, PersistMode,
    config::{BloomConstructionPolicy, FilterPolicy, FilterPolicyEntry},
};

use super::data_file::CID_SIZE;
use super::types::{BlockLocation, IndexEntry, RefCount, WriteCursor};

const WRITE_CURSOR_KEY: &[u8] = b"\x00write_cursor";

const KEYSPACE_NAME: &str = "blocks";

fn bloom_options() -> KeyspaceCreateOptions {
    KeyspaceCreateOptions::default().filter_policy(FilterPolicy::new([
        FilterPolicyEntry::Bloom(BloomConstructionPolicy::FalsePositiveRate(0.01)),
        FilterPolicyEntry::Bloom(BloomConstructionPolicy::FalsePositiveRate(0.01)),
    ]))
}

fn is_corruption_error(e: &fjall::Error) -> bool {
    match e {
        fjall::Error::Io(io_err) => matches!(
            io_err.kind(),
            std::io::ErrorKind::InvalidData | std::io::ErrorKind::UnexpectedEof
        ),
        fjall::Error::Locked | fjall::Error::KeyspaceDeleted => false,
        _ => true,
    }
}

fn serialize_entry(entry: &IndexEntry) -> Vec<u8> {
    postcard::to_allocvec(entry)
        .expect("IndexEntry serialization is infallible for fixed-layout types")
}

fn deserialize_entry(bytes: &[u8]) -> Result<IndexEntry, KeyIndexError> {
    postcard::from_bytes(bytes).map_err(KeyIndexError::Deserialize)
}

fn serialize_cursor(cursor: &WriteCursor) -> Vec<u8> {
    postcard::to_allocvec(cursor)
        .expect("WriteCursor serialization is infallible for fixed-layout types")
}

fn deserialize_cursor(bytes: &[u8]) -> Result<WriteCursor, KeyIndexError> {
    postcard::from_bytes(bytes).map_err(KeyIndexError::Deserialize)
}

#[derive(Debug)]
pub enum KeyIndexError {
    Fjall(fjall::Error),
    Deserialize(postcard::Error),
    MissingEntry,
}

impl std::fmt::Display for KeyIndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fjall(e) => write!(f, "fjall: {e}"),
            Self::Deserialize(e) => write!(f, "deserialize: {e}"),
            Self::MissingEntry => write!(f, "entry not found"),
        }
    }
}

impl std::error::Error for KeyIndexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Fjall(e) => Some(e),
            Self::Deserialize(e) => Some(e),
            Self::MissingEntry => None,
        }
    }
}

impl From<fjall::Error> for KeyIndexError {
    fn from(e: fjall::Error) -> Self {
        Self::Fjall(e)
    }
}

pub enum KeyIndexOpenOutcome {
    Opened(KeyIndex),
    NeedsRebuild(KeyIndex),
}

impl KeyIndexOpenOutcome {
    pub fn into_inner(self) -> KeyIndex {
        match self {
            Self::Opened(idx) | Self::NeedsRebuild(idx) => idx,
        }
    }

    pub fn needs_rebuild(&self) -> bool {
        matches!(self, Self::NeedsRebuild(_))
    }
}

pub struct KeyIndex {
    db: Database,
    blocks: Keyspace,
}

impl KeyIndex {
    pub fn open(path: &Path) -> Result<KeyIndexOpenOutcome, KeyIndexError> {
        match Self::try_open(path) {
            Ok(idx) => Ok(KeyIndexOpenOutcome::Opened(idx)),
            Err(KeyIndexError::Fjall(ref e)) if is_corruption_error(e) => {
                let _ = std::fs::remove_dir_all(path);
                let idx = Self::try_open(path)?;
                Ok(KeyIndexOpenOutcome::NeedsRebuild(idx))
            }
            Err(e) => Err(e),
        }
    }

    fn try_open(path: &Path) -> Result<Self, KeyIndexError> {
        let db = Database::builder(path).open()?;
        let blocks = db.keyspace(KEYSPACE_NAME, bloom_options)?;
        Ok(Self { db, blocks })
    }

    pub fn get(&self, cid_bytes: &[u8; CID_SIZE]) -> Result<Option<IndexEntry>, KeyIndexError> {
        self.blocks
            .get(cid_bytes)?
            .map(|v| deserialize_entry(&v))
            .transpose()
    }

    pub fn has(&self, cid_bytes: &[u8; CID_SIZE]) -> Result<bool, KeyIndexError> {
        self.blocks.contains_key(cid_bytes).map_err(Into::into)
    }

    pub fn put(
        &self,
        cid_bytes: &[u8; CID_SIZE],
        location: BlockLocation,
    ) -> Result<(), KeyIndexError> {
        let entry = match self.get(cid_bytes)? {
            Some(existing) => IndexEntry {
                location: existing.location,
                refcount: existing.refcount.increment(),
            },
            None => IndexEntry {
                location,
                refcount: RefCount::one(),
            },
        };
        self.blocks
            .insert(cid_bytes, serialize_entry(&entry))
            .map_err(Into::into)
    }

    pub fn decrement_refcount(
        &self,
        cid_bytes: &[u8; CID_SIZE],
    ) -> Result<RefCount, KeyIndexError> {
        let existing = self.get(cid_bytes)?.ok_or(KeyIndexError::MissingEntry)?;
        let new_refcount = match existing.refcount.is_zero() {
            true => {
                tracing::warn!(?cid_bytes, "decrement on zero-refcount entry, skipping");
                existing.refcount
            }
            false => existing.refcount.decrement(),
        };
        let updated = IndexEntry {
            location: existing.location,
            refcount: new_refcount,
        };
        self.blocks.insert(cid_bytes, serialize_entry(&updated))?;
        Ok(new_refcount)
    }

    pub fn batch_put(
        &self,
        entries: &[([u8; CID_SIZE], BlockLocation)],
        decrements: &[[u8; CID_SIZE]],
        cursor: WriteCursor,
    ) -> Result<(), KeyIndexError> {
        let mut batch = self.db.batch().durability(Some(PersistMode::SyncData));
        let mut pending: HashMap<[u8; CID_SIZE], IndexEntry> = HashMap::new();

        entries.iter().try_for_each(|(cid_bytes, location)| {
            let entry = match pending.get(cid_bytes).copied().or(self.get(cid_bytes)?) {
                Some(existing) => IndexEntry {
                    location: existing.location,
                    refcount: existing.refcount.increment(),
                },
                None => IndexEntry {
                    location: *location,
                    refcount: RefCount::one(),
                },
            };
            pending.insert(*cid_bytes, entry);
            batch.insert(&self.blocks, cid_bytes.as_slice(), serialize_entry(&entry));
            Ok::<_, KeyIndexError>(())
        })?;

        decrements.iter().try_for_each(|cid_bytes| {
            let existing = pending
                .get(cid_bytes)
                .copied()
                .or(self.get(cid_bytes)?)
                .ok_or(KeyIndexError::MissingEntry)?;
            let new_refcount = match existing.refcount.is_zero() {
                true => {
                    tracing::warn!(?cid_bytes, "decrement on zero-refcount entry, skipping");
                    existing.refcount
                }
                false => existing.refcount.decrement(),
            };
            let updated = IndexEntry {
                location: existing.location,
                refcount: new_refcount,
            };
            pending.insert(*cid_bytes, updated);
            batch.insert(
                &self.blocks,
                cid_bytes.as_slice(),
                serialize_entry(&updated),
            );
            Ok::<_, KeyIndexError>(())
        })?;

        batch.insert(&self.blocks, WRITE_CURSOR_KEY, serialize_cursor(&cursor));

        batch.commit().map_err(Into::into)
    }

    pub fn read_write_cursor(&self) -> Result<Option<WriteCursor>, KeyIndexError> {
        self.blocks
            .get(WRITE_CURSOR_KEY)?
            .map(|v| deserialize_cursor(&v))
            .transpose()
    }

    pub fn persist(&self) -> Result<(), KeyIndexError> {
        self.db.persist(PersistMode::SyncData).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockstore::test_cid;
    use crate::blockstore::types::{BlockLength, BlockOffset, DataFileId};

    fn test_location(file_id: u32, offset: u64, length: u32) -> BlockLocation {
        BlockLocation {
            file_id: DataFileId::new(file_id),
            offset: BlockOffset::new(offset),
            length: BlockLength::new(length),
        }
    }

    fn open_temp() -> (tempfile::TempDir, KeyIndex) {
        let dir = tempfile::TempDir::new().unwrap();
        let outcome = KeyIndex::open(dir.path()).unwrap();
        assert!(!outcome.needs_rebuild());
        (dir, outcome.into_inner())
    }

    #[test]
    fn put_then_get_round_trips() {
        let (_dir, idx) = open_temp();
        let cid = test_cid(1);
        let loc = test_location(0, 100, 256);

        idx.put(&cid, loc).unwrap();
        let entry = idx.get(&cid).unwrap().unwrap();
        assert_eq!(entry.location, loc);
        assert_eq!(entry.refcount, RefCount::one());
    }

    #[test]
    fn get_missing_returns_none() {
        let (_dir, idx) = open_temp();
        assert!(idx.get(&test_cid(42)).unwrap().is_none());
    }

    #[test]
    fn has_missing_returns_false() {
        let (_dir, idx) = open_temp();
        assert!(!idx.has(&test_cid(42)).unwrap());
    }

    #[test]
    fn has_existing_returns_true() {
        let (_dir, idx) = open_temp();
        let cid = test_cid(1);
        idx.put(&cid, test_location(0, 0, 10)).unwrap();
        assert!(idx.has(&cid).unwrap());
    }

    #[test]
    fn duplicate_put_increments_refcount() {
        let (_dir, idx) = open_temp();
        let cid = test_cid(1);
        let loc = test_location(0, 100, 256);

        idx.put(&cid, loc).unwrap();
        idx.put(&cid, test_location(1, 200, 512)).unwrap();

        let entry = idx.get(&cid).unwrap().unwrap();
        assert_eq!(entry.refcount, RefCount::new(2));
        assert_eq!(entry.location, loc);
    }

    #[test]
    fn decrement_refcount_from_two_to_one() {
        let (_dir, idx) = open_temp();
        let cid = test_cid(1);
        idx.put(&cid, test_location(0, 0, 10)).unwrap();
        idx.put(&cid, test_location(0, 0, 10)).unwrap();

        let rc = idx.decrement_refcount(&cid).unwrap();
        assert_eq!(rc, RefCount::one());

        let entry = idx.get(&cid).unwrap().unwrap();
        assert_eq!(entry.refcount, RefCount::one());
    }

    #[test]
    fn decrement_refcount_to_zero_keeps_entry() {
        let (_dir, idx) = open_temp();
        let cid = test_cid(1);
        idx.put(&cid, test_location(0, 0, 10)).unwrap();

        let rc = idx.decrement_refcount(&cid).unwrap();
        assert!(rc.is_zero());

        let entry = idx.get(&cid).unwrap().unwrap();
        assert!(entry.refcount.is_zero());
    }

    #[test]
    fn decrement_missing_entry_errors() {
        let (_dir, idx) = open_temp();
        let result = idx.decrement_refcount(&test_cid(99));
        assert!(matches!(result, Err(KeyIndexError::MissingEntry)));
    }

    #[test]
    fn batch_put_new_entries() {
        let (_dir, idx) = open_temp();
        let entries: Vec<_> = (0u8..3)
            .map(|i| (test_cid(i), test_location(0, i as u64 * 100, 50)))
            .collect();
        let cursor = WriteCursor {
            file_id: DataFileId::new(0),
            offset: BlockOffset::new(300),
        };

        idx.batch_put(&entries, &[], cursor).unwrap();

        entries.iter().for_each(|(cid, loc)| {
            let entry = idx.get(cid).unwrap().unwrap();
            assert_eq!(entry.location, *loc);
            assert_eq!(entry.refcount, RefCount::one());
        });
    }

    #[test]
    fn batch_put_increments_existing() {
        let (_dir, idx) = open_temp();
        let cid = test_cid(1);
        let original_loc = test_location(0, 100, 50);
        idx.put(&cid, original_loc).unwrap();

        let entries = vec![(cid, test_location(1, 200, 60))];
        let cursor = WriteCursor {
            file_id: DataFileId::new(1),
            offset: BlockOffset::new(260),
        };
        idx.batch_put(&entries, &[], cursor).unwrap();

        let entry = idx.get(&cid).unwrap().unwrap();
        assert_eq!(entry.refcount, RefCount::new(2));
        assert_eq!(entry.location, original_loc);
    }

    #[test]
    fn batch_put_with_decrements() {
        let (_dir, idx) = open_temp();
        let cid_a = test_cid(1);
        let cid_b = test_cid(2);
        idx.put(&cid_b, test_location(0, 0, 10)).unwrap();
        idx.put(&cid_b, test_location(0, 0, 10)).unwrap();

        let entries = vec![(cid_a, test_location(0, 100, 50))];
        let decrements = vec![cid_b];
        let cursor = WriteCursor {
            file_id: DataFileId::new(0),
            offset: BlockOffset::new(150),
        };
        idx.batch_put(&entries, &decrements, cursor).unwrap();

        let a = idx.get(&cid_a).unwrap().unwrap();
        assert_eq!(a.refcount, RefCount::one());

        let b = idx.get(&cid_b).unwrap().unwrap();
        assert_eq!(b.refcount, RefCount::one());
    }

    #[test]
    fn batch_put_mixed_new_and_duplicate() {
        let (_dir, idx) = open_temp();
        let existing_cid = test_cid(1);
        let existing_loc = test_location(0, 0, 10);
        idx.put(&existing_cid, existing_loc).unwrap();

        let entries: Vec<_> = (1u8..=4)
            .map(|i| (test_cid(i), test_location(0, i as u64 * 100, 50)))
            .collect();
        let cursor = WriteCursor {
            file_id: DataFileId::new(0),
            offset: BlockOffset::new(500),
        };
        idx.batch_put(&entries, &[], cursor).unwrap();

        let existing = idx.get(&existing_cid).unwrap().unwrap();
        assert_eq!(existing.refcount, RefCount::new(2));
        assert_eq!(existing.location, existing_loc);

        (2u8..=4).for_each(|i| {
            let entry = idx.get(&test_cid(i)).unwrap().unwrap();
            assert_eq!(entry.refcount, RefCount::one());
        });
    }

    #[test]
    fn batch_put_duplicate_cid_in_same_batch() {
        let (_dir, idx) = open_temp();
        let cid = test_cid(1);
        let loc = test_location(0, 100, 50);

        let entries = vec![(cid, loc), (cid, test_location(0, 200, 60))];
        let cursor = WriteCursor {
            file_id: DataFileId::new(0),
            offset: BlockOffset::new(260),
        };
        idx.batch_put(&entries, &[], cursor).unwrap();

        let entry = idx.get(&cid).unwrap().unwrap();
        assert_eq!(entry.refcount, RefCount::new(2));
        assert_eq!(entry.location, loc);
    }

    #[test]
    fn batch_put_entry_then_decrement_same_cid() {
        let (_dir, idx) = open_temp();
        let cid = test_cid(1);
        let loc = test_location(0, 100, 50);

        let entries = vec![(cid, loc)];
        let decrements = vec![cid];
        let cursor = WriteCursor {
            file_id: DataFileId::new(0),
            offset: BlockOffset::new(150),
        };
        idx.batch_put(&entries, &decrements, cursor).unwrap();

        let entry = idx.get(&cid).unwrap().unwrap();
        assert!(entry.refcount.is_zero());
    }

    #[test]
    fn write_cursor_round_trip() {
        let (_dir, idx) = open_temp();
        assert!(idx.read_write_cursor().unwrap().is_none());

        let cursor = WriteCursor {
            file_id: DataFileId::new(3),
            offset: BlockOffset::new(65536),
        };
        let entries = vec![(test_cid(1), test_location(3, 0, 100))];
        idx.batch_put(&entries, &[], cursor).unwrap();

        let read_back = idx.read_write_cursor().unwrap().unwrap();
        assert_eq!(read_back, cursor);
    }

    #[test]
    fn write_cursor_persists_across_reopen() {
        let dir = tempfile::TempDir::new().unwrap();

        let cursor = WriteCursor {
            file_id: DataFileId::new(7),
            offset: BlockOffset::new(99999),
        };

        {
            let idx = KeyIndex::open(dir.path()).unwrap().into_inner();
            let entries = vec![(test_cid(1), test_location(7, 0, 100))];
            idx.batch_put(&entries, &[], cursor).unwrap();
            idx.persist().unwrap();
        }

        {
            let idx = KeyIndex::open(dir.path()).unwrap().into_inner();
            let read_back = idx.read_write_cursor().unwrap().unwrap();
            assert_eq!(read_back, cursor);

            let entry = idx.get(&test_cid(1)).unwrap().unwrap();
            assert_eq!(entry.refcount, RefCount::one());
        }
    }

    #[test]
    fn corrupt_index_triggers_needs_rebuild() {
        let dir = tempfile::TempDir::new().unwrap();

        {
            let idx = KeyIndex::open(dir.path()).unwrap().into_inner();
            idx.put(&test_cid(1), test_location(0, 0, 10)).unwrap();
            idx.persist().unwrap();
        }

        std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .for_each(|entry| {
                let path = entry.path();
                if path.is_file() {
                    std::fs::write(&path, b"corrupted").unwrap();
                }
            });

        let outcome = KeyIndex::open(dir.path()).unwrap();
        assert!(outcome.needs_rebuild());

        let idx = outcome.into_inner();
        assert!(idx.get(&test_cid(1)).unwrap().is_none());
        assert!(idx.read_write_cursor().unwrap().is_none());
    }
}
