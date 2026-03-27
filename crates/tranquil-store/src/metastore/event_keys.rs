use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use super::encoding::KeyBuilder;
use super::keys::{KeyTag, UserHash};

const SEQ_META_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeqMetaValue {
    pub blocks_cids: Vec<String>,
}

impl SeqMetaValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload = postcard::to_allocvec(self).expect("SeqMetaValue serialization cannot fail");
        let mut buf = Vec::with_capacity(1 + payload.len());
        buf.push(SEQ_META_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let (&version, payload) = bytes.split_first()?;
        match version {
            SEQ_META_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

pub fn rev_to_seq_key(user_hash: UserHash, rev: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::REV_TO_SEQ)
        .u64(user_hash.raw())
        .string(rev)
        .build()
}

pub fn rev_to_seq_user_prefix(user_hash: UserHash) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::REV_TO_SEQ)
        .u64(user_hash.raw())
        .build()
}

pub fn seq_meta_key(seq: u64) -> SmallVec<[u8; 128]> {
    KeyBuilder::new().tag(KeyTag::SEQ_META).u64(seq).build()
}

pub fn seq_tombstone_key(seq: u64) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::SEQ_TOMBSTONE)
        .u64(seq)
        .build()
}

pub fn did_events_key(user_hash: UserHash, seq: u64) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::DID_EVENTS)
        .u64(user_hash.raw())
        .u64(seq)
        .build()
}

pub fn did_events_prefix(user_hash: UserHash) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::DID_EVENTS)
        .u64(user_hash.raw())
        .build()
}

pub fn metastore_cursor_key() -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::METASTORE_CURSOR)
        .raw(&[0x00])
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metastore::encoding::KeyReader;

    #[test]
    fn seq_meta_value_roundtrip() {
        let value = SeqMetaValue {
            blocks_cids: vec!["bafyreiblock1".to_owned(), "bafyreiblock2".to_owned()],
        };
        let bytes = value.serialize();
        let decoded = SeqMetaValue::deserialize(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn seq_meta_value_empty_blocks() {
        let value = SeqMetaValue {
            blocks_cids: vec![],
        };
        let bytes = value.serialize();
        let decoded = SeqMetaValue::deserialize(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn seq_meta_schema_version_first_byte() {
        let value = SeqMetaValue {
            blocks_cids: vec![],
        };
        let bytes = value.serialize();
        assert_eq!(bytes[0], SEQ_META_SCHEMA_VERSION);
    }

    #[test]
    fn seq_meta_rejects_unknown_version() {
        let value = SeqMetaValue {
            blocks_cids: vec![],
        };
        let mut bytes = value.serialize();
        bytes[0] = 99;
        assert!(SeqMetaValue::deserialize(&bytes).is_none());
    }

    #[test]
    fn seq_meta_rejects_empty_input() {
        assert!(SeqMetaValue::deserialize(&[]).is_none());
    }

    #[test]
    fn rev_to_seq_key_roundtrip() {
        let hash = UserHash::from_raw(0xDEAD_BEEF_CAFE_BABE);
        let key = rev_to_seq_key(hash, "3k2abcde");
        let mut reader = KeyReader::new(&key);
        assert_eq!(reader.tag(), Some(KeyTag::REV_TO_SEQ.raw()));
        assert_eq!(reader.u64(), Some(0xDEAD_BEEF_CAFE_BABE));
        assert_eq!(reader.string(), Some("3k2abcde".to_owned()));
        assert!(reader.is_empty());
    }

    #[test]
    fn rev_to_seq_keys_sort_by_user_then_rev() {
        let h1 = UserHash::from_raw(1);
        let h2 = UserHash::from_raw(2);
        let k1 = rev_to_seq_key(h1, "abc");
        let k2 = rev_to_seq_key(h1, "def");
        let k3 = rev_to_seq_key(h2, "abc");
        assert!(k1.as_slice() < k2.as_slice());
        assert!(k2.as_slice() < k3.as_slice());
    }

    #[test]
    fn rev_to_seq_user_prefix_is_prefix_of_full_key() {
        let hash = UserHash::from_raw(42);
        let prefix = rev_to_seq_user_prefix(hash);
        let full = rev_to_seq_key(hash, "some_rev");
        assert!(full.as_slice().starts_with(prefix.as_slice()));
    }

    #[test]
    fn seq_meta_key_roundtrip() {
        let key = seq_meta_key(12345);
        let mut reader = KeyReader::new(&key);
        assert_eq!(reader.tag(), Some(KeyTag::SEQ_META.raw()));
        assert_eq!(reader.u64(), Some(12345));
        assert!(reader.is_empty());
    }

    #[test]
    fn seq_meta_keys_sort_by_seq() {
        let k1 = seq_meta_key(1);
        let k2 = seq_meta_key(2);
        let k3 = seq_meta_key(100);
        assert!(k1.as_slice() < k2.as_slice());
        assert!(k2.as_slice() < k3.as_slice());
    }

    #[test]
    fn seq_tombstone_key_roundtrip() {
        let key = seq_tombstone_key(999);
        let mut reader = KeyReader::new(&key);
        assert_eq!(reader.tag(), Some(KeyTag::SEQ_TOMBSTONE.raw()));
        assert_eq!(reader.u64(), Some(999));
        assert!(reader.is_empty());
    }

    #[test]
    fn did_events_key_roundtrip() {
        let hash = UserHash::from_raw(0xCAFE_BABE_DEAD_BEEF);
        let key = did_events_key(hash, 42);
        let mut reader = KeyReader::new(&key);
        assert_eq!(reader.tag(), Some(KeyTag::DID_EVENTS.raw()));
        assert_eq!(reader.u64(), Some(0xCAFE_BABE_DEAD_BEEF));
        assert_eq!(reader.u64(), Some(42));
        assert!(reader.is_empty());
    }

    #[test]
    fn did_events_keys_sort_by_user_then_seq() {
        let h1 = UserHash::from_raw(1);
        let h2 = UserHash::from_raw(2);
        let k1 = did_events_key(h1, 10);
        let k2 = did_events_key(h1, 20);
        let k3 = did_events_key(h2, 5);
        assert!(k1.as_slice() < k2.as_slice());
        assert!(k2.as_slice() < k3.as_slice());
    }

    #[test]
    fn did_events_prefix_is_prefix_of_full_key() {
        let hash = UserHash::from_raw(99);
        let prefix = did_events_prefix(hash);
        let full = did_events_key(hash, 1);
        assert!(full.as_slice().starts_with(prefix.as_slice()));
    }

    #[test]
    fn metastore_cursor_key_roundtrip() {
        let key = metastore_cursor_key();
        let mut reader = KeyReader::new(&key);
        assert_eq!(reader.tag(), Some(KeyTag::METASTORE_CURSOR.raw()));
        assert_eq!(reader.remaining(), &[0x00]);
    }

    #[test]
    fn metastore_cursor_key_is_stable() {
        let k1 = metastore_cursor_key();
        let k2 = metastore_cursor_key();
        assert_eq!(k1.as_slice(), k2.as_slice());
    }
}
