use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use super::encoding::KeyBuilder;
use super::keys::{KeyTag, UserHash};

const SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordValue {
    pub record_cid: Vec<u8>,
    pub takedown_ref: Option<String>,
}

impl RecordValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload = postcard::to_allocvec(self).expect("RecordValue serialization cannot fail");
        let mut buf = Vec::with_capacity(1 + payload.len());
        buf.push(SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let (&version, payload) = bytes.split_first()?;
        match version {
            SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

pub fn record_key(user_hash: UserHash, collection: &str, rkey: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::RECORDS)
        .u64(user_hash.raw())
        .string(collection)
        .string(rkey)
        .build()
}

pub fn record_collection_prefix(user_hash: UserHash, collection: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::RECORDS)
        .u64(user_hash.raw())
        .string(collection)
        .build()
}

pub fn record_user_prefix(user_hash: UserHash) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::RECORDS)
        .u64(user_hash.raw())
        .build()
}

pub fn records_prefix() -> SmallVec<[u8; 128]> {
    KeyBuilder::new().tag(KeyTag::RECORDS).build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metastore::encoding::KeyReader;

    #[test]
    fn record_value_roundtrip() {
        let value = RecordValue {
            record_cid: vec![0x01, 0x71, 0x12, 0x20, 0xAB],
            takedown_ref: None,
        };
        let bytes = value.serialize();
        let decoded = RecordValue::deserialize(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn record_value_with_takedown() {
        let value = RecordValue {
            record_cid: vec![0x01],
            takedown_ref: Some("DMCA-456".to_string()),
        };
        let bytes = value.serialize();
        let decoded = RecordValue::deserialize(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn schema_version_is_first_byte() {
        let value = RecordValue {
            record_cid: vec![0x01],
            takedown_ref: None,
        };
        let bytes = value.serialize();
        assert_eq!(bytes[0], SCHEMA_VERSION);
    }

    #[test]
    fn deserialize_rejects_unknown_schema_version() {
        let value = RecordValue {
            record_cid: vec![0x01],
            takedown_ref: None,
        };
        let mut bytes = value.serialize();
        bytes[0] = 99;
        assert!(RecordValue::deserialize(&bytes).is_none());
    }

    #[test]
    fn deserialize_rejects_empty_input() {
        assert!(RecordValue::deserialize(&[]).is_none());
    }

    #[test]
    fn record_key_roundtrip() {
        let hash = UserHash::from_raw(0xDEAD_BEEF_CAFE_BABE);
        let key = record_key(hash, "app.bsky.feed.post", "3k2abcd");
        let mut reader = KeyReader::new(&key);
        assert_eq!(reader.tag(), Some(KeyTag::RECORDS.raw()));
        assert_eq!(reader.u64(), Some(0xDEAD_BEEF_CAFE_BABE));
        assert_eq!(reader.string(), Some("app.bsky.feed.post".to_string()));
        assert_eq!(reader.string(), Some("3k2abcd".to_string()));
        assert!(reader.is_empty());
    }

    #[test]
    fn record_keys_sort_by_user_then_collection_then_rkey() {
        let h1 = UserHash::from_raw(1);
        let h2 = UserHash::from_raw(2);

        let k1 = record_key(h1, "app.bsky.feed.like", "aaa");
        let k2 = record_key(h1, "app.bsky.feed.post", "aaa");
        let k3 = record_key(h1, "app.bsky.feed.post", "bbb");
        let k4 = record_key(h2, "app.bsky.feed.like", "aaa");

        assert!(k1.as_slice() < k2.as_slice());
        assert!(k2.as_slice() < k3.as_slice());
        assert!(k3.as_slice() < k4.as_slice());
    }

    #[test]
    fn collection_prefix_is_prefix_of_full_key() {
        let hash = UserHash::from_raw(42);
        let prefix = record_collection_prefix(hash, "app.bsky.feed.post");
        let full = record_key(hash, "app.bsky.feed.post", "some_rkey");
        assert!(full.as_slice().starts_with(prefix.as_slice()));
    }

    #[test]
    fn user_prefix_is_prefix_of_collection_prefix() {
        let hash = UserHash::from_raw(42);
        let user_pfx = record_user_prefix(hash);
        let coll_pfx = record_collection_prefix(hash, "app.bsky.feed.post");
        assert!(coll_pfx.as_slice().starts_with(user_pfx.as_slice()));
    }

    #[test]
    fn records_prefix_is_just_tag() {
        let pfx = records_prefix();
        assert_eq!(pfx.as_slice(), &[KeyTag::RECORDS.raw()]);
    }
}
