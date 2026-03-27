use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use super::encoding::KeyBuilder;
use super::keys::{KeyTag, UserHash};

const BLOB_META_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobMetaValue {
    pub size_bytes: i64,
    pub mime_type: String,
    pub storage_key: String,
    pub takedown_ref: Option<String>,
    pub created_at_ms: i64,
}

impl BlobMetaValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload = postcard::to_allocvec(self).expect("BlobMetaValue serialization cannot fail");
        let mut buf = Vec::with_capacity(1 + payload.len());
        buf.push(BLOB_META_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let (&version, payload) = bytes.split_first()?;
        match version {
            BLOB_META_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

pub fn blob_meta_key(user_hash: UserHash, cid_str: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::BLOBS)
        .u64(user_hash.raw())
        .string(cid_str)
        .build()
}

pub fn blob_user_prefix(user_hash: UserHash) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::BLOBS)
        .u64(user_hash.raw())
        .build()
}

pub fn blobs_prefix() -> SmallVec<[u8; 128]> {
    KeyBuilder::new().tag(KeyTag::BLOBS).build()
}

pub fn blob_by_cid_key(cid_str: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::BLOB_BY_CID)
        .string(cid_str)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metastore::encoding::KeyReader;

    #[test]
    fn blob_meta_value_roundtrip() {
        let val = BlobMetaValue {
            size_bytes: 1024,
            mime_type: "image/png".to_owned(),
            storage_key: "blobs/abc/def".to_owned(),
            takedown_ref: None,
            created_at_ms: 1700000000000,
        };
        let bytes = val.serialize();
        let decoded = BlobMetaValue::deserialize(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn blob_meta_value_with_takedown_roundtrip() {
        let val = BlobMetaValue {
            size_bytes: 42,
            mime_type: "text/plain".to_owned(),
            storage_key: "k".to_owned(),
            takedown_ref: Some("mod-123".to_owned()),
            created_at_ms: 0,
        };
        let bytes = val.serialize();
        let decoded = BlobMetaValue::deserialize(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn blob_meta_key_roundtrip() {
        let uh = UserHash::from_did("did:plc:test");
        let key = blob_meta_key(uh, "bafyreiabc");
        let mut reader = KeyReader::new(&key);
        assert_eq!(reader.tag(), Some(KeyTag::BLOBS.raw()));
        assert_eq!(reader.u64(), Some(uh.raw()));
        assert_eq!(reader.string(), Some("bafyreiabc".to_owned()));
        assert!(reader.is_empty());
    }

    #[test]
    fn blob_user_prefix_is_prefix_of_key() {
        let uh = UserHash::from_did("did:plc:test");
        let prefix = blob_user_prefix(uh);
        let key = blob_meta_key(uh, "bafyreiabc");
        assert!(key.starts_with(prefix.as_slice()));
    }

    #[test]
    fn blob_by_cid_key_roundtrip() {
        let key = blob_by_cid_key("bafyreiabc");
        let mut reader = KeyReader::new(&key);
        assert_eq!(reader.tag(), Some(KeyTag::BLOB_BY_CID.raw()));
        assert_eq!(reader.string(), Some("bafyreiabc".to_owned()));
        assert!(reader.is_empty());
    }

    #[test]
    fn blob_meta_key_ordering_by_cid() {
        let uh = UserHash::from_did("did:plc:test");
        let key_a = blob_meta_key(uh, "aaa");
        let key_b = blob_meta_key(uh, "bbb");
        assert!(key_a.as_slice() < key_b.as_slice());
    }

    #[test]
    fn deserialize_unknown_version_returns_none() {
        let val = BlobMetaValue {
            size_bytes: 0,
            mime_type: String::new(),
            storage_key: String::new(),
            takedown_ref: None,
            created_at_ms: 0,
        };
        let mut bytes = val.serialize();
        bytes[0] = 99;
        assert!(BlobMetaValue::deserialize(&bytes).is_none());
    }
}
