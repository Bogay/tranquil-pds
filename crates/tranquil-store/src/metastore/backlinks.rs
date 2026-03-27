use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use super::encoding::KeyBuilder;
use super::keys::{KeyTag, UserHash};

use tranquil_db_traits::BacklinkPath;

const SCHEMA_VERSION: u8 = 1;

pub fn path_to_discriminant(path: BacklinkPath) -> u8 {
    match path {
        BacklinkPath::Subject => 0,
        BacklinkPath::SubjectUri => 1,
    }
}

pub fn discriminant_to_path(d: u8) -> Option<BacklinkPath> {
    match d {
        0 => Some(BacklinkPath::Subject),
        1 => Some(BacklinkPath::SubjectUri),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BacklinkValue {
    pub source_uri: String,
    pub path: u8,
}

impl BacklinkValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload = postcard::to_allocvec(self).expect("BacklinkValue serialization cannot fail");
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

pub fn backlink_key(
    link_target: &str,
    user_hash: UserHash,
    collection: &str,
    rkey: &str,
) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::BACKLINKS)
        .string(link_target)
        .u64(user_hash.raw())
        .string(collection)
        .string(rkey)
        .build()
}

pub fn backlink_target_prefix(link_target: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::BACKLINKS)
        .string(link_target)
        .build()
}

pub fn backlink_target_user_prefix(link_target: &str, user_hash: UserHash) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::BACKLINKS)
        .string(link_target)
        .u64(user_hash.raw())
        .build()
}

pub fn backlink_by_user_key(
    user_hash: UserHash,
    collection: &str,
    rkey: &str,
    link_target: &str,
) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::BACKLINK_BY_USER)
        .u64(user_hash.raw())
        .string(collection)
        .string(rkey)
        .string(link_target)
        .build()
}

pub fn backlink_by_user_prefix(user_hash: UserHash) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::BACKLINK_BY_USER)
        .u64(user_hash.raw())
        .build()
}

pub fn backlink_by_user_record_prefix(
    user_hash: UserHash,
    collection: &str,
    rkey: &str,
) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::BACKLINK_BY_USER)
        .u64(user_hash.raw())
        .string(collection)
        .string(rkey)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metastore::encoding::KeyReader;

    #[test]
    fn discriminant_roundtrip() {
        assert_eq!(
            discriminant_to_path(path_to_discriminant(BacklinkPath::Subject)),
            Some(BacklinkPath::Subject)
        );
        assert_eq!(
            discriminant_to_path(path_to_discriminant(BacklinkPath::SubjectUri)),
            Some(BacklinkPath::SubjectUri)
        );
        assert_eq!(discriminant_to_path(255), None);
        assert_eq!(discriminant_to_path(2), None);
    }

    #[test]
    fn backlink_value_roundtrip() {
        let value = BacklinkValue {
            source_uri: "at://did:plc:abc/app.bsky.feed.like/3k2xyz".to_string(),
            path: path_to_discriminant(BacklinkPath::SubjectUri),
        };
        let bytes = value.serialize();
        let decoded = BacklinkValue::deserialize(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn schema_version_is_first_byte() {
        let value = BacklinkValue {
            source_uri: "at://x".to_string(),
            path: path_to_discriminant(BacklinkPath::Subject),
        };
        let bytes = value.serialize();
        assert_eq!(bytes[0], SCHEMA_VERSION);
    }

    #[test]
    fn deserialize_rejects_unknown_version() {
        let value = BacklinkValue {
            source_uri: "at://x".to_string(),
            path: path_to_discriminant(BacklinkPath::Subject),
        };
        let mut bytes = value.serialize();
        bytes[0] = 99;
        assert!(BacklinkValue::deserialize(&bytes).is_none());
    }

    #[test]
    fn deserialize_rejects_empty() {
        assert!(BacklinkValue::deserialize(&[]).is_none());
    }

    #[test]
    fn backlink_key_roundtrip() {
        let hash = UserHash::from_raw(0xCAFE_BABE_DEAD_BEEF);
        let key = backlink_key(
            "at://did:plc:target/app.bsky.feed.post/3k2abc",
            hash,
            "app.bsky.feed.like",
            "3k2xyz",
        );
        let mut reader = KeyReader::new(&key);
        assert_eq!(reader.tag(), Some(KeyTag::BACKLINKS.raw()));
        assert_eq!(
            reader.string(),
            Some("at://did:plc:target/app.bsky.feed.post/3k2abc".to_string())
        );
        assert_eq!(reader.u64(), Some(0xCAFE_BABE_DEAD_BEEF));
        assert_eq!(reader.string(), Some("app.bsky.feed.like".to_string()));
        assert_eq!(reader.string(), Some("3k2xyz".to_string()));
        assert!(reader.is_empty());
    }

    #[test]
    fn backlink_keys_sort_by_target_then_user_then_collection_then_rkey() {
        let h1 = UserHash::from_raw(1);
        let h2 = UserHash::from_raw(2);

        let k1 = backlink_key("aaa", h1, "col_a", "r1");
        let k2 = backlink_key("aaa", h1, "col_a", "r2");
        let k3 = backlink_key("aaa", h1, "col_b", "r1");
        let k4 = backlink_key("aaa", h2, "col_a", "r1");
        let k5 = backlink_key("bbb", h1, "col_a", "r1");

        assert!(k1.as_slice() < k2.as_slice());
        assert!(k2.as_slice() < k3.as_slice());
        assert!(k3.as_slice() < k4.as_slice());
        assert!(k4.as_slice() < k5.as_slice());
    }

    #[test]
    fn target_prefix_is_prefix_of_full_key() {
        let hash = UserHash::from_raw(42);
        let prefix = backlink_target_prefix("did:plc:target");
        let full = backlink_key("did:plc:target", hash, "col", "rk");
        assert!(full.as_slice().starts_with(prefix.as_slice()));
    }

    #[test]
    fn by_user_key_roundtrip() {
        let hash = UserHash::from_raw(0xDEAD_BEEF_1234_5678);
        let key = backlink_by_user_key(hash, "app.bsky.feed.like", "3k2abc", "did:plc:target");
        let mut reader = KeyReader::new(&key);
        assert_eq!(reader.tag(), Some(KeyTag::BACKLINK_BY_USER.raw()));
        assert_eq!(reader.u64(), Some(0xDEAD_BEEF_1234_5678));
        assert_eq!(reader.string(), Some("app.bsky.feed.like".to_string()));
        assert_eq!(reader.string(), Some("3k2abc".to_string()));
        assert_eq!(reader.string(), Some("did:plc:target".to_string()));
        assert!(reader.is_empty());
    }

    #[test]
    fn by_user_prefix_is_prefix_of_full_key() {
        let hash = UserHash::from_raw(42);
        let prefix = backlink_by_user_prefix(hash);
        let full = backlink_by_user_key(hash, "col", "rk", "target");
        assert!(full.as_slice().starts_with(prefix.as_slice()));
    }

    #[test]
    fn by_user_record_prefix_is_prefix_of_full_key() {
        let hash = UserHash::from_raw(42);
        let prefix = backlink_by_user_record_prefix(hash, "col", "rk");
        let full = backlink_by_user_key(hash, "col", "rk", "target");
        assert!(full.as_slice().starts_with(prefix.as_slice()));
    }

    #[test]
    fn same_rkey_different_collection_produces_distinct_keys() {
        let hash = UserHash::from_raw(42);
        let k1 = backlink_key("target", hash, "app.bsky.feed.like", "self");
        let k2 = backlink_key("target", hash, "app.bsky.graph.follow", "self");
        assert_ne!(k1.as_slice(), k2.as_slice());

        let r1 = backlink_by_user_key(hash, "app.bsky.feed.like", "self", "target");
        let r2 = backlink_by_user_key(hash, "app.bsky.graph.follow", "self", "target");
        assert_ne!(r1.as_slice(), r2.as_slice());
    }
}
