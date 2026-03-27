use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use super::encoding::KeyBuilder;
use super::keys::{KeyTag, UserHash};

const SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RepoStatus {
    Active = 0,
    Takendown = 1,
    Suspended = 2,
    Deactivated = 3,
    Deleted = 4,
}

impl RepoStatus {
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoMetaValue {
    pub repo_root_cid: Vec<u8>,
    pub repo_rev: String,
    pub handle: String,
    pub status: RepoStatus,
    pub deactivated_at_ms: Option<u64>,
    pub takedown_ref: Option<String>,
    #[serde(default)]
    pub did: Option<String>,
}

impl RepoMetaValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload = postcard::to_allocvec(self).expect("RepoMetaValue serialization cannot fail");
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

pub fn repo_meta_key(user_hash: UserHash) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::REPO_META)
        .u64(user_hash.raw())
        .build()
}

pub fn repo_meta_prefix() -> SmallVec<[u8; 128]> {
    KeyBuilder::new().tag(KeyTag::REPO_META).build()
}

pub fn handle_key(handle_lower: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::HANDLES)
        .string(handle_lower)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metastore::encoding::KeyReader;

    #[test]
    fn repo_meta_value_roundtrip() {
        let value = RepoMetaValue {
            repo_root_cid: vec![0x01, 0x71, 0x12, 0x20, 0xAB],
            repo_rev: "3k2a7bcd".to_string(),
            handle: "alice.bsky.social".to_string(),
            status: RepoStatus::Active,
            deactivated_at_ms: None,
            takedown_ref: None,
            did: None,
        };
        let bytes = value.serialize();
        let decoded = RepoMetaValue::deserialize(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn repo_meta_value_with_optional_fields() {
        let value = RepoMetaValue {
            repo_root_cid: vec![0x01],
            repo_rev: "rev1".to_string(),
            handle: "bob.example.com".to_string(),
            status: RepoStatus::Deactivated,
            deactivated_at_ms: Some(1700000000000),
            takedown_ref: Some("DMCA-123".to_string()),
            did: Some("did:plc:bob".to_string()),
        };
        let bytes = value.serialize();
        let decoded = RepoMetaValue::deserialize(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn repo_meta_key_roundtrip() {
        let hash = UserHash::from_raw(0xDEAD_BEEF_CAFE_BABE);
        let key = repo_meta_key(hash);
        let mut reader = KeyReader::new(&key);
        assert_eq!(reader.tag(), Some(KeyTag::REPO_META.raw()));
        assert_eq!(reader.u64(), Some(0xDEAD_BEEF_CAFE_BABE));
        assert!(reader.is_empty());
    }

    #[test]
    fn repo_meta_keys_sort_by_user_hash() {
        let k1 = repo_meta_key(UserHash::from_raw(1));
        let k2 = repo_meta_key(UserHash::from_raw(2));
        let k3 = repo_meta_key(UserHash::from_raw(u64::MAX));
        assert!(k1.as_slice() < k2.as_slice());
        assert!(k2.as_slice() < k3.as_slice());
    }

    #[test]
    fn handle_key_roundtrip() {
        let key = handle_key("alice.bsky.social");
        let mut reader = KeyReader::new(&key);
        assert_eq!(reader.tag(), Some(KeyTag::HANDLES.raw()));
        assert_eq!(reader.string(), Some("alice.bsky.social".to_string()));
        assert!(reader.is_empty());
    }

    #[test]
    fn handle_keys_sort_lexicographically() {
        let k1 = handle_key("alice.example.com");
        let k2 = handle_key("bob.example.com");
        assert!(k1.as_slice() < k2.as_slice());
    }

    #[test]
    fn all_repo_statuses_roundtrip() {
        [
            RepoStatus::Active,
            RepoStatus::Takendown,
            RepoStatus::Suspended,
            RepoStatus::Deactivated,
            RepoStatus::Deleted,
        ]
        .iter()
        .for_each(|&status| {
            let value = RepoMetaValue {
                repo_root_cid: vec![0x01],
                repo_rev: "r".to_string(),
                handle: "h.test".to_string(),
                status,
                deactivated_at_ms: None,
                takedown_ref: None,
                did: None,
            };
            let decoded = RepoMetaValue::deserialize(&value.serialize()).unwrap();
            assert_eq!(decoded.status, status);
        });
    }

    #[test]
    fn repo_status_serialization_stability() {
        [
            (RepoStatus::Active, 0u8),
            (RepoStatus::Takendown, 1),
            (RepoStatus::Suspended, 2),
            (RepoStatus::Deactivated, 3),
            (RepoStatus::Deleted, 4),
        ]
        .iter()
        .for_each(|&(status, expected_byte)| {
            let bytes = postcard::to_allocvec(&status).unwrap();
            assert_eq!(
                bytes,
                [expected_byte],
                "{status:?} serialized to {bytes:?}, expected [{expected_byte}]"
            );
        });
    }

    #[test]
    fn schema_version_is_first_byte() {
        let value = RepoMetaValue {
            repo_root_cid: vec![0x01],
            repo_rev: "r".to_string(),
            handle: "h.test".to_string(),
            status: RepoStatus::Active,
            deactivated_at_ms: None,
            takedown_ref: None,
            did: None,
        };
        let bytes = value.serialize();
        assert_eq!(bytes[0], SCHEMA_VERSION);
        assert_eq!(bytes[0], 1, "schema version must remain 1 for this format");
    }

    #[test]
    fn deserialize_rejects_unknown_schema_version() {
        let value = RepoMetaValue {
            repo_root_cid: vec![0x01],
            repo_rev: "r".to_string(),
            handle: "h.test".to_string(),
            status: RepoStatus::Active,
            deactivated_at_ms: None,
            takedown_ref: None,
            did: None,
        };
        let mut bytes = value.serialize();
        bytes[0] = 99;
        assert!(RepoMetaValue::deserialize(&bytes).is_none());
    }

    #[test]
    fn deserialize_rejects_empty_input() {
        assert!(RepoMetaValue::deserialize(&[]).is_none());
    }
}
