use serde::{Deserialize, Serialize};
use siphasher::sip::SipHasher24;
use std::hash::Hasher;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserHash(u64);

const SIPHASH_KEY0: u64 = 0x7472_616e_7175_696c;
const SIPHASH_KEY1: u64 = 0x7064_735f_7573_6572;

impl UserHash {
    pub fn from_did(did: &str) -> Self {
        let mut hasher = SipHasher24::new_with_keys(SIPHASH_KEY0, SIPHASH_KEY1);
        hasher.write(did.as_bytes());
        Self(hasher.finish())
    }

    pub fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub fn raw(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for UserHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyTag(u8);

impl KeyTag {
    pub const REPO_META: Self = Self(0x01);
    pub const RECORDS: Self = Self(0x02);
    pub const USER_BLOCKS: Self = Self(0x03);
    pub const HANDLES: Self = Self(0x04);
    pub const BLOBS: Self = Self(0x05);
    pub const BACKLINKS: Self = Self(0x06);
    pub const BLOB_BY_CID: Self = Self(0x07);

    pub const USER_MAP: Self = Self(0x10);
    pub const USER_MAP_REVERSE: Self = Self(0x11);

    pub const REV_TO_SEQ: Self = Self(0x20);
    pub const SEQ_META: Self = Self(0x21);
    pub const SEQ_TOMBSTONE: Self = Self(0x22);
    pub const METASTORE_CURSOR: Self = Self(0x23);
    pub const DID_EVENTS: Self = Self(0x24);

    pub const RECORD_BLOBS: Self = Self(0x30);
    pub const BACKLINK_BY_USER: Self = Self(0x31);

    pub const FORMAT_VERSION: Self = Self(0xFF);

    pub const fn raw(self) -> u8 {
        self.0
    }

    pub fn exclusive_prefix_bound(self) -> [u8; 1] {
        match self.0.checked_add(1) {
            Some(next) => [next],
            None => panic!("cannot compute exclusive upper bound for tag 0xFF"),
        }
    }

    #[cfg(test)]
    pub fn from_raw_unchecked(raw: u8) -> Self {
        Self(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_hash_deterministic() {
        let a = UserHash::from_did("did:plc:abc123");
        let b = UserHash::from_did("did:plc:abc123");
        assert_eq!(a, b);
    }

    #[test]
    fn user_hash_different_dids_differ() {
        let a = UserHash::from_did("did:plc:abc123");
        let b = UserHash::from_did("did:plc:xyz789");
        assert_ne!(a, b);
    }

    #[test]
    fn user_hash_display_is_hex() {
        let h = UserHash::from_raw(0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(h.to_string(), "deadbeefcafebabe");
    }

    #[test]
    fn key_tags_are_distinct() {
        let tags = [
            KeyTag::REPO_META,
            KeyTag::RECORDS,
            KeyTag::USER_BLOCKS,
            KeyTag::HANDLES,
            KeyTag::BLOBS,
            KeyTag::BACKLINKS,
            KeyTag::BLOB_BY_CID,
            KeyTag::USER_MAP,
            KeyTag::USER_MAP_REVERSE,
            KeyTag::REV_TO_SEQ,
            KeyTag::SEQ_META,
            KeyTag::SEQ_TOMBSTONE,
            KeyTag::METASTORE_CURSOR,
            KeyTag::DID_EVENTS,
            KeyTag::RECORD_BLOBS,
            KeyTag::BACKLINK_BY_USER,
            KeyTag::FORMAT_VERSION,
        ];
        let mut raw: Vec<u8> = tags.iter().map(|t| t.raw()).collect();
        let original_len = raw.len();
        raw.sort();
        raw.dedup();
        assert_eq!(raw.len(), original_len);
    }

    #[test]
    fn key_tag_ordering() {
        assert!(KeyTag::REPO_META < KeyTag::RECORDS);
        assert!(KeyTag::RECORDS < KeyTag::USER_BLOCKS);
    }

    #[test]
    fn exclusive_prefix_bound_is_tag_plus_one() {
        assert_eq!(
            KeyTag::REPO_META.exclusive_prefix_bound(),
            [KeyTag::REPO_META.raw() + 1]
        );
        assert_eq!(KeyTag::HANDLES.exclusive_prefix_bound(), [0x05]);
    }

    #[test]
    #[should_panic(expected = "cannot compute exclusive upper bound for tag 0xFF")]
    fn exclusive_prefix_bound_panics_for_0xff() {
        KeyTag::FORMAT_VERSION.exclusive_prefix_bound();
    }
}
