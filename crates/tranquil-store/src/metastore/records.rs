use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use tranquil_types::{Nsid, Rkey};

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

pub fn record_key(user_hash: UserHash, collection: &Nsid, rkey: &Rkey) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::RECORDS)
        .u64(user_hash.raw())
        .string(collection)
        .string(rkey)
        .build()
}

pub fn record_collection_prefix(user_hash: UserHash, collection: &Nsid) -> SmallVec<[u8; 128]> {
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

pub fn record_by_cid_key(
    user_hash: UserHash,
    cid_bytes: &[u8],
    collection: &Nsid,
    rkey: &Rkey,
) -> SmallVec<[u8; 128]> {
    record_by_cid_prefix(user_hash, cid_bytes)
        .into_iter()
        .chain(record_by_cid_suffix(collection, rkey))
        .collect()
}

pub fn record_by_cid_suffix(collection: &Nsid, rkey: &Rkey) -> SmallVec<[u8; 128]> {
    KeyBuilder::new().string(collection).string(rkey).build()
}

pub fn record_by_cid_key_from_suffix(
    user_hash: UserHash,
    cid_bytes: &[u8],
    suffix: &[u8],
) -> SmallVec<[u8; 128]> {
    record_by_cid_prefix(user_hash, cid_bytes)
        .into_iter()
        .chain(suffix.iter().copied())
        .collect()
}

pub fn record_key_user_hash_and_suffix(key_bytes: &[u8]) -> Option<(UserHash, &[u8])> {
    let mut reader = super::encoding::KeyReader::new(key_bytes);
    let _tag = reader.tag()?;
    let hash = reader.u64()?;
    Some((UserHash::from_raw(hash), reader.remaining()))
}

pub fn record_by_cid_prefix(user_hash: UserHash, cid_bytes: &[u8]) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::RECORD_BY_CID)
        .u64(user_hash.raw())
        .bytes(cid_bytes)
        .build()
}

pub fn record_by_cid_user_prefix(user_hash: UserHash) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::RECORD_BY_CID)
        .u64(user_hash.raw())
        .build()
}

pub fn record_by_cid_index_prefix() -> SmallVec<[u8; 128]> {
    KeyBuilder::new().tag(KeyTag::RECORD_BY_CID).build()
}

pub fn record_by_cid_built_key() -> SmallVec<[u8; 128]> {
    KeyBuilder::new().tag(KeyTag::RECORD_BY_CID_BUILT).build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metastore::encoding::KeyReader;

    fn nsid(s: &str) -> Nsid {
        s.parse().unwrap()
    }

    fn rkey(s: &str) -> Rkey {
        s.parse().unwrap()
    }

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
        let key = record_key(hash, &nsid("app.bsky.feed.post"), &rkey("3k2abcd"));
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

        let k1 = record_key(h1, &nsid("app.bsky.feed.like"), &rkey("aaa"));
        let k2 = record_key(h1, &nsid("app.bsky.feed.post"), &rkey("aaa"));
        let k3 = record_key(h1, &nsid("app.bsky.feed.post"), &rkey("bbb"));
        let k4 = record_key(h2, &nsid("app.bsky.feed.like"), &rkey("aaa"));

        assert!(k1.as_slice() < k2.as_slice());
        assert!(k2.as_slice() < k3.as_slice());
        assert!(k3.as_slice() < k4.as_slice());
    }

    #[test]
    fn collection_prefix_is_prefix_of_full_key() {
        let hash = UserHash::from_raw(42);
        let prefix = record_collection_prefix(hash, &nsid("app.bsky.feed.post"));
        let full = record_key(hash, &nsid("app.bsky.feed.post"), &rkey("some_rkey"));
        assert!(full.as_slice().starts_with(prefix.as_slice()));
    }

    #[test]
    fn user_prefix_is_prefix_of_collection_prefix() {
        let hash = UserHash::from_raw(42);
        let user_pfx = record_user_prefix(hash);
        let coll_pfx = record_collection_prefix(hash, &nsid("app.bsky.feed.post"));
        assert!(coll_pfx.as_slice().starts_with(user_pfx.as_slice()));
    }

    #[test]
    fn records_prefix_is_just_tag() {
        let pfx = records_prefix();
        assert_eq!(pfx.as_slice(), &[KeyTag::RECORDS.raw()]);
    }

    #[test]
    fn record_by_cid_key_roundtrip() {
        let hash = UserHash::from_raw(0xDEAD_BEEF_CAFE_BABE);
        let cid = [0x01, 0x71, 0x12, 0x20, 0xAB];
        let key = record_by_cid_key(hash, &cid, &nsid("app.bsky.feed.post"), &rkey("3k2abcd"));
        let mut reader = KeyReader::new(&key);
        assert_eq!(reader.tag(), Some(KeyTag::RECORD_BY_CID.raw()));
        assert_eq!(reader.u64(), Some(0xDEAD_BEEF_CAFE_BABE));
        assert_eq!(reader.bytes(), Some(cid.to_vec()));
        assert_eq!(reader.string(), Some("app.bsky.feed.post".to_string()));
        assert_eq!(reader.string(), Some("3k2abcd".to_string()));
        assert!(reader.is_empty());
    }

    #[test]
    fn the_raw_suffix_of_a_records_key_rebuilds_the_same_reverse_key() {
        let hash = UserHash::from_raw(0xDEAD_BEEF_CAFE_BABE);
        let cid = [0x01, 0x71, 0x12, 0x20, 0xAB];
        let collection = nsid("app.bsky.feed.post");
        let rkey = rkey("3k2abcd");

        let forward = record_key(hash, &collection, &rkey);
        let (parsed_hash, suffix) = record_key_user_hash_and_suffix(&forward).unwrap();

        assert_eq!(parsed_hash, hash);
        assert_eq!(suffix, record_by_cid_suffix(&collection, &rkey).as_slice());
        assert_eq!(
            record_by_cid_key_from_suffix(parsed_hash, &cid, suffix).as_slice(),
            record_by_cid_key(hash, &cid, &collection, &rkey).as_slice()
        );
    }

    #[test]
    fn a_records_key_suffix_is_copied_without_revalidating_it() {
        let hash = UserHash::from_raw(5);
        let cid = [0x01, 0x71];
        let forward = KeyBuilder::new()
            .tag(KeyTag::RECORDS)
            .u64(hash.raw())
            .string("not/an/nsid")
            .string("not a valid rkey")
            .build();

        let (parsed_hash, suffix) = record_key_user_hash_and_suffix(&forward)
            .expect("a structurally valid records key parses regardless of its string contents");
        let reverse = record_by_cid_key_from_suffix(parsed_hash, &cid, suffix);

        assert!(reverse.starts_with(record_by_cid_prefix(hash, &cid).as_slice()));
        assert_eq!(&reverse[record_by_cid_prefix(hash, &cid).len()..], suffix);
    }

    #[test]
    fn record_by_cid_key_splits_into_prefix_and_suffix() {
        let hash = UserHash::from_raw(0xDEAD_BEEF_CAFE_BABE);
        let cid = [0x01, 0x71, 0x12, 0x20, 0xAB];
        let collection = nsid("app.bsky.feed.post");
        let rkey = rkey("3k2abcd");
        let key = record_by_cid_key(hash, &cid, &collection, &rkey);
        let prefix = record_by_cid_prefix(hash, &cid);
        let suffix = record_by_cid_suffix(&collection, &rkey);
        assert_eq!(&key[..prefix.len()], prefix.as_slice());
        assert_eq!(&key[prefix.len()..], suffix.as_slice());
    }

    #[test]
    fn record_by_cid_prefix_covers_only_that_cid() {
        let hash = UserHash::from_raw(7);
        let cid = [0x01, 0x02, 0x03];
        let other = [0x01, 0x02, 0x04];
        let prefix = record_by_cid_prefix(hash, &cid);
        let matching = record_by_cid_key(hash, &cid, &nsid("app.bsky.feed.post"), &rkey("a"));
        let different = record_by_cid_key(hash, &other, &nsid("app.bsky.feed.post"), &rkey("a"));
        assert!(matching.as_slice().starts_with(prefix.as_slice()));
        assert!(!different.as_slice().starts_with(prefix.as_slice()));
    }

    #[test]
    fn record_by_cid_prefix_is_not_confused_by_a_longer_cid() {
        let hash = UserHash::from_raw(7);
        let short = [0x01, 0x02];
        let long = [0x01, 0x02, 0x03];
        let prefix = record_by_cid_prefix(hash, &short);
        let longer = record_by_cid_key(hash, &long, &nsid("app.bsky.feed.post"), &rkey("a"));
        assert!(!longer.as_slice().starts_with(prefix.as_slice()));
    }

    #[test]
    fn record_by_cid_user_prefix_isolates_users() {
        let h1 = UserHash::from_raw(1);
        let h2 = UserHash::from_raw(2);
        let cid = [0x09];
        let key = record_by_cid_key(h2, &cid, &nsid("app.bsky.feed.post"), &rkey("a"));
        assert!(
            key.as_slice()
                .starts_with(record_by_cid_user_prefix(h2).as_slice())
        );
        assert!(
            !key.as_slice()
                .starts_with(record_by_cid_user_prefix(h1).as_slice())
        );
    }
}
