use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::backlink_ops::remove_backlinks_for_record;
use super::backlinks::{BacklinkValue, backlink_by_user_key, backlink_key, discriminant_to_path};
use super::encoding::KeyReader;
use super::keys::{KeyTag, UserHash};
use super::records::{RecordValue, record_key};
use super::repo_meta::{RepoMetaValue, repo_meta_key};
use super::user_blocks::{user_block_key, user_block_user_prefix};
use crate::metastore::MetastoreError;

const MUTATION_SET_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitMutationSet {
    pub new_root_cid: Vec<u8>,
    pub new_rev: String,
    pub record_upserts: Vec<RecordMutationUpsert>,
    pub record_deletes: Vec<RecordMutationDelete>,
    pub block_inserts: Vec<Vec<u8>>,
    pub block_deletes: Vec<Vec<u8>>,
    pub backlink_adds: Vec<BacklinkMutation>,
    pub backlink_remove_uris: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordMutationUpsert {
    pub collection: String,
    pub rkey: String,
    pub cid_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordMutationDelete {
    pub collection: String,
    pub rkey: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BacklinkMutation {
    pub uri: String,
    pub path: u8,
    pub link_to: String,
}

const MAX_MUTATION_SET_ENTRIES: usize = 50_000;

impl CommitMutationSet {
    pub fn serialize(&self) -> Result<Vec<u8>, MetastoreError> {
        self.validate_size()?;
        let payload = postcard::to_allocvec(self)
            .map_err(|_| MetastoreError::CorruptData("CommitMutationSet serialization failed"))?;
        let mut buf = Vec::with_capacity(1 + payload.len());
        buf.push(MUTATION_SET_VERSION);
        buf.extend_from_slice(&payload);
        Ok(buf)
    }

    fn validate_size(&self) -> Result<(), MetastoreError> {
        let total = self.record_upserts.len()
            + self.record_deletes.len()
            + self.block_inserts.len()
            + self.block_deletes.len()
            + self.backlink_adds.len()
            + self.backlink_remove_uris.len();
        match total <= MAX_MUTATION_SET_ENTRIES {
            true => Ok(()),
            false => {
                tracing::warn!(
                    total_entries = total,
                    max = MAX_MUTATION_SET_ENTRIES,
                    "CommitMutationSet exceeds entry limit"
                );
                Err(MetastoreError::InvalidInput(
                    "CommitMutationSet exceeds maximum entry count",
                ))
            }
        }
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let (&version, payload) = bytes.split_first()?;
        match version {
            MUTATION_SET_VERSION => match postcard::from_bytes(payload) {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::warn!(%e, "failed to deserialize CommitMutationSet payload");
                    None
                }
            },
            _ => {
                tracing::warn!(version, "unknown CommitMutationSet version");
                None
            }
        }
    }
}

pub fn replay_mutation_set(
    batch: &mut fjall::OwnedWriteBatch,
    repo_data: &fjall::Keyspace,
    indexes: &fjall::Keyspace,
    user_hash: UserHash,
    current_meta: &RepoMetaValue,
    mutation_set: &CommitMutationSet,
) -> Result<(), MetastoreError> {
    mutation_set.validate_size()?;

    let updated_meta = RepoMetaValue {
        repo_root_cid: mutation_set.new_root_cid.clone(),
        repo_rev: mutation_set.new_rev.clone(),
        ..current_meta.clone()
    };
    let meta_key = repo_meta_key(user_hash);
    batch.insert(repo_data, meta_key.as_slice(), updated_meta.serialize());

    mutation_set.record_upserts.iter().for_each(|u| {
        let key = record_key(user_hash, &u.collection, &u.rkey);
        let value = RecordValue {
            record_cid: u.cid_bytes.clone(),
            takedown_ref: None,
        };
        batch.insert(repo_data, key.as_slice(), value.serialize());
    });

    mutation_set.record_deletes.iter().for_each(|d| {
        let key = record_key(user_hash, &d.collection, &d.rkey);
        batch.remove(repo_data, key.as_slice());
    });

    mutation_set.block_inserts.iter().for_each(|cid_bytes| {
        let key = user_block_key(user_hash, &mutation_set.new_rev, cid_bytes);
        batch.insert(repo_data, key.as_slice(), []);
    });

    delete_user_blocks_by_cid_scan(batch, repo_data, user_hash, &mutation_set.block_deletes)?;

    mutation_set
        .backlink_remove_uris
        .iter()
        .try_for_each(|uri_str| {
            let uri = tranquil_types::AtUri::from(uri_str.clone());
            let collection = uri.collection().ok_or(MetastoreError::CorruptData(
                "backlink URI missing collection",
            ))?;
            let rkey = uri
                .rkey()
                .ok_or(MetastoreError::CorruptData("backlink URI missing rkey"))?;

            remove_backlinks_for_record(batch, indexes, user_hash, collection, rkey)
        })?;

    mutation_set.backlink_adds.iter().try_for_each(|bl| {
        let uri = tranquil_types::AtUri::from(bl.uri.clone());
        let collection = uri.collection().ok_or(MetastoreError::CorruptData(
            "backlink URI missing collection",
        ))?;
        let rkey = uri
            .rkey()
            .ok_or(MetastoreError::CorruptData("backlink URI missing rkey"))?;

        match discriminant_to_path(bl.path) {
            None => {
                tracing::warn!(
                    path = bl.path,
                    uri = %bl.uri,
                    "skipping backlink with unknown path discriminant during recovery"
                );
            }
            Some(_) => {
                let primary = backlink_key(&bl.link_to, user_hash, collection, rkey);
                let value = BacklinkValue {
                    source_uri: bl.uri.clone(),
                    path: bl.path,
                };
                batch.insert(indexes, primary.as_slice(), value.serialize());

                let reverse = backlink_by_user_key(user_hash, collection, rkey, &bl.link_to);
                batch.insert(indexes, reverse.as_slice(), []);
            }
        }
        Ok::<_, MetastoreError>(())
    })
}

fn delete_user_blocks_by_cid_scan(
    batch: &mut fjall::OwnedWriteBatch,
    repo_data: &fjall::Keyspace,
    user_hash: UserHash,
    block_cids: &[Vec<u8>],
) -> Result<(), MetastoreError> {
    match block_cids.is_empty() {
        true => Ok(()),
        false => {
            let cid_set: HashSet<&[u8]> = block_cids.iter().map(|c| c.as_slice()).collect();
            let prefix = user_block_user_prefix(user_hash);
            repo_data.prefix(prefix.as_slice()).try_for_each(|guard| {
                let (key_bytes, _) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                match extract_cid_from_user_block_key(&key_bytes) {
                    Some(cid) if cid_set.contains(cid) => {
                        batch.remove(repo_data, key_bytes.as_ref());
                        Ok(())
                    }
                    _ => Ok(()),
                }
            })
        }
    }
}

fn extract_cid_from_user_block_key(key_bytes: &[u8]) -> Option<&[u8]> {
    let mut reader = KeyReader::new(key_bytes);
    let tag = reader.tag()?;

    if tag != KeyTag::USER_BLOCKS.raw() {
        tracing::warn!(
            tag,
            "unexpected key tag in user_block prefix scan during recovery"
        );
        return None;
    }

    if reader.u64().and_then(|_| reader.string()).is_none() {
        tracing::warn!("user_block key has corrupt user_hash or rev during recovery");
        return None;
    }

    let remaining = reader.remaining();
    match remaining.is_empty() {
        true => {
            tracing::warn!("user_block key has no CID suffix during recovery");
            None
        }
        false => Some(remaining),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutation_set_roundtrip() {
        let ms = CommitMutationSet {
            new_root_cid: vec![0x01, 0x71, 0x12, 0x20],
            new_rev: "rev1".to_owned(),
            record_upserts: vec![RecordMutationUpsert {
                collection: "app.bsky.feed.post".to_owned(),
                rkey: "3k2abc".to_owned(),
                cid_bytes: vec![0xDE, 0xAD],
            }],
            record_deletes: vec![RecordMutationDelete {
                collection: "app.bsky.feed.like".to_owned(),
                rkey: "3k2del".to_owned(),
            }],
            block_inserts: vec![vec![0x01, 0x02]],
            block_deletes: vec![vec![0x03, 0x04]],
            backlink_adds: vec![BacklinkMutation {
                uri: "at://did:plc:olaren/app.bsky.feed.like/3k2abc".to_owned(),
                path: 1,
                link_to: "at://did:plc:teq/app.bsky.feed.post/3k2xyz".to_owned(),
            }],
            backlink_remove_uris: vec!["at://did:plc:olaren/app.bsky.feed.like/3k2old".to_owned()],
        };

        let bytes = ms.serialize().unwrap();
        assert_eq!(bytes[0], MUTATION_SET_VERSION);
        let recovered = CommitMutationSet::deserialize(&bytes).unwrap();
        assert_eq!(recovered, ms);
    }

    #[test]
    fn mutation_set_empty_roundtrip() {
        let ms = CommitMutationSet {
            new_root_cid: vec![],
            new_rev: String::new(),
            record_upserts: vec![],
            record_deletes: vec![],
            block_inserts: vec![],
            block_deletes: vec![],
            backlink_adds: vec![],
            backlink_remove_uris: vec![],
        };

        let recovered = CommitMutationSet::deserialize(&ms.serialize().unwrap()).unwrap();
        assert_eq!(recovered, ms);
    }

    #[test]
    fn unknown_version_returns_none() {
        let ms = CommitMutationSet {
            new_root_cid: vec![],
            new_rev: String::new(),
            record_upserts: vec![],
            record_deletes: vec![],
            block_inserts: vec![],
            block_deletes: vec![],
            backlink_adds: vec![],
            backlink_remove_uris: vec![],
        };
        let mut bytes = ms.serialize().unwrap();
        bytes[0] = 99;
        assert!(CommitMutationSet::deserialize(&bytes).is_none());
    }
}
