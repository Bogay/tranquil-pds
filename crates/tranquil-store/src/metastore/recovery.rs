use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use tranquil_types::{AtUri, Nsid, Rkey, Tid};

use super::backlink_ops::remove_backlinks_for_record;
use super::backlinks::{BacklinkValue, backlink_by_user_key, backlink_key, discriminant_to_path};
use super::encoding::KeyReader;
use super::keys::{KeyTag, UserHash};
use super::records::{RecordValue, record_by_cid_key, record_key};
use super::repo_meta::{RepoMetaValue, repo_meta_key};
use super::user_blocks::{user_block_key, user_block_user_prefix};
use crate::metastore::MetastoreError;

const MUTATION_SET_VERSION: u8 = 2;
const MUTATION_SET_VERSION_UNVALIDATED: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitMutationSet {
    pub new_root_cid: Vec<u8>,
    pub new_rev: Tid,
    pub record_upserts: Vec<RecordMutationUpsert>,
    pub record_deletes: Vec<RecordMutationDelete>,
    pub block_inserts: Vec<Vec<u8>>,
    pub block_deletes: Vec<Vec<u8>>,
    pub backlink_adds: Vec<BacklinkMutation>,
    pub backlink_remove_uris: Vec<AtUri>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordMutationUpsert {
    pub collection: Nsid,
    pub rkey: Rkey,
    pub cid_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordMutationDelete {
    pub collection: Nsid,
    pub rkey: Rkey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BacklinkMutation {
    pub uri: AtUri,
    pub path: u8,
    pub link_to: String,
}

#[derive(Deserialize)]
struct UnvalidatedCommitMutationSet {
    new_root_cid: Vec<u8>,
    new_rev: String,
    record_upserts: Vec<UnvalidatedRecordMutationUpsert>,
    record_deletes: Vec<UnvalidatedRecordMutationDelete>,
    block_inserts: Vec<Vec<u8>>,
    block_deletes: Vec<Vec<u8>>,
    backlink_adds: Vec<UnvalidatedBacklinkMutation>,
    backlink_remove_uris: Vec<String>,
}

#[derive(Deserialize)]
struct UnvalidatedRecordMutationUpsert {
    collection: String,
    rkey: String,
    cid_bytes: Vec<u8>,
}

#[derive(Deserialize)]
struct UnvalidatedRecordMutationDelete {
    collection: String,
    rkey: String,
}

#[derive(Deserialize)]
struct UnvalidatedBacklinkMutation {
    uri: String,
    path: u8,
    link_to: String,
}

impl UnvalidatedCommitMutationSet {
    fn into_validated(self) -> Option<CommitMutationSet> {
        let warn = |field: &str, value: &str| {
            tracing::warn!(
                field,
                value,
                "version 1 CommitMutationSet has a value the current validators reject. \
                 Skipping the whole set rahter than replaying it in part."
            );
        };
        let new_rev = Tid::new(self.new_rev.clone())
            .inspect_err(|_| warn("new_rev", &self.new_rev))
            .ok()?;
        let record_upserts = self
            .record_upserts
            .into_iter()
            .map(|u| {
                Some(RecordMutationUpsert {
                    collection: Nsid::new(u.collection.clone())
                        .inspect_err(|_| warn("record_upserts.collection", &u.collection))
                        .ok()?,
                    rkey: Rkey::new(u.rkey.clone())
                        .inspect_err(|_| warn("record_upserts.rkey", &u.rkey))
                        .ok()?,
                    cid_bytes: u.cid_bytes,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        let record_deletes = self
            .record_deletes
            .into_iter()
            .map(|d| {
                Some(RecordMutationDelete {
                    collection: Nsid::new(d.collection.clone())
                        .inspect_err(|_| warn("record_deletes.collection", &d.collection))
                        .ok()?,
                    rkey: Rkey::new(d.rkey.clone())
                        .inspect_err(|_| warn("record_deletes.rkey", &d.rkey))
                        .ok()?,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        let backlink_adds = self
            .backlink_adds
            .into_iter()
            .map(|b| {
                Some(BacklinkMutation {
                    uri: AtUri::new(b.uri.clone())
                        .inspect_err(|_| warn("backlink_adds.uri", &b.uri))
                        .ok()?,
                    path: b.path,
                    link_to: b.link_to,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        let backlink_remove_uris = self
            .backlink_remove_uris
            .into_iter()
            .map(|uri| {
                AtUri::new(uri.clone())
                    .inspect_err(|_| warn("backlink_remove_uris", &uri))
                    .ok()
            })
            .collect::<Option<Vec<_>>>()?;
        Some(CommitMutationSet {
            new_root_cid: self.new_root_cid,
            new_rev,
            record_upserts,
            record_deletes,
            block_inserts: self.block_inserts,
            block_deletes: self.block_deletes,
            backlink_adds,
            backlink_remove_uris,
        })
    }
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
            MUTATION_SET_VERSION_UNVALIDATED => {
                match postcard::from_bytes::<UnvalidatedCommitMutationSet>(payload) {
                    Ok(v) => v.into_validated(),
                    Err(e) => {
                        tracing::warn!(%e, "failed to deserialize version 1 CommitMutationSet payload");
                        None
                    }
                }
            }
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
        repo_rev: mutation_set.new_rev.as_str().to_owned(),
        ..current_meta.clone()
    };
    let meta_key = repo_meta_key(user_hash);
    batch.insert(repo_data, meta_key.as_slice(), updated_meta.serialize());

    mutation_set.record_upserts.iter().try_for_each(|u| {
        let key = record_key(user_hash, &u.collection, &u.rkey);
        let previous = stored_record(repo_data, key.as_slice())?;
        if let Some(prev) = previous
            .as_ref()
            .map(|p| &p.record_cid)
            .filter(|prev| *prev != &u.cid_bytes)
        {
            let stale = record_by_cid_key(user_hash, prev, &u.collection, &u.rkey);
            batch.remove(repo_data, stale.as_slice());
        }
        let value = RecordValue {
            record_cid: u.cid_bytes.clone(),
            takedown_ref: previous.and_then(|p| p.takedown_ref),
        };
        let reverse = record_by_cid_key(user_hash, &u.cid_bytes, &u.collection, &u.rkey);
        batch.insert(repo_data, key.as_slice(), value.serialize());
        batch.insert(repo_data, reverse.as_slice(), []);
        Ok::<(), MetastoreError>(())
    })?;

    mutation_set.record_deletes.iter().try_for_each(|d| {
        let key = record_key(user_hash, &d.collection, &d.rkey);
        if let Some(prev) = stored_record(repo_data, key.as_slice())? {
            let reverse = record_by_cid_key(user_hash, &prev.record_cid, &d.collection, &d.rkey);
            batch.remove(repo_data, reverse.as_slice());
        }
        batch.remove(repo_data, key.as_slice());
        Ok::<(), MetastoreError>(())
    })?;

    let already_recorded: HashSet<Vec<u8>> = match mutation_set.block_inserts.is_empty() {
        true => HashSet::new(),
        false => repo_data
            .prefix(user_block_user_prefix(user_hash).as_slice())
            .map(|guard| {
                let (key_bytes, _) = guard.into_inner().map_err(MetastoreError::Fjall)?;
                Ok(extract_cid_from_user_block_key(key_bytes.as_ref()).map(|c| c.to_vec()))
            })
            .filter_map(Result::transpose)
            .collect::<Result<_, MetastoreError>>()?,
    };
    mutation_set
        .block_inserts
        .iter()
        .filter(|cid_bytes| !cid_bytes.is_empty())
        .filter(|cid_bytes| !already_recorded.contains(cid_bytes.as_slice()))
        .for_each(|cid_bytes| {
            let key = user_block_key(user_hash, &mutation_set.new_rev, cid_bytes);
            batch.insert(repo_data, key.as_slice(), []);
        });

    delete_user_blocks_by_cid_scan(batch, repo_data, user_hash, &mutation_set.block_deletes)?;

    mutation_set
        .backlink_remove_uris
        .iter()
        .try_for_each(|uri| {
            let collection = uri.collection().ok_or(MetastoreError::CorruptData(
                "backlink URI missing collection",
            ))?;
            let rkey = uri
                .rkey()
                .ok_or(MetastoreError::CorruptData("backlink URI missing rkey"))?;

            remove_backlinks_for_record(batch, indexes, user_hash, collection, rkey)
        })?;

    mutation_set.backlink_adds.iter().try_for_each(|bl| {
        let collection = bl.uri.collection().ok_or(MetastoreError::CorruptData(
            "backlink URI missing collection",
        ))?;
        let rkey = bl
            .uri
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
                    source_uri: bl.uri.as_str().to_owned(),
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

fn stored_record(
    repo_data: &fjall::Keyspace,
    key: &[u8],
) -> Result<Option<RecordValue>, MetastoreError> {
    Ok(repo_data
        .get(key)
        .map_err(MetastoreError::Fjall)?
        .and_then(|raw| RecordValue::deserialize(&raw)))
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
            new_rev: Tid::new("3k2abcdefghij").unwrap(),
            record_upserts: vec![RecordMutationUpsert {
                collection: Nsid::new("app.bsky.feed.post").unwrap(),
                rkey: Rkey::new("3k2abc").unwrap(),
                cid_bytes: vec![0xDE, 0xAD],
            }],
            record_deletes: vec![RecordMutationDelete {
                collection: Nsid::new("app.bsky.feed.like").unwrap(),
                rkey: Rkey::new("3k2del").unwrap(),
            }],
            block_inserts: vec![vec![0x01, 0x02]],
            block_deletes: vec![vec![0x03, 0x04]],
            backlink_adds: vec![BacklinkMutation {
                uri: AtUri::new("at://did:plc:olaren/app.bsky.feed.like/3k2abc").unwrap(),
                path: 1,
                link_to: "at://did:plc:teq/app.bsky.feed.post/3k2xyz".to_owned(),
            }],
            backlink_remove_uris: vec![
                AtUri::new("at://did:plc:olaren/app.bsky.feed.like/3k2old").unwrap(),
            ],
        };

        let bytes = ms.serialize().unwrap();
        assert_eq!(bytes[0], MUTATION_SET_VERSION);
        let recovered = CommitMutationSet::deserialize(&bytes).unwrap();
        assert_eq!(recovered, ms);
    }

    #[test]
    fn mutation_set_rejects_a_field_corrupted_into_a_structurally_valid_decode() {
        let ms = CommitMutationSet {
            new_root_cid: vec![0x01],
            new_rev: Tid::new("3k2abcdefghij").unwrap(),
            record_upserts: vec![RecordMutationUpsert {
                collection: Nsid::new("app.bsky.feed.post").unwrap(),
                rkey: Rkey::new("3k2abc").unwrap(),
                cid_bytes: vec![0x02],
            }],
            record_deletes: vec![],
            block_inserts: vec![],
            block_deletes: vec![],
            backlink_adds: vec![],
            backlink_remove_uris: vec![],
        };

        let mut bytes = ms.serialize().unwrap();
        let nsid_start = bytes
            .windows(b"app.bsky.feed.post".len())
            .position(|w| w == b"app.bsky.feed.post")
            .expect("serialized form contains the collection");
        bytes[nsid_start] = b'!';

        assert!(
            CommitMutationSet::deserialize(&bytes).is_none(),
            "a corrupt field that still decodes as a string must be rejected"
        );
    }

    #[test]
    fn mutation_set_empty_roundtrip() {
        let ms = CommitMutationSet {
            new_root_cid: vec![],
            new_rev: Tid::new("3k2abcdefghij").unwrap(),
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
            new_rev: Tid::new("3k2abcdefghij").unwrap(),
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

    fn v1_payload(rev: &str, collection: &str, rkey: &str) -> Vec<u8> {
        #[derive(Serialize)]
        struct V1 {
            new_root_cid: Vec<u8>,
            new_rev: String,
            record_upserts: Vec<V1Upsert>,
            record_deletes: Vec<(String, String)>,
            block_inserts: Vec<Vec<u8>>,
            block_deletes: Vec<Vec<u8>>,
            backlink_adds: Vec<(String, u8, String)>,
            backlink_remove_uris: Vec<String>,
        }
        #[derive(Serialize)]
        struct V1Upsert {
            collection: String,
            rkey: String,
            cid_bytes: Vec<u8>,
        }

        let payload = postcard::to_allocvec(&V1 {
            new_root_cid: vec![0x01, 0x71],
            new_rev: rev.to_owned(),
            record_upserts: vec![V1Upsert {
                collection: collection.to_owned(),
                rkey: rkey.to_owned(),
                cid_bytes: vec![0xDE, 0xAD],
            }],
            record_deletes: vec![],
            block_inserts: vec![vec![0x01, 0x02]],
            block_deletes: vec![],
            backlink_adds: vec![],
            backlink_remove_uris: vec![],
        })
        .unwrap();
        std::iter::once(MUTATION_SET_VERSION_UNVALIDATED)
            .chain(payload)
            .collect()
    }

    #[test]
    fn a_version_1_payload_written_by_an_older_binary_still_replays() {
        let decoded = CommitMutationSet::deserialize(&v1_payload(
            "3k2abcdefghij",
            "app.bsky.feed.post",
            "3k2abc",
        ))
        .expect("a version 1 payload with valid values decodes");

        assert_eq!(decoded.new_rev.as_str(), "3k2abcdefghij");
        assert_eq!(decoded.record_upserts[0].rkey.as_str(), "3k2abc");
        assert_eq!(decoded.block_inserts, vec![vec![0x01, 0x02]]);
    }

    #[test]
    fn a_version_1_payload_the_current_validators_reject_is_skipped_not_fatal() {
        assert!(
            CommitMutationSet::deserialize(&v1_payload("3k2abcdefghij", "not/an/nsid", "3k2abc"))
                .is_none(),
            "a collection the validators reject skips the whole set instead of replaying it in part"
        );
        assert!(
            CommitMutationSet::deserialize(&v1_payload("0", "app.bsky.feed.post", "3k2abc"))
                .is_none(),
            "a rev that isn't a TID skips the set"
        );
    }

    #[test]
    fn a_current_payload_is_written_at_the_validated_version() {
        let ms = CommitMutationSet {
            new_root_cid: vec![0x01],
            new_rev: Tid::new("3k2abcdefghij").unwrap(),
            record_upserts: vec![],
            record_deletes: vec![],
            block_inserts: vec![],
            block_deletes: vec![],
            backlink_adds: vec![],
            backlink_remove_uris: vec![],
        };
        assert_eq!(ms.serialize().unwrap()[0], MUTATION_SET_VERSION);
    }
}
