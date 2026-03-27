use std::sync::Arc;

use fjall::{Database, Keyspace};
use smallvec::SmallVec;
use uuid::Uuid;

use super::MetastoreError;
use super::backlink_ops::BacklinkOps;
use super::backlinks::path_to_discriminant;
use super::encoding::KeyBuilder;
use super::event_ops::EventOps;
use super::keys::{KeyTag, UserHash};
use super::record_ops::{RecordDelete, RecordOps, RecordWrite};
use super::recovery::{
    BacklinkMutation, CommitMutationSet, RecordMutationDelete, RecordMutationUpsert,
};
use super::repo_meta::{RepoMetaValue, repo_meta_key, repo_meta_prefix};
use super::repo_ops::{RepoOps, bytes_to_cid_link, cid_link_to_bytes};
use super::user_block_ops::UserBlockOps;
use super::user_blocks::user_block_user_prefix;
use super::user_hash::UserHashMap;
use crate::blockstore::TranquilBlockStore;
use crate::eventlog::EventLogBridge;
use crate::io::StorageIO;

use tranquil_db_traits::{
    ApplyCommitError, ApplyCommitInput, ApplyCommitResult, BrokenGenesisCommit, ImportBlock,
    ImportRecord, ImportRepoError, RepoEventType, SequenceNumber, UserNeedingRecordBlobsBackfill,
    UserWithoutBlocks,
};
use tranquil_types::{AtUri, CidLink, Did};

use serde::{Deserialize, Serialize};

pub(crate) const RECORD_BLOBS_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RecordBlobsValue {
    pub(crate) blob_cid_bytes: Vec<Vec<u8>>,
}

impl RecordBlobsValue {
    pub(crate) fn serialize(&self) -> Vec<u8> {
        let payload =
            postcard::to_allocvec(self).expect("RecordBlobsValue serialization cannot fail");
        let mut buf = Vec::with_capacity(1 + payload.len());
        buf.push(RECORD_BLOBS_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub(crate) fn deserialize(bytes: &[u8]) -> Option<Self> {
        let (&version, payload) = bytes.split_first()?;
        match version {
            RECORD_BLOBS_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

fn record_blobs_key(user_hash: UserHash, uri: &AtUri) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::RECORD_BLOBS)
        .u64(user_hash.raw())
        .string(uri.as_str())
        .build()
}

pub(crate) fn record_blobs_user_prefix(user_hash: UserHash) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::RECORD_BLOBS)
        .u64(user_hash.raw())
        .build()
}

pub struct CommitOps<S: StorageIO> {
    db: Database,
    repo_data: Keyspace,
    user_hashes: Arc<UserHashMap>,
    repo_ops: RepoOps,
    record_ops: RecordOps,
    user_block_ops: UserBlockOps,
    backlink_ops: BacklinkOps,
    event_ops: EventOps<S>,
    blockstore: Option<TranquilBlockStore>,
}

impl<S: StorageIO> CommitOps<S> {
    pub fn new(
        db: Database,
        repo_data: Keyspace,
        indexes: Keyspace,
        user_hashes: Arc<UserHashMap>,
        bridge: Arc<EventLogBridge<S>>,
    ) -> Self {
        let repo_ops = RepoOps::new(repo_data.clone(), Arc::clone(&user_hashes));
        let record_ops = RecordOps::new(repo_data.clone(), Arc::clone(&user_hashes));
        let user_block_ops = UserBlockOps::new(repo_data.clone(), Arc::clone(&user_hashes));
        let backlink_ops = BacklinkOps::new(indexes, Arc::clone(&user_hashes));
        let event_ops = EventOps::new(db.clone(), repo_data.clone(), bridge);
        Self {
            db,
            repo_data,
            user_hashes,
            repo_ops,
            record_ops,
            user_block_ops,
            backlink_ops,
            event_ops,
            blockstore: None,
        }
    }

    pub fn with_blockstore(mut self, blockstore: TranquilBlockStore) -> Self {
        self.blockstore = Some(blockstore);
        self
    }

    pub fn apply_commit(
        &self,
        input: ApplyCommitInput,
    ) -> Result<ApplyCommitResult, ApplyCommitError> {
        let user_hash = self
            .user_hashes
            .get(&input.user_id)
            .ok_or(ApplyCommitError::RepoNotFound)?;

        let key = repo_meta_key(user_hash);
        let meta = self
            .repo_data
            .get(key.as_slice())
            .map_err(|e| ApplyCommitError::Database(e.to_string()))?
            .and_then(|raw| RepoMetaValue::deserialize(&raw))
            .ok_or(ApplyCommitError::RepoNotFound)?;

        if let Some(expected) = &input.expected_root_cid {
            let current = bytes_to_cid_link(&meta.repo_root_cid)
                .map_err(|e| ApplyCommitError::Database(e.to_string()))?;
            if current != *expected {
                return Err(ApplyCommitError::ConcurrentModification);
            }
        }

        let new_cid_bytes = cid_link_to_bytes(&input.new_root_cid)
            .map_err(|e| ApplyCommitError::Database(e.to_string()))?;

        let is_active = meta.status.is_active();

        let updated_meta = RepoMetaValue {
            repo_root_cid: new_cid_bytes.clone(),
            repo_rev: input.new_rev.clone(),
            ..meta
        };

        let mut batch = self.db.batch();

        self.repo_ops
            .write_repo_meta(&mut batch, user_hash, &updated_meta);

        let upserts: Vec<RecordWrite<'_>> = input
            .record_upserts
            .iter()
            .map(|u| RecordWrite {
                collection: &u.collection,
                rkey: &u.rkey,
                cid: &u.cid,
            })
            .collect();

        self.record_ops
            .upsert_records(&mut batch, user_hash, &upserts)
            .map_err(|e| ApplyCommitError::Database(e.to_string()))?;

        let deletes: Vec<RecordDelete<'_>> = input
            .record_deletes
            .iter()
            .map(|d| RecordDelete {
                collection: &d.collection,
                rkey: &d.rkey,
            })
            .collect();

        self.record_ops
            .delete_records(&mut batch, user_hash, &deletes);

        self.user_block_ops
            .insert_user_blocks(&mut batch, user_hash, &input.new_block_cids, &input.new_rev)
            .map_err(|e| ApplyCommitError::Database(e.to_string()))?;

        self.user_block_ops
            .delete_user_blocks_by_cid(&mut batch, user_hash, &input.obsolete_block_cids)
            .map_err(|e| ApplyCommitError::Database(e.to_string()))?;

        input.backlinks_to_remove.iter().try_for_each(|uri| {
            self.backlink_ops
                .remove_backlinks_by_uri(&mut batch, user_hash, uri)
                .map_err(|e| ApplyCommitError::Database(e.to_string()))
        })?;

        self.backlink_ops
            .add_backlinks(&mut batch, user_hash, &input.backlinks_to_add)
            .map_err(|e| ApplyCommitError::Database(e.to_string()))?;

        let mutation_set = CommitMutationSet {
            new_root_cid: new_cid_bytes.clone(),
            new_rev: input.new_rev.clone(),
            record_upserts: input
                .record_upserts
                .iter()
                .map(|u| {
                    let cid_bytes = cid_link_to_bytes(&u.cid)
                        .map_err(|e| ApplyCommitError::Database(e.to_string()))?;
                    Ok(RecordMutationUpsert {
                        collection: u.collection.as_str().to_owned(),
                        rkey: u.rkey.as_str().to_owned(),
                        cid_bytes,
                    })
                })
                .collect::<Result<Vec<_>, ApplyCommitError>>()?,
            record_deletes: input
                .record_deletes
                .iter()
                .map(|d| RecordMutationDelete {
                    collection: d.collection.as_str().to_owned(),
                    rkey: d.rkey.as_str().to_owned(),
                })
                .collect(),
            block_inserts: input.new_block_cids.clone(),
            block_deletes: input.obsolete_block_cids.clone(),
            backlink_adds: input
                .backlinks_to_add
                .iter()
                .map(|bl| BacklinkMutation {
                    uri: bl.uri.as_str().to_owned(),
                    path: path_to_discriminant(bl.path),
                    link_to: bl.link_to.clone(),
                })
                .collect(),
            backlink_remove_uris: input
                .backlinks_to_remove
                .iter()
                .map(|uri| uri.as_str().to_owned())
                .collect(),
        };
        let mutation_set_bytes = mutation_set
            .serialize()
            .map_err(|e| ApplyCommitError::Database(e.to_string()))?;

        let (seq, deferred) = self
            .event_ops
            .append_commit_event_into_batch(
                &mut batch,
                &input.commit_event,
                Some(&mutation_set_bytes),
            )
            .map_err(|e| ApplyCommitError::Database(e.to_string()))?;

        batch
            .commit()
            .map_err(|e| ApplyCommitError::Database(e.to_string()))?;

        self.event_ops.complete_broadcast(deferred);

        Ok(ApplyCommitResult {
            seq: seq.as_i64(),
            is_account_active: is_active,
        })
    }

    pub fn import_repo_data(
        &self,
        user_id: Uuid,
        blocks: &[ImportBlock],
        records: &[ImportRecord],
        expected_root_cid: Option<&CidLink>,
    ) -> Result<(), ImportRepoError> {
        let user_hash = self
            .user_hashes
            .get(&user_id)
            .ok_or(ImportRepoError::RepoNotFound)?;

        let key = repo_meta_key(user_hash);
        let meta = self
            .repo_data
            .get(key.as_slice())
            .map_err(|e| ImportRepoError::Database(e.to_string()))?
            .and_then(|raw| RepoMetaValue::deserialize(&raw))
            .ok_or(ImportRepoError::RepoNotFound)?;

        if let Some(expected) = expected_root_cid {
            let current = bytes_to_cid_link(&meta.repo_root_cid)
                .map_err(|e| ImportRepoError::Database(e.to_string()))?;
            if current != *expected {
                return Err(ImportRepoError::ConcurrentModification);
            }
        }

        if let Some(bs) = &self.blockstore
            && !blocks.is_empty()
        {
            let block_pairs: Vec<([u8; 36], Vec<u8>)> = blocks
                .iter()
                .map(|b| {
                    let cid: [u8; 36] = b.cid_bytes.as_slice().try_into().map_err(|_| {
                        ImportRepoError::Database(format!(
                            "block CID has invalid length: {} (expected 36)",
                            b.cid_bytes.len()
                        ))
                    })?;
                    Ok((cid, b.data.clone()))
                })
                .collect::<Result<Vec<_>, ImportRepoError>>()?;
            bs.put_blocks_blocking(block_pairs)
                .map_err(|e| ImportRepoError::Database(e.to_string()))?;
        }

        let mut batch = self.db.batch();

        let upserts: Vec<RecordWrite<'_>> = records
            .iter()
            .map(|r| RecordWrite {
                collection: &r.collection,
                rkey: &r.rkey,
                cid: &r.record_cid,
            })
            .collect();

        self.record_ops
            .upsert_records(&mut batch, user_hash, &upserts)
            .map_err(|e| ImportRepoError::Database(e.to_string()))?;

        batch
            .commit()
            .map_err(|e| ImportRepoError::Database(e.to_string()))
    }

    pub fn insert_record_blobs(
        &self,
        repo_id: Uuid,
        record_uris: &[AtUri],
        blob_cids: &[CidLink],
    ) -> Result<(), MetastoreError> {
        let user_hash = self
            .user_hashes
            .get(&repo_id)
            .ok_or(MetastoreError::InvalidInput("unknown user_id"))?;

        let blob_bytes: Vec<Vec<u8>> = blob_cids
            .iter()
            .map(cid_link_to_bytes)
            .collect::<Result<_, _>>()?;

        let serialized = RecordBlobsValue {
            blob_cid_bytes: blob_bytes,
        }
        .serialize();

        let mut batch = self.db.batch();
        record_uris.iter().for_each(|uri| {
            let key = record_blobs_key(user_hash, uri);
            batch.insert(&self.repo_data, key.as_slice(), serialized.as_slice());
        });
        batch.commit().map_err(MetastoreError::Fjall)
    }

    pub fn get_users_needing_record_blobs_backfill(
        &self,
        limit: i64,
    ) -> Result<Vec<UserNeedingRecordBlobsBackfill>, MetastoreError> {
        let limit_usize = usize::try_from(limit).unwrap_or(usize::MAX);

        self.scan_users_missing_prefix(
            record_blobs_user_prefix,
            |meta, user_id| {
                let did = meta
                    .did
                    .map(Did::from)
                    .ok_or(MetastoreError::CorruptData("repo_meta missing did field"))?;
                Ok(UserNeedingRecordBlobsBackfill { user_id, did })
            },
            limit_usize,
        )
    }

    pub fn get_broken_genesis_commits(&self) -> Result<Vec<BrokenGenesisCommit>, MetastoreError> {
        const PAGE_SIZE: usize = 4096;
        self.collect_broken_genesis_page(SequenceNumber::ZERO, Vec::new(), PAGE_SIZE)
    }

    fn collect_broken_genesis_page(
        &self,
        cursor: SequenceNumber,
        acc: Vec<BrokenGenesisCommit>,
        page_size: usize,
    ) -> Result<Vec<BrokenGenesisCommit>, MetastoreError> {
        let limit = i64::try_from(page_size).unwrap_or(i64::MAX);
        let events = self
            .event_ops
            .get_events_since_seq(cursor, Some(limit))
            .map_err(|_| MetastoreError::CorruptData("failed to read events"))?;

        let page_len = events.len();
        let page_high_seq = events.last().map(|e| e.seq).unwrap_or(cursor);

        let results = events.into_iter().fold(acc, |mut results, e| {
            if e.event_type == RepoEventType::Commit
                && e.prev_cid.is_none()
                && e.commit_cid.is_none()
            {
                results.push(BrokenGenesisCommit {
                    seq: e.seq,
                    did: e.did,
                    commit_cid: e.commit_cid,
                });
            }
            results
        });

        match page_len < page_size {
            true => Ok(results),
            false => self.collect_broken_genesis_page(page_high_seq, results, page_size),
        }
    }

    pub fn get_users_without_blocks(&self) -> Result<Vec<UserWithoutBlocks>, MetastoreError> {
        const MAX_RESULTS: usize = 10_000;

        self.scan_users_missing_prefix(
            user_block_user_prefix,
            |meta, user_id| {
                let root_cid = bytes_to_cid_link(&meta.repo_root_cid)?;
                Ok(UserWithoutBlocks {
                    user_id,
                    repo_root_cid: root_cid,
                    repo_rev: match meta.repo_rev.is_empty() {
                        true => None,
                        false => Some(meta.repo_rev),
                    },
                })
            },
            MAX_RESULTS,
        )
    }

    fn scan_users_missing_prefix<T, F, P>(
        &self,
        make_prefix: P,
        build_result: F,
        limit: usize,
    ) -> Result<Vec<T>, MetastoreError>
    where
        F: Fn(RepoMetaValue, Uuid) -> Result<T, MetastoreError>,
        P: Fn(UserHash) -> SmallVec<[u8; 128]>,
    {
        let prefix = repo_meta_prefix();

        self.repo_data
            .prefix(prefix.as_slice())
            .filter_map(|guard| {
                let (key_bytes, val_bytes) = match guard.into_inner() {
                    Ok(pair) => pair,
                    Err(e) => return Some(Err(MetastoreError::Fjall(e))),
                };

                let user_hash = match parse_user_hash_from_key(&key_bytes) {
                    Some(h) => h,
                    None => return Some(Err(MetastoreError::CorruptData("invalid repo_meta key"))),
                };

                let check_prefix = make_prefix(user_hash);
                let has_entries = match self.repo_data.prefix(check_prefix.as_slice()).next() {
                    Some(guard) => match guard.into_inner() {
                        Ok(_) => true,
                        Err(e) => return Some(Err(MetastoreError::Fjall(e))),
                    },
                    None => false,
                };

                match has_entries {
                    true => None,
                    false => {
                        let meta = match RepoMetaValue::deserialize(&val_bytes) {
                            Some(v) => v,
                            None => {
                                return Some(Err(MetastoreError::CorruptData(
                                    "invalid repo_meta value",
                                )));
                            }
                        };
                        let user_id = match self.user_hashes.get_uuid(&user_hash) {
                            Some(id) => id,
                            None => {
                                return Some(Err(MetastoreError::CorruptData(
                                    "user_hash has no reverse mapping",
                                )));
                            }
                        };
                        Some(build_result(meta, user_id))
                    }
                }
            })
            .take(limit)
            .collect()
    }
}

fn parse_user_hash_from_key(key_bytes: &[u8]) -> Option<UserHash> {
    use super::encoding::KeyReader;
    let mut reader = KeyReader::new(key_bytes);
    let _tag = reader.tag()?;
    let hash = reader.u64()?;
    Some(UserHash::from_raw(hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eventlog::{EventLog, EventLogConfig};
    use crate::io::RealIO;
    use crate::metastore::{Metastore, MetastoreConfig};
    use tranquil_db_traits::CommitEventData;
    use tranquil_types::{Handle, Nsid, Rkey};

    struct TestHarness {
        _metastore_dir: tempfile::TempDir,
        _eventlog_dir: tempfile::TempDir,
        metastore: Metastore,
        bridge: Arc<EventLogBridge<RealIO>>,
    }

    fn setup() -> TestHarness {
        let metastore_dir = tempfile::TempDir::new().unwrap();
        let eventlog_dir = tempfile::TempDir::new().unwrap();
        let segments_dir = eventlog_dir.path().join("segments");
        std::fs::create_dir_all(&segments_dir).unwrap();

        let metastore = Metastore::open(
            metastore_dir.path(),
            MetastoreConfig {
                cache_size_bytes: 64 * 1024 * 1024,
            },
        )
        .unwrap();

        let event_log = EventLog::open(
            EventLogConfig {
                segments_dir,
                ..EventLogConfig::default()
            },
            RealIO::new(),
        )
        .unwrap();

        let bridge = Arc::new(EventLogBridge::new(Arc::new(event_log)));

        TestHarness {
            _metastore_dir: metastore_dir,
            _eventlog_dir: eventlog_dir,
            metastore,
            bridge,
        }
    }

    fn test_cid_link(seed: u8) -> CidLink {
        let digest: [u8; 32] = std::array::from_fn(|i| seed.wrapping_add(i as u8));
        let mh = multihash::Multihash::<64>::wrap(0x12, &digest).unwrap();
        let c = cid::Cid::new_v1(0x71, mh);
        CidLink::from_cid(&c)
    }

    fn test_did(name: &str) -> Did {
        Did::from(format!("did:plc:{name}"))
    }

    fn test_handle(name: &str) -> Handle {
        Handle::from(format!("{name}.test.invalid"))
    }

    fn make_commit_ops(h: &TestHarness) -> CommitOps<RealIO> {
        use crate::metastore::partitions::Partition;
        CommitOps::new(
            h.metastore.database().clone(),
            h.metastore.partition(Partition::RepoData).clone(),
            h.metastore.partition(Partition::Indexes).clone(),
            Arc::clone(h.metastore.user_hashes()),
            Arc::clone(&h.bridge),
        )
    }

    fn create_test_repo(h: &TestHarness, name: &str, seed: u8) -> (Uuid, Did, CidLink) {
        let user_id = Uuid::new_v4();
        let did = test_did(name);
        let handle = test_handle(name);
        let cid = test_cid_link(seed);
        h.metastore
            .repo_ops()
            .create_repo(h.metastore.database(), user_id, &did, &handle, &cid, "rev0")
            .unwrap();
        (user_id, did, cid)
    }

    #[test]
    fn apply_commit_updates_records_and_meta() {
        let h = setup();
        let ops = make_commit_ops(&h);
        let (user_id, did, root_cid) = create_test_repo(&h, "alice", 1);

        let new_root = test_cid_link(2);
        let record_cid = test_cid_link(3);
        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let rkey = Rkey::from("3k2abc".to_string());

        let input = ApplyCommitInput {
            user_id,
            did: did.clone(),
            expected_root_cid: Some(root_cid.clone()),
            new_root_cid: new_root.clone(),
            new_rev: "rev1".to_string(),
            new_block_cids: vec![vec![0x01, 0x02]],
            obsolete_block_cids: vec![],
            record_upserts: vec![tranquil_db_traits::RecordUpsert {
                collection: collection.clone(),
                rkey: rkey.clone(),
                cid: record_cid.clone(),
            }],
            record_deletes: vec![],
            backlinks_to_add: vec![],
            backlinks_to_remove: vec![],
            commit_event: CommitEventData {
                did: did.clone(),
                event_type: RepoEventType::Commit,
                commit_cid: Some(new_root.clone()),
                prev_cid: Some(root_cid.clone()),
                ops: None,
                blobs: None,
                blocks_cids: None,
                prev_data_cid: None,
                rev: Some("rev1".to_string()),
            },
        };

        let result = ops.apply_commit(input).unwrap();
        assert!(result.seq > 0);
        assert!(result.is_account_active);

        let repo = h.metastore.repo_ops().get_repo(user_id).unwrap().unwrap();
        assert_eq!(repo.repo_root_cid, new_root);
        assert_eq!(repo.repo_rev.as_deref(), Some("rev1"));

        let found_cid = h
            .metastore
            .record_ops()
            .get_record_cid(user_id, &collection, &rkey)
            .unwrap()
            .unwrap();
        assert_eq!(found_cid, record_cid);
    }

    #[test]
    fn apply_commit_cas_rejects_stale_root() {
        let h = setup();
        let ops = make_commit_ops(&h);
        let (user_id, did, _root_cid) = create_test_repo(&h, "bob", 10);

        let stale_root = test_cid_link(99);
        let new_root = test_cid_link(11);

        let input = ApplyCommitInput {
            user_id,
            did,
            expected_root_cid: Some(stale_root),
            new_root_cid: new_root,
            new_rev: "rev1".to_string(),
            new_block_cids: vec![],
            obsolete_block_cids: vec![],
            record_upserts: vec![],
            record_deletes: vec![],
            backlinks_to_add: vec![],
            backlinks_to_remove: vec![],
            commit_event: CommitEventData {
                did: test_did("bob"),
                event_type: RepoEventType::Commit,
                commit_cid: None,
                prev_cid: None,
                ops: None,
                blobs: None,
                blocks_cids: None,
                prev_data_cid: None,
                rev: Some("rev1".to_string()),
            },
        };

        let result = ops.apply_commit(input);
        assert_eq!(
            result.unwrap_err(),
            ApplyCommitError::ConcurrentModification
        );
    }

    #[test]
    fn apply_commit_returns_repo_not_found_for_unknown_user() {
        let h = setup();
        let ops = make_commit_ops(&h);

        let input = ApplyCommitInput {
            user_id: Uuid::new_v4(),
            did: test_did("nobody"),
            expected_root_cid: None,
            new_root_cid: test_cid_link(1),
            new_rev: "rev1".to_string(),
            new_block_cids: vec![],
            obsolete_block_cids: vec![],
            record_upserts: vec![],
            record_deletes: vec![],
            backlinks_to_add: vec![],
            backlinks_to_remove: vec![],
            commit_event: CommitEventData {
                did: test_did("nobody"),
                event_type: RepoEventType::Commit,
                commit_cid: None,
                prev_cid: None,
                ops: None,
                blobs: None,
                blocks_cids: None,
                prev_data_cid: None,
                rev: None,
            },
        };

        assert_eq!(
            ops.apply_commit(input).unwrap_err(),
            ApplyCommitError::RepoNotFound
        );
    }

    #[test]
    fn apply_commit_record_deletes() {
        let h = setup();
        let ops = make_commit_ops(&h);
        let (user_id, did, root_cid) = create_test_repo(&h, "carol", 20);

        let mid_root = test_cid_link(21);
        let record_cid = test_cid_link(22);
        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let rkey = Rkey::from("3k2del".to_string());

        let insert_input = ApplyCommitInput {
            user_id,
            did: did.clone(),
            expected_root_cid: Some(root_cid.clone()),
            new_root_cid: mid_root.clone(),
            new_rev: "rev1".to_string(),
            new_block_cids: vec![],
            obsolete_block_cids: vec![],
            record_upserts: vec![tranquil_db_traits::RecordUpsert {
                collection: collection.clone(),
                rkey: rkey.clone(),
                cid: record_cid,
            }],
            record_deletes: vec![],
            backlinks_to_add: vec![],
            backlinks_to_remove: vec![],
            commit_event: CommitEventData {
                did: did.clone(),
                event_type: RepoEventType::Commit,
                commit_cid: Some(mid_root.clone()),
                prev_cid: None,
                ops: None,
                blobs: None,
                blocks_cids: None,
                prev_data_cid: None,
                rev: Some("rev1".to_string()),
            },
        };
        ops.apply_commit(insert_input).unwrap();

        assert!(
            h.metastore
                .record_ops()
                .get_record_cid(user_id, &collection, &rkey)
                .unwrap()
                .is_some()
        );

        let final_root = test_cid_link(23);
        let delete_input = ApplyCommitInput {
            user_id,
            did: did.clone(),
            expected_root_cid: Some(mid_root.clone()),
            new_root_cid: final_root.clone(),
            new_rev: "rev2".to_string(),
            new_block_cids: vec![],
            obsolete_block_cids: vec![],
            record_upserts: vec![],
            record_deletes: vec![tranquil_db_traits::RecordDelete {
                collection: collection.clone(),
                rkey: rkey.clone(),
            }],
            backlinks_to_add: vec![],
            backlinks_to_remove: vec![],
            commit_event: CommitEventData {
                did: did.clone(),
                event_type: RepoEventType::Commit,
                commit_cid: Some(final_root.clone()),
                prev_cid: Some(mid_root.clone()),
                ops: None,
                blobs: None,
                blocks_cids: None,
                prev_data_cid: None,
                rev: Some("rev2".to_string()),
            },
        };
        ops.apply_commit(delete_input).unwrap();

        assert!(
            h.metastore
                .record_ops()
                .get_record_cid(user_id, &collection, &rkey)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn apply_commit_event_visible_after_commit() {
        let h = setup();
        let ops = make_commit_ops(&h);
        let (user_id, did, root_cid) = create_test_repo(&h, "dave", 30);

        let new_root = test_cid_link(31);
        let input = ApplyCommitInput {
            user_id,
            did: did.clone(),
            expected_root_cid: Some(root_cid.clone()),
            new_root_cid: new_root.clone(),
            new_rev: "rev1".to_string(),
            new_block_cids: vec![],
            obsolete_block_cids: vec![],
            record_upserts: vec![],
            record_deletes: vec![],
            backlinks_to_add: vec![],
            backlinks_to_remove: vec![],
            commit_event: CommitEventData {
                did: did.clone(),
                event_type: RepoEventType::Commit,
                commit_cid: Some(new_root.clone()),
                prev_cid: Some(root_cid.clone()),
                ops: None,
                blobs: None,
                blocks_cids: None,
                prev_data_cid: None,
                rev: Some("rev1".to_string()),
            },
        };

        let result = ops.apply_commit(input).unwrap();
        let seq = SequenceNumber::from_raw(result.seq);

        let event = ops.event_ops.get_event_by_seq(seq).unwrap().unwrap();
        assert_eq!(event.did, did);
        assert_eq!(event.event_type, RepoEventType::Commit);
        assert_eq!(event.rev.as_deref(), Some("rev1"));
    }

    #[test]
    fn import_repo_data_inserts_records() {
        let h = setup();
        let ops = make_commit_ops(&h);
        let (user_id, _did, root_cid) = create_test_repo(&h, "eve", 40);

        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let rkey = Rkey::from("3k2import".to_string());
        let record_cid = test_cid_link(41);

        ops.import_repo_data(
            user_id,
            &[],
            &[ImportRecord {
                collection: collection.clone(),
                rkey: rkey.clone(),
                record_cid: record_cid.clone(),
            }],
            Some(&root_cid),
        )
        .unwrap();

        let found = h
            .metastore
            .record_ops()
            .get_record_cid(user_id, &collection, &rkey)
            .unwrap()
            .unwrap();
        assert_eq!(found, record_cid);
    }

    #[test]
    fn import_repo_data_cas_rejects_stale_root() {
        let h = setup();
        let ops = make_commit_ops(&h);
        let (user_id, _did, _root_cid) = create_test_repo(&h, "frank", 50);

        let stale = test_cid_link(99);
        let result = ops.import_repo_data(user_id, &[], &[], Some(&stale));
        assert_eq!(result.unwrap_err(), ImportRepoError::ConcurrentModification);
    }

    #[test]
    fn insert_record_blobs_and_backfill_query() {
        let h = setup();
        let ops = make_commit_ops(&h);
        let (user_id_a, did_a, _) = create_test_repo(&h, "grace", 60);
        let (user_id_b, _did_b, _) = create_test_repo(&h, "henry", 61);

        let needing = ops.get_users_needing_record_blobs_backfill(100).unwrap();
        assert_eq!(needing.len(), 2);

        let uri = AtUri::from_parts(did_a.as_str(), "app.bsky.feed.post", "3k2abc");
        let blob_cid = test_cid_link(62);
        ops.insert_record_blobs(user_id_a, &[uri], &[blob_cid])
            .unwrap();

        let needing_after = ops.get_users_needing_record_blobs_backfill(100).unwrap();
        assert_eq!(needing_after.len(), 1);
        assert_eq!(needing_after[0].user_id, user_id_b);
    }

    #[test]
    fn get_users_without_blocks_returns_users_with_no_blocks() {
        let h = setup();
        let ops = make_commit_ops(&h);
        let (user_id_a, did_a, root_a) = create_test_repo(&h, "ivan", 70);
        let (user_id_b, _did_b, _root_b) = create_test_repo(&h, "julia", 71);

        let new_root = test_cid_link(72);
        let input = ApplyCommitInput {
            user_id: user_id_a,
            did: did_a.clone(),
            expected_root_cid: Some(root_a),
            new_root_cid: new_root.clone(),
            new_rev: "rev1".to_string(),
            new_block_cids: vec![vec![0x01, 0x02, 0x03]],
            obsolete_block_cids: vec![],
            record_upserts: vec![],
            record_deletes: vec![],
            backlinks_to_add: vec![],
            backlinks_to_remove: vec![],
            commit_event: CommitEventData {
                did: did_a.clone(),
                event_type: RepoEventType::Commit,
                commit_cid: Some(new_root),
                prev_cid: None,
                ops: None,
                blobs: None,
                blocks_cids: None,
                prev_data_cid: None,
                rev: Some("rev1".to_string()),
            },
        };
        ops.apply_commit(input).unwrap();

        let without = ops.get_users_without_blocks().unwrap();
        assert_eq!(without.len(), 1);
        assert_eq!(without[0].user_id, user_id_b);
    }

    #[test]
    fn apply_commit_without_expected_root_skips_cas() {
        let h = setup();
        let ops = make_commit_ops(&h);
        let (user_id, did, _root_cid) = create_test_repo(&h, "kate", 80);

        let new_root = test_cid_link(81);
        let input = ApplyCommitInput {
            user_id,
            did: did.clone(),
            expected_root_cid: None,
            new_root_cid: new_root.clone(),
            new_rev: "rev_force".to_string(),
            new_block_cids: vec![],
            obsolete_block_cids: vec![],
            record_upserts: vec![],
            record_deletes: vec![],
            backlinks_to_add: vec![],
            backlinks_to_remove: vec![],
            commit_event: CommitEventData {
                did,
                event_type: RepoEventType::Commit,
                commit_cid: None,
                prev_cid: None,
                ops: None,
                blobs: None,
                blocks_cids: None,
                prev_data_cid: None,
                rev: Some("rev_force".to_string()),
            },
        };

        let result = ops.apply_commit(input).unwrap();
        assert!(result.seq > 0);
    }

    #[test]
    fn apply_commit_update_preserves_new_backlinks() {
        use crate::metastore::backlinks::backlink_target_prefix;
        use crate::metastore::partitions::Partition;

        let h = setup();
        let ops = make_commit_ops(&h);
        let (user_id, did, root_cid) = create_test_repo(&h, "backlink_upd", 90);

        let collection = Nsid::from("app.bsky.feed.like".to_string());
        let rkey = Rkey::from("3k2like1".to_string());
        let record_cid = test_cid_link(91);
        let record_uri = AtUri::from_parts(did.as_str(), collection.as_str(), rkey.as_str());

        let mid_root = test_cid_link(92);
        let create_input = ApplyCommitInput {
            user_id,
            did: did.clone(),
            expected_root_cid: Some(root_cid.clone()),
            new_root_cid: mid_root.clone(),
            new_rev: "rev1".to_string(),
            new_block_cids: vec![],
            obsolete_block_cids: vec![],
            record_upserts: vec![tranquil_db_traits::RecordUpsert {
                collection: collection.clone(),
                rkey: rkey.clone(),
                cid: record_cid.clone(),
            }],
            record_deletes: vec![],
            backlinks_to_add: vec![tranquil_db_traits::Backlink {
                uri: record_uri.clone(),
                path: tranquil_db_traits::BacklinkPath::SubjectUri,
                link_to: "at://did:plc:target_a/app.bsky.feed.post/p1".to_string(),
            }],
            backlinks_to_remove: vec![],
            commit_event: CommitEventData {
                did: did.clone(),
                event_type: RepoEventType::Commit,
                commit_cid: Some(mid_root.clone()),
                prev_cid: Some(root_cid.clone()),
                ops: None,
                blobs: None,
                blocks_cids: None,
                prev_data_cid: None,
                rev: Some("rev1".to_string()),
            },
        };
        ops.apply_commit(create_input).unwrap();

        let indexes = h.metastore.partition(Partition::Indexes);
        let target_a_prefix = backlink_target_prefix("at://did:plc:target_a/app.bsky.feed.post/p1");
        let count_a_before = indexes
            .prefix(target_a_prefix.as_slice())
            .map(|g| g.into_inner().expect("scan must not fail"))
            .fold(0, |acc, _| acc + 1);
        assert_eq!(count_a_before, 1);

        let final_root = test_cid_link(93);
        let new_record_cid = test_cid_link(94);
        let update_input = ApplyCommitInput {
            user_id,
            did: did.clone(),
            expected_root_cid: Some(mid_root.clone()),
            new_root_cid: final_root.clone(),
            new_rev: "rev2".to_string(),
            new_block_cids: vec![],
            obsolete_block_cids: vec![],
            record_upserts: vec![tranquil_db_traits::RecordUpsert {
                collection: collection.clone(),
                rkey: rkey.clone(),
                cid: new_record_cid.clone(),
            }],
            record_deletes: vec![],
            backlinks_to_add: vec![tranquil_db_traits::Backlink {
                uri: record_uri.clone(),
                path: tranquil_db_traits::BacklinkPath::SubjectUri,
                link_to: "at://did:plc:target_b/app.bsky.feed.post/p2".to_string(),
            }],
            backlinks_to_remove: vec![record_uri],
            commit_event: CommitEventData {
                did: did.clone(),
                event_type: RepoEventType::Commit,
                commit_cid: Some(final_root.clone()),
                prev_cid: Some(mid_root.clone()),
                ops: None,
                blobs: None,
                blocks_cids: None,
                prev_data_cid: None,
                rev: Some("rev2".to_string()),
            },
        };
        ops.apply_commit(update_input).unwrap();

        let count_a_after = indexes
            .prefix(target_a_prefix.as_slice())
            .map(|g| g.into_inner().expect("scan must not fail"))
            .fold(0, |acc, _| acc + 1);
        assert_eq!(count_a_after, 0);

        let target_b_prefix = backlink_target_prefix("at://did:plc:target_b/app.bsky.feed.post/p2");
        let count_b = indexes
            .prefix(target_b_prefix.as_slice())
            .map(|g| g.into_inner().expect("scan must not fail"))
            .fold(0, |acc, _| acc + 1);
        assert_eq!(count_b, 1);
    }

    #[test]
    fn crash_recovery_replays_mutation_set() {
        let metastore_dir = tempfile::TempDir::new().unwrap();
        let eventlog_dir = tempfile::TempDir::new().unwrap();
        let segments_dir = eventlog_dir.path().join("segments");
        std::fs::create_dir_all(&segments_dir).unwrap();

        let user_id = Uuid::new_v4();
        let did = test_did("crash_alice");
        let handle = test_handle("crash_alice");
        let initial_root = test_cid_link(200);
        let new_root = test_cid_link(201);
        let record_cid = test_cid_link(202);
        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let rkey = Rkey::from("3k2crash".to_string());

        let event_log = EventLog::open(
            EventLogConfig {
                segments_dir: segments_dir.clone(),
                ..EventLogConfig::default()
            },
            RealIO::new(),
        )
        .unwrap();
        let event_log = Arc::new(event_log);
        let bridge = Arc::new(EventLogBridge::new(Arc::clone(&event_log)));

        {
            let metastore = Metastore::open(
                metastore_dir.path(),
                MetastoreConfig {
                    cache_size_bytes: 64 * 1024 * 1024,
                },
            )
            .unwrap();

            metastore
                .repo_ops()
                .create_repo(
                    metastore.database(),
                    user_id,
                    &did,
                    &handle,
                    &initial_root,
                    "rev0",
                )
                .unwrap();
            metastore.persist().unwrap();

            let ops = make_commit_ops_from(&metastore, &bridge);
            let input = ApplyCommitInput {
                user_id,
                did: did.clone(),
                expected_root_cid: Some(initial_root.clone()),
                new_root_cid: new_root.clone(),
                new_rev: "rev1".to_string(),
                new_block_cids: vec![vec![0xAA, 0xBB]],
                obsolete_block_cids: vec![],
                record_upserts: vec![tranquil_db_traits::RecordUpsert {
                    collection: collection.clone(),
                    rkey: rkey.clone(),
                    cid: record_cid.clone(),
                }],
                record_deletes: vec![],
                backlinks_to_add: vec![],
                backlinks_to_remove: vec![],
                commit_event: CommitEventData {
                    did: did.clone(),
                    event_type: RepoEventType::Commit,
                    commit_cid: Some(new_root.clone()),
                    prev_cid: Some(initial_root.clone()),
                    ops: None,
                    blobs: None,
                    blocks_cids: None,
                    prev_data_cid: None,
                    rev: Some("rev1".to_string()),
                },
            };

            let result = ops.apply_commit(input).unwrap();
            assert!(result.seq > 0);
            metastore.persist().unwrap();
        }

        {
            let metastore = Metastore::open(
                metastore_dir.path(),
                MetastoreConfig {
                    cache_size_bytes: 64 * 1024 * 1024,
                },
            )
            .unwrap();

            let event_ops = metastore.event_ops(Arc::clone(&bridge));

            event_ops.write_last_applied_cursor_direct(0).unwrap();
            metastore.persist().unwrap();
        }

        {
            let metastore = Metastore::open(
                metastore_dir.path(),
                MetastoreConfig {
                    cache_size_bytes: 64 * 1024 * 1024,
                },
            )
            .unwrap();

            let repo_before = metastore.repo_ops().get_repo(user_id).unwrap().unwrap();
            assert_eq!(repo_before.repo_root_cid, new_root);

            let event_ops = metastore.event_ops(Arc::clone(&bridge));
            let cursor_before = event_ops.read_last_applied_cursor().unwrap();
            assert_eq!(cursor_before, Some(0));

            let indexes = metastore
                .partition(crate::metastore::partitions::Partition::Indexes)
                .clone();
            let recovered = event_ops.recover_metastore_mutations(&indexes).unwrap();
            assert!(recovered > 0, "should replay at least one event");

            let cursor_after = event_ops.read_last_applied_cursor().unwrap();
            assert!(cursor_after.unwrap_or(0) > 0);
        }
    }

    #[test]
    fn crash_recovery_with_uncommitted_batch() {
        let metastore_dir = tempfile::TempDir::new().unwrap();
        let eventlog_dir = tempfile::TempDir::new().unwrap();
        let segments_dir = eventlog_dir.path().join("segments");
        std::fs::create_dir_all(&segments_dir).unwrap();

        let user_id = Uuid::new_v4();
        let did = test_did("crash_bob");
        let handle = test_handle("crash_bob");
        let initial_root = test_cid_link(210);
        let new_root = test_cid_link(211);
        let record_cid = test_cid_link(212);
        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let rkey = Rkey::from("3k2bob".to_string());

        let event_log = EventLog::open(
            EventLogConfig {
                segments_dir: segments_dir.clone(),
                ..EventLogConfig::default()
            },
            RealIO::new(),
        )
        .unwrap();
        let event_log = Arc::new(event_log);
        let bridge = Arc::new(EventLogBridge::new(Arc::clone(&event_log)));

        {
            let metastore = Metastore::open(
                metastore_dir.path(),
                MetastoreConfig {
                    cache_size_bytes: 64 * 1024 * 1024,
                },
            )
            .unwrap();

            metastore
                .repo_ops()
                .create_repo(
                    metastore.database(),
                    user_id,
                    &did,
                    &handle,
                    &initial_root,
                    "rev0",
                )
                .unwrap();
            metastore.persist().unwrap();

            let event_ops = metastore.event_ops(Arc::clone(&bridge));
            let mutation_set = super::CommitMutationSet {
                new_root_cid: super::cid_link_to_bytes(&new_root).unwrap(),
                new_rev: "rev1".to_string(),
                record_upserts: vec![super::RecordMutationUpsert {
                    collection: collection.as_str().to_owned(),
                    rkey: rkey.as_str().to_owned(),
                    cid_bytes: super::cid_link_to_bytes(&record_cid).unwrap(),
                }],
                record_deletes: vec![],
                block_inserts: vec![vec![0xCC, 0xDD]],
                block_deletes: vec![],
                backlink_adds: vec![],
                backlink_remove_uris: vec![],
            };
            let ms_bytes = mutation_set.serialize().unwrap();

            let commit_data = CommitEventData {
                did: did.clone(),
                event_type: RepoEventType::Commit,
                commit_cid: Some(new_root.clone()),
                prev_cid: Some(initial_root.clone()),
                ops: None,
                blobs: None,
                blocks_cids: None,
                prev_data_cid: None,
                rev: Some("rev1".to_string()),
            };

            let mut batch = metastore.database().batch();
            let (_seq, deferred) = event_ops
                .append_commit_event_into_batch(&mut batch, &commit_data, Some(&ms_bytes))
                .unwrap();

            event_ops.complete_broadcast(deferred);

            drop(batch);

            metastore.persist().unwrap();
        }

        {
            let metastore = Metastore::open(
                metastore_dir.path(),
                MetastoreConfig {
                    cache_size_bytes: 64 * 1024 * 1024,
                },
            )
            .unwrap();

            let repo = metastore.repo_ops().get_repo(user_id).unwrap().unwrap();
            assert_eq!(repo.repo_root_cid, initial_root);

            let record = metastore
                .record_ops()
                .get_record_cid(user_id, &collection, &rkey)
                .unwrap();
            assert!(record.is_none());

            let event_ops = metastore.event_ops(Arc::clone(&bridge));
            let indexes = metastore
                .partition(crate::metastore::partitions::Partition::Indexes)
                .clone();
            let recovered = event_ops.recover_metastore_mutations(&indexes).unwrap();
            assert_eq!(recovered, 1);

            let repo_after = metastore.repo_ops().get_repo(user_id).unwrap().unwrap();
            assert_eq!(repo_after.repo_root_cid, new_root);
            assert_eq!(repo_after.repo_rev.as_deref(), Some("rev1"));

            let record_after = metastore
                .record_ops()
                .get_record_cid(user_id, &collection, &rkey)
                .unwrap();
            assert_eq!(record_after, Some(record_cid));
        }
    }

    fn make_commit_ops_from(
        metastore: &Metastore,
        bridge: &Arc<EventLogBridge<RealIO>>,
    ) -> CommitOps<RealIO> {
        use crate::metastore::partitions::Partition;
        CommitOps::new(
            metastore.database().clone(),
            metastore.partition(Partition::RepoData).clone(),
            metastore.partition(Partition::Indexes).clone(),
            Arc::clone(metastore.user_hashes()),
            Arc::clone(bridge),
        )
    }

    #[test]
    fn apply_commit_backlinks_isolated_by_collection() {
        use crate::metastore::backlinks::{backlink_by_user_prefix, backlink_target_prefix};
        use crate::metastore::partitions::Partition;

        let h = setup();
        let ops = make_commit_ops(&h);
        let (user_id, did, root_cid) = create_test_repo(&h, "col_iso", 95);

        let col_like = Nsid::from("app.bsky.feed.like".to_string());
        let col_repost = Nsid::from("app.bsky.feed.repost".to_string());
        let rkey = Rkey::from("same_rkey".to_string());
        let target = "at://did:plc:someone/app.bsky.feed.post/p1";

        let mid_root = test_cid_link(96);
        let uri_like = AtUri::from_parts(did.as_str(), col_like.as_str(), rkey.as_str());
        let uri_repost = AtUri::from_parts(did.as_str(), col_repost.as_str(), rkey.as_str());

        let input = ApplyCommitInput {
            user_id,
            did: did.clone(),
            expected_root_cid: Some(root_cid.clone()),
            new_root_cid: mid_root.clone(),
            new_rev: "rev1".to_string(),
            new_block_cids: vec![],
            obsolete_block_cids: vec![],
            record_upserts: vec![
                tranquil_db_traits::RecordUpsert {
                    collection: col_like.clone(),
                    rkey: rkey.clone(),
                    cid: test_cid_link(97),
                },
                tranquil_db_traits::RecordUpsert {
                    collection: col_repost.clone(),
                    rkey: rkey.clone(),
                    cid: test_cid_link(98),
                },
            ],
            record_deletes: vec![],
            backlinks_to_add: vec![
                tranquil_db_traits::Backlink {
                    uri: uri_like.clone(),
                    path: tranquil_db_traits::BacklinkPath::SubjectUri,
                    link_to: target.to_string(),
                },
                tranquil_db_traits::Backlink {
                    uri: uri_repost.clone(),
                    path: tranquil_db_traits::BacklinkPath::SubjectUri,
                    link_to: target.to_string(),
                },
            ],
            backlinks_to_remove: vec![],
            commit_event: CommitEventData {
                did: did.clone(),
                event_type: RepoEventType::Commit,
                commit_cid: Some(mid_root.clone()),
                prev_cid: Some(root_cid.clone()),
                ops: None,
                blobs: None,
                blocks_cids: None,
                prev_data_cid: None,
                rev: Some("rev1".to_string()),
            },
        };
        ops.apply_commit(input).unwrap();

        let indexes = h.metastore.partition(Partition::Indexes);
        let user_hash = h.metastore.user_hashes().get(&user_id).unwrap();
        let target_prefix = backlink_target_prefix(target);
        let user_prefix = backlink_by_user_prefix(user_hash);

        assert_eq!(
            indexes
                .prefix(target_prefix.as_slice())
                .map(|g| g.into_inner().expect("scan must not fail"))
                .fold(0, |acc, _| acc + 1),
            2
        );
        assert_eq!(
            indexes
                .prefix(user_prefix.as_slice())
                .map(|g| g.into_inner().expect("scan must not fail"))
                .fold(0, |acc, _| acc + 1),
            2
        );

        let final_root = test_cid_link(99);
        let remove_like = ApplyCommitInput {
            user_id,
            did: did.clone(),
            expected_root_cid: Some(mid_root.clone()),
            new_root_cid: final_root.clone(),
            new_rev: "rev2".to_string(),
            new_block_cids: vec![],
            obsolete_block_cids: vec![],
            record_upserts: vec![],
            record_deletes: vec![],
            backlinks_to_add: vec![],
            backlinks_to_remove: vec![uri_like],
            commit_event: CommitEventData {
                did: did.clone(),
                event_type: RepoEventType::Commit,
                commit_cid: Some(final_root.clone()),
                prev_cid: Some(mid_root.clone()),
                ops: None,
                blobs: None,
                blocks_cids: None,
                prev_data_cid: None,
                rev: Some("rev2".to_string()),
            },
        };
        ops.apply_commit(remove_like).unwrap();

        assert_eq!(
            indexes
                .prefix(target_prefix.as_slice())
                .map(|g| g.into_inner().expect("scan must not fail"))
                .fold(0, |acc, _| acc + 1),
            1
        );
        assert_eq!(
            indexes
                .prefix(user_prefix.as_slice())
                .map(|g| g.into_inner().expect("scan must not fail"))
                .fold(0, |acc, _| acc + 1),
            1
        );
    }
}
