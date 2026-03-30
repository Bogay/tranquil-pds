use std::collections::HashSet;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use fjall::{Database, Keyspace};
use tracing::warn;
use tranquil_db_traits::{
    AccountStatus, CommitEventData, DbError, RepoEventType, SequenceNumber, SequencedEvent,
};
use tranquil_types::{CidLink, Did, Handle};

use super::encoding::{KeyReader, exclusive_upper_bound};
use super::event_keys::{
    did_events_key, did_events_prefix, metastore_cursor_key, rev_to_seq_key,
    rev_to_seq_user_prefix, seq_tombstone_key,
};
use super::keys::UserHash;
use super::recovery::CommitMutationSet;
use super::repo_meta::RepoMetaValue;
use crate::eventlog::{DeferredBroadcast, EventLogBridge, EventLogNotifier};
use crate::io::StorageIO;

const RECOVERY_BATCH_SIZE: usize = 4096;

pub struct EventOps<S: StorageIO> {
    db: Database,
    repo_data: Keyspace,
    bridge: Arc<EventLogBridge<S>>,
}

impl<S: StorageIO + 'static> EventOps<S> {
    pub fn new(db: Database, repo_data: Keyspace, bridge: Arc<EventLogBridge<S>>) -> Self {
        Self {
            db,
            repo_data,
            bridge,
        }
    }

    pub fn notifier(&self) -> EventLogNotifier<S> {
        self.bridge.notifier()
    }

    pub fn notify_update(&self, _seq: SequenceNumber) -> Result<(), DbError> {
        Ok(())
    }

    pub fn insert_commit_event(&self, data: &CommitEventData) -> Result<SequenceNumber, DbError> {
        let event = Self::build_commit_event(data);
        self.append_and_index(&event, &data.did, data.rev.as_deref())
    }

    pub fn append_commit_event_into_batch(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        data: &CommitEventData,
        mutation_set_bytes: Option<&[u8]>,
    ) -> Result<(SequenceNumber, DeferredBroadcast), DbError> {
        let event = Self::build_commit_event(data);
        let payload = crate::eventlog::encode_payload_with_mutations(&event, mutation_set_bytes);
        let (seq, deferred) = self
            .bridge
            .insert_event_group_commit_raw(&data.did, data.event_type, payload)
            .map_err(|e| DbError::Query(e.to_string()))?;

        let seq_u64 = seq_to_u64(seq)?;
        let user_hash = UserHash::from_did(data.did.as_str());
        self.stage_did_event(batch, user_hash, seq_u64);
        if let Some(rev) = &data.rev {
            self.stage_rev_to_seq(batch, user_hash, rev, seq_u64);
        }
        self.write_last_applied_cursor(batch, seq_u64);

        Ok((seq, deferred))
    }

    pub fn complete_broadcast(&self, deferred: DeferredBroadcast) {
        self.bridge.complete_broadcast(deferred);
    }

    fn build_commit_event(data: &CommitEventData) -> SequencedEvent {
        SequencedEvent {
            seq: SequenceNumber::ZERO,
            did: data.did.clone(),
            created_at: Utc::now(),
            event_type: data.event_type,
            commit_cid: data.commit_cid.clone(),
            prev_cid: data.prev_cid.clone(),
            prev_data_cid: data.prev_data_cid.clone(),
            ops: data.ops.clone(),
            blobs: data.blobs.clone(),
            blocks: data
                .blocks
                .clone()
                .map(tranquil_db_traits::EventBlocks::Inline),
            handle: None,
            active: None,
            status: None,
            rev: data.rev.clone(),
        }
    }

    pub fn insert_identity_event(
        &self,
        did: &Did,
        handle: Option<&Handle>,
    ) -> Result<SequenceNumber, DbError> {
        let event = SequencedEvent {
            seq: SequenceNumber::ZERO,
            did: did.clone(),
            created_at: Utc::now(),
            event_type: RepoEventType::Identity,
            commit_cid: None,
            prev_cid: None,
            prev_data_cid: None,
            ops: None,
            blobs: None,
            blocks: None,
            handle: handle.cloned(),
            active: None,
            status: None,
            rev: None,
        };

        self.append_and_index(&event, did, None)
    }

    pub fn insert_account_event(
        &self,
        did: &Did,
        status: AccountStatus,
    ) -> Result<SequenceNumber, DbError> {
        let active = Some(status.is_active());
        let event = SequencedEvent {
            seq: SequenceNumber::ZERO,
            did: did.clone(),
            created_at: Utc::now(),
            event_type: RepoEventType::Account,
            commit_cid: None,
            prev_cid: None,
            prev_data_cid: None,
            ops: None,
            blobs: None,
            blocks: None,
            handle: None,
            active,
            status: Some(status),
            rev: None,
        };

        self.append_and_index(&event, did, None)
    }

    pub fn insert_sync_event(
        &self,
        did: &Did,
        commit_cid: &CidLink,
        rev: Option<&str>,
        commit_bytes: &[u8],
    ) -> Result<SequenceNumber, DbError> {
        let inline = tranquil_db_traits::EventBlockInline {
            cid_bytes: commit_cid
                .to_cid()
                .expect("CidLink invariant: validated at construction")
                .to_bytes(),
            data: commit_bytes.to_vec(),
        };
        let event = SequencedEvent {
            seq: SequenceNumber::ZERO,
            did: did.clone(),
            created_at: Utc::now(),
            event_type: RepoEventType::Sync,
            commit_cid: Some(commit_cid.clone()),
            prev_cid: None,
            prev_data_cid: None,
            ops: None,
            blobs: None,
            blocks: Some(tranquil_db_traits::EventBlocks::Inline(vec![inline])),
            handle: None,
            active: None,
            status: None,
            rev: rev.map(str::to_owned),
        };

        self.append_and_index(&event, did, rev)
    }

    pub fn insert_genesis_commit_event(
        &self,
        did: &Did,
        commit_cid: &CidLink,
        mst_root_cid: &CidLink,
        rev: &str,
        commit_bytes: &[u8],
        mst_root_bytes: &[u8],
    ) -> Result<SequenceNumber, DbError> {
        let commit_block = tranquil_db_traits::EventBlockInline {
            cid_bytes: commit_cid
                .to_cid()
                .expect("CidLink invariant: validated at construction")
                .to_bytes(),
            data: commit_bytes.to_vec(),
        };
        let mst_block = tranquil_db_traits::EventBlockInline {
            cid_bytes: mst_root_cid
                .to_cid()
                .expect("CidLink invariant: validated at construction")
                .to_bytes(),
            data: mst_root_bytes.to_vec(),
        };
        let event = SequencedEvent {
            seq: SequenceNumber::ZERO,
            did: did.clone(),
            created_at: Utc::now(),
            event_type: RepoEventType::Commit,
            commit_cid: Some(commit_cid.clone()),
            prev_cid: None,
            prev_data_cid: Some(mst_root_cid.clone()),
            ops: None,
            blobs: None,
            blocks: Some(tranquil_db_traits::EventBlocks::Inline(vec![
                commit_block,
                mst_block,
            ])),
            handle: None,
            active: None,
            status: None,
            rev: Some(rev.to_owned()),
        };

        self.append_and_index(&event, did, Some(rev))
    }

    pub fn get_events_since_seq(
        &self,
        since: SequenceNumber,
        limit: Option<i64>,
    ) -> Result<Vec<SequencedEvent>, DbError> {
        let events = self.bridge.get_events_since_seq(since, limit)?;
        self.filter_tombstoned(events)
    }

    pub fn get_events_in_seq_range(
        &self,
        start: SequenceNumber,
        end: SequenceNumber,
    ) -> Result<Vec<SequencedEvent>, DbError> {
        let events = self.bridge.get_events_in_seq_range(start, end)?;
        self.filter_tombstoned(events)
    }

    pub fn get_event_by_seq(&self, seq: SequenceNumber) -> Result<Option<SequencedEvent>, DbError> {
        let seq_u64 = match seq.as_u64() {
            Some(v) => v,
            None => return Ok(None),
        };

        if self.is_tombstoned(seq_u64)? {
            return Ok(None);
        }

        self.bridge.get_event_by_seq(seq)
    }

    pub fn get_events_since_cursor(
        &self,
        cursor: SequenceNumber,
        limit: i64,
    ) -> Result<Vec<SequencedEvent>, DbError> {
        let events = self.bridge.get_events_since_cursor(cursor, limit)?;
        self.filter_tombstoned(events)
    }

    pub fn get_max_seq(&self) -> SequenceNumber {
        self.bridge.get_max_seq()
    }

    pub fn get_min_seq_since(
        &self,
        since: DateTime<Utc>,
    ) -> Result<Option<SequenceNumber>, DbError> {
        self.bridge.get_min_seq_since(since)
    }

    pub fn get_blob_cids_since_rev(
        &self,
        did: &Did,
        since_rev: &str,
    ) -> Result<Vec<CidLink>, DbError> {
        let user_hash = UserHash::from_did(did.as_str());

        let key = rev_to_seq_key(user_hash, since_rev);
        let since_seq_u64 = match self.repo_data.get(key).map_err(fjall_to_db)? {
            Some(bytes) => {
                let arr: [u8; 8] = bytes
                    .as_ref()
                    .try_into()
                    .map_err(|_| DbError::Query("corrupt rev_to_seq value".to_owned()))?;
                u64::from_be_bytes(arr)
            }
            None => return Ok(Vec::new()),
        };

        let start_seq = match since_seq_u64.checked_add(1) {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };

        let user_seqs = self.scan_did_events(user_hash, start_seq)?;

        let mut seen = std::collections::BTreeSet::new();
        user_seqs
            .into_iter()
            .try_fold(Vec::new(), |mut acc, seq_u64| {
                if self.is_tombstoned(seq_u64)? {
                    return Ok(acc);
                }
                let seq_sn = SequenceNumber::from_raw(
                    i64::try_from(seq_u64)
                        .map_err(|_| DbError::Query("seq exceeds i64::MAX".to_owned()))?,
                );
                match self.bridge.get_event_by_seq(seq_sn)? {
                    Some(event) if event.rev.is_some() => {
                        if let Some(blobs) = event.blobs {
                            acc.extend(
                                blobs
                                    .into_iter()
                                    .filter(|b| seen.insert(b.clone()))
                                    .map(CidLink::from),
                            );
                        }
                        Ok(acc)
                    }
                    _ => Ok(acc),
                }
            })
    }

    pub fn delete_sequences_except(
        &self,
        did: &Did,
        keep_seq: SequenceNumber,
    ) -> Result<(), DbError> {
        let keep_raw = keep_seq.as_u64().ok_or_else(|| {
            DbError::Query("invalid keep_seq: negative sequence number".to_owned())
        })?;

        let user_hash = UserHash::from_did(did.as_str());

        let prefix = did_events_prefix(user_hash);
        let upper = exclusive_upper_bound(prefix.as_slice())
            .expect("did_events prefix can never be all-0xFF");

        let seqs_to_tombstone: Result<Vec<u64>, DbError> = self
            .repo_data
            .range(prefix.as_slice()..upper.as_slice())
            .map(|guard| {
                let (key, _) = guard.into_inner().map_err(fjall_to_db)?;
                decode_did_events_seq(key.as_ref())
            })
            .filter(|result| match result {
                Ok(seq) => *seq != keep_raw,
                Err(_) => true,
            })
            .collect();

        let seqs = seqs_to_tombstone?;
        let tombstone_set: HashSet<u64> = seqs.iter().copied().collect();

        let stale_rev_keys = self.collect_stale_rev_keys(user_hash, &tombstone_set)?;

        let mut batch = self.db.batch();
        seqs.iter().for_each(|&seq| {
            batch.insert(&self.repo_data, seq_tombstone_key(seq).as_slice(), []);
            batch.remove(&self.repo_data, did_events_key(user_hash, seq).as_slice());
        });
        stale_rev_keys.iter().for_each(|key| {
            batch.remove(&self.repo_data, key.as_slice());
        });
        batch.commit().map_err(fjall_to_db)?;

        Ok(())
    }

    pub fn read_last_applied_cursor(&self) -> Result<Option<u64>, DbError> {
        let key = metastore_cursor_key();
        match self.repo_data.get(key.as_slice()).map_err(fjall_to_db)? {
            Some(bytes) => {
                let arr: [u8; 8] = bytes
                    .as_ref()
                    .try_into()
                    .map_err(|_| DbError::Query("corrupt metastore cursor".to_owned()))?;
                Ok(Some(u64::from_be_bytes(arr)))
            }
            None => Ok(None),
        }
    }

    pub fn write_last_applied_cursor(&self, batch: &mut fjall::OwnedWriteBatch, seq: u64) {
        let key = metastore_cursor_key();
        batch.insert(&self.repo_data, key.as_slice(), seq.to_be_bytes());
    }

    pub fn write_last_applied_cursor_direct(&self, seq: u64) -> Result<(), DbError> {
        let key = metastore_cursor_key();
        self.repo_data
            .insert(key.as_slice(), seq.to_be_bytes())
            .map_err(fjall_to_db)
    }

    pub fn recover_sidecar_indexes(&self) -> Result<u64, DbError> {
        let cursor_seq = self.read_last_applied_cursor()?.unwrap_or(0);
        let max_raw = self.bridge.get_max_seq().as_u64().unwrap_or(0);

        match max_raw <= cursor_seq {
            true => Ok(0),
            false => self.recover_page(cursor_seq, 0),
        }
    }

    pub fn recover_metastore_mutations(&self, indexes: &fjall::Keyspace) -> Result<u64, DbError> {
        let cursor_seq = self.read_last_applied_cursor()?.unwrap_or(0);
        let max_raw = self.bridge.get_max_seq().as_u64().unwrap_or(0);

        match max_raw <= cursor_seq {
            true => Ok(0),
            false => {
                tracing::info!(
                    cursor = cursor_seq,
                    eventlog_max = max_raw,
                    gap = max_raw.saturating_sub(cursor_seq),
                    "replaying metastore mutations from eventlog"
                );
                self.recover_mutations_page(indexes, cursor_seq, 0)
            }
        }
    }

    fn recover_mutations_page(
        &self,
        indexes: &fjall::Keyspace,
        cursor: u64,
        total: u64,
    ) -> Result<u64, DbError> {
        let cursor_sn = SequenceNumber::from_raw(
            i64::try_from(cursor)
                .map_err(|_| DbError::Query("recovery cursor exceeds i64::MAX".to_owned()))?,
        );
        let events_with_mutations = self
            .bridge
            .get_events_with_mutations_since(cursor_sn, RECOVERY_BATCH_SIZE)?;

        match events_with_mutations.is_empty() {
            true => Ok(total),
            false => {
                let page_len = events_with_mutations.len();
                let mut page_high = cursor;
                let mut count = 0u64;

                events_with_mutations.iter().try_for_each(|ewm| {
                    let seq_u64 = match ewm.event.seq.as_u64() {
                        Some(v) => v,
                        None => return Ok(()),
                    };
                    let user_hash = UserHash::from_did(ewm.event.did.as_str());

                    let mut batch = self.db.batch();

                    self.stage_did_event(&mut batch, user_hash, seq_u64);
                    if let Some(rev) = &ewm.event.rev {
                        self.stage_rev_to_seq(&mut batch, user_hash, rev, seq_u64);
                    }

                    if let Some(ms_bytes) = &ewm.mutation_set {
                        let ms = CommitMutationSet::deserialize(ms_bytes).ok_or_else(|| {
                            DbError::Query(format!("corrupt CommitMutationSet at seq {seq_u64}"))
                        })?;

                        let meta_key = super::repo_meta::repo_meta_key(user_hash);
                        let current_meta = self
                            .repo_data
                            .get(meta_key.as_slice())
                            .map_err(fjall_to_db)?
                            .and_then(|raw| RepoMetaValue::deserialize(&raw))
                            .unwrap_or_else(|| RepoMetaValue {
                                repo_root_cid: vec![],
                                repo_rev: String::new(),
                                handle: String::new(),
                                status: super::repo_meta::RepoStatus::Active,
                                deactivated_at_ms: None,
                                takedown_ref: None,
                                did: Some(ewm.event.did.as_str().to_owned()),
                            });

                        super::recovery::replay_mutation_set(
                            &mut batch,
                            &self.repo_data,
                            indexes,
                            user_hash,
                            &current_meta,
                            &ms,
                        )
                        .map_err(|e| DbError::Query(e.to_string()))?;
                    }

                    self.write_last_applied_cursor(&mut batch, seq_u64);
                    batch.commit().map_err(fjall_to_db)?;

                    page_high = seq_u64.max(page_high);
                    count = count.saturating_add(1);
                    Ok::<_, DbError>(())
                })?;

                let new_total = total.saturating_add(count);
                match page_len < RECOVERY_BATCH_SIZE {
                    true => Ok(new_total),
                    false => self.recover_mutations_page(indexes, page_high, new_total),
                }
            }
        }
    }

    fn recover_page(&self, cursor: u64, total: u64) -> Result<u64, DbError> {
        let cursor_sn = SequenceNumber::from_raw(
            i64::try_from(cursor)
                .map_err(|_| DbError::Query("recovery cursor exceeds i64::MAX".to_owned()))?,
        );
        let events = self
            .bridge
            .get_events_since_seq(cursor_sn, Some(RECOVERY_BATCH_SIZE as i64))?;

        match events.is_empty() {
            true => Ok(total),
            false => {
                let page_len = events.len();
                let mut batch = self.db.batch();

                let (batch_high, count) =
                    events.iter().fold((cursor, 0u64), |(high, count), event| {
                        let seq_u64 = match event.seq.as_u64() {
                            Some(v) => v,
                            None => return (high, count),
                        };
                        let user_hash = UserHash::from_did(event.did.as_str());

                        self.stage_did_event(&mut batch, user_hash, seq_u64);
                        if let Some(rev) = &event.rev {
                            self.stage_rev_to_seq(&mut batch, user_hash, rev, seq_u64);
                        }

                        (seq_u64.max(high), count.saturating_add(1))
                    });

                self.write_last_applied_cursor(&mut batch, batch_high);
                batch.commit().map_err(fjall_to_db)?;

                let new_total = total.saturating_add(count);
                match page_len < RECOVERY_BATCH_SIZE {
                    true => Ok(new_total),
                    false => self.recover_page(batch_high, new_total),
                }
            }
        }
    }

    pub fn append_and_stage_indexes(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        event: &SequencedEvent,
        did: &Did,
        rev: Option<&str>,
    ) -> Result<SequenceNumber, DbError> {
        let seq = self
            .bridge
            .insert_event(event)
            .map_err(|e| DbError::Query(e.to_string()))?;

        let seq_u64 = seq_to_u64(seq)?;
        let user_hash = UserHash::from_did(did.as_str());
        self.stage_did_event(batch, user_hash, seq_u64);
        if let Some(rev) = rev {
            self.stage_rev_to_seq(batch, user_hash, rev, seq_u64);
        }
        self.write_last_applied_cursor(batch, seq_u64);

        Ok(seq)
    }

    fn append_and_index(
        &self,
        event: &SequencedEvent,
        did: &Did,
        rev: Option<&str>,
    ) -> Result<SequenceNumber, DbError> {
        let mut batch = self.db.batch();
        let seq = self.append_and_stage_indexes(&mut batch, event, did, rev)?;
        batch.commit().map_err(fjall_to_db)?;
        Ok(seq)
    }

    fn stage_did_event(&self, batch: &mut fjall::OwnedWriteBatch, user_hash: UserHash, seq: u64) {
        let key = did_events_key(user_hash, seq);
        batch.insert(&self.repo_data, key.as_slice(), []);
    }

    fn stage_rev_to_seq(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        user_hash: UserHash,
        rev: &str,
        seq: u64,
    ) {
        let key = rev_to_seq_key(user_hash, rev);
        batch.insert(&self.repo_data, key.as_slice(), seq.to_be_bytes());
    }

    fn scan_did_events(&self, user_hash: UserHash, start_seq: u64) -> Result<Vec<u64>, DbError> {
        let range_start = did_events_key(user_hash, start_seq);
        let range_end = exclusive_upper_bound(did_events_prefix(user_hash).as_slice())
            .expect("did_events prefix can never be all-0xFF");

        self.repo_data
            .range(range_start.as_slice()..range_end.as_slice())
            .try_fold(Vec::new(), |mut acc, guard| {
                let (key, _) = guard.into_inner().map_err(fjall_to_db)?;
                let seq = decode_did_events_seq(key.as_ref())?;
                acc.push(seq);
                Ok(acc)
            })
    }

    fn collect_stale_rev_keys(
        &self,
        user_hash: UserHash,
        tombstone_set: &HashSet<u64>,
    ) -> Result<Vec<Vec<u8>>, DbError> {
        let rev_prefix = rev_to_seq_user_prefix(user_hash);
        let rev_upper = exclusive_upper_bound(rev_prefix.as_slice())
            .expect("rev_to_seq prefix can never be all-0xFF");

        self.repo_data
            .range(rev_prefix.as_slice()..rev_upper.as_slice())
            .try_fold(Vec::new(), |mut acc, guard| {
                let (key, val) = guard.into_inner().map_err(fjall_to_db)?;
                let val_arr: [u8; 8] = val
                    .as_ref()
                    .try_into()
                    .map_err(|_| DbError::Query("corrupt rev_to_seq value".to_owned()))?;
                let stored_seq = u64::from_be_bytes(val_arr);
                if tombstone_set.contains(&stored_seq) {
                    acc.push(key.as_ref().to_vec());
                }
                Ok(acc)
            })
    }

    fn is_tombstoned(&self, seq: u64) -> Result<bool, DbError> {
        let key = seq_tombstone_key(seq);
        match self.repo_data.get(key.as_slice()) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => {
                warn!(seq, error = %e, "tombstone check failed, propagating error");
                Err(fjall_to_db(e))
            }
        }
    }

    fn filter_tombstoned(
        &self,
        events: Vec<SequencedEvent>,
    ) -> Result<Vec<SequencedEvent>, DbError> {
        events.into_iter().try_fold(Vec::new(), |mut acc, e| {
            let tombstoned = match e.seq.as_u64() {
                Some(seq_u64) => self.is_tombstoned(seq_u64)?,
                None => false,
            };
            if !tombstoned {
                acc.push(e);
            }
            Ok(acc)
        })
    }
}

fn fjall_to_db(e: fjall::Error) -> DbError {
    DbError::Query(e.to_string())
}

fn seq_to_u64(seq: SequenceNumber) -> Result<u64, DbError> {
    seq.as_u64()
        .ok_or_else(|| DbError::Query("sequence number is negative".to_owned()))
}

fn decode_did_events_seq(key_bytes: &[u8]) -> Result<u64, DbError> {
    let mut reader = KeyReader::new(key_bytes);
    let _tag = reader.tag();
    let _user_hash = reader.u64();
    reader
        .u64()
        .ok_or_else(|| DbError::Query("corrupt did_events key: missing seq field".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eventlog::{EventLog, EventLogConfig};
    use crate::io::RealIO;
    use sha2::Digest;
    use tranquil_db_traits::RepoEventType;

    struct TestHarness {
        _metastore_dir: tempfile::TempDir,
        _eventlog_dir: tempfile::TempDir,
        event_ops: EventOps<RealIO>,
    }

    fn setup() -> TestHarness {
        let metastore_dir = tempfile::TempDir::new().unwrap();
        let eventlog_dir = tempfile::TempDir::new().unwrap();
        let segments_dir = eventlog_dir.path().join("segments");
        std::fs::create_dir_all(&segments_dir).unwrap();

        let db = fjall::Database::builder(metastore_dir.path())
            .open()
            .unwrap();
        let repo_data = db
            .keyspace("repo_data", fjall::KeyspaceCreateOptions::default)
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
        let event_ops = EventOps::new(db, repo_data, bridge);

        TestHarness {
            _metastore_dir: metastore_dir,
            _eventlog_dir: eventlog_dir,
            event_ops,
        }
    }

    fn test_did() -> Did {
        Did::new("did:plc:testuser1234567890abcdef").unwrap()
    }

    fn test_cid_link() -> CidLink {
        let hash = sha2::Digest::finalize(sha2::Sha256::new());
        let mh = multihash::Multihash::<64>::wrap(0x12, &hash).unwrap();
        let c = cid::Cid::new_v1(0x71, mh);
        CidLink::from_cid(&c)
    }

    #[test]
    fn insert_and_query_commit_event() {
        let h = setup();
        let cid = test_cid_link();
        let data = CommitEventData {
            did: test_did(),
            event_type: RepoEventType::Commit,
            commit_cid: Some(cid.clone()),
            prev_cid: None,
            ops: Some(serde_json::json!([{"action": "create", "path": "app.bsky.feed.post/abc"}])),
            blobs: None,
            blocks: None,
            prev_data_cid: None,
            rev: Some("3k2abcde".to_owned()),
        };

        let seq = h.event_ops.insert_commit_event(&data).unwrap();
        assert!(seq.as_i64() > 0);

        let event = h.event_ops.get_event_by_seq(seq).unwrap().unwrap();
        assert_eq!(event.did.as_str(), test_did().as_str());
        assert_eq!(event.event_type, RepoEventType::Commit);
        assert_eq!(event.commit_cid, Some(cid));
        assert_eq!(event.rev, Some("3k2abcde".to_owned()));
    }

    #[test]
    fn insert_and_query_identity_event() {
        let h = setup();
        let handle = Handle::new("olaren.test").unwrap();

        let seq = h
            .event_ops
            .insert_identity_event(&test_did(), Some(&handle))
            .unwrap();
        assert!(seq.as_i64() > 0);

        let event = h.event_ops.get_event_by_seq(seq).unwrap().unwrap();
        assert_eq!(event.event_type, RepoEventType::Identity);
        assert_eq!(
            event.handle.as_ref().map(|h| h.as_str()),
            Some("olaren.test")
        );
    }

    #[test]
    fn insert_and_query_account_event() {
        let h = setup();

        let seq = h
            .event_ops
            .insert_account_event(&test_did(), AccountStatus::Deactivated)
            .unwrap();
        assert!(seq.as_i64() > 0);

        let event = h.event_ops.get_event_by_seq(seq).unwrap().unwrap();
        assert_eq!(event.event_type, RepoEventType::Account);
        assert_eq!(event.status, Some(AccountStatus::Deactivated));
    }

    #[test]
    fn insert_and_query_sync_event() {
        let h = setup();
        let cid = test_cid_link();

        let seq = h
            .event_ops
            .insert_sync_event(&test_did(), &cid, Some("rev1"), b"sync_commit_bytes")
            .unwrap();
        assert!(seq.as_i64() > 0);

        let event = h.event_ops.get_event_by_seq(seq).unwrap().unwrap();
        assert_eq!(event.event_type, RepoEventType::Sync);
        assert_eq!(event.commit_cid, Some(cid));
        assert_eq!(event.rev, Some("rev1".to_owned()));
    }

    #[test]
    fn insert_genesis_commit_event() {
        let h = setup();
        let commit_cid = test_cid_link();
        let mst_cid = test_cid_link();

        let seq = h
            .event_ops
            .insert_genesis_commit_event(
                &test_did(),
                &commit_cid,
                &mst_cid,
                "genesis_rev",
                b"genesis_commit_bytes",
                b"genesis_mst_bytes",
            )
            .unwrap();
        assert!(seq.as_i64() > 0);

        let event = h.event_ops.get_event_by_seq(seq).unwrap().unwrap();
        assert_eq!(event.event_type, RepoEventType::Commit);
        assert_eq!(event.commit_cid, Some(commit_cid));
        assert_eq!(event.prev_data_cid, Some(mst_cid));
        assert_eq!(event.rev, Some("genesis_rev".to_owned()));
    }

    #[test]
    fn get_events_since_seq_returns_ordered() {
        let h = setup();
        let did = test_did();

        let seq1 = h
            .event_ops
            .insert_account_event(&did, AccountStatus::Active)
            .unwrap();
        let seq2 = h.event_ops.insert_identity_event(&did, None).unwrap();

        let events = h
            .event_ops
            .get_events_since_seq(SequenceNumber::ZERO, None)
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].seq, seq1);
        assert_eq!(events[1].seq, seq2);
    }

    #[test]
    fn get_events_since_seq_with_limit() {
        let h = setup();
        let did = test_did();

        h.event_ops
            .insert_account_event(&did, AccountStatus::Active)
            .unwrap();
        h.event_ops.insert_identity_event(&did, None).unwrap();

        let events = h
            .event_ops
            .get_events_since_seq(SequenceNumber::ZERO, Some(1))
            .unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn get_events_in_seq_range() {
        let h = setup();
        let did = test_did();

        let seq1 = h
            .event_ops
            .insert_account_event(&did, AccountStatus::Active)
            .unwrap();
        let seq2 = h.event_ops.insert_identity_event(&did, None).unwrap();
        let _seq3 = h.event_ops.insert_identity_event(&did, None).unwrap();

        let events = h
            .event_ops
            .get_events_in_seq_range(SequenceNumber::ZERO, seq2)
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].seq, seq1);
    }

    #[test]
    fn cursor_pagination() {
        let h = setup();
        let did = test_did();

        let seqs: Vec<SequenceNumber> = (0..5)
            .map(|_| h.event_ops.insert_identity_event(&did, None).unwrap())
            .collect();

        let page1 = h
            .event_ops
            .get_events_since_cursor(SequenceNumber::ZERO, 2)
            .unwrap();
        assert_eq!(page1.len(), 2);
        assert_eq!(page1[0].seq, seqs[0]);
        assert_eq!(page1[1].seq, seqs[1]);

        let page2 = h
            .event_ops
            .get_events_since_cursor(page1[1].seq, 2)
            .unwrap();
        assert_eq!(page2.len(), 2);
        assert_eq!(page2[0].seq, seqs[2]);
        assert_eq!(page2[1].seq, seqs[3]);

        let page3 = h
            .event_ops
            .get_events_since_cursor(page2[1].seq, 2)
            .unwrap();
        assert_eq!(page3.len(), 1);
        assert_eq!(page3[0].seq, seqs[4]);
    }

    #[test]
    fn get_max_seq() {
        let h = setup();
        assert_eq!(h.event_ops.get_max_seq(), SequenceNumber::ZERO);

        let seq = h
            .event_ops
            .insert_identity_event(&test_did(), None)
            .unwrap();
        assert_eq!(h.event_ops.get_max_seq(), seq);
    }

    #[test]
    fn delete_sequences_except_tombstones_others() {
        let h = setup();
        let did = test_did();
        let cid = test_cid_link();

        let seq1 = h
            .event_ops
            .insert_commit_event(&CommitEventData {
                did: did.clone(),
                event_type: RepoEventType::Commit,
                commit_cid: Some(cid.clone()),
                prev_cid: None,
                ops: None,
                blobs: None,
                blocks: None,
                prev_data_cid: None,
                rev: Some("rev_a".to_owned()),
            })
            .unwrap();

        let seq2 = h
            .event_ops
            .insert_commit_event(&CommitEventData {
                did: did.clone(),
                event_type: RepoEventType::Commit,
                commit_cid: Some(cid.clone()),
                prev_cid: None,
                ops: None,
                blobs: None,
                blocks: None,
                prev_data_cid: None,
                rev: Some("rev_b".to_owned()),
            })
            .unwrap();

        h.event_ops.delete_sequences_except(&did, seq2).unwrap();

        assert!(h.event_ops.get_event_by_seq(seq1).unwrap().is_none());
        assert!(h.event_ops.get_event_by_seq(seq2).unwrap().is_some());
    }

    #[test]
    fn tombstoned_events_filtered_from_range_queries() {
        let h = setup();
        let did = test_did();
        let cid = test_cid_link();

        let _seq1 = h
            .event_ops
            .insert_commit_event(&CommitEventData {
                did: did.clone(),
                event_type: RepoEventType::Commit,
                commit_cid: Some(cid.clone()),
                prev_cid: None,
                ops: None,
                blobs: None,
                blocks: None,
                prev_data_cid: None,
                rev: Some("rev_x".to_owned()),
            })
            .unwrap();

        let seq2 = h
            .event_ops
            .insert_commit_event(&CommitEventData {
                did: did.clone(),
                event_type: RepoEventType::Commit,
                commit_cid: Some(cid.clone()),
                prev_cid: None,
                ops: None,
                blobs: None,
                blocks: None,
                prev_data_cid: None,
                rev: Some("rev_y".to_owned()),
            })
            .unwrap();

        h.event_ops.delete_sequences_except(&did, seq2).unwrap();

        let events = h
            .event_ops
            .get_events_since_seq(SequenceNumber::ZERO, None)
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].seq, seq2);
    }

    #[test]
    fn metastore_cursor_read_write() {
        let h = setup();
        assert_eq!(h.event_ops.read_last_applied_cursor().unwrap(), None);

        h.event_ops.write_last_applied_cursor_direct(42).unwrap();
        assert_eq!(h.event_ops.read_last_applied_cursor().unwrap(), Some(42));

        h.event_ops.write_last_applied_cursor_direct(100).unwrap();
        assert_eq!(h.event_ops.read_last_applied_cursor().unwrap(), Some(100));
    }

    #[test]
    fn inserts_advance_cursor() {
        let h = setup();
        let did = test_did();
        assert_eq!(h.event_ops.read_last_applied_cursor().unwrap(), None);

        let seq1 = h.event_ops.insert_identity_event(&did, None).unwrap();
        assert_eq!(
            h.event_ops.read_last_applied_cursor().unwrap(),
            seq1.as_u64()
        );

        let seq2 = h
            .event_ops
            .insert_account_event(&did, AccountStatus::Active)
            .unwrap();
        assert_eq!(
            h.event_ops.read_last_applied_cursor().unwrap(),
            seq2.as_u64()
        );
        assert!(seq2 > seq1);
    }

    #[test]
    fn get_event_by_seq_none_for_missing() {
        let h = setup();
        let result = h
            .event_ops
            .get_event_by_seq(SequenceNumber::from_raw(9999))
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn get_event_by_seq_none_for_negative() {
        let h = setup();
        let result = h
            .event_ops
            .get_event_by_seq(SequenceNumber::from_raw(-1))
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn multiple_event_types_interleaved() {
        let h = setup();
        let did = test_did();
        let cid = test_cid_link();

        let s1 = h
            .event_ops
            .insert_commit_event(&CommitEventData {
                did: did.clone(),
                event_type: RepoEventType::Commit,
                commit_cid: Some(cid.clone()),
                prev_cid: None,
                ops: None,
                blobs: None,
                blocks: None,
                prev_data_cid: None,
                rev: Some("r1".to_owned()),
            })
            .unwrap();
        let s2 = h.event_ops.insert_identity_event(&did, None).unwrap();
        let s3 = h
            .event_ops
            .insert_account_event(&did, AccountStatus::Active)
            .unwrap();
        let s4 = h
            .event_ops
            .insert_sync_event(&did, &cid, Some("r2"), b"sync_commit_bytes")
            .unwrap();

        let events = h
            .event_ops
            .get_events_since_seq(SequenceNumber::ZERO, None)
            .unwrap();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].event_type, RepoEventType::Commit);
        assert_eq!(events[1].event_type, RepoEventType::Identity);
        assert_eq!(events[2].event_type, RepoEventType::Account);
        assert_eq!(events[3].event_type, RepoEventType::Sync);

        assert!(s1 < s2);
        assert!(s2 < s3);
        assert!(s3 < s4);
    }

    #[test]
    fn delete_sequences_except_tombstones_all_event_types() {
        let h = setup();
        let did = test_did();
        let cid = test_cid_link();

        let _commit_seq = h
            .event_ops
            .insert_commit_event(&CommitEventData {
                did: did.clone(),
                event_type: RepoEventType::Commit,
                commit_cid: Some(cid.clone()),
                prev_cid: None,
                ops: None,
                blobs: None,
                blocks: None,
                prev_data_cid: None,
                rev: Some("rev_keep".to_owned()),
            })
            .unwrap();

        let identity_seq = h.event_ops.insert_identity_event(&did, None).unwrap();

        let account_seq = h
            .event_ops
            .insert_account_event(&did, AccountStatus::Active)
            .unwrap();

        let keep_seq = h
            .event_ops
            .insert_sync_event(&did, &cid, Some("rev_sync"), b"sync_commit_bytes")
            .unwrap();

        h.event_ops.delete_sequences_except(&did, keep_seq).unwrap();

        assert!(
            h.event_ops
                .get_event_by_seq(identity_seq)
                .unwrap()
                .is_none()
        );
        assert!(h.event_ops.get_event_by_seq(account_seq).unwrap().is_none());
        assert!(h.event_ops.get_event_by_seq(keep_seq).unwrap().is_some());
    }

    #[test]
    fn delete_sequences_except_rejects_negative_keep_seq() {
        let h = setup();
        let result = h
            .event_ops
            .delete_sequences_except(&test_did(), SequenceNumber::from_raw(-1));
        assert!(result.is_err());
    }

    #[test]
    fn delete_sequences_except_cleans_rev_to_seq_entries() {
        let h = setup();
        let did = test_did();
        let cid = test_cid_link();
        let user_hash = super::UserHash::from_did(did.as_str());

        let _seq1 = h
            .event_ops
            .insert_commit_event(&CommitEventData {
                did: did.clone(),
                event_type: RepoEventType::Commit,
                commit_cid: Some(cid.clone()),
                prev_cid: None,
                ops: None,
                blobs: None,
                blocks: None,
                prev_data_cid: None,
                rev: Some("rev_old".to_owned()),
            })
            .unwrap();

        let seq2 = h
            .event_ops
            .insert_commit_event(&CommitEventData {
                did: did.clone(),
                event_type: RepoEventType::Commit,
                commit_cid: Some(cid.clone()),
                prev_cid: None,
                ops: None,
                blobs: None,
                blocks: None,
                prev_data_cid: None,
                rev: Some("rev_keep".to_owned()),
            })
            .unwrap();

        let old_key = super::super::event_keys::rev_to_seq_key(user_hash, "rev_old");
        assert!(
            h.event_ops
                .repo_data
                .get(old_key.as_slice())
                .unwrap()
                .is_some()
        );

        h.event_ops.delete_sequences_except(&did, seq2).unwrap();

        assert!(
            h.event_ops
                .repo_data
                .get(old_key.as_slice())
                .unwrap()
                .is_none()
        );

        let keep_key = super::super::event_keys::rev_to_seq_key(user_hash, "rev_keep");
        assert!(
            h.event_ops
                .repo_data
                .get(keep_key.as_slice())
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn delete_sequences_except_cleans_did_events_entries() {
        let h = setup();
        let did = test_did();
        let cid = test_cid_link();
        let user_hash = super::UserHash::from_did(did.as_str());

        let seq1 = h
            .event_ops
            .insert_commit_event(&CommitEventData {
                did: did.clone(),
                event_type: RepoEventType::Commit,
                commit_cid: Some(cid.clone()),
                prev_cid: None,
                ops: None,
                blobs: None,
                blocks: None,
                prev_data_cid: None,
                rev: Some("rev_a".to_owned()),
            })
            .unwrap();

        let seq2 = h
            .event_ops
            .insert_commit_event(&CommitEventData {
                did: did.clone(),
                event_type: RepoEventType::Commit,
                commit_cid: Some(cid.clone()),
                prev_cid: None,
                ops: None,
                blobs: None,
                blocks: None,
                prev_data_cid: None,
                rev: Some("rev_b".to_owned()),
            })
            .unwrap();

        h.event_ops.delete_sequences_except(&did, seq2).unwrap();

        let removed_key =
            super::super::event_keys::did_events_key(user_hash, seq1.as_u64().unwrap());
        assert!(
            h.event_ops
                .repo_data
                .get(removed_key.as_slice())
                .unwrap()
                .is_none()
        );

        let kept_key = super::super::event_keys::did_events_key(user_hash, seq2.as_u64().unwrap());
        assert!(
            h.event_ops
                .repo_data
                .get(kept_key.as_slice())
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn recover_sidecar_indexes_no_gap() {
        let h = setup();
        let did = test_did();

        let seq = h
            .event_ops
            .insert_commit_event(&CommitEventData {
                did: did.clone(),
                event_type: RepoEventType::Commit,
                commit_cid: Some(test_cid_link()),
                prev_cid: None,
                ops: None,
                blobs: None,
                blocks: None,
                prev_data_cid: None,
                rev: Some("rev_1".to_owned()),
            })
            .unwrap();

        h.event_ops
            .write_last_applied_cursor_direct(seq.as_u64().unwrap())
            .unwrap();

        let recovered = h.event_ops.recover_sidecar_indexes().unwrap();
        assert_eq!(recovered, 0);
    }

    #[test]
    fn recover_sidecar_indexes_rebuilds_after_gap() {
        let h = setup();
        let did = test_did();
        let cid = test_cid_link();

        let seq1 = h
            .event_ops
            .insert_commit_event(&CommitEventData {
                did: did.clone(),
                event_type: RepoEventType::Commit,
                commit_cid: Some(cid.clone()),
                prev_cid: None,
                ops: None,
                blobs: None,
                blocks: None,
                prev_data_cid: None,
                rev: Some("rev_1".to_owned()),
            })
            .unwrap();

        h.event_ops
            .write_last_applied_cursor_direct(seq1.as_u64().unwrap())
            .unwrap();

        let crash_event = SequencedEvent {
            seq: SequenceNumber::ZERO,
            did: did.clone(),
            created_at: Utc::now(),
            event_type: RepoEventType::Commit,
            commit_cid: Some(cid.clone()),
            prev_cid: None,
            prev_data_cid: None,
            ops: None,
            blobs: None,
            blocks: None,
            handle: None,
            active: None,
            status: None,
            rev: Some("rev_2".to_owned()),
        };
        h.event_ops.bridge.insert_event(&crash_event).unwrap();

        let identity_event = SequencedEvent {
            seq: SequenceNumber::ZERO,
            did: did.clone(),
            created_at: Utc::now(),
            event_type: RepoEventType::Identity,
            commit_cid: None,
            prev_cid: None,
            prev_data_cid: None,
            ops: None,
            blobs: None,
            blocks: None,
            handle: None,
            active: None,
            status: None,
            rev: None,
        };
        h.event_ops.bridge.insert_event(&identity_event).unwrap();

        let crash_event_3 = SequencedEvent {
            seq: SequenceNumber::ZERO,
            did: did.clone(),
            created_at: Utc::now(),
            event_type: RepoEventType::Commit,
            commit_cid: Some(cid.clone()),
            prev_cid: None,
            prev_data_cid: None,
            ops: None,
            blobs: None,
            blocks: None,
            handle: None,
            active: None,
            status: None,
            rev: Some("rev_3".to_owned()),
        };
        h.event_ops.bridge.insert_event(&crash_event_3).unwrap();

        let user_hash = super::UserHash::from_did(did.as_str());
        let rev2_key = super::super::event_keys::rev_to_seq_key(user_hash, "rev_2");
        assert!(
            h.event_ops
                .repo_data
                .get(rev2_key.as_slice())
                .unwrap()
                .is_none()
        );

        let recovered = h.event_ops.recover_sidecar_indexes().unwrap();
        assert_eq!(recovered, 3);

        assert!(
            h.event_ops
                .repo_data
                .get(rev2_key.as_slice())
                .unwrap()
                .is_some()
        );

        let cursor = h.event_ops.read_last_applied_cursor().unwrap();
        assert!(cursor.is_some());
    }
}
