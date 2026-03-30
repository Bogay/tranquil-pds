use std::collections::HashSet;
use std::fmt;
use std::path::Path;

use crate::blockstore::CID_SIZE;
use crate::blockstore::hash_index::BlockIndex;
use crate::blockstore::{DataFileId, TranquilBlockStore};
use crate::eventlog::{EventLog, EventSequence, SequenceContiguityResult};
use crate::io::StorageIO;
use crate::metastore::Metastore;
use crate::metastore::encoding::KeyBuilder;
use crate::metastore::event_keys::metastore_cursor_key;
use crate::metastore::keys::{KeyTag, UserHash};
use crate::metastore::partitions::Partition;
use crate::metastore::records::RecordValue;
use crate::metastore::repo_meta::RepoMetaValue;

const CLEAN_SHUTDOWN_MARKER: &str = ".clean_shutdown";

#[derive(Debug, Default)]
pub struct ConsistencyReport {
    pub repos_checked: u64,
    pub records_checked: u64,
    pub user_blocks_checked: u64,
    pub handles_checked: u64,
    pub dangling_record_cids: Vec<DanglingCid>,
    pub dangling_root_cids: Vec<DanglingRootCid>,
    pub orphaned_user_repos: Vec<OrphanedUserRepo>,
    pub inconsistent_handles: Vec<InconsistentHandle>,
    pub orphan_data_files: Vec<DataFileId>,
    pub deserialization_failures: u64,
    pub eventlog_contiguity: Option<SequenceContiguityResult>,
    pub cursor_ahead_of_eventlog: bool,
    pub metastore_cursor: Option<EventSequence>,
    pub eventlog_max_seq: Option<EventSequence>,
}

#[derive(Debug, Clone)]
pub struct DanglingCid {
    pub user_hash: UserHash,
    pub collection: String,
    pub rkey: String,
    pub cid_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DanglingRootCid {
    pub user_hash: UserHash,
    pub root_cid_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct OrphanedUserRepo {
    pub user_hash: UserHash,
}

#[derive(Debug, Clone)]
pub struct InconsistentHandle {
    pub handle: String,
    pub mapped_user_hash: UserHash,
    pub problem: HandleProblem,
}

#[derive(Debug, Clone)]
pub enum HandleProblem {
    NoRepoMeta,
    HandleMismatch { repo_handle: String },
}

impl ConsistencyReport {
    pub fn is_consistent(&self) -> bool {
        self.dangling_record_cids.is_empty()
            && self.dangling_root_cids.is_empty()
            && self.orphaned_user_repos.is_empty()
            && self.inconsistent_handles.is_empty()
            && self.orphan_data_files.is_empty()
            && self.deserialization_failures == 0
            && self
                .eventlog_contiguity
                .as_ref()
                .is_none_or(|c| c.is_contiguous())
            && !self.cursor_ahead_of_eventlog
    }

    pub fn has_repairable_issues(&self) -> bool {
        !self.orphan_data_files.is_empty()
    }

    pub fn has_unrecoverable_issues(&self) -> bool {
        !self.dangling_root_cids.is_empty()
            || !self.dangling_record_cids.is_empty()
            || self.deserialization_failures > 0
            || self.cursor_ahead_of_eventlog
    }

    pub fn log_findings(&self) {
        if self.is_consistent() {
            tracing::info!(
                repos = self.repos_checked,
                records = self.records_checked,
                user_blocks = self.user_blocks_checked,
                handles = self.handles_checked,
                "consistency check passed"
            );
            return;
        }

        if !self.dangling_record_cids.is_empty() {
            tracing::warn!(
                count = self.dangling_record_cids.len(),
                "records reference missing blocks"
            );
        }
        if !self.dangling_root_cids.is_empty() {
            tracing::warn!(
                count = self.dangling_root_cids.len(),
                "repo roots reference missing blocks"
            );
        }
        if !self.orphaned_user_repos.is_empty() {
            tracing::warn!(
                count = self.orphaned_user_repos.len(),
                "repos with user_blocks but no repo_meta"
            );
        }
        if !self.inconsistent_handles.is_empty() {
            tracing::warn!(
                count = self.inconsistent_handles.len(),
                "handle index inconsistencies"
            );
        }
        if !self.orphan_data_files.is_empty() {
            tracing::warn!(
                count = self.orphan_data_files.len(),
                files = ?self.orphan_data_files,
                "orphan data files with no index references"
            );
        }
        if self.deserialization_failures > 0 {
            tracing::error!(
                count = self.deserialization_failures,
                "metastore values failed to deserialize"
            );
        }
        if let Some(c) = &self.eventlog_contiguity
            && !c.is_contiguous()
        {
            tracing::warn!(gaps = c.gaps.len(), "eventlog sequence gaps detected");
            c.gaps.iter().take(5).for_each(|gap| {
                tracing::warn!(
                    after_segment = %gap.after_segment,
                    expected = ?gap.expected_seq,
                    actual = ?gap.actual_seq,
                    "eventlog gap"
                );
            });
        }
        if self.cursor_ahead_of_eventlog {
            tracing::error!(
                cursor = ?self.metastore_cursor,
                eventlog_max = ?self.eventlog_max_seq,
                "metastore cursor is ahead of eventlog max sequence"
            );
        }
    }
}

impl fmt::Display for ConsistencyReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_consistent() {
            return write!(
                f,
                "consistent (repos={}, records={}, user_blocks={}, handles={})",
                self.repos_checked,
                self.records_checked,
                self.user_blocks_checked,
                self.handles_checked,
            );
        }

        write!(
            f,
            "INCONSISTENT: dangling_roots={}, dangling_records={}, orphaned_repos={}, \
             inconsistent_handles={}, orphan_files={}, deserialize_failures={}, \
             eventlog_gaps={}, cursor_ahead={}",
            self.dangling_root_cids.len(),
            self.dangling_record_cids.len(),
            self.orphaned_user_repos.len(),
            self.inconsistent_handles.len(),
            self.orphan_data_files.len(),
            self.deserialization_failures,
            self.eventlog_contiguity
                .as_ref()
                .map_or(0, |c| c.gaps.len()),
            self.cursor_ahead_of_eventlog,
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ConsistencyCheckOptions {
    pub check_block_references: bool,
    pub check_handles: bool,
    pub check_user_blocks: bool,
    pub check_eventlog: bool,
    pub check_orphan_files: bool,
}

impl Default for ConsistencyCheckOptions {
    fn default() -> Self {
        Self {
            check_block_references: true,
            check_handles: true,
            check_user_blocks: true,
            check_eventlog: true,
            check_orphan_files: true,
        }
    }
}

pub fn verify_store_consistency<S: StorageIO + 'static>(
    blockstore: &TranquilBlockStore,
    metastore: &Metastore,
    eventlog: &EventLog<S>,
) -> ConsistencyReport {
    verify_store_consistency_with_options(
        blockstore,
        metastore,
        eventlog,
        ConsistencyCheckOptions::default(),
    )
}

pub fn verify_store_consistency_with_options<S: StorageIO + 'static>(
    blockstore: &TranquilBlockStore,
    metastore: &Metastore,
    eventlog: &EventLog<S>,
    options: ConsistencyCheckOptions,
) -> ConsistencyReport {
    let mut report = ConsistencyReport::default();

    let block_index = blockstore.block_index();
    let repo_data = metastore.partition(Partition::RepoData);

    let known_user_hashes = if options.check_block_references {
        let hashes = check_repo_root_cids(repo_data, block_index, &mut report);
        check_record_cids(repo_data, block_index, &mut report);
        hashes
    } else if options.check_user_blocks {
        collect_known_user_hashes(repo_data)
    } else {
        HashSet::new()
    };

    if options.check_user_blocks {
        check_user_blocks(repo_data, &known_user_hashes, &mut report);
    }

    if options.check_handles {
        check_handle_consistency(repo_data, &mut report);
    }

    if options.check_eventlog {
        check_eventlog_contiguity(eventlog, &mut report);
        check_cursor_vs_eventlog(repo_data, eventlog, &mut report);
    }

    if options.check_orphan_files {
        check_orphan_data_files(blockstore, block_index, &mut report);
    }

    report
}

fn check_repo_root_cids(
    repo_data: &fjall::Keyspace,
    block_index: &BlockIndex,
    report: &mut ConsistencyReport,
) -> HashSet<UserHash> {
    let prefix = KeyBuilder::new().tag(KeyTag::REPO_META).build();
    let mut known_user_hashes = HashSet::new();

    repo_data.prefix(prefix.as_slice()).for_each(|guard| {
        let Ok((key_bytes, value_bytes)) = guard.into_inner() else {
            return;
        };

        report.repos_checked = report.repos_checked.saturating_add(1);

        if let Some(h) = extract_user_hash(&key_bytes) {
            known_user_hashes.insert(h);
        }

        let Some(meta) = RepoMetaValue::deserialize(&value_bytes) else {
            tracing::warn!(
                user_hash = ?extract_user_hash(&key_bytes),
                "repo_meta value failed to deserialize"
            );
            report.deserialization_failures = report.deserialization_failures.saturating_add(1);
            return;
        };

        if meta.repo_root_cid.is_empty() {
            return;
        }

        let Some(cid_fixed) = try_cid_bytes_to_fixed(&meta.repo_root_cid) else {
            let Some(user_hash) = extract_user_hash(&key_bytes) else {
                return;
            };
            tracing::warn!(
                %user_hash,
                cid_len = meta.repo_root_cid.len(),
                "repo_meta has non-standard CID length"
            );
            report.dangling_root_cids.push(DanglingRootCid {
                user_hash,
                root_cid_bytes: meta.repo_root_cid,
            });
            return;
        };

        if !block_index.has(&cid_fixed) {
            let Some(user_hash) = extract_user_hash(&key_bytes) else {
                return;
            };
            report.dangling_root_cids.push(DanglingRootCid {
                user_hash,
                root_cid_bytes: meta.repo_root_cid,
            });
        }
    });

    known_user_hashes
}

fn collect_known_user_hashes(repo_data: &fjall::Keyspace) -> HashSet<UserHash> {
    let prefix = KeyBuilder::new().tag(KeyTag::REPO_META).build();
    let mut hashes = HashSet::new();

    repo_data.prefix(prefix.as_slice()).for_each(|guard| {
        if let Ok((key_bytes, _)) = guard.into_inner()
            && let Some(h) = extract_user_hash(&key_bytes)
        {
            hashes.insert(h);
        }
    });

    hashes
}

fn check_record_cids(
    repo_data: &fjall::Keyspace,
    block_index: &BlockIndex,
    report: &mut ConsistencyReport,
) {
    let prefix = KeyBuilder::new().tag(KeyTag::RECORDS).build();

    repo_data.prefix(prefix.as_slice()).for_each(|guard| {
        let Ok((key_bytes, value_bytes)) = guard.into_inner() else {
            return;
        };

        report.records_checked = report.records_checked.saturating_add(1);

        let Some(record) = RecordValue::deserialize(&value_bytes) else {
            tracing::warn!(
                user_hash = ?extract_user_hash(&key_bytes),
                "record value failed to deserialize"
            );
            report.deserialization_failures = report.deserialization_failures.saturating_add(1);
            return;
        };

        let Some(cid_fixed) = try_cid_bytes_to_fixed(&record.record_cid) else {
            let (user_hash, collection, rkey) = parse_record_key(&key_bytes);
            let Some(user_hash) = user_hash else {
                return;
            };
            tracing::warn!(
                %user_hash,
                collection,
                rkey,
                cid_len = record.record_cid.len(),
                "record has non-standard CID length"
            );
            report.dangling_record_cids.push(DanglingCid {
                user_hash,
                collection,
                rkey,
                cid_bytes: record.record_cid,
            });
            return;
        };

        if !block_index.has(&cid_fixed) {
            let (user_hash, collection, rkey) = parse_record_key(&key_bytes);
            let Some(user_hash) = user_hash else {
                return;
            };
            report.dangling_record_cids.push(DanglingCid {
                user_hash,
                collection,
                rkey,
                cid_bytes: record.record_cid,
            });
        }
    });
}

fn check_user_blocks(
    repo_data: &fjall::Keyspace,
    known_user_hashes: &HashSet<UserHash>,
    report: &mut ConsistencyReport,
) {
    let prefix = KeyBuilder::new().tag(KeyTag::USER_BLOCKS).build();
    let mut seen_orphan_hashes: HashSet<UserHash> = HashSet::new();

    repo_data.prefix(prefix.as_slice()).for_each(|guard| {
        let Ok((key_bytes, _)) = guard.into_inner() else {
            return;
        };

        report.user_blocks_checked = report.user_blocks_checked.saturating_add(1);

        let Some(user_hash) = extract_user_hash(&key_bytes) else {
            return;
        };

        if !known_user_hashes.contains(&user_hash) && seen_orphan_hashes.insert(user_hash) {
            report
                .orphaned_user_repos
                .push(OrphanedUserRepo { user_hash });
        }
    });
}

fn check_handle_consistency(repo_data: &fjall::Keyspace, report: &mut ConsistencyReport) {
    let prefix = KeyBuilder::new().tag(KeyTag::HANDLES).build();

    repo_data.prefix(prefix.as_slice()).for_each(|guard| {
        let Ok((key_bytes, value_bytes)) = guard.into_inner() else {
            return;
        };

        report.handles_checked = report.handles_checked.saturating_add(1);

        let handle = parse_handle_from_key(&key_bytes);
        let Some(mapped_hash) = parse_user_hash_from_value(&value_bytes) else {
            return;
        };

        let meta_key = crate::metastore::repo_meta::repo_meta_key(mapped_hash);
        match repo_data.get(meta_key.as_slice()) {
            Ok(Some(meta_bytes)) => {
                let Some(meta) = RepoMetaValue::deserialize(&meta_bytes) else {
                    tracing::warn!(
                        %mapped_hash,
                        handle,
                        "repo_meta value failed to deserialize during handle check"
                    );
                    report.deserialization_failures =
                        report.deserialization_failures.saturating_add(1);
                    return;
                };
                let meta_handle_lower = meta.handle.to_lowercase();
                let handle_lower = handle.to_lowercase();
                if meta_handle_lower != handle_lower {
                    report.inconsistent_handles.push(InconsistentHandle {
                        handle,
                        mapped_user_hash: mapped_hash,
                        problem: HandleProblem::HandleMismatch {
                            repo_handle: meta.handle,
                        },
                    });
                }
            }
            Ok(None) => {
                report.inconsistent_handles.push(InconsistentHandle {
                    handle,
                    mapped_user_hash: mapped_hash,
                    problem: HandleProblem::NoRepoMeta,
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, handle, "repo_meta lookup failed during handle check");
            }
        }
    });
}

fn check_eventlog_contiguity<S: StorageIO + 'static>(
    eventlog: &EventLog<S>,
    report: &mut ConsistencyReport,
) {
    let reader = eventlog.reader();
    if let Err(e) = reader.refresh_segment_ranges() {
        tracing::warn!(error = %e, "failed to refresh segment ranges for contiguity check");
        return;
    }
    report.eventlog_contiguity = Some(reader.check_sequence_contiguity());
}

fn check_cursor_vs_eventlog<S: StorageIO + 'static>(
    repo_data: &fjall::Keyspace,
    eventlog: &EventLog<S>,
    report: &mut ConsistencyReport,
) {
    let cursor_key = metastore_cursor_key();
    let cursor_seq = repo_data
        .get(cursor_key.as_slice())
        .ok()
        .flatten()
        .and_then(|bytes| {
            let arr: [u8; 8] = bytes.as_ref().try_into().ok()?;
            Some(match u64::from_be_bytes(arr) {
                0 => EventSequence::BEFORE_ALL,
                n => EventSequence::new(n),
            })
        });

    let max_seq = eventlog.max_seq();

    report.metastore_cursor = cursor_seq;
    report.eventlog_max_seq = (max_seq != EventSequence::BEFORE_ALL).then_some(max_seq);

    if let Some(cursor) = cursor_seq
        && max_seq != EventSequence::BEFORE_ALL
        && cursor > max_seq
    {
        report.cursor_ahead_of_eventlog = true;
    }
}

fn check_orphan_data_files(
    blockstore: &TranquilBlockStore,
    block_index: &BlockIndex,
    report: &mut ConsistencyReport,
) {
    let disk_files = match blockstore.list_data_files() {
        Ok(files) => files,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list data files for orphan check");
            return;
        }
    };

    let epoch = blockstore.epoch().current();
    let now = crate::wall_clock_ms();
    let indexed_files = block_index.liveness_by_file(epoch, now, 0);

    let indexed_file_ids: HashSet<DataFileId> = indexed_files.keys().copied().collect();

    let active_file_id = block_index.read_write_cursor().map(|c| c.file_id);

    if active_file_id.is_none() && indexed_file_ids.is_empty() {
        return;
    }

    disk_files.iter().for_each(|&fid| {
        let is_active = active_file_id.is_some_and(|active| fid >= active);
        if !is_active && !indexed_file_ids.contains(&fid) {
            report.orphan_data_files.push(fid);
        }
    });
}

fn try_cid_bytes_to_fixed(bytes: &[u8]) -> Option<[u8; CID_SIZE]> {
    bytes.try_into().ok()
}

fn extract_user_hash(key_bytes: &[u8]) -> Option<UserHash> {
    key_bytes
        .get(1..9)?
        .try_into()
        .ok()
        .map(|arr| UserHash::from_raw(u64::from_be_bytes(arr)))
}

fn parse_record_key(key_bytes: &[u8]) -> (Option<UserHash>, String, String) {
    let user_hash = extract_user_hash(key_bytes);
    let mut reader = crate::metastore::encoding::KeyReader::new(key_bytes);
    let _ = reader.tag();
    let _ = reader.u64();
    let collection = reader.string().unwrap_or_default();
    let rkey = reader.string().unwrap_or_default();
    (user_hash, collection, rkey)
}

fn parse_handle_from_key(key_bytes: &[u8]) -> String {
    let mut reader = crate::metastore::encoding::KeyReader::new(key_bytes);
    let _ = reader.tag();
    reader.string().unwrap_or_default()
}

fn parse_user_hash_from_value(value_bytes: &[u8]) -> Option<UserHash> {
    value_bytes
        .get(..8)?
        .try_into()
        .ok()
        .map(|arr| UserHash::from_raw(u64::from_be_bytes(arr)))
}

pub fn repair_known_issues(
    blockstore: &TranquilBlockStore,
    report: &ConsistencyReport,
) -> RepairResult {
    let mut result = RepairResult::default();

    report.orphan_data_files.iter().for_each(|&file_id| {
        let path = blockstore.data_file_path(file_id);
        match std::fs::remove_file(&path) {
            Ok(()) => {
                tracing::info!(%file_id, "removed orphan data file");
                result.orphan_files_removed = result.orphan_files_removed.saturating_add(1);
            }
            Err(e) => {
                tracing::warn!(%file_id, error = %e, "failed to remove orphan data file");
                result.repair_errors = result.repair_errors.saturating_add(1);
            }
        }
    });

    result
}

#[derive(Debug, Default)]
pub struct RepairResult {
    pub orphan_files_removed: u64,
    pub repair_errors: u64,
}

impl RepairResult {
    pub fn had_errors(&self) -> bool {
        self.repair_errors > 0
    }
}

pub fn write_clean_shutdown_marker(data_dir: &Path) -> std::io::Result<()> {
    let marker_path = data_dir.join(CLEAN_SHUTDOWN_MARKER);
    let f = std::fs::File::create(&marker_path)?;
    f.sync_all()?;
    std::fs::File::open(data_dir)?.sync_all()
}

pub fn remove_clean_shutdown_marker(data_dir: &Path) -> std::io::Result<()> {
    let marker_path = data_dir.join(CLEAN_SHUTDOWN_MARKER);
    match std::fs::remove_file(&marker_path) {
        Ok(()) => std::fs::File::open(data_dir)?.sync_all(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

pub fn had_clean_shutdown(data_dir: &Path) -> bool {
    data_dir.join(CLEAN_SHUTDOWN_MARKER).exists()
}
