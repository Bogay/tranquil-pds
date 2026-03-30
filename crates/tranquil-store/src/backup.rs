use std::collections::HashSet;
use std::io::{self, Read};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::blockstore::{
    BlockOffset, BlockstoreSnapshot, CommitEpoch, CommitError, DataFileId, QuiesceGuard,
    RebuildError, TranquilBlockStore,
};
use crate::eventlog::{
    EventLog, EventLogConfig, EventLogFreezeGuard, EventLogSnapshotState, EventSequence,
    EventWithMutations, SegmentId, SegmentOffset,
};
use crate::io::{RealIO, StorageIO};
use crate::metastore::event_keys::{did_events_key, metastore_cursor_key, rev_to_seq_key};
use crate::metastore::keys::UserHash;
use crate::metastore::partitions::Partition;
use crate::metastore::recovery::{CommitMutationSet, replay_mutation_set};
use crate::metastore::repo_meta::{RepoMetaValue, RepoStatus, repo_meta_key};
use crate::metastore::{Metastore, MetastoreConfig, MetastoreError};

const BACKUP_FORMAT_VERSION: u32 = 1;
const MANIFEST_FILENAME: &str = "backup.manifest";
const BLOCKS_DIR: &str = "blocks";
const EVENTS_DIR: &str = "events";
const METASTORE_DIR: &str = "metastore";
const INDEX_DIR: &str = "block_index";
const LOCK_FILE_NAME: &str = ".lock";

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("backup io: {0}")]
    Io(#[from] io::Error),
    #[error("blockstore quiesce failed: {0}")]
    Quiesce(#[from] CommitError),
    #[error("metastore persist failed: {0}")]
    Metastore(#[from] MetastoreError),
    #[error("index error: {0}")]
    Index(io::Error),
    #[error("index rebuild failed: {0}")]
    IndexRebuild(#[from] RebuildError),
    #[error("checksum mismatch for {path}: expected {expected:#018x}, got {actual:#018x}")]
    ChecksumMismatch {
        path: String,
        expected: u64,
        actual: u64,
    },
    #[error("size mismatch for {path}: expected {expected} bytes, got {actual}")]
    SizeMismatch {
        path: String,
        expected: u64,
        actual: u64,
    },
    #[error("missing file in backup: {0}")]
    MissingFile(String),
    #[error("restore verification failed: {0}")]
    RestoreVerification(String),
    #[error("target directory not empty: {0}")]
    TargetNotEmpty(String),
    #[error("incremental chain mismatch: {0}")]
    ChainMismatch(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MetastoreSeqno(u64);

impl MetastoreSeqno {
    pub fn new(seqno: u64) -> Self {
        Self(seqno)
    }

    pub fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupKind {
    #[default]
    Full,
    Incremental,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub version: u32,
    pub created_at_ms: u64,
    pub blockstore: BlockstoreManifest,
    pub eventlog: EventLogManifest,
    pub metastore_seqno: MetastoreSeqno,
    pub files: Vec<BackupFileEntry>,
    #[serde(default)]
    pub kind: BackupKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_blockstore: Option<BlockstoreManifest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_eventlog: Option<EventLogManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockstoreManifest {
    pub write_cursor_file_id: DataFileId,
    pub write_cursor_offset: BlockOffset,
    pub epoch: CommitEpoch,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shard_cursors: Vec<ShardCursorEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardCursorEntry {
    pub file_id: DataFileId,
    pub offset: BlockOffset,
}

impl BlockstoreManifest {
    pub fn min_active_file_id(&self) -> DataFileId {
        match self.shard_cursors.is_empty() {
            true => self.write_cursor_file_id,
            false => self
                .shard_cursors
                .iter()
                .map(|c| c.file_id)
                .min()
                .unwrap_or(self.write_cursor_file_id),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventLogManifest {
    pub max_seq: EventSequence,
    pub active_segment_id: SegmentId,
    pub active_segment_position: SegmentOffset,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupFileEntry {
    pub path: String,
    pub size: u64,
    pub xxh3_checksum: u64,
}

struct ConsistentSnapshot {
    blockstore: BlockstoreSnapshot,
    eventlog: EventLogSnapshotState,
    metastore_seqno: MetastoreSeqno,
    metastore_files: Vec<BackupFileEntry>,
    quiesce_guard: QuiesceGuard,
    _eventlog_guard: EventLogFreezeGuard,
}

enum BackupLineage<'a> {
    Full,
    Incremental { base: &'a BackupManifest },
}

pub struct BackupCoordinator<'a, S: StorageIO> {
    blockstore: &'a TranquilBlockStore,
    eventlog: &'a EventLog<S>,
    metastore: &'a Metastore,
}

impl<'a, S: StorageIO + Send + Sync + 'static> BackupCoordinator<'a, S> {
    pub fn new(
        blockstore: &'a TranquilBlockStore,
        eventlog: &'a EventLog<S>,
        metastore: &'a Metastore,
    ) -> Self {
        Self {
            blockstore,
            eventlog,
            metastore,
        }
    }

    pub fn create_backup(&self, destination: &Path) -> Result<BackupManifest, BackupError> {
        std::fs::create_dir_all(destination)?;

        let ConsistentSnapshot {
            blockstore: bs,
            eventlog: el,
            metastore_seqno,
            metastore_files,
            quiesce_guard,
            _eventlog_guard: eventlog_guard,
        } = self.take_consistent_snapshot(destination)?;

        let mut files = metastore_files;

        copy_blockstore_files(
            &bs,
            DataFileId::new(0),
            self.blockstore.data_dir(),
            &destination.join(BLOCKS_DIR),
            &mut files,
        )?;

        copy_eventlog_files(
            &el,
            SegmentId::new(0),
            self.eventlog.segments_dir(),
            &destination.join(EVENTS_DIR),
            &mut files,
        )?;

        quiesce_guard.resume();
        drop(eventlog_guard);

        let manifest = self.build_manifest(bs, el, metastore_seqno, files, BackupLineage::Full);

        write_manifest(&manifest, destination)?;

        Ok(manifest)
    }

    pub fn create_incremental_backup(
        &self,
        base: &BackupManifest,
        destination: &Path,
    ) -> Result<BackupManifest, BackupError> {
        std::fs::create_dir_all(destination)?;

        let ConsistentSnapshot {
            blockstore: bs,
            eventlog: el,
            metastore_seqno,
            metastore_files,
            quiesce_guard,
            _eventlog_guard: eventlog_guard,
        } = self.take_consistent_snapshot(destination)?;

        let mut files = metastore_files;

        copy_blockstore_files(
            &bs,
            base.blockstore.min_active_file_id(),
            self.blockstore.data_dir(),
            &destination.join(BLOCKS_DIR),
            &mut files,
        )?;

        copy_eventlog_files(
            &el,
            base.eventlog.active_segment_id,
            self.eventlog.segments_dir(),
            &destination.join(EVENTS_DIR),
            &mut files,
        )?;

        quiesce_guard.resume();
        drop(eventlog_guard);

        let manifest = self.build_manifest(
            bs,
            el,
            metastore_seqno,
            files,
            BackupLineage::Incremental { base },
        );

        write_manifest(&manifest, destination)?;

        Ok(manifest)
    }

    fn take_consistent_snapshot(
        &self,
        destination: &Path,
    ) -> Result<ConsistentSnapshot, BackupError> {
        let (bs_snapshot, quiesce_guard) = self.blockstore.quiesce()?;

        let (el_snapshot, eventlog_guard) = self.eventlog.freeze()?;

        self.metastore.persist()?;
        let metastore_seqno = MetastoreSeqno::new(self.metastore.database().seqno());

        let mut metastore_files = Vec::new();
        copy_metastore_files(
            self.metastore.path(),
            &destination.join(METASTORE_DIR),
            &mut metastore_files,
        )?;

        Ok(ConsistentSnapshot {
            blockstore: bs_snapshot,
            eventlog: el_snapshot,
            metastore_seqno,
            metastore_files,
            quiesce_guard,
            _eventlog_guard: eventlog_guard,
        })
    }

    fn build_manifest(
        &self,
        bs: BlockstoreSnapshot,
        el: EventLogSnapshotState,
        metastore_seqno: MetastoreSeqno,
        files: Vec<BackupFileEntry>,
        lineage: BackupLineage<'_>,
    ) -> BackupManifest {
        let (kind, base_blockstore, base_eventlog) = match lineage {
            BackupLineage::Full => (BackupKind::Full, None, None),
            BackupLineage::Incremental { base } => (
                BackupKind::Incremental,
                Some(base.blockstore.clone()),
                Some(base.eventlog.clone()),
            ),
        };

        BackupManifest {
            version: BACKUP_FORMAT_VERSION,
            created_at_ms: crate::wall_clock_ms().raw(),
            blockstore: {
                let max_cursor = bs
                    .shard_cursors
                    .iter()
                    .max_by_key(|c| (c.file_id, c.offset))
                    .copied();
                let shard_cursor_entries: Vec<ShardCursorEntry> = bs
                    .shard_cursors
                    .iter()
                    .map(|c| ShardCursorEntry {
                        file_id: c.file_id,
                        offset: c.offset,
                    })
                    .collect();
                BlockstoreManifest {
                    write_cursor_file_id: max_cursor
                        .map(|c| c.file_id)
                        .unwrap_or(DataFileId::new(0)),
                    write_cursor_offset: max_cursor
                        .map(|c| c.offset)
                        .unwrap_or(BlockOffset::new(0)),
                    epoch: bs.epoch,
                    shard_cursors: shard_cursor_entries,
                }
            },
            eventlog: EventLogManifest {
                max_seq: el.max_seq,
                active_segment_id: el.active_segment_id,
                active_segment_position: el.active_segment_position,
            },
            metastore_seqno,
            files,
            kind,
            base_blockstore,
            base_eventlog,
        }
    }
}

fn copy_blockstore_files(
    snapshot: &BlockstoreSnapshot,
    min_file_id: DataFileId,
    data_dir: &Path,
    dest_dir: &Path,
    files: &mut Vec<BackupFileEntry>,
) -> io::Result<()> {
    std::fs::create_dir_all(dest_dir)?;

    snapshot
        .data_files
        .iter()
        .filter(|&&fid| fid >= min_file_id)
        .try_for_each(|&file_id| {
            let src = data_dir.join(format!("{file_id}.tqb"));

            let max_bytes = snapshot
                .shard_cursors
                .iter()
                .find(|c| c.file_id == file_id)
                .map(|c| c.offset.raw());

            let dest = dest_dir.join(format!("{file_id}.tqb"));
            let size = copy_file_synced(&src, &dest, max_bytes)?;

            if let Some(expected) = max_bytes {
                verify_copy_size(size, expected, &src)?;
            }

            let checksum = checksum_file(&dest)?;

            files.push(BackupFileEntry {
                path: format!("{BLOCKS_DIR}/{file_id}.tqb"),
                size,
                xxh3_checksum: checksum,
            });

            Ok::<(), io::Error>(())
        })?;

    sync_dir(dest_dir)
}

fn copy_eventlog_files(
    snapshot: &EventLogSnapshotState,
    min_segment_id: SegmentId,
    segments_dir: &Path,
    dest_dir: &Path,
    files: &mut Vec<BackupFileEntry>,
) -> io::Result<()> {
    std::fs::create_dir_all(dest_dir)?;

    snapshot
        .sealed_segments
        .iter()
        .filter(|&&sid| sid >= min_segment_id)
        .try_for_each(|&seg_id| {
            let src = segments_dir.join(format!("{seg_id}.tqe"));
            let dest = dest_dir.join(format!("{seg_id}.tqe"));
            let size = copy_file_synced(&src, &dest, None)?;
            let checksum = checksum_file(&dest)?;

            files.push(BackupFileEntry {
                path: format!("{EVENTS_DIR}/{seg_id}.tqe"),
                size,
                xxh3_checksum: checksum,
            });

            Ok::<(), io::Error>(())
        })?;

    let active_src = segments_dir.join(format!("{}.tqe", snapshot.active_segment_id));
    let active_dest = dest_dir.join(format!("{}.tqe", snapshot.active_segment_id));
    let expected = snapshot.active_segment_position.raw();
    let size = copy_file_synced(&active_src, &active_dest, Some(expected))?;
    verify_copy_size(size, expected, &active_src)?;
    let checksum = checksum_file(&active_dest)?;

    files.push(BackupFileEntry {
        path: format!("{EVENTS_DIR}/{}.tqe", snapshot.active_segment_id),
        size,
        xxh3_checksum: checksum,
    });

    sync_dir(dest_dir)
}

fn copy_metastore_files(
    src: &Path,
    dest: &Path,
    files: &mut Vec<BackupFileEntry>,
) -> io::Result<()> {
    std::fs::create_dir_all(dest)?;
    copy_dir_recursive(src, dest, src, files)?;
    sync_dir(dest)
}

fn copy_dir_recursive(
    base: &Path,
    dest_base: &Path,
    current: &Path,
    files: &mut Vec<BackupFileEntry>,
) -> io::Result<()> {
    std::fs::read_dir(current)?.try_for_each(|entry| {
        let entry = entry?;
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();

        if name == LOCK_FILE_NAME {
            return Ok(());
        }

        let path = entry.path();
        let relative = path
            .strip_prefix(base)
            .map_err(|e| io::Error::other(e.to_string()))?;
        let dest_path = dest_base.join(relative);

        match entry.file_type()?.is_dir() {
            true => {
                std::fs::create_dir_all(&dest_path)?;
                copy_dir_recursive(base, dest_base, &path, files)
            }
            false => {
                let size = copy_file_synced(&path, &dest_path, None)?;
                let checksum = checksum_file(&dest_path)?;
                files.push(BackupFileEntry {
                    path: format!("{METASTORE_DIR}/{}", relative.display()),
                    size,
                    xxh3_checksum: checksum,
                });
                Ok(())
            }
        }
    })
}

fn copy_file_synced(src: &Path, dest: &Path, max_bytes: Option<u64>) -> io::Result<u64> {
    let src_file = std::fs::File::open(src)?;
    let mut dest_file = std::fs::File::create(dest)?;
    let total = match max_bytes {
        None => io::copy(&mut &src_file, &mut dest_file)?,
        Some(limit) => io::copy(&mut src_file.take(limit), &mut dest_file)?,
    };
    dest_file.sync_all()?;
    Ok(total)
}

fn verify_copy_size(actual: u64, expected: u64, src: &Path) -> io::Result<()> {
    (actual == expected).then_some(()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("{}: expected {expected} bytes, got {actual}", src.display(),),
        )
    })
}

struct HashWriter(xxhash_rust::xxh3::Xxh3Default);

impl io::Write for HashWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn checksum_file(path: &Path) -> io::Result<u64> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = HashWriter(xxhash_rust::xxh3::Xxh3Default::new());
    io::copy(&mut file, &mut hasher)?;
    Ok(hasher.0.digest())
}

fn write_manifest(manifest: &BackupManifest, destination: &Path) -> io::Result<()> {
    let json = serde_json::to_string_pretty(manifest)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let manifest_path = destination.join(MANIFEST_FILENAME);
    std::fs::write(&manifest_path, json.as_bytes())?;
    let f = std::fs::File::open(&manifest_path)?;
    f.sync_all()?;
    sync_dir(destination)?;
    Ok(())
}

pub fn read_manifest(backup_dir: &Path) -> io::Result<BackupManifest> {
    let data = std::fs::read(backup_dir.join(MANIFEST_FILENAME))?;
    let manifest: BackupManifest =
        serde_json::from_slice(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if manifest.version != BACKUP_FORMAT_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "backup format version {}, expected {BACKUP_FORMAT_VERSION}",
                manifest.version,
            ),
        ));
    }
    Ok(manifest)
}

#[derive(Debug)]
pub struct RestoreResult {
    pub blocks_files_restored: u32,
    pub event_segments_restored: u32,
    pub metastore_files_restored: u32,
}

#[derive(Debug)]
pub struct PitrResult {
    pub restore: RestoreResult,
    pub events_replayed: u64,
    pub target_seq: EventSequence,
}

#[derive(Debug)]
pub enum FileFailure {
    SizeMismatch(String),
    ChecksumMismatch(String),
    Unreadable(String, io::Error),
}

#[derive(Debug)]
pub struct VerifyResult {
    pub total_blocks: u64,
    pub total_events: u64,
    pub corrupted_blocks: u64,
    pub corrupted_events: u64,
    pub file_failures: Vec<FileFailure>,
}

impl VerifyResult {
    pub fn is_healthy(&self) -> bool {
        self.corrupted_blocks == 0 && self.corrupted_events == 0 && self.file_failures.is_empty()
    }
}

fn copy_validated_entry(
    entry: &BackupFileEntry,
    source_dir: &Path,
    target: &Path,
) -> Result<(), BackupError> {
    let src_path = source_dir.join(&entry.path);
    let dest_path = target.join(&entry.path);

    if let Some(parent) = dest_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let size = copy_file_synced(&src_path, &dest_path, None)?;

    if size != entry.size {
        return Err(BackupError::SizeMismatch {
            path: entry.path.clone(),
            expected: entry.size,
            actual: size,
        });
    }

    let actual_checksum = checksum_file(&dest_path)?;
    if actual_checksum != entry.xxh3_checksum {
        return Err(BackupError::ChecksumMismatch {
            path: entry.path.clone(),
            expected: entry.xxh3_checksum,
            actual: actual_checksum,
        });
    }

    Ok(())
}

struct RestoreDirs {
    blocks: std::path::PathBuf,
    events: std::path::PathBuf,
    metastore: std::path::PathBuf,
    index: std::path::PathBuf,
}

impl RestoreDirs {
    fn create(target: &Path) -> Result<Self, BackupError> {
        let dirs = Self {
            blocks: target.join(BLOCKS_DIR),
            events: target.join(EVENTS_DIR),
            metastore: target.join(METASTORE_DIR),
            index: target.join(INDEX_DIR),
        };

        [&dirs.blocks, &dirs.events, &dirs.metastore, &dirs.index]
            .iter()
            .try_for_each(std::fs::create_dir_all)?;

        Ok(dirs)
    }

    fn finalize(
        &self,
        manifest: &BackupManifest,
        file_count: impl Fn(&str) -> u32,
    ) -> Result<RestoreResult, BackupError> {
        [&self.blocks, &self.events, &self.metastore]
            .iter()
            .try_for_each(|d| sync_dir(d))?;

        std::fs::create_dir_all(&self.index).map_err(BackupError::Io)?;

        verify_restored_eventlog(&self.events, manifest)?;
        verify_restored_metastore(&self.metastore)?;

        Ok(RestoreResult {
            blocks_files_restored: file_count(BLOCKS_DIR),
            event_segments_restored: file_count(EVENTS_DIR),
            metastore_files_restored: file_count(METASTORE_DIR),
        })
    }
}

pub fn restore_from_backup(source: &Path, target: &Path) -> Result<RestoreResult, BackupError> {
    reject_nonempty_target(target)?;

    let manifest = read_manifest(source)?;
    validate_manifest_checksums(&manifest, source)?;

    let staging = staging_dir(target)?;

    let result = (|| {
        let dirs = RestoreDirs::create(&staging)?;

        manifest
            .files
            .iter()
            .try_for_each(|entry| copy_validated_entry(entry, source, &staging))?;

        dirs.finalize(&manifest, |prefix| {
            u32::try_from(
                manifest
                    .files
                    .iter()
                    .filter(|e| e.path.starts_with(prefix))
                    .count(),
            )
            .unwrap_or(u32::MAX)
        })
    })();

    promote_or_cleanup(staging, target, result)
}

fn validate_incremental_chain(
    base: &BackupManifest,
    incr: &BackupManifest,
) -> Result<(), BackupError> {
    match incr.kind {
        BackupKind::Incremental => {}
        BackupKind::Full => {
            return Err(BackupError::ChainMismatch(
                "incremental manifest has kind=Full".into(),
            ));
        }
    }

    if incr.created_at_ms < base.created_at_ms {
        return Err(BackupError::ChainMismatch(
            "incremental backup predates its base".into(),
        ));
    }

    match (&incr.base_blockstore, &incr.base_eventlog) {
        (Some(recorded_bs), Some(recorded_el)) => {
            if *recorded_bs != base.blockstore {
                return Err(BackupError::ChainMismatch(
                    "incremental blockstore base does not match provided base manifest".into(),
                ));
            }
            if *recorded_el != base.eventlog {
                return Err(BackupError::ChainMismatch(
                    "incremental eventlog base does not match provided base manifest".into(),
                ));
            }
        }
        _ => {
            return Err(BackupError::ChainMismatch(
                "incremental manifest missing base_blockstore or base_eventlog".into(),
            ));
        }
    }

    if incr.blockstore.epoch < base.blockstore.epoch {
        return Err(BackupError::ChainMismatch(
            "incremental blockstore epoch regressed from base".into(),
        ));
    }

    if incr.eventlog.max_seq < base.eventlog.max_seq {
        return Err(BackupError::ChainMismatch(
            "incremental eventlog max_seq regressed from base".into(),
        ));
    }

    Ok(())
}

pub fn restore_from_incremental(
    base_dir: &Path,
    incremental_dir: &Path,
    target: &Path,
) -> Result<RestoreResult, BackupError> {
    reject_nonempty_target(target)?;

    let base_manifest = read_manifest(base_dir)?;
    let incr_manifest = read_manifest(incremental_dir)?;

    validate_incremental_chain(&base_manifest, &incr_manifest)?;

    validate_manifest_checksums(&base_manifest, base_dir)?;
    validate_manifest_checksums(&incr_manifest, incremental_dir)?;

    let staging = staging_dir(target)?;

    let result = (|| {
        let dirs = RestoreDirs::create(&staging)?;

        let incr_paths: HashSet<&str> = incr_manifest
            .files
            .iter()
            .map(|e| e.path.as_str())
            .collect();

        base_manifest
            .files
            .iter()
            .filter(|entry| !incr_paths.contains(entry.path.as_str()))
            .try_for_each(|entry| copy_validated_entry(entry, base_dir, &staging))?;

        incr_manifest
            .files
            .iter()
            .try_for_each(|entry| copy_validated_entry(entry, incremental_dir, &staging))?;

        dirs.finalize(&incr_manifest, |prefix| {
            let from_base = base_manifest
                .files
                .iter()
                .filter(|e| e.path.starts_with(prefix) && !incr_paths.contains(e.path.as_str()))
                .count();
            let from_incr = incr_manifest
                .files
                .iter()
                .filter(|e| e.path.starts_with(prefix))
                .count();
            u32::try_from(from_base.saturating_add(from_incr)).unwrap_or(u32::MAX)
        })
    })();

    promote_or_cleanup(staging, target, result)
}

pub fn recover_to_sequence(
    backup: &Path,
    eventlog_archive: &Path,
    target_seq: EventSequence,
    target: &Path,
) -> Result<PitrResult, BackupError> {
    let manifest = read_manifest(backup)?;
    let backup_max_seq = manifest.eventlog.max_seq;

    if target_seq < backup_max_seq {
        return Err(BackupError::RestoreVerification(format!(
            "target_seq ({target_seq}) precedes backup max_seq ({backup_max_seq})",
        )));
    }

    let restore = restore_from_backup(backup, target)?;

    if target_seq == backup_max_seq {
        return Ok(PitrResult {
            restore,
            events_replayed: 0,
            target_seq,
        });
    }

    let target_events = target.join(EVENTS_DIR);
    merge_archived_segments(eventlog_archive, &target_events, &manifest)?;

    let metastore = Metastore::open(&target.join(METASTORE_DIR), MetastoreConfig::default())?;

    let eventlog = EventLog::open(
        EventLogConfig {
            segments_dir: target_events,
            ..EventLogConfig::default()
        },
        RealIO::new(),
    )?;

    let eventlog_max = eventlog.max_seq();
    if target_seq > eventlog_max {
        let _ = eventlog.shutdown();
        return Err(BackupError::RestoreVerification(format!(
            "target_seq ({target_seq}) exceeds available eventlog max_seq ({eventlog_max})",
        )));
    }

    let events_replayed =
        replay_mutations_bounded(&eventlog, &metastore, backup_max_seq, target_seq)?;

    metastore.persist()?;
    let _ = eventlog.shutdown();

    Ok(PitrResult {
        restore,
        events_replayed,
        target_seq,
    })
}

const PITR_BATCH_SIZE: usize = 4096;

fn merge_archived_segments(
    archive: &Path,
    target_events: &Path,
    manifest: &BackupManifest,
) -> Result<(), BackupError> {
    let backup_active_id = manifest.eventlog.active_segment_id;

    std::fs::read_dir(archive)?
        .filter(|entry| {
            entry.as_ref().map_or(true, |e| {
                e.path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext == "tqe")
            })
        })
        .try_for_each(|entry| {
            let entry = entry?;
            let src = entry.path();
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();
            let seg_id = name
                .strip_suffix(".tqe")
                .and_then(|s| s.parse::<u32>().ok())
                .map(SegmentId::new);

            match seg_id {
                Some(id) if id > backup_active_id => {
                    let dest = target_events.join(&*file_name);
                    copy_file_synced(&src, &dest, None)?;
                    Ok::<(), io::Error>(())
                }
                Some(id) if id == backup_active_id => {
                    let archive_size = entry.metadata()?.len();
                    let backup_size = manifest.eventlog.active_segment_position.raw();
                    if archive_size > backup_size {
                        let dest = target_events.join(&*file_name);
                        copy_file_synced(&src, &dest, None)?;
                    }
                    Ok(())
                }
                _ => Ok(()),
            }
        })?;

    sync_dir(target_events)?;
    Ok(())
}

fn ewm_to_event_sequence(ewm: &EventWithMutations) -> Result<EventSequence, BackupError> {
    EventSequence::try_from(ewm.event.seq).map_err(|reason| {
        BackupError::RestoreVerification(format!(
            "event sequence {} not convertible: {reason}",
            ewm.event.seq
        ))
    })
}

fn replay_mutations_bounded(
    eventlog: &EventLog<RealIO>,
    metastore: &Metastore,
    from_seq: EventSequence,
    target_seq: EventSequence,
) -> Result<u64, BackupError> {
    let repo_data = metastore.partition(Partition::RepoData);
    let indexes = metastore.partition(Partition::Indexes);
    let db = metastore.database();
    let cursor_key = metastore_cursor_key();

    let mut cursor = from_seq;
    let mut total = 0u64;

    loop {
        let page = eventlog.get_events_with_mutations_since(cursor, PITR_BATCH_SIZE)?;
        let reached_end = page.len() < PITR_BATCH_SIZE;

        let cutoff = page
            .iter()
            .position(|ewm| ewm_to_event_sequence(ewm).is_ok_and(|es| es > target_seq))
            .unwrap_or(page.len());

        let (new_cursor, new_total) =
            page[..cutoff]
                .iter()
                .try_fold((cursor, total), |(_, count), ewm| {
                    let event_es = ewm_to_event_sequence(ewm)?;
                    replay_single_event(db, repo_data, indexes, &cursor_key, ewm, event_es)?;
                    Ok::<_, BackupError>((event_es, count.saturating_add(1)))
                })?;

        cursor = new_cursor;
        total = new_total;

        if cutoff < page.len() || reached_end {
            return Ok(total);
        }
    }
}

fn replay_single_event(
    db: &fjall::Database,
    repo_data: &fjall::Keyspace,
    indexes: &fjall::Keyspace,
    cursor_key: &[u8],
    ewm: &EventWithMutations,
    event_es: EventSequence,
) -> Result<(), BackupError> {
    let seq_raw = event_es.raw();
    let user_hash = UserHash::from_did(ewm.event.did.as_str());
    let mut batch = db.batch();

    let de_key = did_events_key(user_hash, seq_raw);
    batch.insert(repo_data, de_key.as_slice(), []);

    if let Some(rev) = &ewm.event.rev {
        let rs_key = rev_to_seq_key(user_hash, rev);
        batch.insert(repo_data, rs_key.as_slice(), seq_raw.to_be_bytes());
    }

    if let Some(ms_bytes) = &ewm.mutation_set {
        let ms = CommitMutationSet::deserialize(ms_bytes).ok_or_else(|| {
            BackupError::RestoreVerification(format!("corrupt CommitMutationSet at seq {seq_raw}"))
        })?;

        let meta_key = repo_meta_key(user_hash);
        let current_meta = repo_data
            .get(meta_key.as_slice())
            .map_err(MetastoreError::from)?
            .and_then(|raw| RepoMetaValue::deserialize(&raw))
            .unwrap_or_else(|| RepoMetaValue {
                repo_root_cid: vec![],
                repo_rev: String::new(),
                handle: String::new(),
                status: RepoStatus::Active,
                deactivated_at_ms: None,
                takedown_ref: None,
                did: Some(ewm.event.did.as_str().to_owned()),
            });

        replay_mutation_set(
            &mut batch,
            repo_data,
            indexes,
            user_hash,
            &current_meta,
            &ms,
        )
        .map_err(BackupError::Metastore)?;
    }

    batch.insert(repo_data, cursor_key, seq_raw.to_be_bytes());
    batch.commit().map_err(MetastoreError::from)?;

    Ok(())
}

fn reject_nonempty_target(target: &Path) -> Result<(), BackupError> {
    match std::fs::read_dir(target) {
        Ok(mut entries) => match entries.next() {
            Some(_) => Err(BackupError::TargetNotEmpty(target.display().to_string())),
            None => Ok(()),
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(BackupError::Io(e)),
    }
}

fn staging_dir(target: &Path) -> Result<std::path::PathBuf, BackupError> {
    let parent = target.parent().ok_or_else(|| {
        BackupError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "target path has no parent directory",
        ))
    })?;
    std::fs::create_dir_all(parent)?;
    let stem = target
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    let staging = parent.join(format!(".{stem}.restore-staging"));
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    std::fs::create_dir_all(&staging)?;
    Ok(staging)
}

fn promote_or_cleanup<T>(
    staging: std::path::PathBuf,
    target: &Path,
    result: Result<T, BackupError>,
) -> Result<T, BackupError> {
    match result {
        Ok(val) => {
            std::fs::rename(&staging, target)?;
            if let Some(parent) = target.parent() {
                sync_dir(parent)?;
            }
            Ok(val)
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&staging);
            Err(e)
        }
    }
}

fn validate_manifest_checksums(
    manifest: &BackupManifest,
    backup_dir: &Path,
) -> Result<(), BackupError> {
    manifest.files.iter().try_for_each(|entry| {
        let file_path = backup_dir.join(&entry.path);

        let metadata = std::fs::metadata(&file_path).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => BackupError::MissingFile(entry.path.clone()),
            _ => BackupError::Io(e),
        })?;

        let actual_size = metadata.len();
        if actual_size != entry.size {
            return Err(BackupError::SizeMismatch {
                path: entry.path.clone(),
                expected: entry.size,
                actual: actual_size,
            });
        }

        let actual_checksum = checksum_file(&file_path)?;
        if actual_checksum != entry.xxh3_checksum {
            return Err(BackupError::ChecksumMismatch {
                path: entry.path.clone(),
                expected: entry.xxh3_checksum,
                actual: actual_checksum,
            });
        }

        Ok(())
    })
}

fn verify_restored_eventlog(
    events_dir: &Path,
    manifest: &BackupManifest,
) -> Result<(), BackupError> {
    use crate::eventlog::{DEFAULT_INDEX_INTERVAL, MAX_EVENT_PAYLOAD, rebuild_from_segment};

    if manifest.eventlog.max_seq == EventSequence::BEFORE_ALL {
        return Ok(());
    }

    let real_io = RealIO::new();
    let active_path = events_dir.join(format!("{}.tqe", manifest.eventlog.active_segment_id));
    let fd = real_io.open(&active_path, crate::OpenOptions::read_only_existing())?;
    let (_, last_seq) =
        match rebuild_from_segment(&real_io, fd, DEFAULT_INDEX_INTERVAL, MAX_EVENT_PAYLOAD) {
            Ok(result) => {
                real_io.close(fd)?;
                result
            }
            Err(e) => {
                let _ = real_io.close(fd);
                return Err(e.into());
            }
        };

    let restored_max = last_seq.unwrap_or(EventSequence::BEFORE_ALL);
    if restored_max != manifest.eventlog.max_seq {
        return Err(BackupError::RestoreVerification(format!(
            "eventlog max_seq mismatch: manifest={}, restored={}",
            manifest.eventlog.max_seq, restored_max,
        )));
    }

    Ok(())
}

fn verify_restored_metastore(metastore_dir: &Path) -> Result<(), BackupError> {
    let _metastore = Metastore::open(metastore_dir, MetastoreConfig::default())?;
    Ok(())
}

pub fn verify_backup(source: &Path) -> Result<VerifyResult, BackupError> {
    let manifest = read_manifest(source)?;

    let file_failures: Vec<FileFailure> = manifest
        .files
        .iter()
        .filter_map(|entry| {
            let file_path = source.join(&entry.path);
            match std::fs::metadata(&file_path) {
                Err(e) => return Some(FileFailure::Unreadable(entry.path.clone(), e)),
                Ok(m) if m.len() != entry.size => {
                    return Some(FileFailure::SizeMismatch(entry.path.clone()));
                }
                _ => {}
            }
            match checksum_file(&file_path) {
                Ok(actual) if actual != entry.xxh3_checksum => {
                    Some(FileFailure::ChecksumMismatch(entry.path.clone()))
                }
                Err(e) => Some(FileFailure::Unreadable(entry.path.clone(), e)),
                _ => None,
            }
        })
        .collect();

    let io = RealIO::new();
    let blocks_dir = source.join(BLOCKS_DIR);
    let (total_blocks, corrupted_blocks) = match blocks_dir.is_dir() {
        true => verify_blockstore_integrity(&io, &blocks_dir)?,
        false => (0, 0),
    };

    let events_dir = source.join(EVENTS_DIR);
    let (total_events, corrupted_events) = match events_dir.is_dir() {
        true => verify_eventlog_integrity(&io, &events_dir)?,
        false => (0, 0),
    };

    Ok(VerifyResult {
        total_blocks,
        total_events,
        corrupted_blocks,
        corrupted_events,
        file_failures,
    })
}

enum RecordHealth {
    Valid,
    Corrupted,
}

fn tally_record_health(records: impl Iterator<Item = RecordHealth>) -> (u64, u64) {
    records.fold((0u64, 0u64), |(total, corrupted), health| match health {
        RecordHealth::Valid => (total.saturating_add(1), corrupted),
        RecordHealth::Corrupted => (total.saturating_add(1), corrupted.saturating_add(1)),
    })
}

fn verify_blockstore_integrity<S: StorageIO>(
    io: &S,
    blocks_dir: &Path,
) -> Result<(u64, u64), BackupError> {
    use crate::blockstore::{DataFileReader, ReadBlockRecord, list_files_by_extension};

    let file_ids = list_files_by_extension(io, blocks_dir, "tqb")?;

    file_ids.iter().try_fold(
        (0u64, 0u64),
        |(total, corrupted), &file_id| -> Result<(u64, u64), BackupError> {
            let path = blocks_dir.join(format!("{file_id}.tqb"));
            let fd = io.open(&path, crate::OpenOptions::read_only_existing())?;
            let reader = match DataFileReader::open(io, fd) {
                Ok(r) => r,
                Err(e) => {
                    let _ = io.close(fd);
                    return Err(e.into());
                }
            };

            let (ft, fc) = tally_record_health(reader.map(|r| match r {
                Ok(ReadBlockRecord::Valid { .. }) => RecordHealth::Valid,
                _ => RecordHealth::Corrupted,
            }));

            io.close(fd)?;
            Ok((total.saturating_add(ft), corrupted.saturating_add(fc)))
        },
    )
}

fn verify_eventlog_integrity<S: StorageIO>(
    io: &S,
    events_dir: &Path,
) -> Result<(u64, u64), BackupError> {
    use crate::eventlog::{MAX_EVENT_PAYLOAD, ReadEventRecord, SegmentReader};

    let entries = io.list_dir(events_dir)?;
    let mut segment_paths: Vec<std::path::PathBuf> = entries
        .into_iter()
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("tqe"))
        .collect();
    segment_paths.sort();

    segment_paths.iter().try_fold(
        (0u64, 0u64),
        |(total, corrupted), path| -> Result<(u64, u64), BackupError> {
            let fd = io.open(path, crate::OpenOptions::read_only_existing())?;
            let reader = match SegmentReader::open(io, fd, MAX_EVENT_PAYLOAD) {
                Ok(r) => r,
                Err(e) => {
                    let _ = io.close(fd);
                    return Err(e.into());
                }
            };

            let (st, sc) = tally_record_health(reader.map(|r| match r {
                Ok(ReadEventRecord::Valid { .. }) => RecordHealth::Valid,
                _ => RecordHealth::Corrupted,
            }));

            io.close(fd)?;
            Ok((total.saturating_add(st), corrupted.saturating_add(sc)))
        },
    )
}

fn sync_dir(path: &Path) -> io::Result<()> {
    let dir = std::fs::File::open(path)?;
    dir.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockstore::WriteCursor;

    fn make_full_manifest(files: Vec<BackupFileEntry>) -> BackupManifest {
        BackupManifest {
            version: BACKUP_FORMAT_VERSION,
            created_at_ms: 1_700_000_000_000,
            blockstore: BlockstoreManifest {
                write_cursor_file_id: DataFileId::new(5),
                write_cursor_offset: BlockOffset::new(102400),
                epoch: CommitEpoch::new(42),
                shard_cursors: vec![ShardCursorEntry {
                    file_id: DataFileId::new(5),
                    offset: BlockOffset::new(102400),
                }],
            },
            eventlog: EventLogManifest {
                max_seq: EventSequence::new(1000),
                active_segment_id: SegmentId::new(3),
                active_segment_position: SegmentOffset::new(32768),
            },
            metastore_seqno: MetastoreSeqno::new(5000),
            files,
            kind: BackupKind::Full,
            base_blockstore: None,
            base_eventlog: None,
        }
    }

    #[test]
    fn manifest_round_trip() {
        let manifest = make_full_manifest(vec![
            BackupFileEntry {
                path: "blocks/000000.tqb".into(),
                size: 256000,
                xxh3_checksum: 0xDEAD_BEEF_CAFE_1234,
            },
            BackupFileEntry {
                path: "events/00000001.tqe".into(),
                size: 64000,
                xxh3_checksum: 0x1234_5678_9ABC_DEF0,
            },
        ]);

        let json = serde_json::to_string_pretty(&manifest).unwrap();
        let decoded: BackupManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.version, manifest.version);
        assert_eq!(decoded.blockstore.write_cursor_file_id, DataFileId::new(5));
        assert_eq!(decoded.blockstore.epoch, CommitEpoch::new(42));
        assert_eq!(decoded.eventlog.max_seq, EventSequence::new(1000));
        assert_eq!(decoded.metastore_seqno, MetastoreSeqno::new(5000));
        assert_eq!(decoded.files.len(), 2);
        assert_eq!(decoded.files[0].xxh3_checksum, 0xDEAD_BEEF_CAFE_1234);
        assert_eq!(decoded.kind, BackupKind::Full);
        assert!(decoded.base_blockstore.is_none());
    }

    #[test]
    fn checksum_deterministic() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.bin");
        std::fs::write(&path, b"hello world checksum test").unwrap();

        let c1 = checksum_file(&path).unwrap();
        let c2 = checksum_file(&path).unwrap();
        assert_eq!(c1, c2);
        assert_ne!(c1, 0);
    }

    #[test]
    fn copy_file_synced_full() {
        let dir = tempfile::TempDir::new().unwrap();
        let src = dir.path().join("src.bin");
        let dest = dir.path().join("dest.bin");
        let data = vec![0xABu8; 1024];
        std::fs::write(&src, &data).unwrap();

        let copied = copy_file_synced(&src, &dest, None).unwrap();
        assert_eq!(copied, 1024);
        assert_eq!(std::fs::read(&dest).unwrap(), data);
    }

    #[test]
    fn copy_file_synced_partial() {
        let dir = tempfile::TempDir::new().unwrap();
        let src = dir.path().join("src.bin");
        let dest = dir.path().join("dest.bin");
        let data = vec![0xCDu8; 1024];
        std::fs::write(&src, &data).unwrap();

        let copied = copy_file_synced(&src, &dest, Some(512)).unwrap();
        assert_eq!(copied, 512);

        let result = std::fs::read(&dest).unwrap();
        assert_eq!(result.len(), 512);
        assert_eq!(result, &data[..512]);
    }

    #[test]
    fn copy_dir_recursive_skips_lock() {
        let dir = tempfile::TempDir::new().unwrap();
        let src = dir.path().join("src");
        let dest = dir.path().join("dest");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("data.sst"), b"sst data").unwrap();
        std::fs::write(src.join("sub/nested.sst"), b"nested").unwrap();
        std::fs::write(src.join(".lock"), b"locked").unwrap();

        let mut files = Vec::new();
        copy_metastore_files(&src, &dest, &mut files).unwrap();

        assert!(dest.join("data.sst").exists());
        assert!(dest.join("sub/nested.sst").exists());
        assert!(!dest.join(".lock").exists());
        assert_eq!(files.len(), 2);
        assert!(files.iter().all(|f| f.path.starts_with(METASTORE_DIR)));
    }

    #[test]
    fn manifest_write_and_read() {
        let dir = tempfile::TempDir::new().unwrap();
        let manifest = make_full_manifest(Vec::new());

        write_manifest(&manifest, dir.path()).unwrap();
        let loaded = read_manifest(dir.path()).unwrap();
        assert_eq!(loaded.version, BACKUP_FORMAT_VERSION);
        assert_eq!(loaded.kind, BackupKind::Full);
    }

    #[test]
    fn read_manifest_rejects_unknown_version() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut manifest = make_full_manifest(Vec::new());
        manifest.version = 999;

        let json = serde_json::to_string_pretty(&manifest).unwrap();
        std::fs::write(dir.path().join(MANIFEST_FILENAME), json.as_bytes()).unwrap();

        let err = read_manifest(dir.path()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn verify_copy_size_mismatch() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("dummy.bin");
        std::fs::write(&path, b"").unwrap();

        let err = verify_copy_size(100, 200, &path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn legacy_manifest_without_kind_deserializes_as_full() {
        let json = r#"{
            "version": 1,
            "created_at_ms": 42,
            "blockstore": {
                "write_cursor_file_id": 0,
                "write_cursor_offset": 0,
                "epoch": 0
            },
            "eventlog": {
                "max_seq": 0,
                "active_segment_id": 0,
                "active_segment_position": 0
            },
            "metastore_seqno": 0,
            "files": []
        }"#;

        let decoded: BackupManifest = serde_json::from_str(json).unwrap();
        assert_eq!(decoded.kind, BackupKind::Full);
        assert!(decoded.base_blockstore.is_none());
        assert!(decoded.base_eventlog.is_none());
    }

    #[test]
    fn incremental_manifest_round_trip() {
        let base_bs = BlockstoreManifest {
            write_cursor_file_id: DataFileId::new(3),
            write_cursor_offset: BlockOffset::new(50000),
            epoch: CommitEpoch::new(10),
            shard_cursors: vec![ShardCursorEntry {
                file_id: DataFileId::new(3),
                offset: BlockOffset::new(50000),
            }],
        };
        let base_el = EventLogManifest {
            max_seq: EventSequence::new(500),
            active_segment_id: SegmentId::new(2),
            active_segment_position: SegmentOffset::new(16384),
        };

        let manifest = BackupManifest {
            version: BACKUP_FORMAT_VERSION,
            created_at_ms: 1_700_000_000_000,
            blockstore: BlockstoreManifest {
                write_cursor_file_id: DataFileId::new(7),
                write_cursor_offset: BlockOffset::new(200000),
                epoch: CommitEpoch::new(50),
                shard_cursors: vec![ShardCursorEntry {
                    file_id: DataFileId::new(7),
                    offset: BlockOffset::new(200000),
                }],
            },
            eventlog: EventLogManifest {
                max_seq: EventSequence::new(2000),
                active_segment_id: SegmentId::new(5),
                active_segment_position: SegmentOffset::new(65536),
            },
            metastore_seqno: MetastoreSeqno::new(9000),
            files: vec![BackupFileEntry {
                path: "blocks/000007.tqb".into(),
                size: 200000,
                xxh3_checksum: 0xAAAA_BBBB_CCCC_DDDD,
            }],
            kind: BackupKind::Incremental,
            base_blockstore: Some(base_bs.clone()),
            base_eventlog: Some(base_el.clone()),
        };

        let json = serde_json::to_string_pretty(&manifest).unwrap();
        let decoded: BackupManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.kind, BackupKind::Incremental);
        let decoded_base_bs = decoded.base_blockstore.unwrap();
        assert_eq!(decoded_base_bs.write_cursor_file_id, DataFileId::new(3));
        assert_eq!(decoded_base_bs.write_cursor_offset, BlockOffset::new(50000));
        let decoded_base_el = decoded.base_eventlog.unwrap();
        assert_eq!(decoded_base_el.active_segment_id, SegmentId::new(2));
    }

    #[test]
    fn incremental_blockstore_filters_old_files() {
        let base = BlockstoreManifest {
            write_cursor_file_id: DataFileId::new(3),
            write_cursor_offset: BlockOffset::new(50000),
            epoch: CommitEpoch::new(10),
            shard_cursors: vec![ShardCursorEntry {
                file_id: DataFileId::new(3),
                offset: BlockOffset::new(50000),
            }],
        };

        let snapshot = BlockstoreSnapshot {
            shard_cursors: vec![WriteCursor {
                file_id: DataFileId::new(5),
                offset: BlockOffset::new(1024),
            }],
            epoch: CommitEpoch::new(15),
            data_files: vec![
                DataFileId::new(0),
                DataFileId::new(1),
                DataFileId::new(2),
                DataFileId::new(3),
                DataFileId::new(4),
                DataFileId::new(5),
            ],
        };

        let dir = tempfile::TempDir::new().unwrap();
        let data_dir = dir.path().join("data");
        let dest_dir = dir.path().join("dest");
        std::fs::create_dir_all(&data_dir).unwrap();

        (0u32..=5).for_each(|id| {
            let path = data_dir.join(format!("{}.tqb", DataFileId::new(id)));
            std::fs::write(&path, vec![0xABu8; 2048]).unwrap();
        });

        let mut files = Vec::new();
        copy_blockstore_files(
            &snapshot,
            base.write_cursor_file_id,
            &data_dir,
            &dest_dir,
            &mut files,
        )
        .unwrap();

        let copied_ids: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();

        assert_eq!(copied_ids.len(), 3);
        assert!(copied_ids.contains(&"blocks/000003.tqb"));
        assert!(copied_ids.contains(&"blocks/000004.tqb"));
        assert!(copied_ids.contains(&"blocks/000005.tqb"));

        assert!(!dest_dir.join("000000.tqb").exists());
        assert!(!dest_dir.join("000001.tqb").exists());
        assert!(!dest_dir.join("000002.tqb").exists());
    }

    #[test]
    fn incremental_eventlog_filters_old_segments() {
        let base = EventLogManifest {
            max_seq: EventSequence::new(500),
            active_segment_id: SegmentId::new(2),
            active_segment_position: SegmentOffset::new(8192),
        };

        let snapshot = EventLogSnapshotState {
            max_seq: EventSequence::new(1500),
            active_segment_id: SegmentId::new(4),
            active_segment_position: SegmentOffset::new(4096),
            sealed_segments: vec![
                SegmentId::new(0),
                SegmentId::new(1),
                SegmentId::new(2),
                SegmentId::new(3),
            ],
        };

        let dir = tempfile::TempDir::new().unwrap();
        let seg_dir = dir.path().join("segments");
        let dest_dir = dir.path().join("dest");
        std::fs::create_dir_all(&seg_dir).unwrap();

        (0u32..=4).for_each(|id| {
            let path = seg_dir.join(format!("{}.tqe", SegmentId::new(id)));
            std::fs::write(&path, vec![0xCDu8; 4096]).unwrap();
        });

        let mut files = Vec::new();
        copy_eventlog_files(
            &snapshot,
            base.active_segment_id,
            &seg_dir,
            &dest_dir,
            &mut files,
        )
        .unwrap();

        let copied_ids: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();

        assert_eq!(copied_ids.len(), 3);
        assert!(copied_ids.contains(&"events/00000002.tqe"));
        assert!(copied_ids.contains(&"events/00000003.tqe"));
        assert!(copied_ids.contains(&"events/00000004.tqe"));

        assert!(!dest_dir.join("00000000.tqe").exists());
        assert!(!dest_dir.join("00000001.tqe").exists());
    }

    #[test]
    fn incremental_no_change_produces_minimal_delta() {
        let base = BlockstoreManifest {
            write_cursor_file_id: DataFileId::new(2),
            write_cursor_offset: BlockOffset::new(4096),
            epoch: CommitEpoch::new(5),
            shard_cursors: vec![ShardCursorEntry {
                file_id: DataFileId::new(2),
                offset: BlockOffset::new(4096),
            }],
        };

        let snapshot = BlockstoreSnapshot {
            shard_cursors: vec![WriteCursor {
                file_id: DataFileId::new(2),
                offset: BlockOffset::new(4096),
            }],
            epoch: CommitEpoch::new(5),
            data_files: vec![DataFileId::new(0), DataFileId::new(1), DataFileId::new(2)],
        };

        let dir = tempfile::TempDir::new().unwrap();
        let data_dir = dir.path().join("data");
        let dest_dir = dir.path().join("dest");
        std::fs::create_dir_all(&data_dir).unwrap();

        (0u32..=2).for_each(|id| {
            let path = data_dir.join(format!("{}.tqb", DataFileId::new(id)));
            std::fs::write(&path, vec![0u8; 4096]).unwrap();
        });

        let mut files = Vec::new();
        copy_blockstore_files(
            &snapshot,
            base.write_cursor_file_id,
            &data_dir,
            &dest_dir,
            &mut files,
        )
        .unwrap();

        assert_eq!(files.len(), 1);
        assert!(files[0].path.contains("000002"));
    }

    #[test]
    fn chain_validation_rejects_kind_full() {
        let base = make_full_manifest(Vec::new());
        let incr = make_full_manifest(Vec::new());

        let err = validate_incremental_chain(&base, &incr).unwrap_err();
        assert!(matches!(err, BackupError::ChainMismatch(_)));
    }

    #[test]
    fn chain_validation_rejects_mismatched_base() {
        let base = make_full_manifest(Vec::new());
        let mut incr = make_full_manifest(Vec::new());
        incr.kind = BackupKind::Incremental;
        incr.base_blockstore = Some(BlockstoreManifest {
            write_cursor_file_id: DataFileId::new(99),
            write_cursor_offset: BlockOffset::new(0),
            epoch: CommitEpoch::new(0),
            shard_cursors: Vec::new(),
        });
        incr.base_eventlog = Some(base.eventlog.clone());

        let err = validate_incremental_chain(&base, &incr).unwrap_err();
        assert!(matches!(err, BackupError::ChainMismatch(_)));
    }

    #[test]
    fn chain_validation_accepts_matching_base() {
        let base = make_full_manifest(Vec::new());
        let mut incr = make_full_manifest(Vec::new());
        incr.kind = BackupKind::Incremental;
        incr.base_blockstore = Some(base.blockstore.clone());
        incr.base_eventlog = Some(base.eventlog.clone());

        validate_incremental_chain(&base, &incr).unwrap();
    }

    #[test]
    fn chain_validation_rejects_timestamp_regression() {
        let base = make_full_manifest(Vec::new());
        let mut incr = make_full_manifest(Vec::new());
        incr.kind = BackupKind::Incremental;
        incr.base_blockstore = Some(base.blockstore.clone());
        incr.base_eventlog = Some(base.eventlog.clone());
        incr.created_at_ms = base.created_at_ms - 1;

        let err = validate_incremental_chain(&base, &incr).unwrap_err();
        assert!(matches!(err, BackupError::ChainMismatch(_)));
    }

    #[test]
    fn chain_validation_rejects_epoch_regression() {
        let base = make_full_manifest(Vec::new());
        let mut incr = make_full_manifest(Vec::new());
        incr.kind = BackupKind::Incremental;
        incr.base_blockstore = Some(base.blockstore.clone());
        incr.base_eventlog = Some(base.eventlog.clone());
        incr.blockstore.epoch = CommitEpoch::new(base.blockstore.epoch.raw() - 1);

        let err = validate_incremental_chain(&base, &incr).unwrap_err();
        assert!(matches!(err, BackupError::ChainMismatch(_)));
    }

    #[test]
    fn chain_validation_rejects_eventlog_regression() {
        let base = make_full_manifest(Vec::new());
        let mut incr = make_full_manifest(Vec::new());
        incr.kind = BackupKind::Incremental;
        incr.base_blockstore = Some(base.blockstore.clone());
        incr.base_eventlog = Some(base.eventlog.clone());
        incr.eventlog.max_seq = EventSequence::new(base.eventlog.max_seq.raw() - 1);

        let err = validate_incremental_chain(&base, &incr).unwrap_err();
        assert!(matches!(err, BackupError::ChainMismatch(_)));
    }
}
