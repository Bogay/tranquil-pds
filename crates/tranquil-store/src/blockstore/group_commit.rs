use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU32, Ordering};
use std::thread;

use parking_lot::RwLock;

use crate::fsync_order::PostBlockstoreHook;

use super::BlocksSynced;
use crate::io::{FileId, OpenOptions, StorageIO};

use super::data_file::{CID_SIZE, DataFileWriter, ReadBlockRecord, decode_block_record};
use super::hash_index::{BlockIndex, BlockIndexError, CheckpointPositions};
use super::hint::{HintFileWriter, hint_file_path};
use super::manager::DataFileManager;
use super::types::{
    BlockLocation, BlockOffset, BlockstoreSnapshot, CommitEpoch, DataFileId, EpochCounter,
    HintOffset, ShardId, WriteCursor,
};

pub struct FileIdAllocator {
    next: AtomicU32,
}

impl FileIdAllocator {
    pub fn new(max_existing: DataFileId) -> Self {
        Self {
            next: AtomicU32::new(max_existing.raw().saturating_add(1)),
        }
    }

    pub fn allocate(&self) -> DataFileId {
        let id = self
            .next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
            .expect("FileIdAllocator overflow: exhausted u32 file ID space");
        DataFileId::new(id)
    }

    pub fn peek(&self) -> DataFileId {
        DataFileId::new(self.next.load(Ordering::Relaxed))
    }
}

pub struct ActiveFileSet {
    files: RwLock<Vec<DataFileId>>,
}

impl ActiveFileSet {
    pub fn with_capacity(n: usize) -> Self {
        Self {
            files: RwLock::new(Vec::with_capacity(n)),
        }
    }

    pub fn register(&self, shard: ShardId, file_id: DataFileId) {
        let mut files = self.files.write();
        let idx = shard.as_usize();
        if idx >= files.len() {
            files.resize(idx.saturating_add(1), DataFileId::new(0));
        }
        files[idx] = file_id;
    }

    pub fn contains(&self, file_id: DataFileId) -> bool {
        self.files.read().contains(&file_id)
    }

    pub fn snapshot(&self) -> Vec<DataFileId> {
        self.files.read().clone()
    }
}

pub struct ShardHintPositions {
    positions: RwLock<Vec<(DataFileId, HintOffset)>>,
}

impl ShardHintPositions {
    pub fn new(shard_count: u8) -> Self {
        Self {
            positions: RwLock::new(
                (0..shard_count as usize)
                    .map(|_| (DataFileId::new(0), HintOffset::new(0)))
                    .collect(),
            ),
        }
    }

    pub fn update(&self, shard_id: ShardId, file_id: DataFileId, offset: HintOffset) {
        let mut positions = self.positions.write();
        let idx = shard_id.as_usize();
        if idx < positions.len() {
            positions[idx] = (file_id, offset);
        }
    }

    pub fn snapshot(&self) -> CheckpointPositions {
        CheckpointPositions(self.positions.read().clone())
    }
}

#[derive(Debug, Clone)]
pub enum CommitError {
    Io(Arc<io::Error>),
    Index(String),
    ChannelClosed,
    VerifyFailed {
        file_id: DataFileId,
        offset: BlockOffset,
    },
}

impl std::fmt::Display for CommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {}", e.as_ref()),
            Self::Index(e) => write!(f, "index: {e}"),
            Self::ChannelClosed => write!(f, "commit channel closed"),
            Self::VerifyFailed { file_id, offset } => write!(
                f,
                "post-sync verify failed at {file_id}:{} (misdirected write or durable corruption)",
                offset.raw()
            ),
        }
    }
}

impl std::error::Error for CommitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e.as_ref()),
            Self::Index(_) | Self::ChannelClosed | Self::VerifyFailed { .. } => None,
        }
    }
}

impl From<io::Error> for CommitError {
    fn from(e: io::Error) -> Self {
        Self::Io(Arc::new(e))
    }
}

impl From<BlockIndexError> for CommitError {
    fn from(e: BlockIndexError) -> Self {
        Self::Index(e.to_string())
    }
}

use super::compaction::{self, CompactionError};
use super::types::{CidBytes, CompactionResult, RefCount};

type PutResponse = tokio::sync::oneshot::Sender<Result<Vec<BlockLocation>, CommitError>>;
type ApplyResponse = tokio::sync::oneshot::Sender<Result<(), CommitError>>;
type CompactResponse = tokio::sync::oneshot::Sender<Result<CompactionResult, CompactionError>>;
type RepairResponse = tokio::sync::oneshot::Sender<Result<u64, CommitError>>;
type QuiesceResponse = tokio::sync::oneshot::Sender<BlockstoreSnapshot>;
type QuiesceResume = tokio::sync::oneshot::Receiver<()>;

pub enum CommitRequest {
    PutBlocks {
        blocks: Vec<([u8; CID_SIZE], Vec<u8>)>,
        response: PutResponse,
    },
    ApplyCommit {
        blocks: Vec<([u8; CID_SIZE], Vec<u8>)>,
        deleted_cids: Vec<[u8; CID_SIZE]>,
        response: ApplyResponse,
    },
    Compact {
        file_id: DataFileId,
        grace_period_ms: u64,
        response: CompactResponse,
    },
    RepairLeaked {
        leaked_cids: Vec<(CidBytes, RefCount)>,
        response: RepairResponse,
    },
    Quiesce {
        response: QuiesceResponse,
        resume: QuiesceResume,
    },
    Shutdown,
}

#[derive(Debug, Clone)]
pub struct GroupCommitConfig {
    pub max_batch_size: usize,
    pub channel_capacity: usize,
    pub checkpoint_interval_ms: u64,
    pub checkpoint_write_threshold: u64,
    pub verify_persisted_blocks: bool,
}

impl Default for GroupCommitConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 1024,
            channel_capacity: 4096,
            checkpoint_interval_ms: 60_000,
            checkpoint_write_threshold: 100_000,
            verify_persisted_blocks: false,
        }
    }
}

struct ShardContext {
    shard_id: ShardId,
    epoch: EpochCounter,
    file_ids: Arc<FileIdAllocator>,
    active_files: Arc<ActiveFileSet>,
    hint_positions: Arc<ShardHintPositions>,
    verify_persisted_blocks: bool,
}

struct ActiveState {
    file_id: DataFileId,
    fd: FileId,
    position: BlockOffset,
    hint_fd: FileId,
    hint_position: HintOffset,
}

fn log_thread_panic(payload: Box<dyn std::any::Any + Send>, context: &str) {
    let msg = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(|s| s.as_str()))
        .unwrap_or("unknown panic");
    tracing::error!(panic = msg, "{context}");
}

struct SingleShardWriter {
    sender: flume::Sender<CommitRequest>,
    handle: Option<thread::JoinHandle<()>>,
}

impl SingleShardWriter {
    fn spawn<S: StorageIO + 'static>(
        ctx: ShardContext,
        manager: DataFileManager<S>,
        index: Arc<BlockIndex>,
        config: GroupCommitConfig,
        post_sync_hook: Option<Arc<dyn PostBlockstoreHook>>,
        cursor: Option<WriteCursor>,
    ) -> Result<Self, CommitError> {
        let mut state = initialize_active_state(&manager, cursor, &ctx.file_ids)?;
        ctx.active_files.register(ctx.shard_id, state.file_id);
        ctx.hint_positions
            .update(ctx.shard_id, state.file_id, state.hint_position);

        let (sender, receiver) = flume::bounded(config.channel_capacity);

        let handle = thread::Builder::new()
            .name(format!("blockstore-commit-{}", ctx.shard_id))
            .spawn(move || {
                commit_loop(
                    &manager,
                    &index,
                    &receiver,
                    &config,
                    &mut state,
                    post_sync_hook.as_deref(),
                    &ctx,
                );
            })
            .map_err(|e| CommitError::from(io::Error::other(e)))?;

        Ok(Self {
            sender,
            handle: Some(handle),
        })
    }

    fn shutdown(&mut self) {
        let _ = self.sender.send(CommitRequest::Shutdown);
        if let Some(handle) = self.handle.take()
            && let Err(payload) = handle.join()
        {
            log_thread_panic(payload, "group commit thread panicked");
        }
    }
}

impl Drop for SingleShardWriter {
    fn drop(&mut self) {
        let _ = self.sender.try_send(CommitRequest::Shutdown);
        if let Some(handle) = self.handle.take()
            && let Err(payload) = handle.join()
        {
            log_thread_panic(payload, "group commit thread panicked during drop");
        }
    }
}

fn shard_for_cid(cid: &[u8; CID_SIZE], shard_count: u8) -> usize {
    match shard_count {
        0 | 1 => 0,
        n => {
            let hash_bytes: [u8; 8] = cid[4..12].try_into().unwrap();
            let hash = u64::from_le_bytes(hash_bytes);
            match n.is_power_of_two() {
                true => (hash & (n as u64 - 1)) as usize,
                false => (hash % n as u64) as usize,
            }
        }
    }
}

fn pick_shard_for_blocks(blocks: &[([u8; CID_SIZE], Vec<u8>)], shard_count: u8) -> usize {
    match blocks.first() {
        Some((cid, _)) => shard_for_cid(cid, shard_count),
        None => 0,
    }
}

fn pick_shard_for_apply(
    blocks: &[([u8; CID_SIZE], Vec<u8>)],
    deleted_cids: &[[u8; CID_SIZE]],
    shard_count: u8,
) -> usize {
    match blocks.first() {
        Some((cid, _)) => shard_for_cid(cid, shard_count),
        None => match deleted_cids.first() {
            Some(cid) => shard_for_cid(cid, shard_count),
            None => 0,
        },
    }
}

pub struct GroupCommitWriter {
    shards: Vec<SingleShardWriter>,
    epoch: EpochCounter,
    shard_count: u8,
    round_robin: AtomicU8,
    _file_ids: Arc<FileIdAllocator>,
    _active_files: Arc<ActiveFileSet>,
    _hint_positions: Arc<ShardHintPositions>,
}

impl GroupCommitWriter {
    pub fn spawn<S: StorageIO + 'static>(
        make_manager: impl Fn() -> DataFileManager<S>,
        index: Arc<BlockIndex>,
        config: GroupCommitConfig,
    ) -> Result<Self, CommitError> {
        Self::spawn_sharded(make_manager, index, config, None, None, 1, None)
    }

    pub fn spawn_with_hook<S: StorageIO + 'static>(
        make_manager: impl Fn() -> DataFileManager<S>,
        index: Arc<BlockIndex>,
        config: GroupCommitConfig,
        post_sync_hook: Option<Arc<dyn PostBlockstoreHook>>,
        initial_epoch: Option<CommitEpoch>,
    ) -> Result<Self, CommitError> {
        Self::spawn_sharded(
            make_manager,
            index,
            config,
            post_sync_hook,
            initial_epoch,
            1,
            None,
        )
    }

    pub fn spawn_sharded<F, S>(
        make_manager: F,
        index: Arc<BlockIndex>,
        config: GroupCommitConfig,
        post_sync_hook: Option<Arc<dyn PostBlockstoreHook>>,
        initial_epoch: Option<CommitEpoch>,
        shard_count: u8,
        checkpoint_positions: Option<&CheckpointPositions>,
    ) -> Result<Self, CommitError>
    where
        S: StorageIO + 'static,
        F: Fn() -> DataFileManager<S>,
    {
        let shard_count = shard_count.max(1);

        let probe_manager = make_manager();
        let existing_files = probe_manager.list_files()?;
        let max_existing = existing_files.last().copied().unwrap_or(DataFileId::new(0));
        let file_ids = Arc::new(FileIdAllocator::new(max_existing));
        let active_files = Arc::new(ActiveFileSet::with_capacity(shard_count as usize));
        let hint_positions = Arc::new(ShardHintPositions::new(shard_count));
        drop(probe_manager);

        let epoch = match initial_epoch {
            Some(e) => EpochCounter::from_raw(e.raw()),
            None => EpochCounter::new(),
        };

        let global_cursor = index.read_write_cursor();

        let shards: Result<Vec<SingleShardWriter>, CommitError> = (0..shard_count)
            .map(|i| {
                let shard_cursor = checkpoint_positions
                    .and_then(|cp| cp.0.get(i as usize))
                    .filter(|(fid, _)| fid.raw() > 0)
                    .map(|(fid, _)| WriteCursor {
                        file_id: *fid,
                        offset: BlockOffset::new(0),
                    })
                    .or(match i {
                        0 => global_cursor,
                        _ => None,
                    });
                let ctx = ShardContext {
                    shard_id: ShardId::new(i),
                    epoch: epoch.clone(),
                    file_ids: Arc::clone(&file_ids),
                    active_files: Arc::clone(&active_files),
                    hint_positions: Arc::clone(&hint_positions),
                    verify_persisted_blocks: config.verify_persisted_blocks,
                };
                SingleShardWriter::spawn(
                    ctx,
                    make_manager(),
                    Arc::clone(&index),
                    config.clone(),
                    post_sync_hook.clone(),
                    shard_cursor,
                )
            })
            .collect();

        Ok(Self {
            shards: shards?,
            epoch,
            shard_count,
            round_robin: AtomicU8::new(0),
            _file_ids: file_ids,
            _active_files: active_files,
            _hint_positions: hint_positions,
        })
    }

    pub fn epoch(&self) -> &EpochCounter {
        &self.epoch
    }

    pub fn sender_round_robin(&self) -> &flume::Sender<CommitRequest> {
        let idx = self
            .round_robin
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_rem(self.shard_count) as usize;
        &self.shards[idx].sender
    }

    pub fn sender_for_blocks(
        &self,
        blocks: &[([u8; CID_SIZE], Vec<u8>)],
    ) -> &flume::Sender<CommitRequest> {
        &self.shards[pick_shard_for_blocks(blocks, self.shard_count)].sender
    }

    pub fn sender_for_apply(
        &self,
        blocks: &[([u8; CID_SIZE], Vec<u8>)],
        deleted_cids: &[[u8; CID_SIZE]],
    ) -> &flume::Sender<CommitRequest> {
        &self.shards[pick_shard_for_apply(blocks, deleted_cids, self.shard_count)].sender
    }

    pub fn quiesce_all(
        &self,
    ) -> Result<(BlockstoreSnapshot, Vec<tokio::sync::oneshot::Sender<()>>), CommitError> {
        let pending: Result<Vec<_>, CommitError> = self
            .shards
            .iter()
            .map(|shard| {
                let (response_tx, response_rx) = tokio::sync::oneshot::channel();
                let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
                shard
                    .sender
                    .send(CommitRequest::Quiesce {
                        response: response_tx,
                        resume: resume_rx,
                    })
                    .map_err(|_| CommitError::ChannelClosed)?;
                Ok((response_rx, resume_tx))
            })
            .collect();

        let pairs: Result<Vec<_>, CommitError> = pending?
            .into_iter()
            .map(|(response_rx, resume_tx)| {
                let snapshot = response_rx
                    .blocking_recv()
                    .map_err(|_| CommitError::ChannelClosed)?;
                Ok((snapshot, resume_tx))
            })
            .collect();
        let pairs = pairs?;

        let mut all_data_files: Vec<DataFileId> = Vec::new();
        let mut shard_cursors: Vec<WriteCursor> = Vec::new();
        let mut max_epoch = CommitEpoch::zero();

        pairs.iter().for_each(|(snap, _)| {
            shard_cursors.extend(&snap.shard_cursors);
            all_data_files.extend(&snap.data_files);
            if snap.epoch > max_epoch {
                max_epoch = snap.epoch;
            }
        });

        all_data_files.sort();
        all_data_files.dedup();

        let resumes = pairs.into_iter().map(|(_, resume)| resume).collect();

        Ok((
            BlockstoreSnapshot {
                shard_cursors,
                epoch: max_epoch,
                data_files: all_data_files,
            },
            resumes,
        ))
    }

    pub fn shutdown(mut self) {
        self.shards.iter_mut().for_each(|s| s.shutdown());
    }
}

impl Drop for GroupCommitWriter {
    fn drop(&mut self) {
        self.shards.iter_mut().for_each(|s| {
            let _ = s.sender.try_send(CommitRequest::Shutdown);
        });
        self.shards.iter_mut().for_each(|s| {
            if let Some(handle) = s.handle.take()
                && let Err(payload) = handle.join()
            {
                log_thread_panic(payload, "group commit thread panicked during drop");
            }
        });
    }
}

fn initialize_active_state<S: StorageIO>(
    manager: &DataFileManager<S>,
    cursor: Option<WriteCursor>,
    file_ids: &FileIdAllocator,
) -> Result<ActiveState, CommitError> {
    let data_dir = manager.data_dir();

    match cursor {
        Some(wc) => {
            let handle = manager.open_for_append(wc.file_id)?;
            let fd = handle.fd();
            let file_size = manager.io().file_size(fd)?;

            if file_size < wc.offset.raw() {
                return Err(CommitError::from(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "data file smaller than write cursor",
                )));
            }

            let header_end = super::data_file::BLOCK_HEADER_SIZE as u64;
            let position = match file_size < header_end {
                true => {
                    let writer = DataFileWriter::new(manager.io(), fd, wc.file_id)?;
                    writer.sync()?;
                    writer.position()
                }
                false => BlockOffset::new(file_size),
            };

            let hint_path = hint_file_path(data_dir, wc.file_id);
            let hint_fd = manager.io().open(&hint_path, OpenOptions::read_write())?;
            let hint_size = manager.io().file_size(hint_fd)?;

            Ok(ActiveState {
                file_id: wc.file_id,
                fd,
                position,
                hint_fd,
                hint_position: HintOffset::new(hint_size),
            })
        }
        None => {
            let file_id = file_ids.allocate();

            let handle = manager.open_for_append(file_id)?;
            let fd = handle.fd();
            let writer = DataFileWriter::new(manager.io(), fd, file_id)?;
            writer.sync()?;
            let position = writer.position();

            let hint_path = hint_file_path(data_dir, file_id);
            let hint_fd = manager.io().open(&hint_path, OpenOptions::read_write())?;

            manager.io().sync_dir(data_dir)?;

            Ok(ActiveState {
                file_id,
                fd,
                position,
                hint_fd,
                hint_position: HintOffset::new(0),
            })
        }
    }
}

enum BatchEntry {
    Put {
        blocks: Vec<([u8; CID_SIZE], Vec<u8>)>,
        response: PutResponse,
    },
    Apply {
        blocks: Vec<([u8; CID_SIZE], Vec<u8>)>,
        deleted_cids: Vec<[u8; CID_SIZE]>,
        response: ApplyResponse,
    },
}

enum ClassifyResult {
    Batch(BatchEntry),
    Shutdown,
    Compact {
        file_id: DataFileId,
        grace_period_ms: u64,
        response: CompactResponse,
    },
    Repair {
        leaked_cids: Vec<(CidBytes, RefCount)>,
        response: RepairResponse,
    },
    Quiesce {
        response: QuiesceResponse,
        resume: QuiesceResume,
    },
}

fn classify_request(req: CommitRequest) -> ClassifyResult {
    match req {
        CommitRequest::PutBlocks { blocks, response } => {
            ClassifyResult::Batch(BatchEntry::Put { blocks, response })
        }
        CommitRequest::ApplyCommit {
            blocks,
            deleted_cids,
            response,
        } => ClassifyResult::Batch(BatchEntry::Apply {
            blocks,
            deleted_cids,
            response,
        }),
        CommitRequest::Compact {
            file_id,
            grace_period_ms,
            response,
        } => ClassifyResult::Compact {
            file_id,
            grace_period_ms,
            response,
        },
        CommitRequest::RepairLeaked {
            leaked_cids,
            response,
        } => ClassifyResult::Repair {
            leaked_cids,
            response,
        },
        CommitRequest::Quiesce { response, resume } => ClassifyResult::Quiesce { response, resume },
        CommitRequest::Shutdown => ClassifyResult::Shutdown,
    }
}

fn batch_entry_block_count(entry: &BatchEntry) -> usize {
    match entry {
        BatchEntry::Put { blocks, .. } | BatchEntry::Apply { blocks, .. } => blocks.len(),
    }
}

struct DrainResult {
    entries: Vec<BatchEntry>,
    shutdown: bool,
    deferred_compacts: Vec<(DataFileId, u64, CompactResponse)>,
    deferred_repairs: Vec<(Vec<(CidBytes, RefCount)>, RepairResponse)>,
    deferred_quiesces: Vec<(QuiesceResponse, QuiesceResume)>,
}

fn drain_batch(
    receiver: &flume::Receiver<CommitRequest>,
    first: CommitRequest,
    max_batch_size: usize,
) -> DrainResult {
    let first_entry = match classify_request(first) {
        ClassifyResult::Shutdown => {
            return DrainResult {
                entries: Vec::new(),
                shutdown: true,
                deferred_compacts: Vec::new(),
                deferred_repairs: Vec::new(),
                deferred_quiesces: Vec::new(),
            };
        }
        ClassifyResult::Compact {
            file_id,
            grace_period_ms,
            response,
        } => {
            return DrainResult {
                entries: Vec::new(),
                shutdown: false,
                deferred_compacts: vec![(file_id, grace_period_ms, response)],
                deferred_repairs: Vec::new(),
                deferred_quiesces: Vec::new(),
            };
        }
        ClassifyResult::Repair {
            leaked_cids,
            response,
        } => {
            return DrainResult {
                entries: Vec::new(),
                shutdown: false,
                deferred_compacts: Vec::new(),
                deferred_repairs: vec![(leaked_cids, response)],
                deferred_quiesces: Vec::new(),
            };
        }
        ClassifyResult::Quiesce { response, resume } => {
            return DrainResult {
                entries: Vec::new(),
                shutdown: false,
                deferred_compacts: Vec::new(),
                deferred_repairs: Vec::new(),
                deferred_quiesces: vec![(response, resume)],
            };
        }
        ClassifyResult::Batch(entry) => entry,
    };

    let mut block_count = batch_entry_block_count(&first_entry);
    let mut result = DrainResult {
        entries: vec![first_entry],
        shutdown: false,
        deferred_compacts: Vec::new(),
        deferred_repairs: Vec::new(),
        deferred_quiesces: Vec::new(),
    };

    let ingest = |req: CommitRequest, bc: &mut usize, r: &mut DrainResult| -> bool {
        match classify_request(req) {
            ClassifyResult::Shutdown => true,
            ClassifyResult::Compact {
                file_id,
                grace_period_ms,
                response,
            } => {
                r.deferred_compacts
                    .push((file_id, grace_period_ms, response));
                false
            }
            ClassifyResult::Repair {
                leaked_cids,
                response,
            } => {
                r.deferred_repairs.push((leaked_cids, response));
                false
            }
            ClassifyResult::Quiesce { response, resume } => {
                r.deferred_quiesces.push((response, resume));
                false
            }
            ClassifyResult::Batch(entry) => {
                *bc = bc.saturating_add(batch_entry_block_count(&entry));
                r.entries.push(entry);
                false
            }
        }
    };

    while block_count < max_batch_size {
        match receiver.try_recv() {
            Ok(req) => {
                if ingest(req, &mut block_count, &mut result) {
                    result.shutdown = true;
                    break;
                }
            }
            Err(_) => break,
        }
    }

    result
}

fn capture_snapshot<S: StorageIO>(
    manager: &DataFileManager<S>,
    state: &ActiveState,
    epoch: &EpochCounter,
) -> BlockstoreSnapshot {
    BlockstoreSnapshot {
        shard_cursors: vec![WriteCursor {
            file_id: state.file_id,
            offset: state.position,
        }],
        epoch: epoch.current(),
        data_files: manager.list_files().unwrap_or_default(),
    }
}

fn handle_quiesce<S: StorageIO>(
    manager: &DataFileManager<S>,
    state: &ActiveState,
    epoch: &EpochCounter,
    response: QuiesceResponse,
    resume: QuiesceResume,
) {
    let snapshot = capture_snapshot(manager, state, epoch);
    let _ = response.send(snapshot);
    let _ = resume.blocking_recv();
}

fn maybe_checkpoint(
    index: &BlockIndex,
    epoch: &EpochCounter,
    config: &GroupCommitConfig,
    last_checkpoint: &mut std::time::Instant,
    writes_since_checkpoint: &mut u64,
    hint_positions: &ShardHintPositions,
) {
    let interval = std::time::Duration::from_millis(config.checkpoint_interval_ms);
    let elapsed = last_checkpoint.elapsed() >= interval;
    let threshold = *writes_since_checkpoint >= config.checkpoint_write_threshold;
    if !elapsed && !threshold {
        return;
    }
    match index.write_checkpoint(epoch.current(), hint_positions) {
        Ok(()) => {
            *last_checkpoint = std::time::Instant::now();
            *writes_since_checkpoint = 0;
            tracing::debug!("periodic checkpoint written");
        }
        Err(e) => {
            tracing::warn!(error = %e, "periodic checkpoint failed");
        }
    }
}

fn shutdown_checkpoint(
    index: &BlockIndex,
    epoch: &EpochCounter,
    hint_positions: &ShardHintPositions,
) {
    match index.write_checkpoint(epoch.current(), hint_positions) {
        Ok(()) => tracing::debug!("shutdown checkpoint written"),
        Err(e) => tracing::warn!(error = %e, "shutdown checkpoint failed"),
    }
}

fn commit_loop<S: StorageIO>(
    manager: &DataFileManager<S>,
    index: &BlockIndex,
    receiver: &flume::Receiver<CommitRequest>,
    config: &GroupCommitConfig,
    state: &mut ActiveState,
    post_sync_hook: Option<&dyn PostBlockstoreHook>,
    ctx: &ShardContext,
) {
    let epoch = &ctx.epoch;
    let mut last_checkpoint = std::time::Instant::now();
    let mut writes_since_checkpoint: u64 = 0;

    loop {
        let first = match receiver.recv() {
            Ok(CommitRequest::Shutdown) => {
                shutdown_checkpoint(index, epoch, &ctx.hint_positions);
                return;
            }
            Ok(CommitRequest::Compact {
                file_id,
                grace_period_ms,
                response,
            }) => {
                let result = compaction::compact_on_writer_thread(
                    manager,
                    index,
                    file_id,
                    epoch.current(),
                    grace_period_ms,
                    &ctx.file_ids,
                    &ctx.active_files,
                    &ctx.hint_positions,
                    epoch,
                );
                let _ = response.send(result);
                continue;
            }
            Ok(CommitRequest::RepairLeaked {
                leaked_cids,
                response,
            }) => {
                let repaired = index.repair_leaked_refcounts(
                    &leaked_cids,
                    epoch.current(),
                    crate::wall_clock_ms(),
                );
                let _ = response.send(Ok(repaired));
                continue;
            }
            Ok(CommitRequest::Quiesce { response, resume }) => {
                handle_quiesce(manager, state, epoch, response, resume);
                continue;
            }
            Ok(msg) => msg,
            Err(_) => {
                shutdown_checkpoint(index, epoch, &ctx.hint_positions);
                return;
            }
        };

        let drain_start = std::time::Instant::now();
        let drain = drain_batch(receiver, first, config.max_batch_size);
        let drain_us = drain_start.elapsed().as_nanos() as u64 / 1000;

        if !drain.entries.is_empty() {
            tracing::debug!(
                batch_size = drain.entries.len(),
                drain_us,
                file_id = %state.file_id,
                "processing commit batch"
            );

            let result = process_batch(manager, index, &drain.entries, state, ctx);

            if let Ok((ref _dedup, ref proof)) = result {
                run_post_sync_hook(post_sync_hook, proof);
            }

            if let Err(ref e) = result {
                tracing::warn!(error = %e, "commit batch failed");
            }

            if let Ok((ref dedup, _)) = result {
                writes_since_checkpoint =
                    writes_since_checkpoint.saturating_add(dedup.len() as u64);
            }

            dispatch_responses(drain.entries, result.map(|(dedup, _proof)| dedup));
        }

        drain
            .deferred_compacts
            .into_iter()
            .for_each(|(file_id, grace_period_ms, response)| {
                let result = compaction::compact_on_writer_thread(
                    manager,
                    index,
                    file_id,
                    epoch.current(),
                    grace_period_ms,
                    &ctx.file_ids,
                    &ctx.active_files,
                    &ctx.hint_positions,
                    epoch,
                );
                let _ = response.send(result);
            });

        drain
            .deferred_repairs
            .into_iter()
            .for_each(|(leaked_cids, response)| {
                let repaired = index.repair_leaked_refcounts(
                    &leaked_cids,
                    epoch.current(),
                    crate::wall_clock_ms(),
                );
                let _ = response.send(Ok(repaired));
            });

        maybe_checkpoint(
            index,
            epoch,
            config,
            &mut last_checkpoint,
            &mut writes_since_checkpoint,
            &ctx.hint_positions,
        );

        if drain.shutdown {
            drain_and_process_remaining(manager, index, receiver, state, post_sync_hook, ctx);
            return;
        }

        drain
            .deferred_quiesces
            .into_iter()
            .for_each(|(response, resume)| {
                handle_quiesce(manager, state, epoch, response, resume);
            });
    }
}

fn run_post_sync_hook(hook: Option<&dyn PostBlockstoreHook>, proof: &BlocksSynced) {
    if let Some(hook) = hook
        && let Err(e) = hook.on_blocks_synced(proof)
    {
        tracing::error!(error = %e, "post-blockstore sync hook failed");
    }
}

fn drain_and_process_remaining<S: StorageIO>(
    manager: &DataFileManager<S>,
    index: &BlockIndex,
    receiver: &flume::Receiver<CommitRequest>,
    state: &mut ActiveState,
    post_sync_hook: Option<&dyn PostBlockstoreHook>,
    ctx: &ShardContext,
) {
    let epoch = &ctx.epoch;
    let mut entries: Vec<BatchEntry> = Vec::new();
    let mut compacts: Vec<(DataFileId, u64, CompactResponse)> = Vec::new();
    let mut repairs: Vec<(Vec<(CidBytes, RefCount)>, RepairResponse)> = Vec::new();

    std::iter::from_fn(|| receiver.try_recv().ok()).for_each(|req| match classify_request(req) {
        ClassifyResult::Batch(entry) => entries.push(entry),
        ClassifyResult::Compact {
            file_id,
            grace_period_ms,
            response,
        } => compacts.push((file_id, grace_period_ms, response)),
        ClassifyResult::Repair {
            leaked_cids,
            response,
        } => repairs.push((leaked_cids, response)),
        ClassifyResult::Shutdown | ClassifyResult::Quiesce { .. } => {}
    });

    if !entries.is_empty() {
        let result = process_batch(manager, index, &entries, state, ctx);

        if let Ok((ref _dedup, ref proof)) = result {
            run_post_sync_hook(post_sync_hook, proof);
        }

        dispatch_responses(entries, result.map(|(dedup, _proof)| dedup));
    }

    compacts
        .into_iter()
        .for_each(|(file_id, grace_period_ms, response)| {
            let result = compaction::compact_on_writer_thread(
                manager,
                index,
                file_id,
                epoch.current(),
                grace_period_ms,
                &ctx.file_ids,
                &ctx.active_files,
                &ctx.hint_positions,
                epoch,
            );
            let _ = response.send(result);
        });

    repairs.into_iter().for_each(|(leaked_cids, response)| {
        let repaired =
            index.repair_leaked_refcounts(&leaked_cids, epoch.current(), crate::wall_clock_ms());
        let _ = response.send(Ok(repaired));
    });

    shutdown_checkpoint(index, epoch, &ctx.hint_positions);
}

struct RotationState<S: StorageIO> {
    file_id: DataFileId,
    handle: Arc<super::manager::CachedHandle<S>>,
    hint_fd: FileId,
}

fn verify_persisted_blocks<S: StorageIO>(
    manager: &DataFileManager<S>,
    entries: &[([u8; CID_SIZE], BlockLocation)],
) -> Result<(), CommitError> {
    use std::collections::BTreeMap;
    let by_file: BTreeMap<DataFileId, Vec<(&[u8; CID_SIZE], BlockLocation)>> = entries
        .iter()
        .fold(BTreeMap::new(), |mut acc, (cid, loc)| {
            acc.entry(loc.file_id).or_default().push((cid, *loc));
            acc
        });

    by_file.into_iter().try_for_each(|(file_id, locations)| {
        let path = manager.data_file_path(file_id);
        let fd = match manager.io().open(&path, OpenOptions::read_only_existing()) {
            Ok(fd) => fd,
            Err(_) => return Ok(()),
        };
        let file_size = match manager.io().file_size(fd) {
            Ok(s) => s,
            Err(_) => {
                let _ = manager.io().close(fd);
                return Ok(());
            }
        };
        let result = locations.into_iter().try_for_each(|(expected_cid, loc)| {
            verify_block_at(manager, fd, file_size, expected_cid, loc)
        });
        let _ = manager.io().close(fd);
        result
    })
}

#[derive(Debug)]
enum VerifyOutcome {
    NoFaultDetected,
    Faulted,
}

fn verify_block_at<S: StorageIO>(
    manager: &DataFileManager<S>,
    fd: FileId,
    file_size: u64,
    expected_cid: &[u8; CID_SIZE],
    loc: BlockLocation,
) -> Result<(), CommitError> {
    let passed = (0..VERIFY_RETRY_ATTEMPTS).any(|_| {
        matches!(
            verify_once(manager, fd, file_size, expected_cid, loc),
            VerifyOutcome::NoFaultDetected
        )
    });
    match passed {
        true => Ok(()),
        false => Err(CommitError::VerifyFailed {
            file_id: loc.file_id,
            offset: loc.offset,
        }),
    }
}

fn verify_once<S: StorageIO>(
    manager: &DataFileManager<S>,
    fd: FileId,
    file_size: u64,
    expected_cid: &[u8; CID_SIZE],
    loc: BlockLocation,
) -> VerifyOutcome {
    match decode_block_record(manager.io(), fd, loc.offset, file_size) {
        Ok(Some(ReadBlockRecord::Valid { cid_bytes, .. })) if cid_bytes == *expected_cid => {
            VerifyOutcome::NoFaultDetected
        }
        Ok(Some(ReadBlockRecord::Valid { .. })) => {
            tracing::warn!(
                file_id = %loc.file_id,
                offset = loc.offset.raw(),
                "verify: stored CID mismatch (misdirected write)"
            );
            VerifyOutcome::Faulted
        }
        Ok(Some(ReadBlockRecord::Corrupted { .. } | ReadBlockRecord::Truncated { .. }))
        | Ok(None) => {
            tracing::warn!(
                file_id = %loc.file_id,
                offset = loc.offset.raw(),
                "verify: block undecodable at location"
            );
            VerifyOutcome::Faulted
        }
        Err(_) => VerifyOutcome::NoFaultDetected,
    }
}

const VERIFY_RETRY_ATTEMPTS: u32 = 4;

fn rollback_batch<S: StorageIO>(
    manager: &DataFileManager<S>,
    state: &ActiveState,
    rotations: &[RotationState<S>],
) {
    let _ = manager.io().truncate(state.fd, state.position.raw());
    let _ = manager.io().sync(state.fd);
    let _ = manager
        .io()
        .truncate(state.hint_fd, state.hint_position.raw());
    let _ = manager.io().sync(state.hint_fd);
    rotations.iter().for_each(|rot| {
        manager.rollback_rotation(rot.file_id);
        let _ = manager.io().close(rot.hint_fd);
        let _ = manager
            .io()
            .delete(&hint_file_path(manager.data_dir(), rot.file_id));
    });
}

fn process_batch<S: StorageIO>(
    manager: &DataFileManager<S>,
    index: &BlockIndex,
    batch: &[BatchEntry],
    state: &mut ActiveState,
    ctx: &ShardContext,
) -> Result<(HashMap<[u8; CID_SIZE], BlockLocation>, BlocksSynced), CommitError> {
    let epoch = &ctx.epoch;
    let batch_start = std::time::Instant::now();

    let mut dedup: HashMap<[u8; CID_SIZE], BlockLocation> = HashMap::new();
    let mut index_entries: Vec<([u8; CID_SIZE], BlockLocation)> = Vec::new();
    let mut all_decrements: Vec<[u8; CID_SIZE]> = Vec::new();

    let mut current_hint_fd = state.hint_fd;
    let mut rotations: Vec<RotationState<S>> = Vec::new();

    let mut data_writer =
        DataFileWriter::resume(manager.io(), state.fd, state.file_id, state.position);
    let mut hint_writer =
        HintFileWriter::resume(manager.io(), current_hint_fd, state.hint_position);

    if manager.should_rotate(data_writer.position()) {
        data_writer.sync().map_err(CommitError::from)?;
        hint_writer.sync().map_err(CommitError::from)?;

        let next_id = ctx.file_ids.allocate();
        let next_handle = manager.open_for_append(next_id)?;
        let next_fd = next_handle.fd();

        tracing::info!(
            from = %data_writer.file_id(),
            to = %next_id,
            trigger = "batch_boundary",
            "data file rotation"
        );

        data_writer = DataFileWriter::new(manager.io(), next_fd, next_id)?;

        let new_hint_path = hint_file_path(manager.data_dir(), next_id);
        let new_hint_fd = manager
            .io()
            .open(&new_hint_path, OpenOptions::read_write())?;

        manager.io().sync_dir(manager.data_dir())?;

        current_hint_fd = new_hint_fd;
        hint_writer = HintFileWriter::new(manager.io(), new_hint_fd);
        rotations.push(RotationState {
            file_id: next_id,
            handle: next_handle,
            hint_fd: new_hint_fd,
        });
    }

    let mut block_bytes: u64 = 0;
    let mut block_count: u64 = 0;
    let mut dedup_hits: u64 = 0;

    let write_result: Result<(), CommitError> = batch.iter().try_for_each(|entry| {
        let (blocks, decrements) = match entry {
            BatchEntry::Put { blocks, .. } => (blocks.as_slice(), None),
            BatchEntry::Apply {
                blocks,
                deleted_cids,
                ..
            } => (blocks.as_slice(), Some(deleted_cids.as_slice())),
        };

        blocks.iter().try_for_each(|(cid_bytes, data)| {
            let location = match dedup.get(cid_bytes) {
                Some(&loc) => {
                    dedup_hits = dedup_hits.saturating_add(1);
                    hint_writer.append_hint(cid_bytes, &loc)?;
                    loc
                }
                None => match index.get(cid_bytes) {
                    Some(existing) => {
                        dedup_hits = dedup_hits.saturating_add(1);
                        let loc = existing.location;
                        hint_writer.append_hint(cid_bytes, &loc)?;
                        dedup.insert(*cid_bytes, loc);
                        loc
                    }
                    None => {
                        let loc = data_writer.append_block(cid_bytes, data)?;
                        hint_writer.append_hint(cid_bytes, &loc)?;

                        block_bytes = block_bytes.saturating_add(data.len() as u64);
                        block_count = block_count.saturating_add(1);
                        dedup.insert(*cid_bytes, loc);
                        loc
                    }
                },
            };

            index_entries.push((*cid_bytes, location));
            Ok::<_, CommitError>(())
        })?;

        if let Some(decs) = decrements {
            all_decrements.extend_from_slice(decs);
        }

        Ok::<_, CommitError>(())
    });

    if let Err(e) = write_result {
        rollback_batch(manager, state, &rotations);
        return Err(e);
    }

    let write_nanos = batch_start.elapsed().as_nanos() as u64;

    let current_epoch = epoch.current();
    let now = crate::wall_clock_ms();

    let rollback_on_err = |e: CommitError| -> CommitError {
        rollback_batch(manager, state, &rotations);
        e
    };

    all_decrements
        .iter()
        .try_for_each(|cid| hint_writer.append_decrement(cid, current_epoch, now))
        .map_err(|e| rollback_on_err(CommitError::from(e)))?;

    let t = std::time::Instant::now();
    data_writer.sync().map_err(|e| rollback_on_err(e.into()))?;
    if ctx.verify_persisted_blocks {
        verify_persisted_blocks(manager, &index_entries).map_err(rollback_on_err)?;
    }
    let batch_record_count = u32::try_from(
        block_count
            .saturating_add(dedup_hits)
            .saturating_add(all_decrements.len() as u64),
    )
    .unwrap_or(u32::MAX);
    hint_writer
        .append_commit_marker(
            current_epoch.raw(),
            batch_record_count,
            data_writer.file_id(),
            data_writer.position(),
        )
        .map_err(|e| rollback_on_err(CommitError::from(e)))?;
    hint_writer.sync().map_err(|e| rollback_on_err(e.into()))?;
    let sync_nanos = t.elapsed().as_nanos() as u64;

    if !rotations.is_empty() {
        let old_file_id = state.file_id;
        let old_hint_fd = state.hint_fd;
        let last_idx = rotations.len() - 1;
        rotations.iter().enumerate().for_each(|(i, rot)| {
            if i == last_idx {
                manager.commit_rotation(rot.file_id, &rot.handle);
                ctx.active_files.register(ctx.shard_id, rot.file_id);
            } else {
                let _ = manager.io().close(rot.hint_fd);
                manager.evict_handle(rot.file_id);
            }
        });
        manager.evict_handle(old_file_id);
        let _ = manager.io().close(old_hint_fd);
    }

    state.file_id = data_writer.file_id();
    state.fd = data_writer.fd();
    state.position = data_writer.position();
    state.hint_fd = current_hint_fd;
    state.hint_position = hint_writer.position();

    let cursor = WriteCursor {
        file_id: state.file_id,
        offset: state.position,
    };
    let t = std::time::Instant::now();
    index
        .batch_put_and_advance_position(
            &index_entries,
            &all_decrements,
            cursor,
            current_epoch,
            now,
            super::hash_index::PositionUpdate {
                hint_positions: &ctx.hint_positions,
                shard_id: ctx.shard_id,
                file_id: state.file_id,
                offset: state.hint_position,
            },
        )
        .map_err(CommitError::from)?;
    let index_nanos = t.elapsed().as_nanos() as u64;

    epoch.advance();

    let total_nanos = batch_start.elapsed().as_nanos() as u64;

    tracing::info!(
        blocks = block_count,
        bytes = block_bytes,
        dedup_hits,
        decrements = all_decrements.len(),
        entries = batch.len(),
        write_us = write_nanos / 1000,
        sync_us = sync_nanos / 1000,
        index_us = index_nanos / 1000,
        total_us = total_nanos / 1000,
        "commit batch profile"
    );

    Ok((dedup, BlocksSynced::new()))
}

fn dispatch_responses(
    batch: Vec<BatchEntry>,
    result: Result<HashMap<[u8; CID_SIZE], BlockLocation>, CommitError>,
) {
    match result {
        Err(e) => {
            batch.into_iter().for_each(|entry| {
                let err = e.clone();
                match entry {
                    BatchEntry::Put { response, .. } => {
                        let _ = response.send(Err(err));
                    }
                    BatchEntry::Apply { response, .. } => {
                        let _ = response.send(Err(err));
                    }
                }
            });
        }
        Ok(written) => {
            batch.into_iter().for_each(|entry| match entry {
                BatchEntry::Put {
                    blocks, response, ..
                } => {
                    let result: Result<Vec<BlockLocation>, CommitError> = blocks
                        .iter()
                        .map(|(cid, _)| match written.get(cid) {
                            Some(&loc) => Ok(loc),
                            None => {
                                tracing::error!(
                                    ?cid,
                                    "committed CID missing from dedup map, this is a bug"
                                );
                                Err(CommitError::from(io::Error::other(
                                    "committed CID missing from dedup map",
                                )))
                            }
                        })
                        .collect();
                    let _ = response.send(result);
                }
                BatchEntry::Apply { response, .. } => {
                    let _ = response.send(Ok(()));
                }
            });
        }
    }
}
