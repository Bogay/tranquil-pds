use std::collections::HashMap;
use std::io;
use std::num::NonZeroU8;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use cid::Cid;
use jacquard_repo::error::RepoError;
use jacquard_repo::repo::CommitData;
use jacquard_repo::storage::BlockStore;

use crate::fsync_order::PostBlockstoreHook;
use crate::io::{OpenOptions, RealIO, StorageIO};

use super::cid_util::hash_to_cid;
use super::compaction::CompactionError;
use super::data_file::{BLOCK_RECORD_OVERHEAD, CID_SIZE, ReadBlockRecord};
use super::group_commit::{CommitError, CommitRequest, GroupCommitConfig, GroupCommitWriter};
use super::hash_index::BlockIndex;
use super::manager::DataFileManager;
use super::reader::{BlockStoreReader, ReadError};
use super::types::{
    BlockLocation, BlockOffset, CollectionResult, CompactionResult, DataFileId, EpochCounter,
    LivenessInfo, WallClockMs,
};

fn cid_to_bytes(cid: &Cid) -> Result<[u8; CID_SIZE], RepoError> {
    let raw = cid.to_bytes();
    let len = raw.len();
    raw.try_into().map_err(|_| {
        RepoError::storage(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "CID byte length {len} differs from expected {CID_SIZE}, only CIDv1 + SHA-256 is supported"
            ),
        ))
    })
}

fn commit_error_to_repo(e: CommitError) -> RepoError {
    match e {
        CommitError::Io(io_err) => {
            RepoError::storage(io::Error::new(io_err.kind(), io_err.to_string()))
        }
        CommitError::Index(idx_err) => RepoError::storage(io::Error::other(idx_err.to_string())),
        CommitError::ChannelClosed => RepoError::storage(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "blockstore commit channel closed",
        )),
        CommitError::VerifyFailed { file_id, offset } => RepoError::storage(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("post-sync verify failed at {file_id}:{}", offset.raw()),
        )),
    }
}

fn read_error_to_repo(e: ReadError) -> RepoError {
    match e {
        ReadError::Io(io_err) => {
            RepoError::storage(io::Error::new(io_err.kind(), io_err.to_string()))
        }
        ReadError::Corrupted { file_id, offset } => RepoError::storage(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("corrupted block at {file_id}:{}", offset.raw()),
        )),
    }
}

pub const DEFAULT_SHARD_COUNT: u8 = 1;

#[derive(Debug, Clone)]
pub struct BlockStoreConfig {
    pub data_dir: PathBuf,
    pub index_dir: PathBuf,
    pub max_file_size: u64,
    pub group_commit: GroupCommitConfig,
    pub shard_count: u8,
}

impl BlockStoreConfig {
    pub fn new(data_dir: PathBuf, index_dir: PathBuf) -> Self {
        Self {
            data_dir,
            index_dir,
            max_file_size: super::manager::DEFAULT_MAX_FILE_SIZE,
            group_commit: GroupCommitConfig::default(),
            shard_count: DEFAULT_SHARD_COUNT,
        }
    }
}

pub struct QuiesceGuard {
    resume_txs: Vec<tokio::sync::oneshot::Sender<()>>,
}

impl QuiesceGuard {
    pub fn resume(mut self) {
        self.resume_txs.drain(..).for_each(|tx| {
            let _ = tx.send(());
        });
    }
}

impl Drop for QuiesceGuard {
    fn drop(&mut self) {
        self.resume_txs.drain(..).for_each(|tx| {
            let _ = tx.send(());
        });
    }
}

pub struct TranquilBlockStore<S: StorageIO + Send + Sync + 'static = RealIO> {
    writer: Arc<WriterHandle>,
    reader: Arc<BlockStoreReader<S>>,
    index: Arc<BlockIndex>,
    epoch: EpochCounter,
    data_dir: PathBuf,
}

impl<S: StorageIO + Send + Sync + 'static> Clone for TranquilBlockStore<S> {
    fn clone(&self) -> Self {
        Self {
            writer: Arc::clone(&self.writer),
            reader: Arc::clone(&self.reader),
            index: Arc::clone(&self.index),
            epoch: self.epoch.clone(),
            data_dir: self.data_dir.clone(),
        }
    }
}

struct WriterHandle {
    inner: parking_lot::Mutex<Option<GroupCommitWriter>>,
}

impl WriterHandle {
    fn with<R>(&self, f: impl FnOnce(&GroupCommitWriter) -> R) -> Result<R, CommitError> {
        match self.inner.lock().as_ref() {
            Some(w) => Ok(f(w)),
            None => Err(CommitError::ChannelClosed),
        }
    }
}

impl Drop for WriterHandle {
    fn drop(&mut self) {
        if let Some(w) = self.inner.lock().take() {
            w.shutdown();
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct OpenRetryPolicy {
    pub max_attempts: NonZeroU8,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for OpenRetryPolicy {
    fn default() -> Self {
        const DEFAULT_MAX_ATTEMPTS: NonZeroU8 = NonZeroU8::new(5).unwrap();
        Self {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(2),
        }
    }
}

impl TranquilBlockStore<RealIO> {
    pub fn open(config: BlockStoreConfig) -> Result<Self, RepoError> {
        Self::open_with_hook(config, None)
    }

    pub fn open_with_hook(
        config: BlockStoreConfig,
        post_sync_hook: Option<Arc<dyn PostBlockstoreHook>>,
    ) -> Result<Self, RepoError> {
        Self::open_with_io_hook(config, RealIO::new, post_sync_hook)
    }

    pub fn open_with_retry(
        config: BlockStoreConfig,
        policy: OpenRetryPolicy,
    ) -> Result<Self, RepoError> {
        retry_with_backoff(policy, &mut |_| Self::open(config.clone()))
    }
}

fn retry_with_backoff<T, F>(policy: OpenRetryPolicy, op: &mut F) -> Result<T, RepoError>
where
    F: FnMut(u8) -> Result<T, RepoError>,
{
    retry_attempt(policy, op, 0, policy.initial_backoff)
}

fn retry_attempt<T, F>(
    policy: OpenRetryPolicy,
    op: &mut F,
    attempt: u8,
    backoff: Duration,
) -> Result<T, RepoError>
where
    F: FnMut(u8) -> Result<T, RepoError>,
{
    match op(attempt) {
        Ok(t) => Ok(t),
        Err(e) if attempt + 1 >= policy.max_attempts.get() => Err(e),
        Err(e) => {
            tracing::warn!(
                attempt,
                error = %e,
                backoff_ms = u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX),
                "blockstore open failed, retrying"
            );
            std::thread::sleep(backoff);
            retry_attempt(
                policy,
                op,
                attempt + 1,
                (backoff * 2).min(policy.max_backoff),
            )
        }
    }
}

impl<S: StorageIO + Send + Sync + 'static> TranquilBlockStore<S> {
    pub fn open_with_io<F>(config: BlockStoreConfig, make_io: F) -> Result<Self, RepoError>
    where
        F: Fn() -> S + Send + Sync + Clone + 'static,
    {
        Self::open_with_io_hook(config, make_io, None)
    }

    pub fn open_with_io_hook<F>(
        config: BlockStoreConfig,
        make_io: F,
        post_sync_hook: Option<Arc<dyn PostBlockstoreHook>>,
    ) -> Result<Self, RepoError>
    where
        F: Fn() -> S + Send + Sync + Clone + 'static,
    {
        if config.data_dir == config.index_dir {
            return Err(RepoError::storage(io::Error::new(
                io::ErrorKind::InvalidInput,
                "data_dir and index_dir must be different directories",
            )));
        }
        std::fs::create_dir_all(&config.data_dir).map_err(RepoError::storage)?;
        std::fs::create_dir_all(&config.index_dir).map_err(RepoError::storage)?;

        let index = BlockIndex::open(&config.index_dir).map_err(RepoError::storage)?;

        let io = make_io();

        let (replayed, file_cursors) = super::hint::replay_hints_into_block_index(
            &io,
            &config.data_dir,
            &index,
            index.loaded_checkpoint_positions(),
        )
        .map_err(|e| RepoError::storage(io::Error::other(e.to_string())))?;

        if replayed > 0 {
            tracing::info!(replayed, "replayed hint records after checkpoint");
        }

        Self::recover_from_file_cursors(&io, &config.data_dir, &index, &file_cursors)?;

        let index = Arc::new(index);

        let data_dir = config.data_dir;
        let max_file_size = config.max_file_size;
        let shard_count = config.shard_count;
        let data_dir_for_closure = data_dir.clone();
        let make_io_for_manager = make_io.clone();
        let make_manager = move || {
            DataFileManager::new(
                make_io_for_manager(),
                data_dir_for_closure.clone(),
                max_file_size,
            )
        };

        let checkpoint_epoch = index.loaded_checkpoint_epoch();
        let checkpoint_positions = index.loaded_checkpoint_positions();
        let writer = GroupCommitWriter::spawn_sharded(
            make_manager,
            Arc::clone(&index),
            config.group_commit,
            post_sync_hook,
            checkpoint_epoch,
            shard_count,
            checkpoint_positions,
        )
        .map_err(commit_error_to_repo)?;
        let epoch = writer.epoch().clone();

        let manager_for_reader = Arc::new(DataFileManager::new(
            make_io(),
            data_dir.clone(),
            max_file_size,
        ));
        let reader = Arc::new(BlockStoreReader::new(
            Arc::clone(&index),
            manager_for_reader,
        ));

        Ok(Self {
            writer: Arc::new(WriterHandle {
                inner: parking_lot::Mutex::new(Some(writer)),
            }),
            reader,
            index,
            epoch,
            data_dir,
        })
    }

    fn recover_from_file_cursors(
        io: &S,
        data_dir: &Path,
        index: &BlockIndex,
        file_cursors: &HashMap<DataFileId, BlockOffset>,
    ) -> Result<(), RepoError> {
        let all_data_files =
            super::list_files_by_extension(io, data_dir, super::manager::DATA_FILE_EXTENSION)
                .map_err(RepoError::storage)?;

        if all_data_files.is_empty() {
            return Ok(());
        }

        let header_start = BlockOffset::new(super::data_file::BLOCK_HEADER_SIZE as u64);

        all_data_files.iter().try_for_each(|&fid| {
            let start_offset = file_cursors.get(&fid).copied().unwrap_or(header_start);
            Self::replay_single_file(io, data_dir, index, fid, start_offset)
        })
    }

    fn replay_single_file(
        io: &S,
        data_dir: &Path,
        index: &BlockIndex,
        file_id: DataFileId,
        start_offset: BlockOffset,
    ) -> Result<(), RepoError> {
        let file_path = data_dir.join(format!("{file_id}.{}", super::manager::DATA_FILE_EXTENSION));

        let fd = match io.open(&file_path, OpenOptions::read_write_existing()) {
            Ok(fd) => fd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                tracing::error!(
                    file_id = %file_id,
                    "cursor references missing data file, possible data loss, skipping replay"
                );
                return Ok(());
            }
            Err(e) => return Err(RepoError::storage(e)),
        };

        let hint_path = super::hint::hint_file_path(data_dir, file_id);
        let hint_exists = io
            .open(&hint_path, OpenOptions::read_only_existing())
            .map(|fd| {
                let _ = io.close(fd);
            })
            .is_ok();

        let result = Self::scan_and_index(io, index, fd, file_id, start_offset, hint_exists);

        let _ = io.close(fd);

        result
    }

    fn scan_and_index(
        io: &S,
        index: &BlockIndex,
        fd: crate::io::FileId,
        file_id: DataFileId,
        start_offset: BlockOffset,
        hint_exists: bool,
    ) -> Result<(), RepoError> {
        let file_size = io.file_size(fd).map_err(RepoError::storage)?;

        if file_size <= start_offset.raw() {
            return Ok(());
        }

        let scan_pos = &mut { start_offset };
        let (scanned_entries, last_valid_end) = std::iter::from_fn(|| {
            match super::data_file::decode_block_record(io, fd, *scan_pos, file_size) {
                Err(e) => Some(Err(e)),
                Ok(None) => None,
                Ok(Some(ReadBlockRecord::Valid {
                    offset,
                    cid_bytes,
                    data,
                })) => {
                    let raw_len = match u32::try_from(data.len()) {
                        Ok(n) if n <= super::types::MAX_BLOCK_SIZE => n,
                        _ => return None,
                    };
                    let length = super::types::BlockLength::new(raw_len);
                    let record_size = BLOCK_RECORD_OVERHEAD as u64 + u64::from(raw_len);
                    let new_end = offset.advance(record_size);
                    *scan_pos = new_end;
                    Some(Ok((
                        cid_bytes,
                        BlockLocation {
                            file_id,
                            offset,
                            length,
                        },
                        new_end,
                    )))
                }
                Ok(Some(ReadBlockRecord::Corrupted { .. } | ReadBlockRecord::Truncated { .. })) => {
                    None
                }
            }
        })
        .try_fold(
            (Vec::new(), start_offset),
            |(mut entries, _), item: io::Result<_>| {
                let (cid, loc, new_end) = item?;
                entries.push((cid, loc));
                Ok::<_, io::Error>((entries, new_end))
            },
        )
        .map_err(|e| {
            tracing::warn!(
                file_id = %file_id,
                offset = scan_pos.raw(),
                error = %e,
                "IO error during recovery scan, aborting to preserve durable tail"
            );
            RepoError::storage(e)
        })?;

        if file_size > last_valid_end.raw() {
            tracing::info!(
                file_id = %file_id,
                truncating_from = last_valid_end.raw(),
                file_size,
                scanned_count = scanned_entries.len(),
                "truncating partial/unacked tail"
            );
            io.truncate(fd, last_valid_end.raw())
                .map_err(RepoError::storage)?;
            io.sync(fd).map_err(RepoError::storage)?;
        }

        if !scanned_entries.is_empty() {
            tracing::info!(
                file_id = %file_id,
                scanned = scanned_entries.len(),
                hint_exists,
                "reindexing blocks past hint coverage"
            );
            let cursor = super::types::WriteCursor {
                file_id,
                offset: last_valid_end,
            };
            index
                .batch_put_if_absent(&scanned_entries, cursor)
                .map_err(|e| RepoError::storage(io::Error::other(e.to_string())))?;
        }

        Ok(())
    }

    pub fn epoch(&self) -> &EpochCounter {
        &self.epoch
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn data_file_path(&self, file_id: DataFileId) -> PathBuf {
        self.reader.manager().data_file_path(file_id)
    }

    pub fn quiesce(&self) -> Result<(super::types::BlockstoreSnapshot, QuiesceGuard), CommitError> {
        let (snapshot, resumes) = self.writer.with(|w| w.quiesce_all())??;
        Ok((
            snapshot,
            QuiesceGuard {
                resume_txs: resumes,
            },
        ))
    }

    pub fn collect_dead_blocks(&self, grace_period_ms: u64) -> Result<CollectionResult, RepoError> {
        let current_epoch = self.epoch.current();
        let now = WallClockMs::now();
        Ok(self
            .index
            .collect_dead_blocks(current_epoch, now, grace_period_ms))
    }

    pub fn compact_file(
        &self,
        file_id: DataFileId,
        grace_period_ms: u64,
    ) -> Result<CompactionResult, CompactionError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let sender = self
            .writer
            .with(|w| w.sender_round_robin().clone())
            .map_err(|_| CompactionError::ChannelClosed)?;
        sender
            .send(CommitRequest::Compact {
                file_id,
                grace_period_ms,
                response: tx,
            })
            .map_err(|_| CompactionError::ChannelClosed)?;
        let result = rx
            .blocking_recv()
            .map_err(|_| CompactionError::ChannelClosed)?;
        if result.is_ok() {
            self.reader.manager().evict_handle(file_id);
        }
        result
    }

    pub fn compaction_liveness(
        &self,
        grace_period_ms: u64,
    ) -> Result<HashMap<DataFileId, LivenessInfo>, RepoError> {
        let current_epoch = self.epoch.current();
        let now = WallClockMs::now();
        Ok(self
            .index
            .liveness_by_file(current_epoch, now, grace_period_ms))
    }

    pub fn cleanup_gc_meta(&self) -> Result<u64, RepoError> {
        Ok(self.index.cleanup_stale_gc_meta())
    }

    pub fn liveness_info(&self, file_id: DataFileId) -> Result<LivenessInfo, RepoError> {
        Ok(self.index.liveness_info(file_id))
    }

    pub fn approximate_block_count(&self) -> u64 {
        self.index.approximate_block_count()
    }

    pub fn block_index(&self) -> &Arc<BlockIndex> {
        &self.index
    }

    pub fn find_leaked_refcounts(
        &self,
        is_reachable: impl Fn(&super::types::CidBytes) -> bool,
    ) -> Result<(Vec<(super::types::CidBytes, super::types::RefCount)>, u64), RepoError> {
        Ok(self.index.find_leaked_refcounts(is_reachable))
    }

    pub fn repair_leaked_refcounts(
        &self,
        leaked_cids: &[(super::types::CidBytes, super::types::RefCount)],
    ) -> Result<u64, RepoError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let sender = self
            .writer
            .with(|w| w.sender_round_robin().clone())
            .map_err(commit_error_to_repo)?;
        sender
            .send(CommitRequest::RepairLeaked {
                leaked_cids: leaked_cids.to_vec(),
                response: tx,
            })
            .map_err(|_| commit_error_to_repo(CommitError::ChannelClosed))?;
        rx.blocking_recv()
            .map_err(|_| commit_error_to_repo(CommitError::ChannelClosed))?
            .map_err(commit_error_to_repo)
    }

    pub fn get_block_sync(
        &self,
        cid_bytes: &[u8; CID_SIZE],
    ) -> Result<Option<bytes::Bytes>, RepoError> {
        self.reader.get(cid_bytes).map_err(read_error_to_repo)
    }

    pub fn list_data_files(&self) -> Result<Vec<DataFileId>, RepoError> {
        self.reader
            .manager()
            .list_files()
            .map_err(RepoError::storage)
    }

    pub fn put_blocks_blocking(
        &self,
        blocks: Vec<([u8; CID_SIZE], Vec<u8>)>,
    ) -> Result<(), RepoError> {
        if blocks.is_empty() {
            return Ok(());
        }
        let sender = self
            .writer
            .with(|w| w.sender_for_blocks(&blocks).clone())
            .map_err(commit_error_to_repo)?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        sender
            .send(CommitRequest::PutBlocks {
                blocks,
                response: tx,
            })
            .map_err(|_| commit_error_to_repo(CommitError::ChannelClosed))?;
        rx.blocking_recv()
            .map_err(|_| commit_error_to_repo(CommitError::ChannelClosed))?
            .map_err(commit_error_to_repo)?;
        Ok(())
    }

    pub fn apply_commit_blocking(
        &self,
        blocks: Vec<([u8; CID_SIZE], Vec<u8>)>,
        deleted_cids: Vec<[u8; CID_SIZE]>,
    ) -> Result<(), RepoError> {
        let sender = self
            .writer
            .with(|w| w.sender_for_apply(&blocks, &deleted_cids).clone())
            .map_err(commit_error_to_repo)?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        sender
            .send(CommitRequest::ApplyCommit {
                blocks,
                deleted_cids,
                response: tx,
            })
            .map_err(|_| commit_error_to_repo(CommitError::ChannelClosed))?;
        rx.blocking_recv()
            .map_err(|_| commit_error_to_repo(CommitError::ChannelClosed))?
            .map_err(commit_error_to_repo)
    }

    async fn send_put_blocks(
        &self,
        blocks: Vec<([u8; CID_SIZE], Vec<u8>)>,
    ) -> Result<Vec<BlockLocation>, RepoError> {
        let sender = self
            .writer
            .with(|w| w.sender_for_blocks(&blocks).clone())
            .map_err(commit_error_to_repo)?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        sender
            .send_async(CommitRequest::PutBlocks {
                blocks,
                response: tx,
            })
            .await
            .map_err(|_| commit_error_to_repo(CommitError::ChannelClosed))?;
        rx.await
            .map_err(|_| commit_error_to_repo(CommitError::ChannelClosed))?
            .map_err(commit_error_to_repo)
    }

    async fn send_apply_commit(
        &self,
        blocks: Vec<([u8; CID_SIZE], Vec<u8>)>,
        deleted_cids: Vec<[u8; CID_SIZE]>,
    ) -> Result<(), RepoError> {
        let sender = self
            .writer
            .with(|w| w.sender_for_apply(&blocks, &deleted_cids).clone())
            .map_err(commit_error_to_repo)?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        sender
            .send_async(CommitRequest::ApplyCommit {
                blocks,
                deleted_cids,
                response: tx,
            })
            .await
            .map_err(|_| commit_error_to_repo(CommitError::ChannelClosed))?;
        rx.await
            .map_err(|_| commit_error_to_repo(CommitError::ChannelClosed))?
            .map_err(commit_error_to_repo)
    }
}

impl<S: StorageIO + Send + Sync + 'static> BlockStore for TranquilBlockStore<S> {
    async fn get(&self, cid: &Cid) -> Result<Option<Bytes>, RepoError> {
        let cid_bytes = cid_to_bytes(cid)?;
        let reader = Arc::clone(&self.reader);
        tokio::task::spawn_blocking(move || reader.get(&cid_bytes))
            .await
            .map_err(RepoError::task_failed)?
            .map_err(read_error_to_repo)
    }

    async fn put(&self, data: &[u8]) -> Result<Cid, RepoError> {
        let cid = hash_to_cid(data);
        let cid_bytes = cid_to_bytes(&cid)?;
        self.send_put_blocks(vec![(cid_bytes, data.to_vec())])
            .await?;
        Ok(cid)
    }

    async fn has(&self, cid: &Cid) -> Result<bool, RepoError> {
        let cid_bytes = cid_to_bytes(cid)?;
        let reader = Arc::clone(&self.reader);
        tokio::task::spawn_blocking(move || reader.has(&cid_bytes))
            .await
            .map_err(RepoError::task_failed)?
            .map_err(read_error_to_repo)
    }

    async fn put_many(
        &self,
        blocks: impl IntoIterator<Item = (Cid, Bytes)> + Send,
    ) -> Result<(), RepoError> {
        let entries: Vec<([u8; CID_SIZE], Vec<u8>)> = blocks
            .into_iter()
            .map(|(cid, data)| Ok((cid_to_bytes(&cid)?, data.to_vec())))
            .collect::<Result<Vec<_>, RepoError>>()?;
        if entries.is_empty() {
            return Ok(());
        }
        self.send_put_blocks(entries).await?;
        Ok(())
    }

    async fn get_many(&self, cids: &[Cid]) -> Result<Vec<Option<Bytes>>, RepoError> {
        if cids.is_empty() {
            return Ok(Vec::new());
        }
        let cid_bytes: Vec<[u8; CID_SIZE]> = cids
            .iter()
            .map(cid_to_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        let reader = Arc::clone(&self.reader);
        tokio::task::spawn_blocking(move || reader.get_many(&cid_bytes))
            .await
            .map_err(RepoError::task_failed)?
            .map_err(read_error_to_repo)
    }

    async fn apply_commit(&self, commit: CommitData) -> Result<(), RepoError> {
        let blocks: Vec<([u8; CID_SIZE], Vec<u8>)> = commit
            .blocks
            .into_iter()
            .map(|(cid, data)| Ok((cid_to_bytes(&cid)?, data.to_vec())))
            .collect::<Result<Vec<_>, RepoError>>()?;
        let deleted_cids: Vec<[u8; CID_SIZE]> = commit
            .deleted_cids
            .iter()
            .map(cid_to_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        self.send_apply_commit(blocks, deleted_cids).await
    }
}

impl<S: StorageIO + Send + Sync + 'static> TranquilBlockStore<S> {
    pub async fn decrement_refs(&self, cids: &[Cid]) -> Result<(), RepoError> {
        if cids.is_empty() {
            return Ok(());
        }
        let deleted_cids: Vec<[u8; CID_SIZE]> = cids
            .iter()
            .map(cid_to_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        self.send_apply_commit(Vec::new(), deleted_cids).await
    }

    pub fn refcount_of(&self, cid: &Cid) -> Result<Option<u32>, RepoError> {
        let cid_bytes = cid_to_bytes(cid)?;
        Ok(self.index.get(&cid_bytes).map(|entry| entry.refcount.raw()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use crate::blockstore::data_file::{
        BLOCK_FORMAT_VERSION, BLOCK_HEADER_SIZE, BLOCK_MAGIC, encode_block_record,
    };
    use crate::blockstore::manager::DATA_FILE_EXTENSION;
    use crate::io::FileId;

    struct EioOnReadAtRange {
        inner: RealIO,
        target_path: PathBuf,
        target_min: u64,
        target_max: u64,
        fired: AtomicBool,
        fd_paths: Mutex<HashMap<FileId, PathBuf>>,
    }

    impl StorageIO for EioOnReadAtRange {
        fn open(&self, path: &Path, opts: OpenOptions) -> io::Result<FileId> {
            let fd = self.inner.open(path, opts)?;
            self.fd_paths.lock().unwrap().insert(fd, path.to_path_buf());
            Ok(fd)
        }

        fn close(&self, fd: FileId) -> io::Result<()> {
            self.fd_paths.lock().unwrap().remove(&fd);
            self.inner.close(fd)
        }

        fn read_at(&self, fd: FileId, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            let path_match = self.fd_paths.lock().unwrap().get(&fd).cloned();
            let in_target_range = path_match.as_ref() == Some(&self.target_path)
                && offset >= self.target_min
                && offset <= self.target_max;
            if in_target_range && !self.fired.swap(true, Ordering::SeqCst) {
                return Err(io::Error::other("simulated EIO on read"));
            }
            self.inner.read_at(fd, offset, buf)
        }

        fn write_at(&self, fd: FileId, offset: u64, buf: &[u8]) -> io::Result<usize> {
            self.inner.write_at(fd, offset, buf)
        }

        fn sync(&self, fd: FileId) -> io::Result<()> {
            self.inner.sync(fd)
        }

        fn file_size(&self, fd: FileId) -> io::Result<u64> {
            self.inner.file_size(fd)
        }

        fn truncate(&self, fd: FileId, size: u64) -> io::Result<()> {
            self.inner.truncate(fd, size)
        }

        fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
            self.inner.rename(from, to)
        }

        fn delete(&self, path: &Path) -> io::Result<()> {
            self.inner.delete(path)
        }

        fn mkdir(&self, path: &Path) -> io::Result<()> {
            self.inner.mkdir(path)
        }

        fn sync_dir(&self, path: &Path) -> io::Result<()> {
            self.inner.sync_dir(path)
        }

        fn list_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
            self.inner.list_dir(path)
        }
    }

    #[test]
    fn scan_and_index_does_not_truncate_acked_block_on_transient_eio() {
        let tmp = tempfile::TempDir::new().unwrap();
        let data_dir = tmp.path().join("data");
        let index_dir = tmp.path().join("index");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::create_dir_all(&index_dir).unwrap();

        let file_id = DataFileId::new(0);
        let file_path = data_dir.join(format!("{file_id}.{DATA_FILE_EXTENSION}"));

        let setup = RealIO::new();
        let fd = setup.open(&file_path, OpenOptions::read_write()).unwrap();
        let mut header = [0u8; BLOCK_HEADER_SIZE];
        header[..4].copy_from_slice(&BLOCK_MAGIC);
        header[4] = BLOCK_FORMAT_VERSION;
        setup.write_all_at(fd, 0, &header).unwrap();

        let cid_a = [0xAAu8; CID_SIZE];
        let data_a = vec![1u8; 64];
        let block_a_offset = BlockOffset::new(BLOCK_HEADER_SIZE as u64);
        let len_a = encode_block_record(&setup, fd, block_a_offset, &cid_a, &data_a).unwrap();

        let block_b_offset_raw = BLOCK_HEADER_SIZE as u64 + len_a;
        let block_b_offset = BlockOffset::new(block_b_offset_raw);
        let cid_b = [0xBBu8; CID_SIZE];
        let data_b = vec![2u8; 64];
        let len_b = encode_block_record(&setup, fd, block_b_offset, &cid_b, &data_b).unwrap();

        setup.sync(fd).unwrap();
        setup.close(fd).unwrap();
        drop(setup);

        let total_size = block_b_offset_raw + len_b;
        assert_eq!(std::fs::metadata(&file_path).unwrap().len(), total_size);

        let wrapper = EioOnReadAtRange {
            inner: RealIO::new(),
            target_path: file_path.clone(),
            target_min: block_b_offset_raw,
            target_max: block_b_offset_raw + (BLOCK_RECORD_OVERHEAD as u64) - 1,
            fired: AtomicBool::new(false),
            fd_paths: Mutex::new(HashMap::new()),
        };

        let index = BlockIndex::open(&index_dir).unwrap();

        let result = TranquilBlockStore::<EioOnReadAtRange>::replay_single_file(
            &wrapper,
            &data_dir,
            &index,
            file_id,
            BlockOffset::new(BLOCK_HEADER_SIZE as u64),
        );

        assert!(
            result.is_err(),
            "replay must surface transient EIO instead of silently truncating"
        );

        let post_size = std::fs::metadata(&file_path).unwrap().len();
        assert_eq!(
            post_size, total_size,
            "scan truncated durable acked block past EIO point: expected {total_size} bytes, got {post_size}"
        );
    }

    fn instant_policy(max_attempts: u8) -> OpenRetryPolicy {
        OpenRetryPolicy {
            max_attempts: NonZeroU8::new(max_attempts).expect("max_attempts must be nonzero"),
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
        }
    }

    #[test]
    fn retry_with_backoff_succeeds_on_first_attempt() {
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let result = retry_with_backoff(instant_policy(5), &mut |_| {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok::<u8, RepoError>(42)
        });
        assert_eq!(result.expect("ok"), 42);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn retry_with_backoff_recovers_after_transient_failures() {
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let result = retry_with_backoff(instant_policy(5), &mut |_| {
            let n = calls.fetch_add(1, Ordering::Relaxed);
            if n >= 2 {
                Ok::<u8, RepoError>(7)
            } else {
                Err(RepoError::storage(io::Error::other("transient EIO")))
            }
        });
        assert_eq!(result.expect("ok"), 7);
        assert_eq!(calls.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn retry_with_backoff_gives_up_after_max_attempts() {
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let result: Result<u8, RepoError> = retry_with_backoff(instant_policy(3), &mut |_| {
            calls.fetch_add(1, Ordering::Relaxed);
            Err(RepoError::storage(io::Error::other("permanent EIO")))
        });
        assert!(result.is_err(), "expected exhaustion error");
        assert_eq!(calls.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn retry_with_backoff_passes_attempt_index_to_op() {
        let observed = std::sync::Mutex::new(Vec::<u8>::new());
        let _result: Result<(), RepoError> =
            retry_with_backoff(instant_policy(4), &mut |attempt| {
                observed.lock().unwrap().push(attempt);
                Err(RepoError::storage(io::Error::other("EIO")))
            });
        assert_eq!(*observed.lock().unwrap(), vec![0, 1, 2, 3]);
    }
}
