use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use cid::Cid;
use jacquard_repo::error::RepoError;
use jacquard_repo::repo::CommitData;
use jacquard_repo::storage::BlockStore;
use multihash::Multihash;
use sha2::{Digest, Sha256};

use crate::fsync_order::PostBlockstoreHook;
use crate::io::{OpenOptions, RealIO, StorageIO};

use super::compaction::CompactionError;
use super::data_file::{BLOCK_RECORD_OVERHEAD, CID_SIZE, ReadBlockRecord};
use super::group_commit::{CommitError, CommitRequest, GroupCommitConfig, GroupCommitWriter};
use super::hash_index::BlockIndex;
use super::manager::DataFileManager;
use super::reader::{BlockStoreReader, ReadError};
use super::types::{
    BlockLength, BlockLocation, BlockOffset, CollectionResult, CompactionResult, DataFileId,
    EpochCounter, LivenessInfo, WallClockMs, WriteCursor,
};

const DAG_CBOR_CODEC: u64 = 0x71;
const SHA2_256_CODE: u64 = 0x12;

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

fn hash_and_cid(data: &[u8]) -> Result<Cid, RepoError> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    let multihash = Multihash::wrap(SHA2_256_CODE, &hash).map_err(|e| {
        RepoError::storage(io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    })?;
    Ok(Cid::new_v1(DAG_CBOR_CODEC, multihash))
}

fn block_index_err_to_repo(e: super::hash_index::BlockIndexError) -> RepoError {
    RepoError::storage(io::Error::other(e.to_string()))
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

#[derive(Clone)]
pub struct TranquilBlockStore {
    writer: Arc<WriterHandle>,
    reader: Arc<BlockStoreReader<RealIO>>,
    index: Arc<BlockIndex>,
    epoch: EpochCounter,
    data_dir: PathBuf,
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

impl TranquilBlockStore {
    pub fn open(config: BlockStoreConfig) -> Result<Self, RepoError> {
        Self::open_with_hook(config, None)
    }

    pub fn open_with_hook(
        config: BlockStoreConfig,
        post_sync_hook: Option<Arc<dyn PostBlockstoreHook>>,
    ) -> Result<Self, RepoError> {
        if config.data_dir == config.index_dir {
            return Err(RepoError::storage(io::Error::new(
                io::ErrorKind::InvalidInput,
                "data_dir and index_dir must be different directories",
            )));
        }
        std::fs::create_dir_all(&config.data_dir).map_err(RepoError::storage)?;
        std::fs::create_dir_all(&config.index_dir).map_err(RepoError::storage)?;

        let index = BlockIndex::open(&config.index_dir).map_err(RepoError::storage)?;

        let io = RealIO::new();

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
        let make_manager = move || {
            DataFileManager::new(RealIO::new(), data_dir_for_closure.clone(), max_file_size)
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
            RealIO::new(),
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

    fn recover_from_file_cursors<S: StorageIO>(
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

    fn replay_single_file<S: StorageIO>(
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

        let result = Self::scan_and_index(io, index, fd, file_id, start_offset);

        let _ = io.close(fd);

        result
    }

    fn scan_and_index<S: StorageIO>(
        io: &S,
        index: &BlockIndex,
        fd: crate::io::FileId,
        file_id: DataFileId,
        start_offset: BlockOffset,
    ) -> Result<(), RepoError> {
        let file_size = io.file_size(fd).map_err(RepoError::storage)?;

        if file_size <= start_offset.raw() {
            return Ok(());
        }

        let scan_pos = &mut { start_offset };
        let (recovered_entries, last_valid_end) = std::iter::from_fn(|| {
            match super::data_file::decode_block_record(io, fd, *scan_pos, file_size) {
                Err(e) => {
                    tracing::warn!(
                        file_id = %file_id,
                        offset = scan_pos.raw(),
                        error = %e,
                        "IO error during recovery scan, stopping"
                    );
                    None
                }
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
                    let length = BlockLength::new(raw_len);
                    let record_size = BLOCK_RECORD_OVERHEAD as u64 + u64::from(raw_len);
                    *scan_pos = scan_pos.advance(record_size);
                    Some((
                        cid_bytes,
                        BlockLocation {
                            file_id,
                            offset,
                            length,
                        },
                    ))
                }
                Ok(Some(ReadBlockRecord::Corrupted { .. } | ReadBlockRecord::Truncated { .. })) => {
                    None
                }
            }
        })
        .fold(
            (Vec::new(), start_offset),
            |(mut entries, _), (cid_bytes, location)| {
                let new_end = location
                    .offset
                    .advance(BLOCK_RECORD_OVERHEAD as u64 + location.length.as_u64());
                entries.push((cid_bytes, location));
                (entries, new_end)
            },
        );

        if file_size > last_valid_end.raw() {
            tracing::info!(
                file_id = %file_id,
                truncating_from = last_valid_end.raw(),
                file_size,
                "truncating partial/corrupted tail"
            );
            io.truncate(fd, last_valid_end.raw())
                .map_err(RepoError::storage)?;
            io.sync(fd).map_err(RepoError::storage)?;
        }

        if !recovered_entries.is_empty() {
            let new_cursor = WriteCursor {
                file_id,
                offset: last_valid_end,
            };
            let inserted = index
                .batch_put_if_absent(&recovered_entries, new_cursor)
                .map_err(block_index_err_to_repo)?;
            tracing::info!(
                file_id = %file_id,
                scanned = recovered_entries.len(),
                inserted,
                new_cursor_offset = last_valid_end.raw(),
                "recovery data file scan"
            );
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

impl BlockStore for TranquilBlockStore {
    async fn get(&self, cid: &Cid) -> Result<Option<Bytes>, RepoError> {
        let cid_bytes = cid_to_bytes(cid)?;
        let reader = Arc::clone(&self.reader);
        tokio::task::spawn_blocking(move || reader.get(&cid_bytes))
            .await
            .map_err(RepoError::task_failed)?
            .map_err(read_error_to_repo)
    }

    async fn put(&self, data: &[u8]) -> Result<Cid, RepoError> {
        let cid = hash_and_cid(data)?;
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

impl TranquilBlockStore {
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
