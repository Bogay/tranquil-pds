use std::io;

use crate::io::{FileId, OpenOptions, StorageIO};

use super::data_file::{DataFileReader, DataFileWriter, ReadBlockRecord};
use super::group_commit::{ActiveFileSet, FileIdAllocator};
use super::hash_index::{BlockIndex, BlockIndexError};
use super::hint::{HintFileWriter, hint_file_path};
use super::manager::DataFileManager;
use super::types::{
    BlockLocation, CidBytes, CommitEpoch, CompactionResult, CompactionStats, DataFileId,
    WallClockMs,
};

#[derive(Debug)]
pub enum CompactionError {
    Io(io::Error),
    Index(BlockIndexError),
    ChannelClosed,
    ActiveFileCannotBeCompacted,
}

impl std::fmt::Display for CompactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Index(e) => write!(f, "index: {e}"),
            Self::ChannelClosed => write!(f, "commit channel closed"),
            Self::ActiveFileCannotBeCompacted => {
                write!(f, "cannot compact the active data file")
            }
        }
    }
}

impl std::error::Error for CompactionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Index(e) => Some(e),
            Self::ChannelClosed | Self::ActiveFileCannotBeCompacted => None,
        }
    }
}

impl From<io::Error> for CompactionError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<BlockIndexError> for CompactionError {
    fn from(e: BlockIndexError) -> Self {
        Self::Index(e)
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn compact_on_writer_thread<S: StorageIO>(
    manager: &DataFileManager<S>,
    index: &BlockIndex,
    source_file_id: DataFileId,
    current_epoch: CommitEpoch,
    grace_period_ms: u64,
    file_ids: &FileIdAllocator,
    active_files: &ActiveFileSet,
    hint_positions: &super::group_commit::ShardHintPositions,
    epoch: &super::types::EpochCounter,
    now: WallClockMs,
) -> Result<CompactionResult, CompactionError> {
    if active_files.contains(source_file_id) {
        return Err(CompactionError::ActiveFileCannotBeCompacted);
    }

    let source_handle = match manager.open_for_read(source_file_id) {
        Ok(handle) => handle,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return purge_phantom_file(manager, index, hint_positions, epoch, source_file_id);
        }
        Err(e) => return Err(CompactionError::Io(e)),
    };
    let source_size = manager.io().file_size(source_handle.fd())?;

    let new_file_id = file_ids.allocate();

    let result = stream_compact(
        manager,
        index,
        source_file_id,
        source_handle.fd(),
        new_file_id,
        current_epoch,
        grace_period_ms,
        now,
    );

    match result {
        Err(e) => {
            manager.delete_data_file(new_file_id).ok();
            manager
                .io()
                .delete(&hint_file_path(manager.data_dir(), new_file_id))
                .ok();
            Err(e)
        }
        Ok((new_size, live_count, dead_count, new_hint_offset)) => {
            match live_count {
                0 => hint_positions.forget_extra(new_file_id),
                _ => hint_positions.record_extra(new_file_id, new_hint_offset),
            }
            hint_positions.forget_extra(source_file_id);

            index
                .write_checkpoint(epoch.current(), hint_positions)
                .map_err(CompactionError::Io)?;

            manager.delete_data_file(source_file_id)?;
            manager
                .io()
                .delete(&hint_file_path(manager.data_dir(), source_file_id))
                .ok();
            if live_count == 0 {
                manager.delete_data_file(new_file_id).ok();
                manager
                    .io()
                    .delete(&hint_file_path(manager.data_dir(), new_file_id))
                    .ok();
            }
            manager.io().sync_dir(manager.data_dir())?;

            let reclaimed_bytes = source_size.saturating_sub(new_size);

            tracing::info!(
                source = %source_file_id,
                dest = %new_file_id,
                old_size = source_size,
                new_size,
                live_count,
                dead_count,
                reclaimed_bytes,
                "compaction complete"
            );

            Ok(CompactionResult::Compacted(CompactionStats {
                file_id: source_file_id,
                old_size: source_size,
                new_size,
                live_blocks: live_count,
                dead_blocks: dead_count,
                reclaimed_bytes,
            }))
        }
    }
}

fn purge_phantom_file<S: StorageIO>(
    manager: &DataFileManager<S>,
    index: &BlockIndex,
    hint_positions: &super::group_commit::ShardHintPositions,
    epoch: &super::types::EpochCounter,
    source_file_id: DataFileId,
) -> Result<CompactionResult, CompactionError> {
    let phantom_blocks = index.purge_by_file_id(source_file_id);

    tracing::warn!(
        file_id = %source_file_id,
        phantom_blocks,
        "source data file missing on disk, purged phantom index entries"
    );

    hint_positions.forget_extra(source_file_id);

    manager
        .io()
        .delete(&hint_file_path(manager.data_dir(), source_file_id))
        .ok();
    manager.io().sync_dir(manager.data_dir()).ok();

    index
        .write_checkpoint(epoch.current(), hint_positions)
        .map_err(CompactionError::Io)?;

    Ok(CompactionResult::Purged {
        file_id: source_file_id,
        phantom_blocks,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn repair_blocks_on_writer_thread<S: StorageIO>(
    manager: &DataFileManager<S>,
    index: &BlockIndex,
    blocks: &[(CidBytes, Vec<u8>)],
    current_epoch: CommitEpoch,
    file_ids: &FileIdAllocator,
    hint_positions: &super::group_commit::ShardHintPositions,
    epoch: &super::types::EpochCounter,
) -> Result<u64, CompactionError> {
    if blocks.is_empty() {
        return Ok(0);
    }

    let new_file_id = file_ids.allocate();
    let new_handle = manager.open_for_append(new_file_id)?;
    let mut writer = DataFileWriter::new(manager.io(), new_handle.fd(), new_file_id)?;

    let hint_path = hint_file_path(manager.data_dir(), new_file_id);
    let hint_fd = manager.io().open(&hint_path, OpenOptions::read_write())?;
    let mut hint_writer = HintFileWriter::new(manager.io(), hint_fd);

    let mut relocations: Vec<(CidBytes, BlockLocation)> = Vec::with_capacity(blocks.len());
    let write_result = blocks.iter().try_for_each(|(cid, data)| {
        let refcount = index.get(cid).map(|e| e.refcount.raw()).unwrap_or(1).max(1);
        let loc = writer.append_block(cid, data)?;
        hint_writer.append_relocate(cid, &loc, refcount)?;
        relocations.push((*cid, loc));
        Ok::<_, CompactionError>(())
    });

    let record_count = u32::try_from(relocations.len()).unwrap_or(u32::MAX);
    let writer_position = writer.position();
    let finalize = write_result
        .and_then(|()| writer.sync().map_err(CompactionError::from))
        .and_then(|()| {
            hint_writer
                .append_commit_marker(
                    current_epoch.raw(),
                    record_count,
                    new_file_id,
                    writer_position,
                )
                .map_err(CompactionError::from)
        })
        .and_then(|()| hint_writer.sync().map_err(CompactionError::from))
        .and_then(|()| {
            manager
                .io()
                .sync_dir(manager.data_dir())
                .map_err(CompactionError::from)
        })
        .and_then(|()| manager.io().barrier().map_err(CompactionError::from));

    let final_hint_offset = hint_writer.position();
    let _ = manager.io().close(hint_fd);

    if let Err(e) =
        finalize.and_then(|()| verify_repaired_blocks(manager, new_file_id, &relocations))
    {
        manager.delete_data_file(new_file_id).ok();
        manager
            .io()
            .delete(&hint_file_path(manager.data_dir(), new_file_id))
            .ok();
        return Err(e);
    }

    hint_positions.record_extra(new_file_id, final_hint_offset);
    index.apply_compaction(&relocations, &[]);
    index
        .write_checkpoint(epoch.current(), hint_positions)
        .map_err(CompactionError::Io)?;

    tracing::info!(
        dest = %new_file_id,
        repaired = relocations.len(),
        "structural repair complete"
    );

    Ok(relocations.len() as u64)
}

fn verify_repaired_blocks<S: StorageIO>(
    manager: &DataFileManager<S>,
    file_id: DataFileId,
    relocations: &[(CidBytes, BlockLocation)],
) -> Result<(), CompactionError> {
    let handle = manager.open_for_read(file_id)?;
    let file_size = manager.io().file_size(handle.fd())?;
    relocations.iter().try_for_each(|(cid, loc)| {
        match super::data_file::decode_block_record(
            manager.io(),
            handle.fd(),
            loc.offset,
            file_size,
        ) {
            Ok(Some(ReadBlockRecord::Valid { cid_bytes, .. })) if cid_bytes == *cid => Ok(()),
            _ => Err(CompactionError::Io(io::Error::other(
                "repaired block failed read-back verification",
            ))),
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn stream_compact<S: StorageIO>(
    manager: &DataFileManager<S>,
    index: &BlockIndex,
    source_file_id: DataFileId,
    source_fd: FileId,
    new_file_id: DataFileId,
    current_epoch: CommitEpoch,
    grace_period_ms: u64,
    now: WallClockMs,
) -> Result<(u64, u64, u64, super::types::HintOffset), CompactionError> {
    let mut reader = DataFileReader::open(manager.io(), source_fd)?;

    let new_handle = manager.open_for_append(new_file_id)?;
    let mut writer = DataFileWriter::new(manager.io(), new_handle.fd(), new_file_id)?;

    let hint_path = hint_file_path(manager.data_dir(), new_file_id);
    let hint_fd = manager.io().open(&hint_path, OpenOptions::read_write())?;
    let mut hint_writer = HintFileWriter::new(manager.io(), hint_fd);

    let mut relocations: Vec<(CidBytes, BlockLocation)> = Vec::new();
    let mut dead_cids: Vec<CidBytes> = Vec::new();
    let mut live_count: u64 = 0;
    let mut dead_count: u64 = 0;

    let scan_result = reader.try_for_each(|r| {
        let record = r?;
        match record {
            ReadBlockRecord::Valid {
                cid_bytes, data, ..
            } => match index.get(&cid_bytes) {
                Some(e) if e.location.file_id == source_file_id && !e.refcount.is_zero() => {
                    let loc = writer.append_block(&cid_bytes, &data)?;
                    hint_writer.append_relocate(&cid_bytes, &loc, e.refcount.raw())?;
                    relocations.push((cid_bytes, loc));
                    live_count = live_count.saturating_add(1);
                }
                Some(e) if e.location.file_id == source_file_id && e.refcount.is_zero() => {
                    let eligible =
                        index.is_gc_eligible(&cid_bytes, current_epoch, now, grace_period_ms);
                    match eligible {
                        true => {
                            tracing::debug!(
                                ?cid_bytes,
                                file_id = %source_file_id,
                                "gc: collecting dead block"
                            );
                            hint_writer.append_remove(&cid_bytes)?;
                            dead_cids.push(cid_bytes);
                            dead_count = dead_count.saturating_add(1);
                        }
                        false => {
                            let loc = writer.append_block(&cid_bytes, &data)?;
                            hint_writer.append_relocate(&cid_bytes, &loc, e.refcount.raw())?;
                            relocations.push((cid_bytes, loc));
                            live_count = live_count.saturating_add(1);
                        }
                    }
                }
                _ => {}
            },
            ReadBlockRecord::Corrupted { .. } | ReadBlockRecord::Truncated { .. } => {}
        }
        Ok::<_, CompactionError>(())
    });

    let record_count =
        u32::try_from((live_count as u128).saturating_add(dead_count as u128)).unwrap_or(u32::MAX);
    let writer_position = writer.position();
    let finalize_result = scan_result
        .and_then(|()| writer.sync().map_err(CompactionError::from))
        .and_then(|()| {
            hint_writer
                .append_commit_marker(
                    current_epoch.raw(),
                    record_count,
                    new_file_id,
                    writer_position,
                )
                .map_err(CompactionError::from)
        })
        .and_then(|()| hint_writer.sync().map_err(CompactionError::from))
        .and_then(|()| {
            manager
                .io()
                .sync_dir(manager.data_dir())
                .map_err(CompactionError::from)
        })
        .and_then(|()| manager.io().barrier().map_err(CompactionError::from));

    let final_hint_offset = hint_writer.position();
    let _ = manager.io().close(hint_fd);

    finalize_result?;

    let new_size = writer.position().raw();

    index.apply_compaction(&relocations, &dead_cids);

    Ok((new_size, live_count, dead_count, final_hint_offset))
}
