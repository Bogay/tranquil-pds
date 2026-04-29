mod cid_util;
mod compaction;
mod data_file;
mod group_commit;
pub mod hash_index;
mod hint;
mod manager;
mod reader;
mod store;
mod types;

pub use cid_util::{DAG_CBOR_CODEC, SHA2_256_CODE, hash_to_cid, hash_to_cid_bytes};
pub use compaction::CompactionError;
pub use data_file::{
    BLOCK_FORMAT_VERSION, BLOCK_HEADER_SIZE, BLOCK_MAGIC, BLOCK_RECORD_OVERHEAD, CID_SIZE,
    DataFileReader, DataFileWriter, ReadBlockRecord, ValidBlock, decode_block_record,
    encode_block_record,
};
pub use group_commit::{
    ActiveFileSet, CommitError, CommitRequest, FileIdAllocator, GroupCommitConfig,
    GroupCommitWriter, ShardHintPositions,
};
pub use hint::{
    HINT_FILE_EXTENSION, HINT_RECORD_SIZE, HintFileReader, HintFileWriter, HintIndex,
    ReadHintRecord, RebuildError, decode_hint_record, hint_file_path, scan_hints_to_memory,
};
pub use manager::{CachedHandle, DEFAULT_MAX_FILE_SIZE, DataFileManager};
pub use reader::{BlockStoreReader, ReadError};
pub use store::QuiesceGuard;
pub use store::{BlockStoreConfig, DEFAULT_SHARD_COUNT, OpenRetryPolicy, TranquilBlockStore};
pub use types::{
    BlockLength, BlockLocation, BlockOffset, BlockstoreSnapshot, CidBytes, CollectionResult,
    CommitEpoch, CompactionResult, DataFileId, EpochCounter, HintOffset, IndexEntry, LivenessInfo,
    MAX_BLOCK_SIZE, RefCount, ShardId, WallClockMs, WriteCursor,
};

use std::io;
use std::path::Path;

use crate::io::StorageIO;

pub struct BlocksSynced(());

impl BlocksSynced {
    pub(in crate::blockstore) fn new() -> Self {
        Self(())
    }
}

pub fn list_files_by_extension<S: StorageIO>(
    io: &S,
    dir: &Path,
    extension: &str,
) -> io::Result<Vec<DataFileId>> {
    let entries = io.list_dir(dir)?;
    let mut ids: Vec<DataFileId> = entries
        .iter()
        .filter_map(|path| {
            let stem = path.file_stem()?.to_str()?;
            let ext = path.extension()?.to_str()?;
            (ext == extension).then(|| stem.parse::<u32>().ok().map(DataFileId::new))?
        })
        .collect();
    ids.sort();
    Ok(ids)
}

#[cfg(test)]
pub(crate) fn test_cid(seed: u8) -> [u8; CID_SIZE] {
    test_cid_u16(seed as u16)
}

#[cfg(test)]
pub(crate) fn test_cid_u16(seed: u16) -> [u8; CID_SIZE] {
    let mut cid = [0u8; CID_SIZE];
    cid[0] = 0x01;
    cid[1] = 0x71;
    cid[2] = 0x12;
    cid[3] = 0x20;
    cid[4..6].copy_from_slice(&seed.to_le_bytes());
    (6..CID_SIZE).for_each(|i| cid[i] = (seed as u8).wrapping_add(i as u8));
    cid
}
