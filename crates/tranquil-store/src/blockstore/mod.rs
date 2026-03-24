mod data_file;
mod group_commit;
mod hint;
mod key_index;
mod manager;
mod reader;
mod store;
mod types;

pub use data_file::{
    BLOCK_FORMAT_VERSION, BLOCK_HEADER_SIZE, BLOCK_MAGIC, BLOCK_RECORD_OVERHEAD, CID_SIZE,
    DataFileReader, DataFileWriter, ReadBlockRecord, ValidBlock, decode_block_record,
    encode_block_record,
};
pub use group_commit::{CommitError, CommitRequest, GroupCommitConfig, GroupCommitWriter};
pub use hint::{
    HINT_FILE_EXTENSION, HINT_RECORD_SIZE, HintFileReader, HintFileWriter, ReadHintRecord,
    RebuildError, decode_hint_record, hint_file_path, rebuild_index_from_data_files,
    rebuild_index_from_hints,
};
pub use key_index::{KeyIndex, KeyIndexError, KeyIndexOpenOutcome};
pub use manager::{DEFAULT_MAX_FILE_SIZE, DataFileManager};
pub use reader::{BlockStoreReader, ReadError};
pub use store::{BlockStoreConfig, TranquilBlockStore};
pub use types::{
    BlockLength, BlockLocation, BlockOffset, DataFileId, HintOffset, IndexEntry, MAX_BLOCK_SIZE,
    RefCount, WriteCursor,
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

pub(crate) fn list_files_by_extension<S: StorageIO>(
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
