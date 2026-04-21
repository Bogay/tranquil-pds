use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use bytes::Bytes;

use crate::io::{FileId, StorageIO};

use super::data_file::{CID_SIZE, ReadBlockRecord, decode_block_record};
use super::hash_index::BlockIndex;
use super::manager::DataFileManager;
use super::types::{BlockLocation, BlockOffset, DataFileId};

#[derive(Debug, Clone)]
pub enum ReadError {
    Io(Arc<io::Error>),
    Corrupted {
        file_id: DataFileId,
        offset: BlockOffset,
    },
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Corrupted { file_id, offset } => {
                write!(f, "corrupted block at {file_id}:{}", offset.raw())
            }
        }
    }
}

impl std::error::Error for ReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e.as_ref()),
            Self::Corrupted { .. } => None,
        }
    }
}

impl From<io::Error> for ReadError {
    fn from(e: io::Error) -> Self {
        Self::Io(Arc::new(e))
    }
}

pub struct BlockStoreReader<S: StorageIO> {
    index: Arc<BlockIndex>,
    manager: Arc<DataFileManager<S>>,
}

impl<S: StorageIO> Clone for BlockStoreReader<S> {
    fn clone(&self) -> Self {
        Self {
            index: Arc::clone(&self.index),
            manager: Arc::clone(&self.manager),
        }
    }
}

impl<S: StorageIO> BlockStoreReader<S> {
    pub fn new(index: Arc<BlockIndex>, manager: Arc<DataFileManager<S>>) -> Self {
        Self { index, manager }
    }

    pub fn manager(&self) -> &DataFileManager<S> {
        &self.manager
    }

    pub fn get(&self, cid: &[u8; CID_SIZE]) -> Result<Option<Bytes>, ReadError> {
        match self.index.get(cid) {
            Some(e) => self.read_block_at(e.location).map(Some),
            None => Ok(None),
        }
    }

    pub fn has(&self, cid: &[u8; CID_SIZE]) -> Result<bool, ReadError> {
        Ok(self.index.has(cid))
    }

    pub fn get_many(&self, cids: &[[u8; CID_SIZE]]) -> Result<Vec<Option<Bytes>>, ReadError> {
        let mut results: Vec<Option<Bytes>> = vec![None; cids.len()];

        let index_lookups: Vec<(usize, BlockLocation)> = cids
            .iter()
            .enumerate()
            .filter_map(|(i, cid)| self.index.get(cid).map(|entry| (i, entry.location)))
            .collect();
        self.read_locations_into(&index_lookups, &mut results)?;

        Ok(results)
    }

    fn read_locations_into(
        &self,
        lookups: &[(usize, BlockLocation)],
        results: &mut [Option<Bytes>],
    ) -> Result<(), ReadError> {
        let mut by_file: HashMap<DataFileId, Vec<(usize, BlockLocation)>> = HashMap::new();
        lookups.iter().for_each(|&(idx, loc)| {
            by_file.entry(loc.file_id).or_default().push((idx, loc));
        });

        by_file.into_iter().try_for_each(|(file_id, mut entries)| {
            let handle = self.manager.open_for_read(file_id)?;
            let file_size = self.manager.io().file_size(handle.fd())?;
            entries.sort_by_key(|(_, loc)| loc.offset);
            entries.into_iter().try_for_each(|(orig_idx, loc)| {
                let data = self.decode_and_validate(handle.fd(), file_size, loc)?;
                results[orig_idx] = Some(data);
                Ok::<_, ReadError>(())
            })
        })
    }

    fn read_block_at(&self, location: BlockLocation) -> Result<Bytes, ReadError> {
        let handle = self.manager.open_for_read(location.file_id)?;
        let file_size = self.manager.io().file_size(handle.fd())?;
        self.decode_and_validate(handle.fd(), file_size, location)
    }

    fn decode_and_validate(
        &self,
        fd: FileId,
        file_size: u64,
        location: BlockLocation,
    ) -> Result<Bytes, ReadError> {
        let attempt_once = || -> Result<Bytes, ReadError> {
            match decode_block_record(self.manager.io(), fd, location.offset, file_size)? {
                Some(ReadBlockRecord::Valid { data, .. })
                    if data.len() == location.length.raw() as usize =>
                {
                    Ok(Bytes::from(data))
                }
                Some(ReadBlockRecord::Valid { .. }) => Err(ReadError::Corrupted {
                    file_id: location.file_id,
                    offset: location.offset,
                }),
                Some(
                    ReadBlockRecord::Corrupted { offset } | ReadBlockRecord::Truncated { offset },
                ) => Err(ReadError::Corrupted {
                    file_id: location.file_id,
                    offset,
                }),
                None => Err(ReadError::Corrupted {
                    file_id: location.file_id,
                    offset: location.offset,
                }),
            }
        };
        (0..READ_RETRY_ATTEMPTS.saturating_sub(1))
            .find_map(|_| match attempt_once() {
                Ok(bytes) => Some(Ok(bytes)),
                Err(ReadError::Corrupted { .. }) => None,
                Err(e) => Some(Err(e)),
            })
            .unwrap_or_else(attempt_once)
    }
}

const READ_RETRY_ATTEMPTS: u32 = 4;
