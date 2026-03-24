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

use super::data_file::{BLOCK_RECORD_OVERHEAD, CID_SIZE, ReadBlockRecord};
use super::group_commit::{CommitError, CommitRequest, GroupCommitConfig, GroupCommitWriter};
use super::hint::{rebuild_index_from_data_files, rebuild_index_from_hints};
use super::key_index::KeyIndex;
use super::manager::DataFileManager;
use super::reader::{BlockStoreReader, ReadError};
use super::types::{BlockLength, BlockLocation, BlockOffset, DataFileId, WriteCursor};

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
        ReadError::Index(idx_err) => RepoError::storage(io::Error::other(idx_err.to_string())),
        ReadError::Corrupted { file_id, offset } => RepoError::storage(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("corrupted block at {file_id}:{}", offset.raw()),
        )),
    }
}

#[derive(Debug, Clone)]
pub struct BlockStoreConfig {
    pub data_dir: PathBuf,
    pub index_dir: PathBuf,
    pub max_file_size: u64,
    pub group_commit: GroupCommitConfig,
}

#[derive(Clone)]
pub struct TranquilBlockStore {
    sender: flume::Sender<CommitRequest>,
    reader: Arc<BlockStoreReader<RealIO>>,
    _writer_handle: Arc<WriterHandle>,
}

struct WriterHandle {
    writer: parking_lot::Mutex<Option<GroupCommitWriter>>,
}

impl Drop for WriterHandle {
    fn drop(&mut self) {
        if let Some(w) = self.writer.lock().take() {
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

        let io = RealIO::new();
        let outcome = KeyIndex::open(&config.index_dir)
            .map_err(|e| RepoError::storage(io::Error::other(e.to_string())))?;

        let needs_full_rebuild = outcome.needs_rebuild();
        let index = Arc::new(outcome.into_inner());

        if needs_full_rebuild {
            tracing::warn!("fjall index corrupt or missing, rebuilding from hints/data files");
            Self::rebuild_index(&io, &config.data_dir, &index)?;
        } else {
            Self::recover_from_cursor(&io, &config.data_dir, &index)?;
        }

        let manager_for_writer =
            DataFileManager::new(RealIO::new(), config.data_dir.clone(), config.max_file_size);
        let writer = GroupCommitWriter::spawn_with_hook(
            manager_for_writer,
            Arc::clone(&index),
            config.group_commit,
            post_sync_hook,
        )
        .map_err(commit_error_to_repo)?;
        let sender = writer.sender().clone();

        let manager_for_reader = Arc::new(DataFileManager::new(
            RealIO::new(),
            config.data_dir,
            config.max_file_size,
        ));
        let reader = Arc::new(BlockStoreReader::new(
            Arc::clone(&index),
            manager_for_reader,
        ));

        Ok(Self {
            sender,
            reader,
            _writer_handle: Arc::new(WriterHandle {
                writer: parking_lot::Mutex::new(Some(writer)),
            }),
        })
    }

    fn rebuild_index<S: StorageIO>(
        io: &S,
        data_dir: &Path,
        index: &KeyIndex,
    ) -> Result<(), RepoError> {
        match rebuild_index_from_hints(io, data_dir, index) {
            Ok(()) => {
                tracing::info!("index rebuilt from hint files");
                Ok(())
            }
            Err(hint_err) => {
                tracing::warn!(
                    error = %hint_err,
                    "hint-based rebuild failed, falling back to data file scan"
                );
                rebuild_index_from_data_files(io, data_dir, index)
                    .map_err(|e| RepoError::storage(io::Error::other(e.to_string())))?;
                tracing::info!("index rebuilt from data files");
                Ok(())
            }
        }
    }

    fn recover_from_cursor<S: StorageIO>(
        io: &S,
        data_dir: &Path,
        index: &KeyIndex,
    ) -> Result<(), RepoError> {
        let map_idx = |e: super::key_index::KeyIndexError| {
            RepoError::storage(io::Error::other(e.to_string()))
        };

        let cursor = index.read_write_cursor().map_err(map_idx)?;

        let all_data_files =
            super::list_files_by_extension(io, data_dir, super::manager::DATA_FILE_EXTENSION)
                .map_err(RepoError::storage)?;

        match cursor {
            None if !all_data_files.is_empty() => {
                tracing::warn!("no write cursor but data files exist, rebuilding index");
                Self::rebuild_index(io, data_dir, index)
            }
            None => Ok(()),
            Some(wc) => {
                tracing::info!(
                    cursor_file = %wc.file_id,
                    cursor_offset = wc.offset.raw(),
                    "starting recovery from write cursor"
                );
                Self::replay_single_file(io, data_dir, index, wc.file_id, wc.offset)?;

                let orphan_count = all_data_files
                    .iter()
                    .filter(|&&fid| fid > wc.file_id)
                    .count();
                if orphan_count > 0 {
                    tracing::info!(
                        orphan_files = orphan_count,
                        "scanning data files past cursor for un-indexed blocks"
                    );
                }

                all_data_files
                    .iter()
                    .copied()
                    .filter(|&fid| fid > wc.file_id)
                    .try_for_each(|fid| {
                        Self::replay_single_file(
                            io,
                            data_dir,
                            index,
                            fid,
                            BlockOffset::new(super::data_file::BLOCK_HEADER_SIZE as u64),
                        )
                    })
            }
        }
    }

    fn replay_single_file<S: StorageIO>(
        io: &S,
        data_dir: &Path,
        index: &KeyIndex,
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
        index: &KeyIndex,
        fd: crate::io::FileId,
        file_id: DataFileId,
        start_offset: BlockOffset,
    ) -> Result<(), RepoError> {
        let map_idx = |e: super::key_index::KeyIndexError| {
            RepoError::storage(io::Error::other(e.to_string()))
        };

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
            tracing::info!(
                file_id = %file_id,
                recovered = recovered_entries.len(),
                new_cursor_offset = last_valid_end.raw(),
                "replayed un-indexed blocks past write cursor"
            );
            index
                .batch_put(&recovered_entries, &[], new_cursor)
                .map_err(map_idx)?;
        }

        Ok(())
    }

    pub fn put_blocks_blocking(
        &self,
        blocks: Vec<([u8; CID_SIZE], Vec<u8>)>,
    ) -> Result<(), RepoError> {
        if blocks.is_empty() {
            return Ok(());
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.sender
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

    async fn send_put_blocks(
        &self,
        blocks: Vec<([u8; CID_SIZE], Vec<u8>)>,
    ) -> Result<Vec<BlockLocation>, RepoError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.sender
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
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.sender
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

#[cfg(test)]
mod tests {
    use super::super::manager::DEFAULT_MAX_FILE_SIZE;
    use super::*;

    fn test_config(dir: &Path) -> BlockStoreConfig {
        BlockStoreConfig {
            data_dir: dir.join("data"),
            index_dir: dir.join("index"),
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            group_commit: GroupCommitConfig::default(),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn put_and_get_round_trips() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(test_config(dir.path())).unwrap();

        let data = b"hello blockstore";
        let cid = store.put(data).await.unwrap();

        let retrieved = store.get(&cid).await.unwrap().unwrap();
        assert_eq!(&retrieved[..], data);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn get_missing_returns_none() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(test_config(dir.path())).unwrap();

        let fake_cid = hash_and_cid(b"nonexistent").unwrap();
        assert!(store.get(&fake_cid).await.unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn has_returns_correct_values() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(test_config(dir.path())).unwrap();

        let data = b"existence check";
        let cid = store.put(data).await.unwrap();

        assert!(store.has(&cid).await.unwrap());

        let fake_cid = hash_and_cid(b"does not exist").unwrap();
        assert!(!store.has(&fake_cid).await.unwrap());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn put_many_and_get_many() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(test_config(dir.path())).unwrap();

        let items: Vec<(Cid, Bytes)> = (0u8..10)
            .map(|i| {
                let data = vec![i; (i as usize + 1) * 32];
                let cid = hash_and_cid(&data).unwrap();
                (cid, Bytes::from(data))
            })
            .collect();

        let cids: Vec<Cid> = items.iter().map(|(c, _)| *c).collect();
        let expected: Vec<Bytes> = items.iter().map(|(_, d)| d.clone()).collect();

        store.put_many(items).await.unwrap();

        let results = store.get_many(&cids).await.unwrap();
        assert_eq!(results.len(), 10);
        results
            .iter()
            .zip(expected.iter())
            .for_each(|(result, exp)| {
                assert_eq!(result.as_ref().unwrap().as_ref(), exp.as_ref());
            });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn get_many_with_mixed_hits_and_misses() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(test_config(dir.path())).unwrap();

        let data_a = b"block a";
        let data_b = b"block b";
        let cid_a = store.put(data_a).await.unwrap();
        let cid_b = store.put(data_b).await.unwrap();
        let cid_missing = hash_and_cid(b"missing").unwrap();

        let results = store.get_many(&[cid_a, cid_missing, cid_b]).await.unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].as_ref().unwrap().as_ref(), data_a);
        assert!(results[1].is_none());
        assert_eq!(results[2].as_ref().unwrap().as_ref(), data_b);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn put_many_empty_is_noop() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(test_config(dir.path())).unwrap();
        store
            .put_many(std::iter::empty::<(Cid, Bytes)>())
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn apply_commit_with_blocks_and_deletes() {
        use jacquard_common::types::integer::LimitedU32;
        use jacquard_common::types::string::Tid;
        use std::collections::BTreeMap;

        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(test_config(dir.path())).unwrap();

        let data_keep = b"keep this block";
        let data_delete = b"delete this block";
        let cid_keep = store.put(data_keep).await.unwrap();
        let cid_delete = store.put(data_delete).await.unwrap();

        assert!(store.has(&cid_keep).await.unwrap());
        assert!(store.has(&cid_delete).await.unwrap());

        let new_data = b"new block from commit";
        let new_cid = hash_and_cid(new_data).unwrap();

        let mut blocks = BTreeMap::new();
        blocks.insert(new_cid, Bytes::from(new_data.as_slice()));

        let commit = CommitData {
            cid: new_cid,
            rev: Tid::now(LimitedU32::MIN),
            since: None,
            prev: None,
            data: new_cid,
            prev_data: None,
            blocks,
            relevant_blocks: BTreeMap::new(),
            deleted_cids: vec![cid_delete],
        };

        store.apply_commit(commit).await.unwrap();

        assert!(store.has(&cid_keep).await.unwrap());
        assert!(store.has(&new_cid).await.unwrap());
        let new_retrieved = store.get(&new_cid).await.unwrap().unwrap();
        assert_eq!(&new_retrieved[..], new_data);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn duplicate_put_returns_same_cid() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(test_config(dir.path())).unwrap();

        let data = b"identical content";
        let cid1 = store.put(data).await.unwrap();
        let cid2 = store.put(data).await.unwrap();

        assert_eq!(cid1, cid2);

        let retrieved = store.get(&cid1).await.unwrap().unwrap();
        assert_eq!(&retrieved[..], data);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn reopen_preserves_data() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = test_config(dir.path());

        let cid = {
            let store = TranquilBlockStore::open(config.clone()).unwrap();
            let data = b"persistent data";
            let cid = store.put(data).await.unwrap();
            assert!(store.has(&cid).await.unwrap());
            drop(store);
            cid
        };

        {
            let store = TranquilBlockStore::open(config).unwrap();
            let retrieved = store.get(&cid).await.unwrap().unwrap();
            assert_eq!(&retrieved[..], b"persistent data");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_puts_from_multiple_tasks() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TranquilBlockStore::open(test_config(dir.path())).unwrap();

        let handles: Vec<_> = (0u8..50)
            .map(|i| {
                let store = store.clone();
                tokio::spawn(async move {
                    let data = vec![i; (i as usize + 1) * 16];
                    let cid = store.put(&data).await.unwrap();
                    (cid, data)
                })
            })
            .collect();

        let results: Vec<(Cid, Vec<u8>)> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        let verify_handles: Vec<_> = results
            .into_iter()
            .map(|(cid, expected)| {
                let store = store.clone();
                tokio::spawn(async move {
                    let retrieved = store.get(&cid).await.unwrap().unwrap();
                    assert_eq!(&retrieved[..], &expected[..]);
                })
            })
            .collect();

        futures::future::join_all(verify_handles)
            .await
            .into_iter()
            .for_each(|r| r.unwrap());
    }

    mod sim {
        use super::*;
        use crate::SimulatedIO;
        use crate::blockstore::data_file::{BLOCK_RECORD_OVERHEAD, CID_SIZE, DataFileWriter};
        use crate::blockstore::hint::{HintFileWriter, hint_file_path};
        use crate::blockstore::key_index::KeyIndex;
        use crate::blockstore::manager::DataFileManager;
        use crate::blockstore::reader::BlockStoreReader;
        use crate::blockstore::types::{BlockOffset, DataFileId, WriteCursor};
        use futures::StreamExt;
        use std::path::Path;
        use std::sync::Arc;

        use crate::blockstore::test_cid_u16 as sim_test_cid;

        struct SimHarness {
            sim: Arc<SimulatedIO>,
            data_dir: &'static Path,
            index_dir: tempfile::TempDir,
        }

        impl SimHarness {
            fn new(seed: u64) -> Self {
                let sim = Arc::new(SimulatedIO::pristine(seed));
                let data_dir = Path::new("/data");
                sim.mkdir(data_dir).unwrap();
                sim.sync_dir(data_dir).unwrap();
                Self {
                    sim,
                    data_dir,
                    index_dir: tempfile::TempDir::new().unwrap(),
                }
            }

            fn fresh_index_dir(&mut self) {
                self.index_dir = tempfile::TempDir::new().unwrap();
            }

            fn open_index(&self) -> KeyIndex {
                KeyIndex::open(self.index_dir.path()).unwrap().into_inner()
            }

            fn ensure_data_file(&self, file_id: DataFileId) -> BlockOffset {
                let manager = DataFileManager::with_default_max_size(
                    Arc::clone(&self.sim),
                    self.data_dir.to_path_buf(),
                );
                let fd = manager.open_for_append(file_id).unwrap();
                let file_size = self.sim.file_size(fd).unwrap();
                match file_size {
                    0 => {
                        let w = DataFileWriter::new(&*self.sim, fd, file_id).unwrap();
                        w.sync().unwrap();
                        self.sim.sync_dir(self.data_dir).unwrap();
                        w.position()
                    }
                    n => BlockOffset::new(n),
                }
            }

            fn write_blocks(
                &self,
                file_id: DataFileId,
                start_pos: BlockOffset,
                seeds: std::ops::Range<u16>,
                data_size: usize,
                sync: bool,
            ) -> (BlockOffset, Vec<([u8; CID_SIZE], BlockLocation)>) {
                let path = self.data_dir.join(format!(
                    "{file_id}.{}",
                    crate::blockstore::manager::DATA_FILE_EXTENSION
                ));
                let fd = self
                    .sim
                    .open(&path, crate::io::OpenOptions::read_write())
                    .unwrap();
                let mut writer = DataFileWriter::resume(&*self.sim, fd, file_id, start_pos);

                let hint_path = hint_file_path(self.data_dir, file_id);
                let hint_fd = self
                    .sim
                    .open(&hint_path, crate::io::OpenOptions::read_write())
                    .unwrap();
                let hint_size = self.sim.file_size(hint_fd).unwrap();
                let mut hint_writer = HintFileWriter::resume(
                    &*self.sim,
                    hint_fd,
                    crate::blockstore::types::HintOffset::new(hint_size),
                );

                let entries: Vec<_> = seeds
                    .map(|seed| {
                        let cid = sim_test_cid(seed);
                        let data = vec![seed as u8; data_size];
                        let loc = writer.append_block(&cid, &data).unwrap();
                        hint_writer
                            .append_hint(&cid, loc.file_id, loc.offset, loc.length)
                            .unwrap();
                        (cid, loc)
                    })
                    .collect();

                if sync {
                    writer.sync().unwrap();
                    hint_writer.sync().unwrap();
                    self.sim.sync_dir(self.data_dir).unwrap();
                }

                let pos = writer.position();
                let _ = self.sim.close(hint_fd);
                let _ = self.sim.close(fd);
                (pos, entries)
            }

            fn index_entries(
                &self,
                index: &KeyIndex,
                entries: &[([u8; CID_SIZE], BlockLocation)],
                cursor: WriteCursor,
            ) {
                index.batch_put(entries, &[], cursor).unwrap();
                index.persist().unwrap();
            }

            fn make_reader(&self, index: Arc<KeyIndex>) -> BlockStoreReader<Arc<SimulatedIO>> {
                let manager = Arc::new(DataFileManager::with_default_max_size(
                    Arc::clone(&self.sim),
                    self.data_dir.to_path_buf(),
                ));
                BlockStoreReader::new(index, manager)
            }

            fn recover(&self, index: &KeyIndex) {
                TranquilBlockStore::recover_from_cursor(&*self.sim, self.data_dir, index).unwrap();
            }

            fn rebuild(&self, index: &KeyIndex) {
                TranquilBlockStore::rebuild_index(&*self.sim, self.data_dir, index).unwrap();
            }
        }

        #[test]
        fn sim_crash_and_recover_blocks() {
            (0u64..200).for_each(|seed| {
                let h = SimHarness::new(seed);
                let file_id = DataFileId::new(0);

                let total_blocks = ((seed % 47) + 10) as u16;
                let indexed_count = ((seed % total_blocks as u64) + 1) as u16;
                let unsynced_start = total_blocks;
                let unsynced_count = ((seed % 5) + 1) as u16;

                let start_pos = h.ensure_data_file(file_id);
                let (synced_end, entries) =
                    h.write_blocks(file_id, start_pos, 0..total_blocks, 64, true);

                let index = h.open_index();
                let indexed = &entries[..indexed_count as usize];
                let cursor_end = indexed
                    .last()
                    .map(|(_, loc)| {
                        loc.offset
                            .advance(BLOCK_RECORD_OVERHEAD as u64 + loc.length.as_u64())
                    })
                    .unwrap_or(start_pos);
                h.index_entries(
                    &index,
                    indexed,
                    WriteCursor {
                        file_id,
                        offset: cursor_end,
                    },
                );
                index.persist().unwrap();
                drop(index);

                let _ = h.write_blocks(
                    file_id,
                    synced_end,
                    unsynced_start..unsynced_start + unsynced_count,
                    64,
                    false,
                );

                h.sim.crash();

                let recovered_index = h.open_index();
                h.recover(&recovered_index);

                let idx = Arc::new(recovered_index);
                let reader = h.make_reader(Arc::clone(&idx));

                (0..total_blocks).for_each(|i| {
                    let cid = sim_test_cid(i);
                    let entry = idx.get(&cid).unwrap();
                    assert!(
                        entry.is_some(),
                        "seed={seed} synced block {i}/{total_blocks} missing, indexed={indexed_count}"
                    );
                    match reader.get(&cid) {
                        Ok(Some(actual)) => {
                            assert_eq!(
                                actual.len(),
                                64,
                                "seed={seed} block {i} wrong length"
                            );
                            assert_eq!(
                                actual[0],
                                i as u8,
                                "seed={seed} block {i} data mismatch"
                            );
                        }
                        other => panic!(
                            "seed={seed} block {i} expected readable, got {other:?}"
                        ),
                    }
                });

                (unsynced_start..unsynced_start + unsynced_count).for_each(|i| {
                    let cid = sim_test_cid(i);
                    assert!(
                        idx.get(&cid).unwrap().is_none(),
                        "seed={seed} unsynced block {i} should not appear in index"
                    );
                });
            });
        }

        #[test]
        fn sim_refcounts_and_deletes() {
            (0u64..100).for_each(|seed| {
                let h = SimHarness::new(seed);
                let file_id = DataFileId::new(0);
                let start_pos = h.ensure_data_file(file_id);

                let dup_count = (seed % 5) as u32 + 2;
                let data_size = ((seed % 7) as usize + 1) * 32;

                let dup_cid = sim_test_cid(0);
                let dup_data = vec![0u8; data_size];
                let unique_cid = sim_test_cid(1);
                let unique_data = vec![1u8; data_size];

                let path = h.data_dir.join(format!(
                    "{file_id}.{}",
                    crate::blockstore::manager::DATA_FILE_EXTENSION
                ));
                let fd = h
                    .sim
                    .open(&path, crate::io::OpenOptions::read_write())
                    .unwrap();
                let mut writer = DataFileWriter::resume(&*h.sim, fd, file_id, start_pos);

                let loc_dup = writer.append_block(&dup_cid, &dup_data).unwrap();
                let loc_unique = writer.append_block(&unique_cid, &unique_data).unwrap();
                writer.sync().unwrap();
                h.sim.sync_dir(h.data_dir).unwrap();
                let end_pos = writer.position();
                let _ = h.sim.close(fd);

                let index = h.open_index();

                let mut entries: Vec<_> = (0..dup_count).map(|_| (dup_cid, loc_dup)).collect();
                entries.push((unique_cid, loc_unique));
                h.index_entries(
                    &index,
                    &entries,
                    WriteCursor {
                        file_id,
                        offset: end_pos,
                    },
                );

                let dup_entry = index.get(&dup_cid).unwrap().unwrap();
                assert_eq!(
                    dup_entry.refcount.raw(),
                    dup_count,
                    "seed={seed} expected refcount {dup_count}"
                );
                let unique_entry = index.get(&unique_cid).unwrap().unwrap();
                assert_eq!(unique_entry.refcount.raw(), 1);

                let dec_count = (seed % dup_count as u64) as u32 + 1;
                let decrements: Vec<_> = (0..dec_count).map(|_| dup_cid).collect();
                index
                    .batch_put(
                        &[],
                        &decrements,
                        WriteCursor {
                            file_id,
                            offset: end_pos,
                        },
                    )
                    .unwrap();

                let dup_after = index.get(&dup_cid).unwrap().unwrap();
                assert_eq!(
                    dup_after.refcount.raw(),
                    dup_count - dec_count,
                    "seed={seed} refcount after {dec_count} decrements"
                );

                let idx = Arc::new(index);
                let reader = h.make_reader(Arc::clone(&idx));

                let dup_read = reader.get(&dup_cid).unwrap().unwrap();
                assert_eq!(&dup_read[..], &dup_data[..], "seed={seed}");
                let unique_read = reader.get(&unique_cid).unwrap().unwrap();
                assert_eq!(&unique_read[..], &unique_data[..], "seed={seed}");

                drop(reader);
                let index = Arc::into_inner(idx).unwrap();

                let remaining = dup_count - dec_count;
                let final_decrements: Vec<_> = (0..remaining).map(|_| dup_cid).collect();
                index
                    .batch_put(
                        &[],
                        &final_decrements,
                        WriteCursor {
                            file_id,
                            offset: end_pos,
                        },
                    )
                    .unwrap();

                let dup_zero = index.get(&dup_cid).unwrap().unwrap();
                assert!(
                    dup_zero.refcount.is_zero(),
                    "seed={seed} expected zero refcount"
                );

                let idx = Arc::new(index);
                let reader = h.make_reader(idx);
                let still_readable = reader.get(&dup_cid).unwrap();
                assert!(
                    still_readable.is_some(),
                    "seed={seed} zero-refcount block should still be readable, GC not implemented"
                );
            });
        }

        #[test]
        fn sim_repeated_crash_recover_cycles() {
            (0u64..150).for_each(|seed| {
                let mut h = SimHarness::new(seed);
                let file_id = DataFileId::new(0);
                let mut next_seed: u16 = 0;
                let mut all_committed: Vec<u16> = Vec::new();

                let cycles = (seed % 4) + 2;
                (0..cycles).for_each(|cycle| {
                    let start_pos = h.ensure_data_file(file_id);

                    let count = ((seed.wrapping_add(cycle)) % 15 + 3) as u16;
                    let range = next_seed..next_seed + count;
                    let (end_pos, entries) = h.write_blocks(file_id, start_pos, range, 48, true);
                    next_seed += count;

                    let index = h.open_index();
                    h.index_entries(
                        &index,
                        &entries,
                        WriteCursor {
                            file_id,
                            offset: end_pos,
                        },
                    );
                    drop(index);

                    all_committed.extend(
                        entries
                            .iter()
                            .map(|(cid, _)| u16::from_le_bytes([cid[4], cid[5]])),
                    );

                    let unsynced = ((seed.wrapping_add(cycle)) % 3 + 1) as u16;
                    let _ = h.write_blocks(
                        file_id,
                        end_pos,
                        next_seed + 1000..next_seed + 1000 + unsynced,
                        48,
                        false,
                    );

                    h.sim.crash();
                    h.fresh_index_dir();

                    let rebuilt = h.open_index();
                    h.rebuild(&rebuilt);

                    all_committed.iter().for_each(|&s| {
                        let cid = sim_test_cid(s);
                        assert!(
                            rebuilt.has(&cid).unwrap(),
                            "seed={seed} cycle={cycle} block {s} lost after rebuild"
                        );
                    });

                    let idx = Arc::new(rebuilt);
                    let reader = h.make_reader(Arc::clone(&idx));
                    all_committed.iter().for_each(|&s| {
                        let cid = sim_test_cid(s);
                        match reader.get(&cid) {
                            Ok(Some(data)) => {
                                assert_eq!(data.len(), 48);
                                assert_eq!(data[0], s as u8);
                            }
                            other => panic!("seed={seed} cycle={cycle} block {s}: {other:?}"),
                        }
                    });

                    drop(reader);
                    drop(idx);
                });
            });
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn corrupt_fjall_triggers_rebuild_from_hints() {
            let dir = tempfile::TempDir::new().unwrap();
            let config = test_config(dir.path());

            let cids: Vec<Cid> = {
                let store = TranquilBlockStore::open(config.clone()).unwrap();
                let cids = futures::stream::iter(0u8..20)
                    .fold(Vec::new(), |mut acc, i| {
                        let store = store.clone();
                        async move {
                            let data = vec![i; (i as usize + 1) * 16];
                            acc.push(store.put(&data).await.unwrap());
                            acc
                        }
                    })
                    .await;
                drop(store);
                cids
            };

            fn corrupt_dir_recursive(dir: &Path) {
                std::fs::read_dir(dir)
                    .unwrap()
                    .filter_map(|e| e.ok())
                    .for_each(|entry| {
                        let path = entry.path();
                        if path.is_file() {
                            std::fs::write(&path, b"corrupted").unwrap();
                        } else if path.is_dir() {
                            corrupt_dir_recursive(&path);
                        }
                    });
            }
            corrupt_dir_recursive(&config.index_dir);

            let store = TranquilBlockStore::open(config).unwrap();

            futures::stream::iter(cids.iter())
                .fold((), |(), cid| {
                    let store = store.clone();
                    let cid = *cid;
                    async move {
                        assert!(
                            store.has(&cid).await.unwrap(),
                            "block {cid} should be accessible after fjall rebuild"
                        );
                        assert!(
                            store.get(&cid).await.unwrap().is_some(),
                            "block {cid} should be readable after fjall rebuild"
                        );
                    }
                })
                .await;
        }
    }
}
