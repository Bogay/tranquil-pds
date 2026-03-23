use std::cell::Cell;
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::thread;

use crate::io::{FileId, OpenOptions, StorageIO};

use super::data_file::{CID_SIZE, DataFileWriter};
use super::hint::{HintFileWriter, hint_file_path};
use super::key_index::{KeyIndex, KeyIndexError};
use super::manager::DataFileManager;
use super::types::{BlockLocation, BlockOffset, DataFileId, HintOffset, WriteCursor};

#[derive(Debug, Clone)]
pub enum CommitError {
    Io(Arc<io::Error>),
    Index(Arc<KeyIndexError>),
    ChannelClosed,
}

impl std::fmt::Display for CommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {}", e.as_ref()),
            Self::Index(e) => write!(f, "index: {}", e.as_ref()),
            Self::ChannelClosed => write!(f, "commit channel closed"),
        }
    }
}

impl std::error::Error for CommitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e.as_ref()),
            Self::Index(e) => Some(e.as_ref()),
            Self::ChannelClosed => None,
        }
    }
}

impl From<io::Error> for CommitError {
    fn from(e: io::Error) -> Self {
        Self::Io(Arc::new(e))
    }
}

impl From<KeyIndexError> for CommitError {
    fn from(e: KeyIndexError) -> Self {
        Self::Index(Arc::new(e))
    }
}

type PutResponse = tokio::sync::oneshot::Sender<Result<Vec<BlockLocation>, CommitError>>;
type ApplyResponse = tokio::sync::oneshot::Sender<Result<(), CommitError>>;

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
    Shutdown,
}

#[derive(Debug, Clone)]
pub struct GroupCommitConfig {
    pub max_batch_size: usize,
    pub channel_capacity: usize,
}

impl Default for GroupCommitConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 1024,
            channel_capacity: 4096,
        }
    }
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

pub struct GroupCommitWriter {
    sender: flume::Sender<CommitRequest>,
    handle: Option<thread::JoinHandle<()>>,
}

impl GroupCommitWriter {
    pub fn spawn<S: StorageIO + 'static>(
        manager: DataFileManager<S>,
        index: Arc<KeyIndex>,
        config: GroupCommitConfig,
    ) -> Result<Self, CommitError> {
        let cursor = index.read_write_cursor().map_err(CommitError::from)?;
        let mut state = initialize_active_state(&manager, cursor)?;

        let (sender, receiver) = flume::bounded(config.channel_capacity);

        let handle = thread::Builder::new()
            .name("blockstore-group-commit".into())
            .spawn(move || {
                commit_loop(&manager, &*index, &receiver, &config, &mut state);
            })
            .map_err(|e| CommitError::from(io::Error::other(e)))?;

        Ok(Self {
            sender,
            handle: Some(handle),
        })
    }

    pub fn sender(&self) -> &flume::Sender<CommitRequest> {
        &self.sender
    }

    pub fn shutdown(mut self) {
        let _ = self.sender.send(CommitRequest::Shutdown);
        if let Some(handle) = self.handle.take()
            && let Err(payload) = handle.join()
        {
            log_thread_panic(payload, "group commit thread panicked");
        }
    }
}

impl Drop for GroupCommitWriter {
    fn drop(&mut self) {
        let _ = self.sender.try_send(CommitRequest::Shutdown);
        if let Some(handle) = self.handle.take()
            && let Err(payload) = handle.join()
        {
            log_thread_panic(payload, "group commit thread panicked during drop");
        }
    }
}

fn initialize_active_state<S: StorageIO>(
    manager: &DataFileManager<S>,
    cursor: Option<WriteCursor>,
) -> Result<ActiveState, CommitError> {
    let data_dir = manager.data_dir();
    let existing_files = manager.list_files()?;

    match cursor {
        Some(wc) => {
            let fd = manager.open_for_append(wc.file_id)?;
            let file_size = manager.io().file_size(fd)?;

            if file_size < wc.offset.raw() {
                return Err(CommitError::from(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "data file smaller than write cursor",
                )));
            }

            let hint_path = hint_file_path(data_dir, wc.file_id);
            let hint_fd = manager.io().open(&hint_path, OpenOptions::read_write())?;
            let hint_size = manager.io().file_size(hint_fd)?;

            Ok(ActiveState {
                file_id: wc.file_id,
                fd,
                position: BlockOffset::new(file_size),
                hint_fd,
                hint_position: HintOffset::new(hint_size),
            })
        }
        None => {
            let file_id = existing_files
                .last()
                .copied()
                .map(|id| id.next())
                .unwrap_or_else(|| DataFileId::new(0));

            let fd = manager.open_for_append(file_id)?;
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

fn classify_request(req: CommitRequest) -> Result<BatchEntry, ()> {
    match req {
        CommitRequest::PutBlocks { blocks, response } => Ok(BatchEntry::Put { blocks, response }),
        CommitRequest::ApplyCommit {
            blocks,
            deleted_cids,
            response,
        } => Ok(BatchEntry::Apply {
            blocks,
            deleted_cids,
            response,
        }),
        CommitRequest::Shutdown => Err(()),
    }
}

fn batch_entry_block_count(entry: &BatchEntry) -> usize {
    match entry {
        BatchEntry::Put { blocks, .. } | BatchEntry::Apply { blocks, .. } => blocks.len(),
    }
}

fn drain_batch(
    receiver: &flume::Receiver<CommitRequest>,
    first: CommitRequest,
    max_batch_size: usize,
) -> (Vec<BatchEntry>, bool) {
    let first_entry = match classify_request(first) {
        Err(()) => return (Vec::new(), true),
        Ok(entry) => entry,
    };

    let block_count = Cell::new(batch_entry_block_count(&first_entry));
    let mut entries = vec![first_entry];

    let saw_shutdown = std::iter::from_fn(|| receiver.try_recv().ok())
        .take_while(|_| block_count.get() < max_batch_size)
        .try_for_each(|req| match classify_request(req) {
            Err(()) => Err(()),
            Ok(entry) => {
                block_count.set(
                    block_count
                        .get()
                        .saturating_add(batch_entry_block_count(&entry)),
                );
                entries.push(entry);
                Ok(())
            }
        })
        .is_err();

    (entries, saw_shutdown)
}

fn commit_loop<S: StorageIO>(
    manager: &DataFileManager<S>,
    index: &KeyIndex,
    receiver: &flume::Receiver<CommitRequest>,
    config: &GroupCommitConfig,
    state: &mut ActiveState,
) {
    loop {
        let first = match receiver.recv() {
            Ok(CommitRequest::Shutdown) => return,
            Ok(msg) => msg,
            Err(_) => return,
        };

        let (batch, shutdown_after) = drain_batch(receiver, first, config.max_batch_size);

        tracing::debug!(
            batch_size = batch.len(),
            file_id = %state.file_id,
            "processing commit batch"
        );

        let result = process_batch(manager, index, &batch, state);

        if let Err(ref e) = result {
            tracing::warn!(error = %e, "commit batch failed");
        }

        dispatch_responses(batch, result);

        if shutdown_after {
            drain_and_process_remaining(manager, index, receiver, state);
            return;
        }
    }
}

fn drain_and_process_remaining<S: StorageIO>(
    manager: &DataFileManager<S>,
    index: &KeyIndex,
    receiver: &flume::Receiver<CommitRequest>,
    state: &mut ActiveState,
) {
    let entries: Vec<BatchEntry> = std::iter::from_fn(|| receiver.try_recv().ok())
        .filter_map(|req| classify_request(req).ok())
        .collect();

    if entries.is_empty() {
        return;
    }

    let result = process_batch(manager, index, &entries, state);
    dispatch_responses(entries, result);
}

struct RotationState {
    file_id: DataFileId,
    fd: FileId,
}

fn process_batch<S: StorageIO>(
    manager: &DataFileManager<S>,
    index: &KeyIndex,
    batch: &[BatchEntry],
    state: &mut ActiveState,
) -> Result<HashMap<[u8; CID_SIZE], BlockLocation>, CommitError> {
    let mut dedup: HashMap<[u8; CID_SIZE], BlockLocation> = HashMap::new();
    let mut index_entries: Vec<([u8; CID_SIZE], BlockLocation)> = Vec::new();
    let mut all_decrements: Vec<[u8; CID_SIZE]> = Vec::new();

    let mut current_hint_fd = state.hint_fd;
    let mut rotation: Option<RotationState> = None;

    let mut data_writer =
        DataFileWriter::resume(manager.io(), state.fd, state.file_id, state.position);
    let mut hint_writer =
        HintFileWriter::resume(manager.io(), current_hint_fd, state.hint_position);

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
                Some(&loc) => loc,
                None => {
                    if manager.should_rotate(data_writer.position()) {
                        data_writer.sync()?;
                        hint_writer.sync()?;

                        let (next_id, next_fd) = manager.prepare_rotation(data_writer.file_id())?;

                        tracing::info!(
                            from = %data_writer.file_id(),
                            to = %next_id,
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
                        rotation = Some(RotationState {
                            file_id: next_id,
                            fd: next_fd,
                        });
                    }

                    let loc = data_writer.append_block(cid_bytes, data)?;
                    hint_writer.append_hint(cid_bytes, loc.file_id, loc.offset, loc.length)?;

                    dedup.insert(*cid_bytes, loc);
                    loc
                }
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
        if let Some(rot) = rotation {
            manager.rollback_rotation(rot.file_id, rot.fd);
        }
        return Err(e);
    }

    data_writer.sync()?;
    hint_writer.sync()?;

    if let Some(ref rot) = rotation {
        manager.commit_rotation(rot.file_id, rot.fd);
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
    index
        .batch_put(&index_entries, &all_decrements, cursor)
        .map_err(CommitError::from)?;

    Ok(dedup)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RealIO;
    use crate::blockstore::data_file::DataFileReader;
    use crate::blockstore::manager::DATA_FILE_EXTENSION;
    use crate::blockstore::test_cid;
    use futures::StreamExt;

    fn setup_real(dir: &std::path::Path) -> (DataFileManager<RealIO>, Arc<KeyIndex>) {
        let data_dir = dir.join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let index_dir = dir.join("index");
        let manager = DataFileManager::with_default_max_size(RealIO::new(), data_dir);
        let index = Arc::new(KeyIndex::open(&index_dir).unwrap().into_inner());
        (manager, index)
    }

    async fn put_blocks(
        sender: &flume::Sender<CommitRequest>,
        blocks: Vec<([u8; CID_SIZE], Vec<u8>)>,
    ) -> Result<Vec<BlockLocation>, CommitError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        sender
            .send_async(CommitRequest::PutBlocks {
                blocks,
                response: tx,
            })
            .await
            .map_err(|_| CommitError::ChannelClosed)?;
        rx.await.map_err(|_| CommitError::ChannelClosed)?
    }

    async fn apply_commit_req(
        sender: &flume::Sender<CommitRequest>,
        blocks: Vec<([u8; CID_SIZE], Vec<u8>)>,
        deleted_cids: Vec<[u8; CID_SIZE]>,
    ) -> Result<(), CommitError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        sender
            .send_async(CommitRequest::ApplyCommit {
                blocks,
                deleted_cids,
                response: tx,
            })
            .await
            .map_err(|_| CommitError::ChannelClosed)?;
        rx.await.map_err(|_| CommitError::ChannelClosed)?
    }

    fn count_data_file_blocks(data_dir: &std::path::Path) -> usize {
        let io = RealIO::new();
        let data_files =
            super::super::list_files_by_extension(&io, data_dir, DATA_FILE_EXTENSION).unwrap();
        data_files
            .iter()
            .map(|&fid| {
                let path = data_dir.join(format!("{fid}.tqb"));
                let fd = io.open(&path, OpenOptions::read_only_existing()).unwrap();
                let count = DataFileReader::open(&io, fd)
                    .unwrap()
                    .valid_blocks()
                    .unwrap()
                    .len();
                let _ = io.close(fd);
                count
            })
            .sum()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_100_writes_from_10_tasks() {
        let dir = tempfile::TempDir::new().unwrap();
        let (manager, index) = setup_real(dir.path());
        let data_dir = manager.data_dir().to_path_buf();
        let writer =
            GroupCommitWriter::spawn(manager, index, GroupCommitConfig::default()).unwrap();
        let sender = writer.sender().clone();

        let handles: Vec<_> = (0u8..10)
            .map(|task_id| {
                let sender = sender.clone();
                tokio::spawn(async move {
                    let blocks: Vec<_> = (0u8..10)
                        .map(|block_id| {
                            let idx = task_id * 10 + block_id;
                            (test_cid(idx), vec![idx; (idx as usize + 1) * 8])
                        })
                        .collect();

                    futures::stream::iter(blocks)
                        .fold(
                            Vec::<BlockLocation>::new(),
                            |mut acc, (cid, data): ([u8; CID_SIZE], Vec<u8>)| {
                                let sender = sender.clone();
                                async move {
                                    let locs =
                                        put_blocks(&sender, vec![(cid, data)]).await.unwrap();
                                    acc.extend(locs);
                                    acc
                                }
                            },
                        )
                        .await
                })
            })
            .collect();

        let all_locations: Vec<Vec<BlockLocation>> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        let total: usize = all_locations.iter().map(|v| v.len()).sum();
        assert_eq!(total, 100);

        writer.shutdown();

        let index_dir = dir.path().join("index");
        let index = KeyIndex::open(&index_dir).unwrap().into_inner();
        (0u8..100).for_each(|i| {
            assert!(
                index.has(&test_cid(i)).unwrap(),
                "block {i} missing from index"
            );
        });

        assert_eq!(count_data_file_blocks(&data_dir), 100);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn duplicate_cids_in_same_batch_write_once() {
        let dir = tempfile::TempDir::new().unwrap();
        let (manager, index) = setup_real(dir.path());
        let data_dir = manager.data_dir().to_path_buf();
        let writer =
            GroupCommitWriter::spawn(manager, index, GroupCommitConfig::default()).unwrap();
        let sender = writer.sender().clone();

        let cid = test_cid(42);
        let data = vec![0xAB; 128];
        let blocks = vec![
            (cid, data.clone()),
            (cid, data.clone()),
            (cid, data.clone()),
        ];

        let locations = put_blocks(&sender, blocks).await.unwrap();

        assert_eq!(locations.len(), 3);
        assert_eq!(locations[0], locations[1]);
        assert_eq!(locations[1], locations[2]);

        writer.shutdown();

        let index_dir = dir.path().join("index");
        let index = KeyIndex::open(&index_dir).unwrap().into_inner();
        let entry = index.get(&cid).unwrap().unwrap();
        assert_eq!(entry.refcount.raw(), 3);

        assert_eq!(
            count_data_file_blocks(&data_dir),
            1,
            "duplicate CID should only be written once to data file"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn apply_commit_with_blocks_and_deletes() {
        let dir = tempfile::TempDir::new().unwrap();
        let (manager, index) = setup_real(dir.path());
        let writer =
            GroupCommitWriter::spawn(manager, index, GroupCommitConfig::default()).unwrap();
        let sender = writer.sender().clone();

        let cid_a = test_cid(1);
        let cid_b = test_cid(2);
        put_blocks(
            &sender,
            vec![(cid_a, vec![0x01; 64]), (cid_b, vec![0x02; 64])],
        )
        .await
        .unwrap();

        let cid_c = test_cid(3);
        apply_commit_req(&sender, vec![(cid_c, vec![0x03; 64])], vec![cid_a])
            .await
            .unwrap();

        writer.shutdown();

        let index_dir = dir.path().join("index");
        let index = KeyIndex::open(&index_dir).unwrap().into_inner();
        assert_eq!(index.get(&cid_a).unwrap().unwrap().refcount.raw(), 0);
        assert_eq!(index.get(&cid_b).unwrap().unwrap().refcount.raw(), 1);
        assert_eq!(index.get(&cid_c).unwrap().unwrap().refcount.raw(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn graceful_shutdown_processes_remaining() {
        let dir = tempfile::TempDir::new().unwrap();
        let (manager, index) = setup_real(dir.path());
        let writer =
            GroupCommitWriter::spawn(manager, index, GroupCommitConfig::default()).unwrap();
        let sender = writer.sender().clone();

        let cid = test_cid(99);
        let locations = put_blocks(&sender, vec![(cid, vec![0xFF; 32])])
            .await
            .unwrap();
        assert_eq!(locations.len(), 1);

        writer.shutdown();

        let index_dir = dir.path().join("index");
        let index = KeyIndex::open(&index_dir).unwrap().into_inner();
        assert!(index.has(&cid).unwrap());
    }

    #[test]
    fn sim_crash_between_write_and_fsync_loses_unsynced() {
        use crate::SimulatedIO;
        use std::path::Path;
        use std::sync::Arc;

        let sim = Arc::new(SimulatedIO::pristine(42));
        let data_dir = Path::new("/data");
        sim.mkdir(data_dir).unwrap();
        sim.sync_dir(data_dir).unwrap();

        let manager =
            DataFileManager::with_default_max_size(Arc::clone(&sim), data_dir.to_path_buf());
        let fd = manager.open_for_append(DataFileId::new(0)).unwrap();
        let mut writer = DataFileWriter::new(&*sim, fd, DataFileId::new(0)).unwrap();

        let synced_cids: Vec<_> = (0u8..5)
            .map(|i| {
                let cid = test_cid(i);
                let _ = writer.append_block(&cid, &vec![i; 64]).unwrap();
                cid
            })
            .collect();
        writer.sync().unwrap();
        sim.sync_dir(data_dir).unwrap();

        (5u8..10).for_each(|i| {
            let cid = test_cid(i);
            let _ = writer.append_block(&cid, &vec![i; 64]).unwrap();
        });

        sim.crash();

        let fd_after = sim
            .open(Path::new("/data/000000.tqb"), OpenOptions::read())
            .unwrap();
        let recovered = DataFileReader::open(&*sim, fd_after)
            .unwrap()
            .valid_blocks()
            .unwrap();

        assert!(
            recovered.len() <= 5,
            "expected at most 5 synced blocks, got {}",
            recovered.len()
        );

        recovered.iter().enumerate().for_each(|(i, (_, cid, _))| {
            assert_eq!(*cid, synced_cids[i], "recovered block {i} CID mismatch");
        });
    }

    #[test]
    fn sim_crash_between_fsync_and_index_update_recovers_via_hints() {
        use crate::SimulatedIO;
        use crate::blockstore::data_file::{BLOCK_HEADER_SIZE, BLOCK_RECORD_OVERHEAD};
        use crate::blockstore::hint::rebuild_index_from_hints;
        use crate::blockstore::types::BlockLength;
        use std::path::Path;
        use std::sync::Arc;

        let sim = Arc::new(SimulatedIO::pristine(42));
        let data_dir = Path::new("/data");
        sim.mkdir(data_dir).unwrap();
        sim.sync_dir(data_dir).unwrap();

        let manager =
            DataFileManager::with_default_max_size(Arc::clone(&sim), data_dir.to_path_buf());
        let fd = manager.open_for_append(DataFileId::new(0)).unwrap();
        let mut writer = DataFileWriter::new(&*sim, fd, DataFileId::new(0)).unwrap();

        let phase1_cids: Vec<_> = (0u8..3)
            .map(|i| {
                let cid = test_cid(i);
                let _ = writer.append_block(&cid, &vec![i; 64]).unwrap();
                cid
            })
            .collect();
        writer.sync().unwrap();
        let phase1_end = writer.position();

        let real_dir = tempfile::TempDir::new().unwrap();
        let index_path = real_dir.path().join("index");
        let index = KeyIndex::open(&index_path).unwrap().into_inner();

        let entries: Vec<_> = phase1_cids
            .iter()
            .enumerate()
            .map(|(i, cid)| {
                let offset = BlockOffset::new(
                    BLOCK_HEADER_SIZE as u64 + i as u64 * (BLOCK_RECORD_OVERHEAD as u64 + 64),
                );
                (
                    *cid,
                    BlockLocation {
                        file_id: DataFileId::new(0),
                        offset,
                        length: BlockLength::new(64),
                    },
                )
            })
            .collect();
        index
            .batch_put(
                &entries,
                &[],
                WriteCursor {
                    file_id: DataFileId::new(0),
                    offset: phase1_end,
                },
            )
            .unwrap();
        index.persist().unwrap();

        let phase2_cids: Vec<_> = (10u8..15)
            .map(|i| {
                let cid = test_cid(i);
                let _ = writer.append_block(&cid, &vec![i; 128]).unwrap();
                cid
            })
            .collect();
        writer.sync().unwrap();
        sim.sync_dir(data_dir).unwrap();

        let hint_path = hint_file_path(data_dir, DataFileId::new(0));
        let hint_fd = sim.open(&hint_path, OpenOptions::read_write()).unwrap();
        let mut hint_writer = HintFileWriter::new(&*sim, hint_fd);

        let mut offset_tracker = BlockOffset::new(BLOCK_HEADER_SIZE as u64);
        phase1_cids.iter().for_each(|cid| {
            hint_writer
                .append_hint(
                    cid,
                    DataFileId::new(0),
                    offset_tracker,
                    BlockLength::new(64),
                )
                .unwrap();
            offset_tracker = offset_tracker.advance(BLOCK_RECORD_OVERHEAD as u64 + 64);
        });
        phase2_cids.iter().for_each(|cid| {
            hint_writer
                .append_hint(
                    cid,
                    DataFileId::new(0),
                    offset_tracker,
                    BlockLength::new(128),
                )
                .unwrap();
            offset_tracker = offset_tracker.advance(BLOCK_RECORD_OVERHEAD as u64 + 128);
        });
        hint_writer.sync().unwrap();
        sim.sync_dir(data_dir).unwrap();

        sim.crash();

        drop(index);
        let rebuilt_index_path = real_dir.path().join("rebuilt_index");
        let rebuilt_index = KeyIndex::open(&rebuilt_index_path).unwrap().into_inner();
        rebuild_index_from_hints(&*sim, data_dir, &rebuilt_index).unwrap();

        phase1_cids.iter().for_each(|cid| {
            assert!(
                rebuilt_index.has(cid).unwrap(),
                "phase1 CID should be in rebuilt index"
            );
        });
        phase2_cids.iter().for_each(|cid| {
            assert!(
                rebuilt_index.has(cid).unwrap(),
                "phase2 CID should be in rebuilt index, was synced and hinted before crash"
            );
        });

        let cursor = rebuilt_index.read_write_cursor().unwrap().unwrap();
        assert!(
            cursor.offset.raw() > phase1_end.raw(),
            "cursor should be past phase1 after rebuild"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rotation_during_batch() {
        let dir = tempfile::TempDir::new().unwrap();
        let data_dir = dir.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let index_dir = dir.path().join("index");

        let small_max = 512u64;
        let manager = DataFileManager::new(RealIO::new(), data_dir.clone(), small_max);
        let index = Arc::new(KeyIndex::open(&index_dir).unwrap().into_inner());
        let writer =
            GroupCommitWriter::spawn(manager, index, GroupCommitConfig::default()).unwrap();
        let sender = writer.sender().clone();

        let all_cids: Vec<_> = (0u8..20).map(test_cid).collect();

        let handles: Vec<_> = all_cids
            .iter()
            .map(|&cid| {
                let sender = sender.clone();
                tokio::spawn(async move {
                    put_blocks(&sender, vec![(cid, vec![cid[4]; 100])])
                        .await
                        .unwrap()
                })
            })
            .collect();

        let results: Vec<_> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        assert_eq!(results.len(), 20);

        writer.shutdown();

        let io = RealIO::new();
        let data_files =
            super::super::list_files_by_extension(&io, &data_dir, DATA_FILE_EXTENSION).unwrap();
        assert!(
            data_files.len() > 1,
            "expected rotation to create multiple files, got {}",
            data_files.len()
        );

        let index = KeyIndex::open(&index_dir).unwrap().into_inner();
        all_cids.iter().for_each(|cid| {
            assert!(index.has(cid).unwrap());
        });
    }
}
