use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use bytes::Bytes;

use crate::io::{FileId, StorageIO};

use super::data_file::{CID_SIZE, ReadBlockRecord, decode_block_record};
use super::key_index::{KeyIndex, KeyIndexError};
use super::manager::DataFileManager;
use super::types::{BlockLocation, BlockOffset, DataFileId};

#[derive(Debug, Clone)]
pub enum ReadError {
    Io(Arc<io::Error>),
    Index(Arc<KeyIndexError>),
    Corrupted {
        file_id: DataFileId,
        offset: BlockOffset,
    },
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Index(e) => write!(f, "index: {e}"),
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
            Self::Index(e) => Some(e.as_ref()),
            Self::Corrupted { .. } => None,
        }
    }
}

impl From<io::Error> for ReadError {
    fn from(e: io::Error) -> Self {
        Self::Io(Arc::new(e))
    }
}

impl From<KeyIndexError> for ReadError {
    fn from(e: KeyIndexError) -> Self {
        Self::Index(Arc::new(e))
    }
}

pub struct BlockStoreReader<S: StorageIO> {
    index: Arc<KeyIndex>,
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
    pub fn new(index: Arc<KeyIndex>, manager: Arc<DataFileManager<S>>) -> Self {
        Self { index, manager }
    }

    pub fn get(&self, cid: &[u8; CID_SIZE]) -> Result<Option<Bytes>, ReadError> {
        let entry = match self.index.get(cid)? {
            Some(e) => e,
            None => return Ok(None),
        };
        self.read_block_at(entry.location).map(Some)
    }

    pub fn has(&self, cid: &[u8; CID_SIZE]) -> Result<bool, ReadError> {
        self.index.has(cid).map_err(ReadError::from)
    }

    pub fn get_many(&self, cids: &[[u8; CID_SIZE]]) -> Result<Vec<Option<Bytes>>, ReadError> {
        let mut results: Vec<Option<Bytes>> = vec![None; cids.len()];

        let lookups: Vec<(usize, BlockLocation)> = cids
            .iter()
            .enumerate()
            .filter_map(|(i, cid)| match self.index.get(cid) {
                Ok(Some(entry)) => Some(Ok((i, entry.location))),
                Ok(None) => None,
                Err(e) => Some(Err(ReadError::from(e))),
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut by_file: HashMap<DataFileId, Vec<(usize, BlockLocation)>> = HashMap::new();
        lookups.into_iter().for_each(|(idx, loc)| {
            by_file.entry(loc.file_id).or_default().push((idx, loc));
        });

        by_file.into_iter().try_for_each(|(file_id, mut entries)| {
            let fd = self.manager.open_for_read(file_id)?;
            let file_size = self.manager.io().file_size(fd)?;

            entries.sort_by_key(|(_, loc)| loc.offset);

            entries.into_iter().try_for_each(|(orig_idx, loc)| {
                let data = self.decode_and_validate(fd, file_size, loc)?;
                results[orig_idx] = Some(data);
                Ok::<_, ReadError>(())
            })
        })?;

        Ok(results)
    }

    fn read_block_at(&self, location: BlockLocation) -> Result<Bytes, ReadError> {
        let fd = self.manager.open_for_read(location.file_id)?;
        let file_size = self.manager.io().file_size(fd)?;
        self.decode_and_validate(fd, file_size, location)
    }

    fn decode_and_validate(
        &self,
        fd: FileId,
        file_size: u64,
        location: BlockLocation,
    ) -> Result<Bytes, ReadError> {
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
            Some(ReadBlockRecord::Corrupted { offset } | ReadBlockRecord::Truncated { offset }) => {
                Err(ReadError::Corrupted {
                    file_id: location.file_id,
                    offset,
                })
            }
            None => Err(ReadError::Corrupted {
                file_id: location.file_id,
                offset: location.offset,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RealIO;
    use crate::blockstore::data_file::CID_SIZE;
    use crate::blockstore::group_commit::{CommitRequest, GroupCommitConfig, GroupCommitWriter};
    use crate::blockstore::key_index::KeyIndex;
    use crate::blockstore::manager::DataFileManager;
    use crate::blockstore::test_cid;
    use futures::StreamExt;

    struct TestHarness {
        _dir: tempfile::TempDir,
        index: Arc<KeyIndex>,
        manager: Arc<DataFileManager<RealIO>>,
        writer: Option<GroupCommitWriter>,
        sender: flume::Sender<CommitRequest>,
    }

    impl TestHarness {
        fn new() -> Self {
            let dir = tempfile::TempDir::new().unwrap();
            let data_dir = dir.path().join("data");
            std::fs::create_dir_all(&data_dir).unwrap();
            let index_dir = dir.path().join("index");
            let manager = Arc::new(DataFileManager::with_default_max_size(
                RealIO::new(),
                data_dir,
            ));
            let index = Arc::new(KeyIndex::open(&index_dir).unwrap().into_inner());
            let writer = GroupCommitWriter::spawn(
                DataFileManager::with_default_max_size(RealIO::new(), dir.path().join("data")),
                Arc::clone(&index),
                GroupCommitConfig::default(),
            )
            .unwrap();
            let sender = writer.sender().clone();

            Self {
                _dir: dir,
                index,
                manager,
                writer: Some(writer),
                sender,
            }
        }

        fn reader(&self) -> BlockStoreReader<RealIO> {
            BlockStoreReader::new(Arc::clone(&self.index), Arc::clone(&self.manager))
        }

        async fn put_blocks(
            &self,
            blocks: Vec<([u8; CID_SIZE], Vec<u8>)>,
        ) -> Result<Vec<super::super::types::BlockLocation>, super::super::group_commit::CommitError>
        {
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.sender
                .send_async(CommitRequest::PutBlocks {
                    blocks,
                    response: tx,
                })
                .await
                .map_err(|_| super::super::group_commit::CommitError::ChannelClosed)?;
            rx.await
                .map_err(|_| super::super::group_commit::CommitError::ChannelClosed)?
        }

        fn shutdown(&mut self) {
            if let Some(w) = self.writer.take() {
                w.shutdown();
            }
        }
    }

    impl Drop for TestHarness {
        fn drop(&mut self) {
            self.shutdown();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_existing_block() {
        let mut harness = TestHarness::new();
        let cid = test_cid(1);
        let data = vec![0xAB; 256];
        harness.put_blocks(vec![(cid, data.clone())]).await.unwrap();
        harness.shutdown();

        let reader = harness.reader();
        let result = reader.get(&cid).unwrap().unwrap();
        assert_eq!(&result[..], &data[..]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_missing_block_returns_none() {
        let mut harness = TestHarness::new();
        harness.shutdown();

        let reader = harness.reader();
        assert!(reader.get(&test_cid(99)).unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_many_mixed_hits_and_misses() {
        let mut harness = TestHarness::new();
        let blocks: Vec<_> = (0u8..5)
            .map(|i| (test_cid(i), vec![i; (i as usize + 1) * 32]))
            .collect();
        harness.put_blocks(blocks.clone()).await.unwrap();
        harness.shutdown();

        let reader = harness.reader();
        let query: Vec<[u8; CID_SIZE]> = vec![
            test_cid(0),
            test_cid(99),
            test_cid(2),
            test_cid(100),
            test_cid(4),
        ];
        let results = reader.get_many(&query).unwrap();

        assert_eq!(results.len(), 5);
        assert_eq!(&results[0].as_ref().unwrap()[..], &blocks[0].1[..]);
        assert!(results[1].is_none());
        assert_eq!(&results[2].as_ref().unwrap()[..], &blocks[2].1[..]);
        assert!(results[3].is_none());
        assert_eq!(&results[4].as_ref().unwrap()[..], &blocks[4].1[..]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn has_returns_true_for_existing() {
        let mut harness = TestHarness::new();
        let cid = test_cid(1);
        harness
            .put_blocks(vec![(cid, vec![0xFF; 64])])
            .await
            .unwrap();
        harness.shutdown();

        let reader = harness.reader();
        assert!(reader.has(&cid).unwrap());
        assert!(!reader.has(&test_cid(99)).unwrap());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn checksum_mismatch_returns_error() {
        let mut harness = TestHarness::new();
        let cid = test_cid(1);
        let data = vec![0xAA; 256];
        harness.put_blocks(vec![(cid, data)]).await.unwrap();
        harness.shutdown();

        let entry = harness.index.get(&cid).unwrap().unwrap();
        let loc = entry.location;
        let data_file_path = harness.manager.data_file_path(loc.file_id);

        let corrupt_offset = loc.offset.raw() + super::super::data_file::CID_SIZE as u64 + 4 + 128;
        let file_bytes = std::fs::read(&data_file_path).unwrap();
        let mut corrupted = file_bytes;
        corrupted[corrupt_offset as usize] ^= 0xFF;
        std::fs::write(&data_file_path, &corrupted).unwrap();

        let fresh_manager = Arc::new(DataFileManager::with_default_max_size(
            RealIO::new(),
            harness.manager.data_dir().to_path_buf(),
        ));
        let reader = BlockStoreReader::new(Arc::clone(&harness.index), fresh_manager);
        let result = reader.get(&cid);
        assert!(
            matches!(result, Err(ReadError::Corrupted { .. })),
            "expected Corrupted error, got {result:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn spawn_blocking_does_not_block_tokio_workers() {
        let mut harness = TestHarness::new();
        let blocks: Vec<_> = (0u8..200).map(|i| (test_cid(i), vec![i; 1024])).collect();
        harness.put_blocks(blocks).await.unwrap();
        harness.shutdown();

        let reader = harness.reader();
        let reader = Arc::new(reader);

        let timer_handle = tokio::spawn(futures::stream::iter(0..100).fold(
            std::time::Duration::ZERO,
            |max_drift, _| async move {
                let start = std::time::Instant::now();
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                let drift = start
                    .elapsed()
                    .saturating_sub(std::time::Duration::from_millis(1));
                max_drift.max(drift)
            },
        ));

        let read_handles: Vec<_> = (0..8)
            .map(|_| {
                let reader = Arc::clone(&reader);
                tokio::spawn(futures::stream::iter(0u8..200).fold(
                    (0u64, 200u64),
                    move |(total_us, count), i| {
                        let reader = Arc::clone(&reader);
                        async move {
                            let cid = test_cid(i);
                            let start = std::time::Instant::now();
                            let result = tokio::task::spawn_blocking(move || reader.get(&cid))
                                .await
                                .unwrap();
                            let elapsed_us = start.elapsed().as_micros() as u64;
                            assert!(result.unwrap().is_some());
                            (total_us.saturating_add(elapsed_us), count)
                        }
                    },
                ))
            })
            .collect();

        let timer_drift = timer_handle.await.unwrap();
        assert!(
            timer_drift < std::time::Duration::from_millis(5),
            "timer drift {timer_drift:?} exceeds 5ms, reads may be blocking tokio workers"
        );

        let stats: Vec<(u64, u64)> = futures::future::join_all(read_handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();
        let total_us: u64 = stats.iter().map(|(us, _)| us).sum();
        let total_count: u64 = stats.iter().map(|(_, c)| c).sum();
        let avg_us = total_us / total_count.max(1);
        eprintln!("avg read latency: {avg_us}us across {total_count} reads");
    }

    use crate::blockstore::test_cid_u16 as stress_cid;

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn stress_50_writers_20_readers() {
        let dir = tempfile::TempDir::new().unwrap();
        let data_dir = dir.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let index_dir = dir.path().join("index");
        let index = Arc::new(KeyIndex::open(&index_dir).unwrap().into_inner());
        let manager_for_writer =
            DataFileManager::with_default_max_size(RealIO::new(), data_dir.clone());
        let writer = GroupCommitWriter::spawn(
            manager_for_writer,
            Arc::clone(&index),
            GroupCommitConfig::default(),
        )
        .unwrap();
        let sender = writer.sender().clone();
        let manager_for_reader = Arc::new(DataFileManager::with_default_max_size(
            RealIO::new(),
            data_dir,
        ));
        let reader = BlockStoreReader::new(Arc::clone(&index), manager_for_reader);

        let committed = Arc::new(std::sync::Mutex::new(Vec::<(u16, Vec<u8>)>::new()));
        let writer_done = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let writer_handles: Vec<_> = (0u16..50)
            .map(|writer_id| {
                let sender = sender.clone();
                let committed = Arc::clone(&committed);
                tokio::spawn(async move {
                    futures::stream::iter(0u16..200)
                        .fold((), |(), block_id| {
                            let sender = sender.clone();
                            let committed = Arc::clone(&committed);
                            async move {
                                let seed = writer_id * 200 + block_id;
                                let cid = stress_cid(seed);
                                let size = ((seed as usize % 256) + 1) * 4;
                                let data = vec![seed as u8; size];
                                let (tx, rx) = tokio::sync::oneshot::channel();
                                sender
                                    .send_async(CommitRequest::PutBlocks {
                                        blocks: vec![(cid, data.clone())],
                                        response: tx,
                                    })
                                    .await
                                    .unwrap();
                                rx.await.unwrap().unwrap();
                                committed.lock().unwrap().push((seed, data));
                            }
                        })
                        .await;
                })
            })
            .collect();

        let reader_handles: Vec<_> = (0..20)
            .map(|_| {
                let reader = reader.clone();
                let committed = Arc::clone(&committed);
                let done = Arc::clone(&writer_done);
                tokio::spawn(async move {
                    let reads = std::sync::atomic::AtomicU64::new(0);
                    (0..5000)
                        .take_while(|_| {
                            let is_done = done.load(std::sync::atomic::Ordering::Relaxed);
                            let has_reads = reads.load(std::sync::atomic::Ordering::Relaxed) > 100;
                            !(is_done && has_reads)
                        })
                        .for_each(|_| {
                            let snapshot = committed.lock().unwrap().clone();
                            if let Some((seed, expected)) = snapshot.last() {
                                let cid = stress_cid(*seed);
                                match reader.get(&cid) {
                                    Ok(Some(actual)) => {
                                        assert_eq!(&actual[..], &expected[..]);
                                        reads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    }
                                    Ok(None) => {}
                                    Err(e) => panic!("read error: {e}"),
                                }
                            }
                            std::thread::yield_now();
                        });
                    reads.load(std::sync::atomic::Ordering::Relaxed)
                })
            })
            .collect();

        futures::future::join_all(writer_handles)
            .await
            .into_iter()
            .for_each(|r| r.unwrap());
        writer_done.store(true, std::sync::atomic::Ordering::Relaxed);

        let read_counts: Vec<u64> = futures::future::join_all(reader_handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        let total_reads: u64 = read_counts.iter().sum();
        eprintln!("total reader reads: {total_reads}");
        assert!(total_reads > 0);

        writer.shutdown();

        let final_committed = committed.lock().unwrap();
        assert_eq!(final_committed.len(), 10_000);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_read_write() {
        let mut harness = TestHarness::new();
        let sender = harness.sender.clone();
        let reader = harness.reader();

        let written_cids = Arc::new(std::sync::Mutex::new(Vec::<(u8, Vec<u8>)>::new()));
        let writer_done = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let writer_handle = {
            let written = Arc::clone(&written_cids);
            tokio::spawn(async move {
                futures::stream::iter(0u8..50)
                    .fold((), |(), i| {
                        let sender = sender.clone();
                        let written = Arc::clone(&written);
                        async move {
                            let cid = test_cid(i);
                            let data = vec![i; (i as usize + 1) * 16];
                            let (tx, rx) = tokio::sync::oneshot::channel();
                            sender
                                .send_async(CommitRequest::PutBlocks {
                                    blocks: vec![(cid, data.clone())],
                                    response: tx,
                                })
                                .await
                                .unwrap();
                            rx.await.unwrap().unwrap();
                            written.lock().unwrap().push((i, data));
                        }
                    })
                    .await;
            })
        };

        let reader_handles: Vec<_> = (0..4)
            .map(|_| {
                let reader = reader.clone();
                let written = Arc::clone(&written_cids);
                let done = Arc::clone(&writer_done);
                tokio::spawn(async move {
                    let reads = std::sync::atomic::AtomicU64::new(0);

                    (0..2000)
                        .take_while(|_| {
                            let is_done = done.load(std::sync::atomic::Ordering::Relaxed);
                            let has_reads = reads.load(std::sync::atomic::Ordering::Relaxed) > 0;
                            !(is_done && has_reads)
                        })
                        .for_each(|_| {
                            let snapshot = written.lock().unwrap().clone();
                            snapshot.iter().for_each(|(seed, expected_data)| {
                                let cid = test_cid(*seed);
                                match reader.get(&cid) {
                                    Ok(Some(actual)) => {
                                        assert_eq!(
                                            &actual[..],
                                            &expected_data[..],
                                            "data mismatch for block {seed}"
                                        );
                                        reads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    }
                                    Ok(None) => {}
                                    Err(e) => panic!("read error for block {seed}: {e}"),
                                }
                            });
                            std::thread::yield_now();
                        });
                    reads.load(std::sync::atomic::Ordering::Relaxed)
                })
            })
            .collect();

        writer_handle.await.unwrap();
        writer_done.store(true, std::sync::atomic::Ordering::Relaxed);

        let read_counts: Vec<u64> = futures::future::join_all(reader_handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        let total_reads: u64 = read_counts.iter().sum();
        assert!(
            total_reads > 0,
            "readers should have completed at least some reads"
        );

        let final_snapshot = written_cids.lock().unwrap().clone();
        assert_eq!(final_snapshot.len(), 50);

        final_snapshot.iter().for_each(|(seed, expected_data)| {
            let cid = test_cid(*seed);
            let actual = reader.get(&cid).unwrap().unwrap();
            assert_eq!(
                &actual[..],
                &expected_data[..],
                "final verification failed for block {seed}"
            );
        });

        harness.shutdown();
    }
}
